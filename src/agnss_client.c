/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * OSCORE A-GNSS client. See agnss_client.h.
 *
 * Wire contract: agnss-schema.md (frozen). The CBOR field keys here mirror that
 * document exactly. The C struct field names below follow the Nordic
 * nrf_modem_gnss.h A-GNSS data structures.
 *
 * VERIFY BEFORE FLASHING: the struct field names/widths/signedness must match
 * the nrf_modem_gnss.h pinned by the project's west manifest. A silent mismatch
 * produces bad fixes rather than a build error for fields that happen to line up
 * by type. This is the struct-verification risk called out in agnss-design.md.
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <string.h>
#include <errno.h>
#include <nrf_modem_gnss.h>

#include <oscore_cloud/agnss_client.h>
#include <oscore_cloud/cloud_client.h>
#include <oscore_cloud/cbor.h>

/* Mirror of the agnss.Type* bits in the Go server (agnss-schema.md 1.3). */
#define AGNSS_TYPE_UTC        (1U << 0)
#define AGNSS_TYPE_EPHEMERIS  (1U << 1)
#define AGNSS_TYPE_ALMANAC    (1U << 2)
#define AGNSS_TYPE_KLOBUCHAR  (1U << 3)
#define AGNSS_TYPE_NEQUICK    (1U << 4)
#define AGNSS_TYPE_SYSTEM_TIME (1U << 5)
#define AGNSS_TYPE_LOCATION   (1U << 6)
#define AGNSS_TYPE_INTEGRITY  (1U << 7)

#define AGNSS_MAX_SV 32

LOG_MODULE_DECLARE(cloud, CONFIG_APP_CLOUD_LOG_LEVEL);

/* Block2 response accumulation buffer. A full GPS constellation is up to 32
 * ephemerides at ~180 B of CBOR each, which together with the clock/UTC/iono
 * elements reaches ~6 KiB (worst case ~7.4 KiB), so size for 8 KiB. */
static uint8_t resp_buf[8192];
static size_t resp_len;

/* SZX 5 = 512 B blocks. 1024 B (SZX 6) was tried but the OSCORE response fails
 * to decrypt (psa_aead_decrypt -> unexpected_result_from_ext_lib, surfaced as
 * -3); 512 B is the proven-good size shared with the FOTA download path. */
#define AGNSS_BLOCK2_SZX 5

/* ---- request build ------------------------------------------------------ */

static uint32_t request_type_mask(const struct nrf_modem_gnss_agnss_data_frame *req)
{
	uint32_t mask = 0;

	if (req->data_flags & NRF_MODEM_GNSS_AGNSS_GPS_UTC_REQUEST) {
		mask |= AGNSS_TYPE_UTC;
	}
	if (req->data_flags & NRF_MODEM_GNSS_AGNSS_KLOBUCHAR_REQUEST) {
		mask |= AGNSS_TYPE_KLOBUCHAR;
	}
	if (req->data_flags & NRF_MODEM_GNSS_AGNSS_NEQUICK_REQUEST) {
		mask |= AGNSS_TYPE_NEQUICK;
	}
	if (req->data_flags & NRF_MODEM_GNSS_AGNSS_GPS_SYS_TIME_AND_SV_TOW_REQUEST) {
		mask |= AGNSS_TYPE_SYSTEM_TIME;
	}
	if (req->data_flags & NRF_MODEM_GNSS_AGNSS_POSITION_REQUEST) {
		mask |= AGNSS_TYPE_LOCATION;
	}
	if (req->data_flags & NRF_MODEM_GNSS_AGNSS_INTEGRITY_REQUEST) {
		mask |= AGNSS_TYPE_INTEGRITY;
	}

	/* Per-system ephemeris/almanac needs (GPS is system index 0). */
	for (int i = 0; i < req->system_count; i++) {
		if (req->system[i].sv_mask_ephe) {
			mask |= AGNSS_TYPE_EPHEMERIS;
		}
		if (req->system[i].sv_mask_alm) {
			mask |= AGNSS_TYPE_ALMANAC;
		}
	}

	return mask;
}

static size_t build_request(uint8_t *buf, size_t bufsz, uint32_t mask)
{
	size_t off = 0;

	if (bufsz < 16) {
		return 0;
	}
	off += cbor_write_map_header(buf + off, 1);
	off += cbor_write_tstr(buf + off, "t", 1);
	off += cbor_write_uint(buf + off, mask);
	return off;
}

/* ---- response accumulation ---------------------------------------------- */

static int accumulate_sink(const uint8_t *data, size_t len, void *ctx)
{
	ARG_UNUSED(ctx);

	if (resp_len + len > sizeof(resp_buf)) {
		LOG_ERR("A-GNSS response exceeds %zu B buffer", sizeof(resp_buf));
		return -ENOMEM;
	}
	memcpy(resp_buf + resp_len, data, len);
	resp_len += len;
	return 0;
}

/* ---- CBOR decode helpers ------------------------------------------------ */

static int read_int(struct cbor_reader *r, int64_t *out)
{
	uint8_t major;
	uint64_t arg;
	int err = cbor_read_head(r, &major, &arg);

	if (err) {
		return err;
	}
	if (major == CBOR_MAJOR_UINT) {
		*out = (int64_t)arg;
	} else if (major == CBOR_MAJOR_NINT) {
		*out = -1 - (int64_t)arg;
	} else {
		return -EINVAL;
	}
	return 0;
}

/* Read a text-string map key into buf (NUL-terminated). */
static int read_key(struct cbor_reader *r, char *buf, size_t bufsz)
{
	uint8_t major;
	uint64_t arg;
	int err = cbor_read_head(r, &major, &arg);

	if (err) {
		return err;
	}
	if (major != CBOR_MAJOR_TSTR || arg >= bufsz || (r->pos + arg) > r->len) {
		return -EINVAL;
	}
	memcpy(buf, r->buf + r->pos, arg);
	buf[arg] = '\0';
	r->pos += (size_t)arg;
	return 0;
}

/* Read a map/array header of the expected major type and return its count. */
static int read_container(struct cbor_reader *r, uint8_t expect_major, uint64_t *count)
{
	uint8_t major;
	int err = cbor_read_head(r, &major, count);

	if (err) {
		return err;
	}
	return (major == expect_major) ? 0 : -EINVAL;
}

/* ---- element parsers ---------------------------------------------------- */

/* Parsed assistance held until all CBOR elements are decoded. */
struct agnss_decoded {
	bool have_clk;
	bool have_utc;
	bool have_iono;
	struct nrf_modem_gnss_agnss_gps_data_system_time_and_sv_tow clk;
	struct nrf_modem_gnss_agnss_gps_data_utc utc;
	struct nrf_modem_gnss_agnss_data_klobuchar iono;
	struct nrf_modem_gnss_agnss_gps_data_ephemeris eph[AGNSS_MAX_SV];
	size_t eph_count;
};

static int decode_system_clock(struct cbor_reader *r,
			       struct nrf_modem_gnss_agnss_gps_data_system_time_and_sv_tow *clk,
			       uint64_t *gps_week_out, uint64_t *tow_ms_out)
{
	/* Wire contract (agnss-schema.md) carries GPS week + time-of-week (ms),
	 * the LPP-native shape. The modem's system-time model is day-number +
	 * time-of-day, so convert here. The wire `wn` is the full (era-resolved)
	 * GPS week: the server reconstructs it from the truncated 10-bit RRLP
	 * gpsWeek before encoding, so no rollover handling is needed here.
	 */
	uint64_t gps_week = 0;
	uint64_t tow_ms = 0;
	uint64_t n;
	int err = read_container(r, CBOR_MAJOR_MAP, &n);

	if (err) {
		return err;
	}
	memset(clk, 0, sizeof(*clk));
	for (uint64_t i = 0; i < n; i++) {
		char key[8];
		int64_t v;

		if ((err = read_key(r, key, sizeof(key)))) {
			return err;
		}
		if ((err = read_int(r, &v))) {
			return err;
		}
		if (!strcmp(key, "wn")) {
			gps_week = (uint64_t)v;
		} else if (!strcmp(key, "tow")) {
			tow_ms = (uint64_t)v;
		}
		/* "tdu" (TOW uncertainty) and "clkd" (clock drift) have no field in
		 * the modem system-time model; they are skipped.
		 */
	}

	uint64_t tow_s = tow_ms / 1000U;
	uint64_t total_s = gps_week * 604800U + tow_s;

	clk->date_day = (uint16_t)(total_s / 86400U);
	clk->time_full_s = (uint32_t)(total_s % 86400U);
	clk->time_frac_ms = (uint16_t)(tow_ms % 1000U);
	clk->sv_mask = 0; /* No per-satellite TOW elements in Phase 1. */
	*gps_week_out = gps_week;
	*tow_ms_out = tow_ms;
	return 0;
}

static int write_system_clock(const struct nrf_modem_gnss_agnss_gps_data_system_time_and_sv_tow *clk,
			      uint64_t gps_week, uint64_t tow_ms)
{
	int err;

	LOG_INF("A-GNSS clk: wn=%llu tow_ms=%llu -> day=%u time_s=%u frac_ms=%u",
		gps_week, tow_ms, clk->date_day, clk->time_full_s, clk->time_frac_ms);
	err = nrf_modem_gnss_agnss_write((void *)clk, sizeof(*clk),
					 NRF_MODEM_GNSS_AGNSS_GPS_SYSTEM_CLOCK_AND_TOWS);
	return err;
}

static int decode_utc(struct cbor_reader *r, struct nrf_modem_gnss_agnss_gps_data_utc *utc)
{
	uint64_t n;
	int err = read_container(r, CBOR_MAJOR_MAP, &n);

	if (err) {
		return err;
	}
	memset(utc, 0, sizeof(*utc));
	for (uint64_t i = 0; i < n; i++) {
		char key[8];
		int64_t v;

		if ((err = read_key(r, key, sizeof(key)))) {
			return err;
		}
		if ((err = read_int(r, &v))) {
			return err;
		}
		if (!strcmp(key, "a0")) {
			utc->a0 = (int32_t)v;
		} else if (!strcmp(key, "a1")) {
			utc->a1 = (int32_t)v;
		} else if (!strcmp(key, "dtls")) {
			utc->delta_tls = (int8_t)v;
		} else if (!strcmp(key, "tot")) {
			utc->tot = (uint8_t)v;
		} else if (!strcmp(key, "wnt")) {
			utc->wn_t = (uint8_t)v;
		} else if (!strcmp(key, "wnlsf")) {
			utc->wn_lsf = (uint8_t)v;
		} else if (!strcmp(key, "dn")) {
			utc->dn = (int8_t)v;
		} else if (!strcmp(key, "dtlsf")) {
			utc->delta_tlsf = (int8_t)v;
		}
	}
	return 0;
}

static int write_utc(const struct nrf_modem_gnss_agnss_gps_data_utc *utc)
{
	return nrf_modem_gnss_agnss_write((void *)utc, sizeof(*utc),
					  NRF_MODEM_GNSS_AGNSS_GPS_UTC_PARAMETERS);
}

static int parse_int_array(struct cbor_reader *r, int32_t *out, size_t count)
{
	uint64_t n;
	int err = read_container(r, CBOR_MAJOR_ARRAY, &n);

	if (err) {
		return err;
	}
	if (n != count) {
		return -EINVAL;
	}
	for (uint64_t i = 0; i < n; i++) {
		int64_t v;

		if ((err = read_int(r, &v))) {
			return err;
		}
		out[i] = (int32_t)v;
	}
	return 0;
}

static int decode_klobuchar(struct cbor_reader *r, struct nrf_modem_gnss_agnss_data_klobuchar *kb)
{
	int32_t alpha[4] = { 0 };
	int32_t beta[4] = { 0 };
	uint64_t n;
	int err = read_container(r, CBOR_MAJOR_MAP, &n);

	if (err) {
		return err;
	}
	memset(kb, 0, sizeof(*kb));
	for (uint64_t i = 0; i < n; i++) {
		char key[8];

		if ((err = read_key(r, key, sizeof(key)))) {
			return err;
		}
		if (!strcmp(key, "a")) {
			if ((err = parse_int_array(r, alpha, 4))) {
				return err;
			}
		} else if (!strcmp(key, "b")) {
			if ((err = parse_int_array(r, beta, 4))) {
				return err;
			}
		} else {
			if ((err = cbor_skip(r))) {
				return err;
			}
		}
	}
	kb->alpha0 = (int8_t)alpha[0];
	kb->alpha1 = (int8_t)alpha[1];
	kb->alpha2 = (int8_t)alpha[2];
	kb->alpha3 = (int8_t)alpha[3];
	kb->beta0 = (int8_t)beta[0];
	kb->beta1 = (int8_t)beta[1];
	kb->beta2 = (int8_t)beta[2];
	kb->beta3 = (int8_t)beta[3];
	return 0;
}

static int write_klobuchar(const struct nrf_modem_gnss_agnss_data_klobuchar *kb)
{
	return nrf_modem_gnss_agnss_write((void *)kb, sizeof(*kb),
					  NRF_MODEM_GNSS_AGNSS_KLOBUCHAR_IONOSPHERIC_CORRECTION);
}

static int parse_ephemeris(struct cbor_reader *r, struct nrf_modem_gnss_agnss_gps_data_ephemeris *e)
{
	uint64_t n;
	int err = read_container(r, CBOR_MAJOR_MAP, &n);

	if (err) {
		return err;
	}
	memset(e, 0, sizeof(*e));
	for (uint64_t i = 0; i < n; i++) {
		char key[8];
		int64_t v;

		if ((err = read_key(r, key, sizeof(key)))) {
			return err;
		}
		if ((err = read_int(r, &v))) {
			return err;
		}
		if (!strcmp(key, "sv")) {
			e->sv_id = (uint8_t)v;
		} else if (!strcmp(key, "h")) {
			e->health = (uint8_t)v;
		} else if (!strcmp(key, "iodc")) {
			e->iodc = (uint16_t)v;
		} else if (!strcmp(key, "toc")) {
			e->toc = (uint16_t)v;
		} else if (!strcmp(key, "af2")) {
			e->af2 = (int8_t)v;
		} else if (!strcmp(key, "af1")) {
			e->af1 = (int16_t)v;
		} else if (!strcmp(key, "af0")) {
			e->af0 = (int32_t)v;
		} else if (!strcmp(key, "tgd")) {
			e->tgd = (int8_t)v;
		} else if (!strcmp(key, "ura")) {
			e->ura = (uint8_t)v;
		} else if (!strcmp(key, "fi")) {
			e->fit_int = (uint8_t)v;
		} else if (!strcmp(key, "crs")) {
			e->crs = (int16_t)v;
		} else if (!strcmp(key, "dn")) {
			e->delta_n = (int16_t)v;
		} else if (!strcmp(key, "m0")) {
			e->m0 = (int32_t)v;
		} else if (!strcmp(key, "cuc")) {
			e->cuc = (int16_t)v;
		} else if (!strcmp(key, "e")) {
			e->e = (uint32_t)v;
		} else if (!strcmp(key, "cus")) {
			e->cus = (int16_t)v;
		} else if (!strcmp(key, "sa")) {
			e->sqrt_a = (uint32_t)v;
		} else if (!strcmp(key, "toe")) {
			e->toe = (uint16_t)v;
		} else if (!strcmp(key, "cic")) {
			e->cic = (int16_t)v;
		} else if (!strcmp(key, "om0")) {
			e->omega0 = (int32_t)v;
		} else if (!strcmp(key, "cis")) {
			e->cis = (int16_t)v;
		} else if (!strcmp(key, "i0")) {
			e->i0 = (int32_t)v;
		} else if (!strcmp(key, "crc")) {
			e->crc = (int16_t)v;
		} else if (!strcmp(key, "w")) {
			e->w = (int32_t)v;
		} else if (!strcmp(key, "odot")) {
			e->omega_dot = (int32_t)v;
		} else if (!strcmp(key, "idot")) {
			e->idot = (int16_t)v;
		}
	}
	return 0;
}

static int write_ephemerides(const struct nrf_modem_gnss_agnss_gps_data_ephemeris *eph,
			     size_t count)
{
	int err;

	for (size_t i = 0; i < count; i++) {
		err = nrf_modem_gnss_agnss_write((void *)&eph[i], sizeof(eph[i]),
						 NRF_MODEM_GNSS_AGNSS_GPS_EPHEMERIDES);
		if (err) {
			LOG_ERR("A-GNSS: ephemeris SV %u write failed: %d", eph[i].sv_id, err);
			return err;
		}
	}
	return 0;
}

static int parse_ephemerides(struct cbor_reader *r,
			     struct nrf_modem_gnss_agnss_gps_data_ephemeris *eph, size_t *count)
{
	uint64_t n;
	int err = read_container(r, CBOR_MAJOR_ARRAY, &n);

	if (err) {
		return err;
	}
	if (n > AGNSS_MAX_SV) {
		LOG_WRN("A-GNSS: %llu ephemerides, capping at %d", n, AGNSS_MAX_SV);
		n = AGNSS_MAX_SV;
	}
	for (uint64_t i = 0; i < n; i++) {
		if ((err = parse_ephemeris(r, &eph[i]))) {
			return err;
		}
	}
	*count = (size_t)n;
	return 0;
}

static int decode_and_write(const uint8_t *buf, size_t len)
{
	/* Decode the full map first, then write in modem-required order (clock
	 * before ephemerides). CBOR map key order is not guaranteed on the wire. */
	struct cbor_reader r;
	uint64_t entries;
	int err;
	struct agnss_decoded decoded = { 0 };
	uint64_t gps_week = 0;
	uint64_t tow_ms = 0;

	cbor_reader_init(&r, buf, len);
	err = read_container(&r, CBOR_MAJOR_MAP, &entries);
	if (err) {
		LOG_ERR("A-GNSS response is not a CBOR map: %d", err);
		return err;
	}

	for (uint64_t i = 0; i < entries; i++) {
		char key[8];

		if ((err = read_key(&r, key, sizeof(key)))) {
			return err;
		}
		if (!strcmp(key, "clk")) {
			err = decode_system_clock(&r, &decoded.clk, &gps_week, &tow_ms);
			decoded.have_clk = (err == 0);
		} else if (!strcmp(key, "utc")) {
			err = decode_utc(&r, &decoded.utc);
			decoded.have_utc = (err == 0);
		} else if (!strcmp(key, "iono")) {
			err = decode_klobuchar(&r, &decoded.iono);
			decoded.have_iono = (err == 0);
		} else if (!strcmp(key, "eph")) {
			err = parse_ephemerides(&r, decoded.eph, &decoded.eph_count);
		} else {
			/* "loc" (reference location) and any future element: skip. */
			err = cbor_skip(&r);
		}
		if (err) {
			LOG_ERR("A-GNSS: decode element '%s': %d", key, err);
			return err;
		}
		LOG_DBG("A-GNSS: decoded element '%s'", key);
	}

	if (decoded.have_clk) {
		err = write_system_clock(&decoded.clk, gps_week, tow_ms);
		if (err) {
			LOG_ERR("A-GNSS: clk write failed: %d", err);
			return err;
		}
	} else {
		LOG_WRN("A-GNSS: response had no clk element");
	}
	if (decoded.have_utc) {
		err = write_utc(&decoded.utc);
		if (err) {
			LOG_ERR("A-GNSS: utc write failed: %d", err);
			return err;
		}
	}
	if (decoded.have_iono) {
		err = write_klobuchar(&decoded.iono);
		if (err) {
			LOG_ERR("A-GNSS: iono write failed: %d", err);
			return err;
		}
	} else {
		LOG_WRN("A-GNSS: response had no iono element");
	}
	if (decoded.eph_count > 0) {
		err = write_ephemerides(decoded.eph, decoded.eph_count);
		if (err) {
			return err;
		}
		LOG_INF("A-GNSS: wrote %zu ephemerides", decoded.eph_count);
	}

	return 0;
}

/* ---- public API --------------------------------------------------------- */

int agnss_client_fetch(const struct nrf_modem_gnss_agnss_data_frame *req)
{
	uint8_t req_buf[16];
	size_t req_size;
	uint32_t mask;
	int err;

	if (!req) {
		return -EINVAL;
	}

	mask = request_type_mask(req);
	LOG_DBG("A-GNSS request: data_flags=0x%x type mask=0x%x", req->data_flags, mask);

	req_size = build_request(req_buf, sizeof(req_buf), mask);
	if (req_size == 0) {
		return -ENOMEM;
	}

	resp_len = 0;
	err = cloud_client_oscore_block2_post("a", req_buf, req_size, AGNSS_BLOCK2_SZX,
					      accumulate_sink, NULL);
	if (err) {
		LOG_ERR("A-GNSS Block2 POST /a failed: %d", err);
		return err;
	}

	LOG_DBG("A-GNSS: received %zu B assistance", resp_len);
	if (resp_len == 0) {
		LOG_WRN("A-GNSS: empty assistance response");
		return 0;
	}

	err = decode_and_write(resp_buf, resp_len);
	if (err) {
		LOG_ERR("A-GNSS: decode/write failed: %d", err);
		return err;
	}

	LOG_INF("A-GNSS assistance applied to modem");
	return 0;
}
