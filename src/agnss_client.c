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

#if defined(CONFIG_OSCORE_CLOUD_AGNSS_GALILEO) && defined(CONFIG_SETTINGS)
#include <zephyr/settings/settings.h>
#endif
#if defined(CONFIG_OSCORE_CLOUD_AGNSS_GALILEO) && defined(CONFIG_SHELL)
#include <zephyr/shell/shell.h>
#include <zephyr/sys/reboot.h>
#endif

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
#define AGNSS_TYPE_GAL_EPHEMERIS (1U << 8)
#define AGNSS_TYPE_GGTO       (1U << 9)
#define AGNSS_TYPE_GAL_ALMANAC (1U << 10)

#define AGNSS_MAX_SV 32
#define AGNSS_MAX_GAL_SV 36

LOG_MODULE_REGISTER(agnss_client, CONFIG_OSCORE_CLOUD_LOG_LEVEL);

/* Block2 response accumulation buffer. A full GPS constellation is up to 32
 * ephemerides at ~180 B of CBOR each, which together with the clock/UTC/iono
 * elements reaches ~6 KiB (worst case ~7.4 KiB), so size for 8 KiB. Galileo
 * adds up to 36 more ephemerides (~150 B text-key, ~110 B compact), so an
 * unpruned ("all") text-key response needs ~13 KiB. Pruned compact responses
 * stay far below either (9 GPS + 9 GAL = 1.4 KiB). */
#if defined(CONFIG_OSCORE_CLOUD_AGNSS_GALILEO)
static uint8_t resp_buf[14336];
#else
static uint8_t resp_buf[8192];
#endif
static size_t resp_len;

/* Block2 size shared with the FOTA and P-GPS downloads (see the Kconfig help). */
#define AGNSS_BLOCK2_SZX CONFIG_OSCORE_CLOUD_BLOCK2_SZX

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

	if (req->data_flags & NRF_MODEM_GNSS_AGNSS_GGTO_REQUEST) {
		mask |= AGNSS_TYPE_GGTO;
	}

	/* Per-system ephemeris/almanac needs. GPS and QZSS share the GPS bits;
	 * Galileo has its own (old servers ignore them). */
	for (int i = 0; i < req->system_count; i++) {
		bool gal = (req->system[i].system_id == NRF_MODEM_GNSS_SYSTEM_GAL);

		if (req->system[i].sv_mask_ephe) {
			mask |= gal ? AGNSS_TYPE_GAL_EPHEMERIS : AGNSS_TYPE_EPHEMERIS;
		}
		if (req->system[i].sv_mask_alm) {
			mask |= gal ? AGNSS_TYPE_GAL_ALMANAC : AGNSS_TYPE_ALMANAC;
		}
	}

	return mask;
}

/* Galileo ephemeris need of the frame (request key "ge"), 0 if none. */
static uint64_t request_gal_ephe_mask(const struct nrf_modem_gnss_agnss_data_frame *req)
{
	for (int i = 0; i < req->system_count; i++) {
		if (req->system[i].system_id == NRF_MODEM_GNSS_SYSTEM_GAL) {
			return req->system[i].sv_mask_ephe;
		}
	}
	return 0;
}

#if defined(CONFIG_OSCORE_CLOUD_AGNSS_GALILEO)
/* Same margin the Location library uses for GPS (method_gnss.c
 * AGNSS_EXPIRY_THRESHOLD): data expiring within 80 min counts as needed. */
#define GAL_EXPIRY_THRESHOLD_MIN 80
#define GAL_ALL_SV_MASK 0xFFFFFFFFFULL /* E1..E36 */

/* Test switch (shell "agnss gal on|off", persisted in settings key
 * "agnss/gal_off") to compare TTFF with and without Galileo assistance. */
#define GAL_OFF_SETTINGS_KEY "agnss/gal_off"
static bool gal_off;

#if defined(CONFIG_SETTINGS)
static int u8_load_cb(const char *key, size_t len, settings_read_cb read_cb, void *cb_arg,
		      void *param)
{
	uint8_t v = 0;

	ARG_UNUSED(key);
	if (len == sizeof(v) && read_cb(cb_arg, &v, sizeof(v)) == sizeof(v)) {
		*(uint8_t *)param = v;
	}
	return 0;
}
#endif

static bool galileo_disabled(void)
{
#if defined(CONFIG_SETTINGS)
	static bool loaded;

	if (!loaded) {
		uint8_t v = 0;

		loaded = true;
		(void)settings_load_subtree_direct(GAL_OFF_SETTINGS_KEY, u8_load_cb, &v);
		gal_off = (v != 0);
	}
#endif
	return gal_off;
}

/*
 * GALILEO-LOCLIB-GAP: the NCS Location library (lib/location/method_gnss.c,
 * nrf 9f9725b23b, 2026-11) builds the A-GNSS need from
 * nrf_modem_gnss_agnss_expiry_get() itself, but only for GPS and QZSS
 * (method_gnss_agnss_expiry_process()), and method_gnss_assistance_request()
 * overwrites data_flags without NRF_MODEM_GNSS_AGNSS_GGTO_REQUEST. So on an
 * nRF92 the frame we get never asks for Galileo. Nordic confirmed the library
 * needs work there. Until it does, re-read the expiry here and add the
 * Galileo ephemeris need and the GGTO flag ourselves.
 *
 * When the Location library starts emitting a NRF_MODEM_GNSS_SYSTEM_GAL entry
 * or the GGTO flag, the LOG_WRN below fires: delete this function (and the
 * pointer in att cloud_location.c).
 */
static void augment_galileo_need(struct nrf_modem_gnss_agnss_data_frame *frame)
{
	static bool loclib_warned;
	struct nrf_modem_gnss_agnss_expiry expiry;
	uint64_t gal_ephe = 0;
	bool gal_seen = false;
	bool gps_ephe = false;
	int err;

	bool loclib_has_gal = (frame->data_flags & NRF_MODEM_GNSS_AGNSS_GGTO_REQUEST) != 0;

	if (galileo_disabled()) {
		LOG_INF("A-GNSS: Galileo assistance disabled (agnss gal off)");
		return;
	}

	for (int i = 0; i < frame->system_count; i++) {
		if (frame->system[i].system_id == NRF_MODEM_GNSS_SYSTEM_GAL) {
			loclib_has_gal = true;
		}
		if (frame->system[i].system_id == NRF_MODEM_GNSS_SYSTEM_GPS &&
		    frame->system[i].sv_mask_ephe) {
			gps_ephe = true;
		}
	}
	if (loclib_has_gal) {
		if (!loclib_warned) {
			LOG_WRN("Location lib now requests Galileo itself; "
				"remove augment_galileo_need() (GALILEO-LOCLIB-GAP)");
			loclib_warned = true;
		}
		return;
	}

	err = nrf_modem_gnss_agnss_expiry_get(&expiry);
	if (err) {
		LOG_WRN("A-GNSS: expiry_get failed (%d), no Galileo need", err);
		return;
	}

	for (int i = 0; i < expiry.sv_count; i++) {
		if (expiry.sv[i].system_id != NRF_MODEM_GNSS_SYSTEM_GAL) {
			continue;
		}
		gal_seen = true;
		if (expiry.sv[i].sv_id >= 1 && expiry.sv[i].sv_id <= AGNSS_MAX_GAL_SV &&
		    expiry.sv[i].ephe_expiry <= GAL_EXPIRY_THRESHOLD_MIN) {
			gal_ephe |= 1ULL << (expiry.sv[i].sv_id - 1);
		}
	}
	if (!gal_seen) {
		LOG_DBG("A-GNSS: modem reports no Galileo SVs, not requesting Galileo");
		return;
	}

	/* Like QZSS in the Location library: whenever GPS ephemerides are
	 * fetched, fetch all Galileo ones too (the download is cheap after
	 * server-side pruning). */
	if (gps_ephe) {
		gal_ephe = GAL_ALL_SV_MASK;
	}
	if (gal_ephe && frame->system_count < NRF_MODEM_GNSS_MAX_SYSTEMS) {
		struct nrf_modem_gnss_agnss_system_data_need *sys =
			&frame->system[frame->system_count++];

		sys->system_id = NRF_MODEM_GNSS_SYSTEM_GAL;
		sys->sv_mask_ephe = gal_ephe;
		sys->sv_mask_alm = 0; /* Galileo almanacs are not served */
	}
	if (gal_ephe || expiry.ggto_expiry <= GAL_EXPIRY_THRESHOLD_MIN) {
		frame->data_flags |= NRF_MODEM_GNSS_AGNSS_GGTO_REQUEST;
	}
	/* NeQuick is Galileo's ionosphere model; the Location library already
	 * asks for it in its request-everything set, but be explicit. */
	if (gal_ephe) {
		frame->data_flags |= NRF_MODEM_GNSS_AGNSS_NEQUICK_REQUEST;
	}
	LOG_INF("A-GNSS: Galileo need ephe=0x%llx ggto_expiry=%u min (added to request)",
		gal_ephe, expiry.ggto_expiry);
}
#endif /* CONFIG_OSCORE_CLOUD_AGNSS_GALILEO */

/* Worst-case request: map header + t/w/e/n/all/ge + a position hint (two
 * float64) or a serving cell (mcc/mnc/tac/ci/rp/ta): ~90 B. 128 B is
 * comfortable. */
#define AGNSS_REQ_BUF 128

static size_t build_request(uint8_t *buf, size_t bufsz, uint32_t mask, uint64_t gal_mask,
			    const struct agnss_fetch_opts *o)
{
	size_t off = 0;
	bool pos = o->have_pos;
	bool cell = !pos && o->have_cell;

	/* Count map entries: t, w, e are always present. */
	size_t n = 3;

	if (o->max_sv > 0) {
		n++;
	}
	if (o->all) {
		n++;
	}
	if (gal_mask) {
		n++;
	}
	if (pos) {
		n += 3; /* lat, lon, unc */
	} else if (cell) {
		n += 4; /* mcc, mnc, tac, ci */
		if (o->rsrp != 0) {
			n++;
		}
		if (o->ta != 0) {
			n++;
		}
	}

	if (bufsz < AGNSS_REQ_BUF) {
		return 0;
	}

	off += cbor_write_map_header(buf + off, n);
	off += cbor_write_tstr(buf + off, "t", 1);
	off += cbor_write_uint(buf + off, mask);
	off += cbor_write_tstr(buf + off, "w", 1);
	off += cbor_write_uint(buf + off, o->window_s);
	off += cbor_write_tstr(buf + off, "e", 1);
	off += cbor_write_uint(buf + off, o->encoding);
	if (o->max_sv > 0) {
		off += cbor_write_tstr(buf + off, "n", 1);
		off += cbor_write_uint(buf + off, o->max_sv);
	}
	if (o->all) {
		off += cbor_write_tstr(buf + off, "all", 3);
		off += cbor_write_bool(buf + off, true);
	}
	if (gal_mask) {
		off += cbor_write_tstr(buf + off, "ge", 2);
		off += cbor_write_uint(buf + off, gal_mask);
	}
	if (pos) {
		off += cbor_write_tstr(buf + off, "lat", 3);
		off += cbor_write_double(buf + off, o->lat);
		off += cbor_write_tstr(buf + off, "lon", 3);
		off += cbor_write_double(buf + off, o->lon);
		off += cbor_write_tstr(buf + off, "unc", 3);
		off += cbor_write_uint(buf + off, o->unc_m);
	} else if (cell) {
		off += cbor_write_tstr(buf + off, "mcc", 3);
		off += cbor_write_uint(buf + off, o->mcc);
		off += cbor_write_tstr(buf + off, "mnc", 3);
		off += cbor_write_uint(buf + off, o->mnc);
		off += cbor_write_tstr(buf + off, "tac", 3);
		off += cbor_write_uint(buf + off, o->tac);
		off += cbor_write_tstr(buf + off, "ci", 2);
		off += cbor_write_uint(buf + off, o->ci);
		if (o->rsrp != 0) {
			off += cbor_write_tstr(buf + off, "rp", 2);
			off += cbor_write_int(buf + off, o->rsrp);
		}
		if (o->ta != 0) {
			off += cbor_write_tstr(buf + off, "ta", 2);
			off += cbor_write_uint(buf + off, o->ta);
		}
	}
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
	bool have_loc;
	struct nrf_modem_gnss_agnss_gps_data_system_time_and_sv_tow clk;
	struct nrf_modem_gnss_agnss_gps_data_utc utc;
	struct nrf_modem_gnss_agnss_data_klobuchar iono;
	struct nrf_modem_gnss_agnss_data_location loc;
	struct nrf_modem_gnss_agnss_gps_data_ephemeris eph[AGNSS_MAX_SV];
	size_t eph_count;
#if defined(CONFIG_OSCORE_CLOUD_AGNSS_GALILEO)
	bool have_neq;
	bool have_ggto;
	struct nrf_modem_gnss_agnss_data_nequick neq;
	struct nrf_modem_gnss_agnss_data_ggto ggto;
	struct nrf_modem_gnss_agnss_gal_data_ephemeris gal_eph[AGNSS_MAX_GAL_SV];
	size_t gal_eph_count;
#endif
};

/* Read a CBOR double (major 7, additional info 27 / 0xfb). The server always
 * encodes reference-position lat/lon as float64 (agnss cbor.go encFloat). */
static int read_double(struct cbor_reader *r, double *out)
{
	uint8_t major;
	uint64_t arg;
	int err = cbor_read_head(r, &major, &arg);

	if (err) {
		return err;
	}
	if (major != CBOR_MAJOR_SIMPLE) {
		return -EINVAL;
	}
	union {
		uint64_t u;
		double d;
	} v;

	v.u = arg;
	*out = v.d;
	return 0;
}

/* Encode a 1-sigma horizontal uncertainty (metres) into the 3GPP TS 23.032
 * "uncertainty code" K used by nrf_modem_gnss_agnss_data_location: the decoded
 * radius is r = 10 * (1.1^K - 1) m. Return the smallest K whose radius covers
 * the requested value (never under-state the uncertainty), clamped to 0..127. */
static uint8_t encode_uncertainty(uint32_t r_m)
{
	double factor = 1.0; /* 1.1^K */

	for (uint8_t k = 0; k < 127; k++) {
		if (10.0 * (factor - 1.0) >= (double)r_m) {
			return k;
		}
		factor *= 1.1;
	}
	return 127;
}

static int32_t round_to_i32(double x)
{
	return (int32_t)(x >= 0.0 ? x + 0.5 : x - 0.5);
}

/* Fill the modem location-assistance struct from geodetic degrees + a 1-sigma
 * horizontal uncertainty. Latitude codes at 2^23/90, longitude at 2^24/360
 * (nrf_modem_gnss.h). Altitude is left unknown (unc_altitude = 255). */
static void fill_location(struct nrf_modem_gnss_agnss_data_location *l,
			  double lat, double lon, uint32_t unc_m)
{
	int32_t lat_n = round_to_i32(lat * (8388608.0 / 90.0));
	int32_t lon_n = round_to_i32(lon * (16777216.0 / 360.0));

	if (lat_n > 8388607) {
		lat_n = 8388607;
	} else if (lat_n < -8388607) {
		lat_n = -8388607;
	}
	if (lon_n > 8388607) {
		lon_n = 8388607;
	} else if (lon_n < -8388607) {
		lon_n = -8388607;
	}

	memset(l, 0, sizeof(*l));
	l->latitude = lat_n;
	l->longitude = lon_n;
	l->altitude = 0;
	l->unc_semimajor = encode_uncertainty(unc_m);
	l->unc_semiminor = l->unc_semimajor;
	l->orientation_major = 0;
	l->unc_altitude = 255; /* altitude unknown */
	l->confidence = 68;    /* 1-sigma */
}

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

/* Text-key reference location: map { lat: f64, lon: f64, unc: uint }. */
static int decode_location(struct cbor_reader *r, struct nrf_modem_gnss_agnss_data_location *l)
{
	double lat = 0, lon = 0;
	uint32_t unc = 0;
	uint64_t n;
	int err = read_container(r, CBOR_MAJOR_MAP, &n);

	if (err) {
		return err;
	}
	for (uint64_t i = 0; i < n; i++) {
		char key[8];

		if ((err = read_key(r, key, sizeof(key)))) {
			return err;
		}
		if (!strcmp(key, "lat")) {
			if ((err = read_double(r, &lat))) {
				return err;
			}
		} else if (!strcmp(key, "lon")) {
			if ((err = read_double(r, &lon))) {
				return err;
			}
		} else if (!strcmp(key, "unc")) {
			int64_t v;

			if ((err = read_int(r, &v))) {
				return err;
			}
			unc = (uint32_t)v;
		} else {
			if ((err = cbor_skip(r))) {
				return err;
			}
		}
	}
	fill_location(l, lat, lon, unc);
	return 0;
}

/* Compact reference location: array [ lat: f64, lon: f64, unc: uint ]. */
static int decode_location_compact(struct cbor_reader *r,
				   struct nrf_modem_gnss_agnss_data_location *l)
{
	double lat = 0, lon = 0;
	int64_t unc = 0;
	uint64_t n;
	int err = read_container(r, CBOR_MAJOR_ARRAY, &n);

	if (err) {
		return err;
	}
	if (n != 3) {
		return -EINVAL;
	}
	if ((err = read_double(r, &lat)) || (err = read_double(r, &lon)) ||
	    (err = read_int(r, &unc))) {
		return err;
	}
	fill_location(l, lat, lon, (uint32_t)unc);
	return 0;
}

static int write_location(const struct nrf_modem_gnss_agnss_data_location *l)
{
	LOG_INF("A-GNSS loc: lat_n=%d lon_n=%d unc_smaj=%u", l->latitude, l->longitude,
		l->unc_semimajor);
	return nrf_modem_gnss_agnss_write((void *)l, sizeof(*l),
					  NRF_MODEM_GNSS_AGNSS_LOCATION);
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

/* ---- compact positional-array element parsers (agnss-schema.md 1.4) ------ */

/* Read a fixed-length CBOR array of signed integers into out[0..count). */
static int read_int_array(struct cbor_reader *r, int64_t *out, size_t count)
{
	uint64_t n;
	int err = read_container(r, CBOR_MAJOR_ARRAY, &n);

	if (err) {
		return err;
	}
	if (n != count) {
		return -EINVAL;
	}
	for (uint64_t i = 0; i < count; i++) {
		if ((err = read_int(r, &out[i]))) {
			return err;
		}
	}
	return 0;
}

static int decode_system_clock_compact(struct cbor_reader *r,
			       struct nrf_modem_gnss_agnss_gps_data_system_time_and_sv_tow *clk,
			       uint64_t *gps_week_out, uint64_t *tow_ms_out)
{
	int64_t v[4]; /* wn, tow, tdu, clkd */
	int err = read_int_array(r, v, 4);

	if (err) {
		return err;
	}
	uint64_t gps_week = (uint64_t)v[0];
	uint64_t tow_ms = (uint64_t)v[1];

	memset(clk, 0, sizeof(*clk));
	uint64_t tow_s = tow_ms / 1000U;
	uint64_t total_s = gps_week * 604800U + tow_s;

	clk->date_day = (uint16_t)(total_s / 86400U);
	clk->time_full_s = (uint32_t)(total_s % 86400U);
	clk->time_frac_ms = (uint16_t)(tow_ms % 1000U);
	clk->sv_mask = 0;
	*gps_week_out = gps_week;
	*tow_ms_out = tow_ms;
	return 0;
}

static int decode_utc_compact(struct cbor_reader *r, struct nrf_modem_gnss_agnss_gps_data_utc *utc)
{
	int64_t v[8]; /* a0, a1, dtls, tot, wnt, wnlsf, dn, dtlsf */
	int err = read_int_array(r, v, 8);

	if (err) {
		return err;
	}
	memset(utc, 0, sizeof(*utc));
	utc->a0 = (int32_t)v[0];
	utc->a1 = (int32_t)v[1];
	utc->delta_tls = (int8_t)v[2];
	utc->tot = (uint8_t)v[3];
	utc->wn_t = (uint8_t)v[4];
	utc->wn_lsf = (uint8_t)v[5];
	utc->dn = (int8_t)v[6];
	utc->delta_tlsf = (int8_t)v[7];
	return 0;
}

static int decode_klobuchar_compact(struct cbor_reader *r,
				    struct nrf_modem_gnss_agnss_data_klobuchar *kb)
{
	int64_t v[8]; /* a0..a3, b0..b3 */
	int err = read_int_array(r, v, 8);

	if (err) {
		return err;
	}
	memset(kb, 0, sizeof(*kb));
	kb->alpha0 = (int8_t)v[0];
	kb->alpha1 = (int8_t)v[1];
	kb->alpha2 = (int8_t)v[2];
	kb->alpha3 = (int8_t)v[3];
	kb->beta0 = (int8_t)v[4];
	kb->beta1 = (int8_t)v[5];
	kb->beta2 = (int8_t)v[6];
	kb->beta3 = (int8_t)v[7];
	return 0;
}

/* Frozen 27-field order, mirrors the Go EncodeBundleCompact / agnss-schema.md 1.4. */
static int parse_ephemeris_compact(struct cbor_reader *r,
				   struct nrf_modem_gnss_agnss_gps_data_ephemeris *e)
{
	int64_t v[27];
	int err = read_int_array(r, v, 27);

	if (err) {
		return err;
	}
	memset(e, 0, sizeof(*e));
	e->sv_id = (uint8_t)v[0];
	e->health = (uint8_t)v[1];
	e->iodc = (uint16_t)v[2];
	e->toc = (uint16_t)v[3];
	e->af2 = (int8_t)v[4];
	e->af1 = (int16_t)v[5];
	e->af0 = (int32_t)v[6];
	e->tgd = (int8_t)v[7];
	e->ura = (uint8_t)v[8];
	e->fit_int = (uint8_t)v[9];
	/* v[10] = iode: no modem field */
	e->crs = (int16_t)v[11];
	e->delta_n = (int16_t)v[12];
	e->m0 = (int32_t)v[13];
	e->cuc = (int16_t)v[14];
	e->e = (uint32_t)v[15];
	e->cus = (int16_t)v[16];
	e->sqrt_a = (uint32_t)v[17];
	e->toe = (uint16_t)v[18];
	e->cic = (int16_t)v[19];
	e->omega0 = (int32_t)v[20];
	e->cis = (int16_t)v[21];
	e->i0 = (int32_t)v[22];
	e->crc = (int16_t)v[23];
	e->w = (int32_t)v[24];
	e->omega_dot = (int32_t)v[25];
	e->idot = (int16_t)v[26];
	return 0;
}

static int parse_ephemerides_compact(struct cbor_reader *r,
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
		if ((err = parse_ephemeris_compact(r, &eph[i]))) {
			return err;
		}
	}
	*count = (size_t)n;
	return 0;
}

#if defined(CONFIG_OSCORE_CLOUD_AGNSS_GALILEO)
/* ---- Galileo elements (agnss-schema.md 1.2 neq/ggto/geph, 1.4 compact) ---- */

/* Key tables in the FROZEN compact order (= modem struct field order). The
 * text-key form carries the same fields by name, so both encodings decode
 * into one int64 array and share a single struct fill. */
static const char *const neq_keys[] = { "ai0", "ai1", "ai2", "sc", "sv" };
static const char *const ggto_keys[] = { "a0", "a1", "t0g", "wn" };
static const char *const geph_keys[] = {
	"sv", "toc", "af2", "af1", "af0", "tgd", "sisa", "toe", "w", "dn", "m0", "odot",
	"e", "idot", "sa", "i0", "om0", "crs", "cis", "cus", "crc", "cic", "cuc",
};
#define GEPH_FIELDS ARRAY_SIZE(geph_keys)

/* Read one element as ints in table order: a fixed-length array (compact) or
 * a text-key map (unknown keys skipped, missing keys left 0). */
static int read_fields(struct cbor_reader *r, bool compact, const char *const *keys,
		       size_t nkeys, int64_t *v)
{
	uint64_t n;
	int err;

	memset(v, 0, nkeys * sizeof(*v));
	if (compact) {
		return read_int_array(r, v, nkeys);
	}
	err = read_container(r, CBOR_MAJOR_MAP, &n);
	if (err) {
		return err;
	}
	for (uint64_t i = 0; i < n; i++) {
		char key[8];
		size_t k;

		if ((err = read_key(r, key, sizeof(key)))) {
			return err;
		}
		for (k = 0; k < nkeys && strcmp(key, keys[k]); k++) {
		}
		err = (k < nkeys) ? read_int(r, &v[k]) : cbor_skip(r);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int decode_nequick(struct cbor_reader *r, bool compact,
			  struct nrf_modem_gnss_agnss_data_nequick *q)
{
	int64_t v[ARRAY_SIZE(neq_keys)];
	int err = read_fields(r, compact, neq_keys, ARRAY_SIZE(neq_keys), v);

	if (err) {
		return err;
	}
	q->ai0 = (int16_t)v[0];
	q->ai1 = (int16_t)v[1];
	q->ai2 = (int16_t)v[2];
	q->storm_cond = (uint8_t)v[3];
	q->storm_valid = (uint8_t)v[4];
	return 0;
}

static int decode_ggto(struct cbor_reader *r, bool compact,
		       struct nrf_modem_gnss_agnss_data_ggto *g)
{
	int64_t v[ARRAY_SIZE(ggto_keys)];
	int err = read_fields(r, compact, ggto_keys, ARRAY_SIZE(ggto_keys), v);

	if (err) {
		return err;
	}
	g->a0 = (int16_t)v[0];
	g->a1 = (int16_t)v[1];
	g->t0g = (uint16_t)v[2];
	g->wn = (uint16_t)v[3];
	return 0;
}

static int decode_gal_ephemerides(struct cbor_reader *r, bool compact,
				  struct nrf_modem_gnss_agnss_gal_data_ephemeris *eph, size_t *count)
{
	uint64_t n;
	int err = read_container(r, CBOR_MAJOR_ARRAY, &n);

	if (err) {
		return err;
	}
	*count = 0;
	for (uint64_t i = 0; i < n; i++) {
		int64_t v[GEPH_FIELDS];
		struct nrf_modem_gnss_agnss_gal_data_ephemeris *e;

		if ((err = read_fields(r, compact, geph_keys, GEPH_FIELDS, v))) {
			return err;
		}
		if (*count >= AGNSS_MAX_GAL_SV) {
			continue; /* keep consuming; cap reached */
		}
		e = &eph[(*count)++];
		memset(e, 0, sizeof(*e));
		e->sv_id = (uint8_t)v[0];
		e->toc = (uint16_t)v[1];
		e->af2 = (int8_t)v[2];
		e->af1 = (int32_t)v[3];
		e->af0 = (int32_t)v[4];
		e->tgd = (int16_t)v[5];
		e->sisa = (uint8_t)v[6];
		e->toe = (uint16_t)v[7];
		e->w = (int32_t)v[8];
		e->delta_n = (int16_t)v[9];
		e->m0 = (int32_t)v[10];
		e->omega_dot = (int32_t)v[11];
		e->e = (uint32_t)v[12];
		e->idot = (int16_t)v[13];
		e->sqrt_a = (uint32_t)v[14];
		e->i0 = (int32_t)v[15];
		e->omega0 = (int32_t)v[16];
		e->crs = (int16_t)v[17];
		e->cis = (int16_t)v[18];
		e->cus = (int16_t)v[19];
		e->crc = (int16_t)v[20];
		e->cic = (int16_t)v[21];
		e->cuc = (int16_t)v[22];
	}
	return 0;
}

/* Write the Galileo ionosphere and time offset. Optional refinements like
 * UTC/iono: a rejection is logged and the apply continues. */
static void write_galileo_aux(const struct agnss_decoded *d)
{
	int err;

	if (d->have_neq) {
		err = nrf_modem_gnss_agnss_write((void *)&d->neq, sizeof(d->neq),
						 NRF_MODEM_GNSS_AGNSS_NEQUICK_IONOSPHERIC_CORRECTION);
		if (err) {
			LOG_WRN("A-GNSS: nequick write failed: %d (continuing)", err);
		}
	}
	if (d->have_ggto) {
		/* GGTO is the LPP time model (3GPP TS 36.355
		 * GNSS-TimeModelElement): t0g (16 s LSB) and wn are a time tag in
		 * Galileo System Time, so wn is the GST week (GPS week - 1024). With
		 * the GPS week the modem tracks Galileo but drops every SV from the
		 * fix. The server already sends it that way (agnss-schema.md ggto),
		 * so the element is written unchanged. */
		err = nrf_modem_gnss_agnss_write((void *)&d->ggto, sizeof(d->ggto),
						 NRF_MODEM_GNSS_AGNSS_GGTO);
		if (err) {
			LOG_WRN("A-GNSS: ggto write failed: %d (continuing)", err);
		} else {
			LOG_DBG("A-GNSS: ggto a0=%d a1=%d t0g=%u wn=%u", d->ggto.a0, d->ggto.a1,
				d->ggto.t0g, d->ggto.wn);
		}
	}
}

/* Galileo ephemerides are supplementary: a rejected SV is logged and skipped
 * so it cannot cost the GPS ephemerides already written. */
static void write_gal_ephemerides(const struct nrf_modem_gnss_agnss_gal_data_ephemeris *eph,
				  size_t count)
{
	size_t ok = 0;

	for (size_t i = 0; i < count; i++) {
		int err = nrf_modem_gnss_agnss_write((void *)&eph[i], sizeof(eph[i]),
						     NRF_MODEM_GNSS_AGNSS_GAL_EPHEMERIDES);
		if (err) {
			LOG_WRN("A-GNSS: Galileo E%02u ephemeris write failed: %d", eph[i].sv_id,
				err);
		} else {
			ok++;
		}
	}
	LOG_INF("A-GNSS: wrote %zu/%zu Galileo ephemerides", ok, count);
}
#endif /* CONFIG_OSCORE_CLOUD_AGNSS_GALILEO */

static int decode_and_write(const uint8_t *buf, size_t len, uint8_t encoding)
{
	/* Decode the full map first, then write in modem-required order (clock
	 * before ephemerides). CBOR map key order is not guaranteed on the wire. */
	struct cbor_reader r;
	uint64_t entries;
	int err;
	/* Static: with Galileo the decoded set is ~4.5 KiB, too much for the
	 * caller's stack. Fetches are serialized (resp_buf is static too). */
	static struct agnss_decoded decoded;
	uint64_t gps_week = 0;
	uint64_t tow_ms = 0;
	bool compact = (encoding == 1);

	memset(&decoded, 0, sizeof(decoded));
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
			err = compact ? decode_system_clock_compact(&r, &decoded.clk, &gps_week, &tow_ms)
				      : decode_system_clock(&r, &decoded.clk, &gps_week, &tow_ms);
			decoded.have_clk = (err == 0);
		} else if (!strcmp(key, "utc")) {
			err = compact ? decode_utc_compact(&r, &decoded.utc)
				      : decode_utc(&r, &decoded.utc);
			decoded.have_utc = (err == 0);
		} else if (!strcmp(key, "iono")) {
			err = compact ? decode_klobuchar_compact(&r, &decoded.iono)
				      : decode_klobuchar(&r, &decoded.iono);
			decoded.have_iono = (err == 0);
		} else if (!strcmp(key, "loc")) {
			err = compact ? decode_location_compact(&r, &decoded.loc)
				      : decode_location(&r, &decoded.loc);
			decoded.have_loc = (err == 0);
		} else if (!strcmp(key, "eph")) {
			err = compact ? parse_ephemerides_compact(&r, decoded.eph, &decoded.eph_count)
				      : parse_ephemerides(&r, decoded.eph, &decoded.eph_count);
#if defined(CONFIG_OSCORE_CLOUD_AGNSS_GALILEO)
		} else if (!strcmp(key, "neq")) {
			err = decode_nequick(&r, compact, &decoded.neq);
			decoded.have_neq = (err == 0);
		} else if (!strcmp(key, "ggto")) {
			err = decode_ggto(&r, compact, &decoded.ggto);
			decoded.have_ggto = (err == 0);
		} else if (!strcmp(key, "geph")) {
			err = decode_gal_ephemerides(&r, compact, decoded.gal_eph,
						     &decoded.gal_eph_count);
#endif
		} else {
			/* Any future element: skip. */
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
	/* Location, UTC and iono are optional refinements. A modem rejection of any
	 * one of them (e.g. -EINVAL on an out-of-range field) must not abort the
	 * apply and cost us the ephemerides, which are what actually accelerate the
	 * fix — log and continue.
	 */
	if (decoded.have_loc) {
		err = write_location(&decoded.loc);
		if (err) {
			LOG_WRN("A-GNSS: loc write failed: %d (continuing)", err);
		}
	}
	if (decoded.have_utc) {
		err = write_utc(&decoded.utc);
		if (err) {
			LOG_WRN("A-GNSS: utc write failed: %d (continuing)", err);
		}
	}
	if (decoded.have_iono) {
		err = write_klobuchar(&decoded.iono);
		if (err) {
			LOG_WRN("A-GNSS: iono write failed: %d (continuing)", err);
		}
	} else {
		LOG_WRN("A-GNSS: response had no iono element");
	}
#if defined(CONFIG_OSCORE_CLOUD_AGNSS_GALILEO)
	write_galileo_aux(&decoded);
#endif
	if (decoded.eph_count > 0) {
		err = write_ephemerides(decoded.eph, decoded.eph_count);
		if (err) {
			return err;
		}
		LOG_INF("A-GNSS: wrote %zu ephemerides", decoded.eph_count);
	}
#if defined(CONFIG_OSCORE_CLOUD_AGNSS_GALILEO)
	if (decoded.gal_eph_count > 0) {
		write_gal_ephemerides(decoded.gal_eph, decoded.gal_eph_count);
	}
#endif

	return 0;
}

/* ---- public API --------------------------------------------------------- */

int agnss_client_fetch_ex(const struct nrf_modem_gnss_agnss_data_frame *req,
			  const struct agnss_fetch_opts *opts)
{
	uint8_t req_buf[AGNSS_REQ_BUF];
	size_t req_size;
	uint32_t mask;
	int err;
	struct agnss_fetch_opts o;
	struct nrf_modem_gnss_agnss_data_frame frame;

	if (!req) {
		return -EINVAL;
	}
	frame = *req;
#if defined(CONFIG_OSCORE_CLOUD_AGNSS_GALILEO)
	augment_galileo_need(&frame);
#endif

	if (opts) {
		o = *opts;
	} else {
		memset(&o, 0, sizeof(o));
		o.window_s = CONFIG_OSCORE_CLOUD_AGNSS_WINDOW_S_DEFAULT;
		o.max_sv = CONFIG_OSCORE_CLOUD_AGNSS_MAX_SV_DEFAULT;
		o.encoding = IS_ENABLED(CONFIG_OSCORE_CLOUD_AGNSS_COMPACT) ? 1 : 0;
	}

	mask = request_type_mask(&frame);
	LOG_DBG("A-GNSS request: data_flags=0x%x type mask=0x%x w=%u n=%u e=%u",
		frame.data_flags, mask, o.window_s, o.max_sv, o.encoding);

	req_size = build_request(req_buf, sizeof(req_buf), mask, request_gal_ephe_mask(&frame), &o);
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

	err = decode_and_write(resp_buf, resp_len, o.encoding);
	if (err) {
		LOG_ERR("A-GNSS: decode/write failed: %d", err);
		return err;
	}

	LOG_INF("A-GNSS assistance applied to modem");
	return 0;
}

int agnss_client_fetch(const struct nrf_modem_gnss_agnss_data_frame *req)
{
	return agnss_client_fetch_ex(req, NULL);
}

#if defined(CONFIG_OSCORE_CLOUD_AGNSS_GALILEO) && defined(CONFIG_SHELL)
/* ---- test shell: Galileo on/off and forced cold start ------------------- */

static int cmd_agnss_gal(const struct shell *sh, size_t argc, char **argv)
{
	if (argc < 2) {
		(void)galileo_disabled();
		shell_print(sh, "Galileo assistance: %s", gal_off ? "off" : "on");
		return 0;
	}
	if (!strcmp(argv[1], "on")) {
		gal_off = false;
	} else if (!strcmp(argv[1], "off")) {
		gal_off = true;
	} else {
		shell_error(sh, "usage: agnss gal [on|off]");
		return -EINVAL;
	}
#if defined(CONFIG_SETTINGS)
	uint8_t v = gal_off ? 1 : 0;
	int err = settings_save_one(GAL_OFF_SETTINGS_KEY, &v, sizeof(v));

	if (err) {
		shell_warn(sh, "not persisted: settings_save_one %d", err);
	}
#endif
	shell_print(sh, "Galileo assistance: %s", gal_off ? "off" : "on");
	return 0;
}

static int cmd_agnss_cold(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	/* Everything the modem keeps between fixes: ephemerides, almanacs, iono,
	 * last fix, time, UTC, TCXO offset, EKF. GNSS must be stopped (between
	 * location searches). The reboot also resets the Location library's
	 * 60 min A-GNSS request rate limit, so the next search fetches fresh
	 * assistance. */
	int err = nrf_modem_gnss_nv_data_delete(0x5FF);

	if (err) {
		shell_error(sh, "nv_data_delete failed: %d (GNSS running? retry between searches)",
			    err);
		return err;
	}
	shell_print(sh, "GNSS data deleted, rebooting for a cold start");
	k_sleep(K_MSEC(200));
	sys_reboot(SYS_REBOOT_COLD);
	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sub_agnss,
	SHELL_CMD_ARG(gal, NULL, "Galileo assistance [on|off] (persisted)", cmd_agnss_gal, 1, 1),
	SHELL_CMD(cold, NULL, "Delete all GNSS data and reboot (cold start test)", cmd_agnss_cold),
	SHELL_SUBCMD_SET_END);
SHELL_CMD_REGISTER(agnss, &sub_agnss, "A-GNSS test commands", NULL);
#endif /* CONFIG_OSCORE_CLOUD_AGNSS_GALILEO && CONFIG_SHELL */
