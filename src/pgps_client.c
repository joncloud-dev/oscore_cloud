/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * OSCORE predicted-GNSS (P-GPS) client. See pgps_client.h.
 *
 * Wire contract: agnss-schema.md section 3 (frozen). The /p response is a CBOR
 * map { gen, next, win:[ { toe, e:1, eph:[<27-int arrays>] } ] }; each window's
 * ephemerides use the same frozen 27-element compact layout as A-GNSS section
 * 1.4, so the per-SV decode is shared with agnss_client.c.
 *
 * VERIFY BEFORE FLASHING: the modem struct field names/widths/signedness must
 * match the nrf_modem_gnss.h pinned by the west manifest (same caveat as the
 * A-GNSS client). The compact layout below is copied verbatim from the working
 * agnss_client, so it should already agree.
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <string.h>
#include <errno.h>
#include <nrf_modem_gnss.h>
#include <date_time.h>

#include <oscore_cloud/pgps_client.h>
#include <oscore_cloud/pgps_store.h>
#include <oscore_cloud/cloud_client.h>
#include <oscore_cloud/cbor.h>

LOG_MODULE_REGISTER(pgps_client, CONFIG_OSCORE_CLOUD_LOG_LEVEL);

/* PGPS_MAX_SV, PGPS_WINDOW_SPAN, PGPS_WINDOW_HALF and struct pgps_window come
 * from pgps_store.h: the flash slot layout and the RAM view are the same thing.
 */

/* GPS-UTC offset (leap seconds). Only used to bin the current instant into a 4 h
 * window and to stamp the injected system clock; a second of slop is harmless
 * for window selection. Verify periodically. */
#define PGPS_GPS_UTC_LEAP_S 18

/* GPS epoch (1980-01-06T00:00:00Z) as Unix milliseconds. The device wall clock
 * (date_time_now) is Unix time; GPS system time counts from this epoch, and both
 * the /p `from` request field and the modem system clock use continuous GPS
 * seconds since 1980 — matching the Go server's nowGPSSeconds()
 * (time.Now().Unix() - 315964800). */
#define PGPS_GPS_EPOCH_UNIX_MS 315964800000LL

/* SZX 5 = 512 B blocks: the proven-good OSCORE Block2 size shared with A-GNSS
 * and FOTA (1024 B triggers a decrypt failure, see agnss_client.c). */
#define PGPS_BLOCK2_SZX 5

/* Block2 response accumulation buffer. A pruned window is ~16 SV * ~78 B ~=
 * 1.3 KiB, so a six-window batch reaches ~8 KiB; size for headroom. This bounds
 * one batch (CONFIG_OSCORE_CLOUD_PGPS_FETCH_BATCH), not the whole horizon --
 * long fetches are split across several requests. */
static uint8_t resp_buf[12288];
static size_t resp_len;

/* ---- window store ------------------------------------------------------- */

/* Generation metadata from the most recent response. `gen` and `next` always
 * precede `win` in the encoding (see EncodePGPSResponse in the Go server), so a
 * window is always committed with its own generation id. */
static uint32_t last_gen;
static uint32_t last_next;

/* What the last successful injection fed the modem (for soak-test reporting). */
static struct pgps_inject_info last_inject;
static bool have_last_inject;

#ifdef CONFIG_OSCORE_CLOUD_PGPS_STORE

/* Flash-backed: one staging buffer to decode into, one cache holding the window
 * most recently read back for injection. */
static struct pgps_window staging;
static struct pgps_window inject_cache;
static bool inject_cache_valid;

static int store_open(void)
{
	return pgps_store_init();
}

/* Where to decode the next window. Never fails: the flash ring, not RAM, bounds
 * how many windows we can hold. */
static struct pgps_window *window_for_decode(void)
{
	return &staging;
}

static int window_commit(struct pgps_window *w)
{
	int err = pgps_store_put(w->toe, w->gen, w->sv_count, w->eph);

	if (err == 0 && inject_cache_valid && inject_cache.toe == w->toe) {
		/* The cached copy just went stale. */
		inject_cache_valid = false;
	}
	return err;
}

static void window_store_reset(void)
{
	/* Nothing to do: the ring is append-only and self-expiring, and dropping
	 * the whole horizon because one batch failed would be the opposite of
	 * what the store is for. Use `pgps store erase` to wipe it. */
	inject_cache_valid = false;
}

static bool window_have_covering(uint64_t now_s)
{
	return pgps_store_have_covering(now_s);
}

/* Return the window covering now_s, reading it from flash unless the cache
 * already holds it. */
static struct pgps_window *window_find_covering(uint64_t now_s)
{
	uint32_t toe = (uint32_t)((now_s / PGPS_WINDOW_SPAN) * PGPS_WINDOW_SPAN + PGPS_WINDOW_HALF);

	if (inject_cache_valid && inject_cache.toe == toe) {
		return &inject_cache;
	}
	if (pgps_store_get_covering(now_s, &inject_cache) != 0) {
		inject_cache_valid = false;
		return NULL;
	}
	inject_cache_valid = true;
	return &inject_cache;
}

#else /* !CONFIG_OSCORE_CLOUD_PGPS_STORE */

/* RAM-only: windows live in a fixed array for this power cycle. */
static struct pgps_window windows[CONFIG_OSCORE_CLOUD_PGPS_MAX_WINDOWS];
static size_t window_count;

static int store_open(void)
{
	return 0;
}

static struct pgps_window *window_for_decode(void)
{
	if (window_count >= ARRAY_SIZE(windows)) {
		return NULL;
	}
	return &windows[window_count];
}

static int window_commit(struct pgps_window *w)
{
	ARG_UNUSED(w); /* already decoded in place */
	window_count++;
	return 0;
}

static void window_store_reset(void)
{
	window_count = 0;
}

static struct pgps_window *window_find_covering(uint64_t now_s)
{
	for (size_t i = 0; i < window_count; i++) {
		uint32_t toe = windows[i].toe;

		if (now_s + PGPS_WINDOW_HALF >= toe && now_s < (uint64_t)toe + PGPS_WINDOW_HALF) {
			return &windows[i];
		}
	}
	return NULL;
}

static bool window_have_covering(uint64_t now_s)
{
	struct pgps_window *w = window_find_covering(now_s);

	return w != NULL && w->sv_count > 0;
}

#endif /* CONFIG_OSCORE_CLOUD_PGPS_STORE */

/* ---- GPS time ----------------------------------------------------------- */

/* Current GPS time from the device wall clock. Returns false if the wall clock
 * is not yet valid. total_s is continuous GPS seconds; frac_ms the sub-second
 * remainder. */
static bool current_gps_time(uint64_t *total_s, uint16_t *frac_ms)
{
	int64_t now_ms;

	if (date_time_now(&now_ms) != 0) {
		return false;
	}
	/* Unix ms -> continuous GPS seconds since 1980-01-06 (+ leap offset). */
	int64_t gps_ms = now_ms - PGPS_GPS_EPOCH_UNIX_MS + (int64_t)PGPS_GPS_UTC_LEAP_S * 1000;

	if (gps_ms < 0) {
		gps_ms = 0;
	}
	if (total_s) {
		*total_s = (uint64_t)gps_ms / 1000U;
	}
	if (frac_ms) {
		*frac_ms = (uint16_t)((uint64_t)gps_ms % 1000U);
	}
	return true;
}

/* ---- request build ------------------------------------------------------ */

/* Worst-case request: map header + from/n + a position hint (two float64 + unc)
 * + m + mov. 96 B is comfortable. */
#define PGPS_REQ_BUF 96

static size_t build_request(uint8_t *buf, size_t bufsz, const struct pgps_fetch_opts *o,
			    uint32_t from)
{
	size_t off = 0;
	size_t n = 2; /* from, n always present */

	if (o->have_pos) {
		n += 3; /* lat, lon, unc */
	}
	if (o->max_sv > 0) {
		n++;
	}
	if (o->moving) {
		n++;
	}
	if (o->all) {
		n++;
	}

	if (bufsz < PGPS_REQ_BUF) {
		return 0;
	}

	off += cbor_write_map_header(buf + off, n);
	off += cbor_write_tstr(buf + off, "from", 4);
	off += cbor_write_uint(buf + off, from);
	off += cbor_write_tstr(buf + off, "n", 1);
	off += cbor_write_uint(buf + off, o->n);
	if (o->have_pos) {
		off += cbor_write_tstr(buf + off, "lat", 3);
		off += cbor_write_double(buf + off, o->lat);
		off += cbor_write_tstr(buf + off, "lon", 3);
		off += cbor_write_double(buf + off, o->lon);
		off += cbor_write_tstr(buf + off, "unc", 3);
		off += cbor_write_uint(buf + off, o->unc_m);
	}
	if (o->max_sv > 0) {
		off += cbor_write_tstr(buf + off, "m", 1);
		off += cbor_write_uint(buf + off, o->max_sv);
	}
	if (o->moving) {
		off += cbor_write_tstr(buf + off, "mov", 3);
		off += cbor_write_bool(buf + off, true);
	}
	if (o->all) {
		off += cbor_write_tstr(buf + off, "all", 3);
		off += cbor_write_bool(buf + off, true);
	}
	return off;
}

/* ---- response accumulation ---------------------------------------------- */

static int accumulate_sink(const uint8_t *data, size_t len, void *ctx)
{
	ARG_UNUSED(ctx);

	if (resp_len + len > sizeof(resp_buf)) {
		LOG_ERR("P-GPS response exceeds %zu B buffer", sizeof(resp_buf));
		return -ENOMEM;
	}
	memcpy(resp_buf + resp_len, data, len);
	resp_len += len;
	return 0;
}

/* ---- CBOR decode helpers (shared shape with agnss_client.c) -------------- */

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

static int read_uint(struct cbor_reader *r, uint64_t *out)
{
	uint8_t major;
	uint64_t arg;
	int err = cbor_read_head(r, &major, &arg);

	if (err) {
		return err;
	}
	if (major != CBOR_MAJOR_UINT) {
		return -EINVAL;
	}
	*out = arg;
	return 0;
}

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

static int read_container(struct cbor_reader *r, uint8_t expect_major, uint64_t *count)
{
	uint8_t major;
	int err = cbor_read_head(r, &major, count);

	if (err) {
		return err;
	}
	return (major == expect_major) ? 0 : -EINVAL;
}

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

/* Frozen 27-field order, mirrors EncodeBundleCompact / agnss-schema.md 1.4. */
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

/* Parse one { toe, e, eph:[...] } window map into slot. Returns 0 on success. */
static int parse_window(struct cbor_reader *r, struct pgps_window *slot)
{
	uint64_t n;
	int err = read_container(r, CBOR_MAJOR_MAP, &n);

	if (err) {
		return err;
	}
	memset(slot, 0, sizeof(*slot));
	for (uint64_t i = 0; i < n; i++) {
		char key[8];

		if ((err = read_key(r, key, sizeof(key)))) {
			return err;
		}
		if (!strcmp(key, "toe")) {
			uint64_t toe;

			if ((err = read_uint(r, &toe))) {
				return err;
			}
			slot->toe = (uint32_t)toe;
		} else if (!strcmp(key, "eph")) {
			uint64_t count;

			if ((err = read_container(r, CBOR_MAJOR_ARRAY, &count))) {
				return err;
			}
			if (count > PGPS_MAX_SV) {
				LOG_WRN("P-GPS: window has %llu SVs, capping at %d", count,
					PGPS_MAX_SV);
			}
			for (uint64_t s = 0; s < count; s++) {
				if (s < PGPS_MAX_SV) {
					if ((err = parse_ephemeris_compact(r, &slot->eph[s]))) {
						return err;
					}
					slot->sv_count = (uint8_t)(s + 1);
				} else {
					/* Keep the cursor aligned past the surplus SVs. */
					if ((err = cbor_skip(r))) {
						return err;
					}
				}
			}
		} else {
			/* "e" (encoding marker) and any future field: skip. */
			if ((err = cbor_skip(r))) {
				return err;
			}
		}
	}
	return 0;
}

/* Decode one /p response, committing each window to the store as it is parsed.
 * *stored is incremented per window written. */
static int decode_response(const uint8_t *buf, size_t len, uint16_t *stored)
{
	struct cbor_reader r;
	uint64_t entries;
	int err;

	cbor_reader_init(&r, buf, len);
	err = read_container(&r, CBOR_MAJOR_MAP, &entries);
	if (err) {
		LOG_ERR("P-GPS response is not a CBOR map: %d", err);
		return err;
	}

	last_gen = 0;
	last_next = 0;

	for (uint64_t i = 0; i < entries; i++) {
		char key[8];

		if ((err = read_key(&r, key, sizeof(key)))) {
			return err;
		}
		if (!strcmp(key, "gen")) {
			uint64_t v;

			if ((err = read_uint(&r, &v))) {
				return err;
			}
			last_gen = (uint32_t)v;
		} else if (!strcmp(key, "next")) {
			uint64_t v;

			if ((err = read_uint(&r, &v))) {
				return err;
			}
			last_next = (uint32_t)v;
		} else if (!strcmp(key, "win")) {
			uint64_t count;

			if ((err = read_container(&r, CBOR_MAJOR_ARRAY, &count))) {
				return err;
			}
			for (uint64_t w = 0; w < count; w++) {
				struct pgps_window *slot = window_for_decode();

				if (slot == NULL) {
					/* RAM store full; keep the cursor valid and
					 * drop the rest of the batch. */
					LOG_WRN("P-GPS: no room for window %llu of %llu",
						w + 1, count);
					if ((err = cbor_skip(&r))) {
						return err;
					}
					continue;
				}

				if ((err = parse_window(&r, slot))) {
					return err;
				}
				if (slot->sv_count == 0) {
					LOG_WRN("P-GPS: window toe=%u has no SVs; dropped",
						slot->toe);
					continue;
				}

				slot->gen = last_gen;

				err = window_commit(slot);
				if (err) {
					LOG_ERR("P-GPS: storing window toe=%u failed: %d",
						slot->toe, err);
					return err;
				}
				if (stored) {
					(*stored)++;
				}
				LOG_INF("P-GPS: window toe=%u, %u SVs", slot->toe, slot->sv_count);
			}
		} else {
			if ((err = cbor_skip(&r))) {
				return err;
			}
		}
	}

	LOG_INF("P-GPS: gen=%u, a newer generation is expected at GPS %u", last_gen, last_next);
	return 0;
}

/* ---- injection ---------------------------------------------------------- */

static int32_t round_to_i32(double x)
{
	return (int32_t)(x >= 0.0 ? x + 0.5 : x - 0.5);
}

/* 3GPP TS 23.032 uncertainty code K: radius r = 10 * (1.1^K - 1) m. Smallest K
 * whose radius covers r_m (never under-states), clamped 0..127. */
static uint8_t encode_uncertainty(uint32_t r_m)
{
	double factor = 1.0;

	for (uint8_t k = 0; k < 127; k++) {
		if (10.0 * (factor - 1.0) >= (double)r_m) {
			return k;
		}
		factor *= 1.1;
	}
	return 127;
}

static void fill_location(struct nrf_modem_gnss_agnss_data_location *l, double lat, double lon,
			  uint32_t unc_m)
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

int pgps_client_inject_now(const struct pgps_fetch_opts *pos)
{
	uint64_t now_s;
	uint16_t frac_ms;

	if (!current_gps_time(&now_s, &frac_ms)) {
		LOG_WRN("P-GPS: wall clock not valid; cannot select/inject a window");
		return -EAGAIN;
	}

	struct pgps_window *win = window_find_covering(now_s);

	if (!win || win->sv_count == 0) {
		LOG_WRN("P-GPS: no stored window covers now (gps_s=%llu)", now_s);
		return -ENOENT;
	}

	/* System clock from the device wall clock (the /p response carries no clk
	 * element; the device stamps its own time — see pgps-implementation-plan.md
	 * 8.3). Write it first: it seeds ephemeris propagation. */
	struct nrf_modem_gnss_agnss_gps_data_system_time_and_sv_tow clk;

	memset(&clk, 0, sizeof(clk));
	clk.date_day = (uint16_t)(now_s / 86400U);
	clk.time_full_s = (uint32_t)(now_s % 86400U);
	clk.time_frac_ms = frac_ms;
	clk.sv_mask = 0;

	int err = nrf_modem_gnss_agnss_write(&clk, sizeof(clk),
					     NRF_MODEM_GNSS_AGNSS_GPS_SYSTEM_CLOCK_AND_TOWS);
	if (err) {
		LOG_ERR("P-GPS: system clock write failed: %d", err);
		return err;
	}
	LOG_INF("P-GPS clk: gps_s=%llu -> day=%u time_s=%u frac_ms=%u", now_s, clk.date_day,
		clk.time_full_s, clk.time_frac_ms);

	/* Optional reference location (a modem rejection here must not cost us the
	 * ephemerides, which are what accelerate the fix). */
	if (pos && pos->have_pos) {
		struct nrf_modem_gnss_agnss_data_location loc;

		fill_location(&loc, pos->lat, pos->lon, pos->unc_m);
		err = nrf_modem_gnss_agnss_write(&loc, sizeof(loc), NRF_MODEM_GNSS_AGNSS_LOCATION);
		if (err) {
			LOG_WRN("P-GPS: location write failed: %d (continuing)", err);
		}
	}

	for (uint8_t i = 0; i < win->sv_count; i++) {
		err = nrf_modem_gnss_agnss_write(&win->eph[i], sizeof(win->eph[i]),
						 NRF_MODEM_GNSS_AGNSS_GPS_EPHEMERIDES);
		if (err) {
			LOG_ERR("P-GPS: ephemeris SV %u write failed: %d", win->eph[i].sv_id, err);
			return err;
		}
	}

	last_inject.toe = win->toe;
	last_inject.gen = win->gen;
	/* How stale the prediction was at the moment it fed a fix. This is the
	 * axis the horizon experiment plots TTFF against, so capture it here
	 * rather than at query time. */
	last_inject.gen_age_s = (win->gen && now_s > win->gen) ? (uint32_t)(now_s - win->gen) : 0;
	last_inject.sv_count = win->sv_count;
	have_last_inject = true;

	LOG_INF("P-GPS: injected window toe=%u gen=%u (%u SVs) for gps_s=%llu; prediction is %u h "
		"old, %u min into the window", win->toe, win->gen, win->sv_count, now_s,
		(unsigned)(last_inject.gen_age_s / 3600U),
		(unsigned)((now_s + PGPS_WINDOW_HALF - win->toe) / 60U));
	return 0;
}

bool pgps_client_have_window_now(void)
{
	uint64_t now_s;

	if (!current_gps_time(&now_s, NULL)) {
		return false;
	}
	return window_have_covering(now_s);
}

int pgps_client_last_inject(struct pgps_inject_info *out)
{
	if (!have_last_inject) {
		return -ENOENT;
	}
	if (out) {
		*out = last_inject;
	}
	return 0;
}

/* ---- batched fetch ------------------------------------------------------ */

/* A long horizon cannot arrive in one response: 84 windows is ~97 kB, well past
 * resp_buf and past the server's per-device continuation cache. A run is
 * therefore a sequence of POSTs of at most FETCH_BATCH windows each, with `from`
 * advancing one batch per step, so the caller keeps servicing telemetry and the
 * GNSS search between batches (the same cooperative shape as
 * fota_client_step()). */
#define PGPS_FETCH_BATCH CONFIG_OSCORE_CLOUD_PGPS_FETCH_BATCH

/* Response bytes one window costs, so a batch can be sized to resp_buf.
 * Per-SV compact ephemeris is ~78 B on the wire; round up for the per-window
 * map framing. A pruned window keeps 12-16 SVs (agnss-schema.md 3.3), while an
 * `all` fetch returns the whole constellation and so costs twice as much -- the
 * reason a batch size tuned for pruned windows overflows resp_buf when pruning
 * is off. */
#define PGPS_BYTES_PER_SV     80
#define PGPS_WINDOW_FRAMING_B 32
#define PGPS_PRUNED_SV        16
#define PGPS_RESP_FRAMING_B   64 /* gen/next plus the top-level map + array heads */

static struct {
	bool active;
	struct pgps_fetch_opts opts; /* pruning hints, reused for every batch */
	uint32_t from;               /* window start to request next, GPS seconds */
	uint16_t remaining;          /* windows still wanted */
	uint16_t stored;             /* windows written so far this run */
	uint16_t batch;              /* windows per request; shrinks if one overflows */
	int last_err;
} fetch;

/* Largest batch whose response is expected to fit resp_buf. Capped by the
 * Kconfig batch size, floored at one window. */
static uint16_t batch_limit(const struct pgps_fetch_opts *o)
{
	size_t per_window = (size_t)(o->all ? PGPS_MAX_SV : PGPS_PRUNED_SV) * PGPS_BYTES_PER_SV +
			    PGPS_WINDOW_FRAMING_B;
	size_t fits = (sizeof(resp_buf) - PGPS_RESP_FRAMING_B) / per_window;

	if (fits == 0) {
		return 1;
	}
	return (uint16_t)MIN(fits, (size_t)PGPS_FETCH_BATCH);
}

/* Snap a GPS second down to the start of the 4 h window containing it, which is
 * what the server does with `from` anyway. */
static uint32_t snap_window_start(uint64_t gps_s)
{
	return (uint32_t)((gps_s / PGPS_WINDOW_SPAN) * PGPS_WINDOW_SPAN);
}

int pgps_client_fetch_begin(const struct pgps_fetch_opts *opts, uint16_t total_windows)
{
	uint64_t now_s = 0;

	if (fetch.active) {
		return -EBUSY;
	}

	memset(&fetch, 0, sizeof(fetch));
	if (opts) {
		fetch.opts = *opts;
	}

	if (total_windows == 0) {
		total_windows = fetch.opts.n;
	}
	if (total_windows == 0) {
		total_windows = CONFIG_OSCORE_CLOUD_PGPS_WINDOW_COUNT_DEFAULT;
	}

	if (fetch.opts.from != 0) {
		fetch.from = snap_window_start(fetch.opts.from);
	} else {
		(void)current_gps_time(&now_s, NULL);
		fetch.from = snap_window_start(now_s);
	}

	fetch.remaining = total_windows;
	fetch.batch = batch_limit(&fetch.opts);
	fetch.active = true;

	/* Without the flash ring the RAM array is the whole horizon, so a new run
	 * has to clear it to make room; with the ring this only drops the
	 * injection cache, since the ring is self-expiring. */
	window_store_reset();

	LOG_INF("P-GPS fetch: %u window(s) from GPS %u in batches of %u%s", total_windows,
		fetch.from, fetch.batch,
		fetch.opts.all ? " (full constellation, so smaller batches)" : "");
	return 0;
}

/* Issue one /p request for up to `n` windows starting at `from`. Sets *got to
 * the number of windows actually stored. */
static int fetch_one_batch(uint16_t n, uint16_t *got)
{
	uint8_t req_buf[PGPS_REQ_BUF];
	struct pgps_fetch_opts o = fetch.opts;
	size_t req_size;
	int err;

	o.n = n;

	req_size = build_request(req_buf, sizeof(req_buf), &o, fetch.from);
	if (req_size == 0) {
		return -ENOMEM;
	}

	LOG_DBG("P-GPS request: from=%u n=%u m=%u mov=%d all=%d pos=%d", fetch.from, o.n, o.max_sv,
		o.moving, o.all, o.have_pos);

	resp_len = 0;
	err = cloud_client_oscore_block2_post("p", req_buf, req_size, PGPS_BLOCK2_SZX,
					      accumulate_sink, NULL);
	if (err) {
		LOG_ERR("P-GPS Block2 POST /p failed: %d", err);
		return err;
	}

	LOG_DBG("P-GPS: received %zu B", resp_len);
	if (resp_len == 0) {
		LOG_WRN("P-GPS: empty response");
		return 0;
	}

	err = decode_response(resp_buf, resp_len, got);
	if (err) {
		LOG_ERR("P-GPS: decode failed: %d", err);
		return err;
	}
	return 0;
}

enum pgps_step pgps_client_step(void)
{
	uint16_t n;
	uint16_t got = 0;
	int err;

	if (!fetch.active) {
		return PGPS_STEP_IDLE;
	}

	n = MIN(fetch.remaining, fetch.batch);

	err = fetch_one_batch(n, &got);
	if (err == -ENOMEM && fetch.batch > 1) {
		/* The response did not fit resp_buf, so the per-window estimate
		 * above was optimistic for this server/constellation. Halve the
		 * batch and retry the same `from` rather than abandoning the run;
		 * nothing was stored, so there is nothing to undo. */
		fetch.batch /= 2;
		LOG_WRN("P-GPS: batch of %u did not fit; retrying with %u", n, fetch.batch);
		return PGPS_STEP_MORE;
	}
	if (err) {
		fetch.last_err = err;
		fetch.active = false;
		LOG_WRN("P-GPS fetch stopped after %u window(s): %d", fetch.stored, err);
		return PGPS_STEP_DONE;
	}

	/* The server clamps to `n`, but do not trust the count for the arithmetic
	 * below: an over-long response would underflow `remaining`. */
	got = MIN(got, n);
	fetch.stored += got;

	/* The server clamps to its published horizon, so a short batch means we
	 * have reached the end of what it can serve; asking again would only
	 * re-fetch the same windows. */
	if (got < n) {
		fetch.active = false;
		LOG_INF("P-GPS fetch done: %u window(s) stored (server horizon reached, %u not "
			"available)", fetch.stored, fetch.remaining - got);
		fetch.remaining -= got;
		return PGPS_STEP_DONE;
	}

	fetch.remaining -= got;
	fetch.from += (uint32_t)got * PGPS_WINDOW_SPAN;

	if (fetch.remaining == 0) {
		fetch.active = false;
		LOG_INF("P-GPS fetch done: %u window(s) stored", fetch.stored);
		return PGPS_STEP_DONE;
	}

	return PGPS_STEP_MORE;
}

void pgps_client_fetch_status(uint16_t *stored, uint16_t *remaining, int *last_err)
{
	if (stored) {
		*stored = fetch.stored;
	}
	if (remaining) {
		*remaining = fetch.remaining;
	}
	if (last_err) {
		*last_err = fetch.last_err;
	}
}

/* ---- public API --------------------------------------------------------- */

int pgps_client_init(void)
{
	return store_open();
}

int pgps_client_fetch(const struct pgps_fetch_opts *opts)
{
	enum pgps_step step;
	int err = pgps_client_fetch_begin(opts, 0);

	if (err) {
		return err;
	}

	do {
		step = pgps_client_step();
	} while (step == PGPS_STEP_MORE);

	pgps_client_fetch_status(NULL, NULL, &err);
	return err;
}
