/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * OSCORE predicted-GNSS (P-GPS) client: fetches multi-day predicted GPS
 * assistance from the OSCORE cloud (POST /p, CBOR over Block2), stores the
 * returned 4 h ephemeris windows, and injects the window covering the current
 * time into the modem. See pgps-implementation-plan.md and the frozen /p wire
 * contract in agnss-schema.md section 3.
 *
 * With CONFIG_OSCORE_CLOUD_PGPS_STORE the windows go into a flash ring
 * (pgps_store.h) so a multi-day horizon survives reboots and the device can fix
 * from stored predictions while completely offline. Without it they live in RAM
 * for the current power cycle only.
 *
 * A long horizon cannot arrive in one response (84 windows is ~97 kB), so a
 * fetch for more than CONFIG_OSCORE_CLOUD_PGPS_FETCH_BATCH windows is split
 * into a sequence of requests. Use pgps_client_fetch() when blocking for the
 * whole run is acceptable, or fetch_begin() + step() to interleave the batches
 * with other traffic on the shared socket.
 */

#ifndef PGPS_CLIENT_H
#define PGPS_CLIENT_H

#include <stdbool.h>
#include <stdint.h>

#include <oscore_cloud/pgps_store.h>

/**
 * Optional tuning for pgps_client_fetch(). Zero-initialise and set only the
 * fields you need; the request-build code omits absent hints. The fields map to
 * the /p request keys from/n/lat/lon/unc/m/mov (agnss-schema.md 3.1).
 */
struct pgps_fetch_opts {
	uint32_t from; /* GPS seconds of the first window wanted; 0 = now */
	uint16_t n;    /* total number of consecutive 4 h windows; 0 = Kconfig default */
	uint8_t max_sv; /* cap on SVs per window ("m"); 0 = uncapped */
	bool moving;    /* device is mobile ("mov"); server relaxes the mask */
	bool all;       /* "all": request the full constellation, skip server pruning */

	/* Coarse position hint for per-window pruning (and injected as the modem
	 * reference location). */
	bool have_pos;
	double lat;     /* degrees */
	double lon;     /* degrees */
	uint32_t unc_m; /* uncertainty, metres */
};

/** What the last successful injection actually fed the modem. */
struct pgps_inject_info {
	uint32_t toe;       /* centre of the injected window, GPS seconds */
	uint32_t gen;       /* generation the window was published under */
	uint32_t gen_age_s; /* how old the prediction was when injected, seconds */
	uint8_t sv_count;   /* ephemerides written */
};

/** Progress of a batched fetch, mirroring the FOTA download's step idiom. */
enum pgps_step {
	PGPS_STEP_IDLE, /* no fetch in progress */
	PGPS_STEP_MORE, /* a batch was handled; call again for the next one */
	PGPS_STEP_DONE, /* the run finished (check fetch_status for the outcome) */
};

/**
 * Open the window store. Safe to call more than once; a no-op when the flash
 * ring is disabled. Returns 0 on success or a negative errno.
 */
int pgps_client_init(void);

/**
 * Fetch predicted assistance and store the returned windows, blocking until the
 * whole run completes. Equivalent to pgps_client_fetch_begin() followed by
 * pgps_client_step() until it stops returning PGPS_STEP_MORE, so a request for
 * a long horizon issues several POSTs back to back. Must be called when the
 * cloud client is connected. Returns 0 on success or a negative errno.
 */
int pgps_client_fetch(const struct pgps_fetch_opts *opts);

/**
 * Start a batched fetch of total_windows windows (0 = opts->n, or the Kconfig
 * default when that is 0 too). Nothing is sent yet; each pgps_client_step()
 * call issues one request. Returns 0 on success, -EBUSY if a run is already in
 * progress.
 */
int pgps_client_fetch_begin(const struct pgps_fetch_opts *opts, uint16_t total_windows);

/**
 * Issue the next request of a batched fetch. Blocks for one /p round trip only,
 * so the caller keeps servicing other work between batches. Returns
 * PGPS_STEP_IDLE when no run is active.
 */
enum pgps_step pgps_client_step(void);

/**
 * Progress of the current or last fetch run. stored = windows written so far;
 * remaining = windows still wanted (non-zero after PGPS_STEP_DONE means the run
 * stopped early); last_err = the errno that stopped it, 0 if none. Any pointer
 * may be NULL.
 */
void pgps_client_fetch_status(uint16_t *stored, uint16_t *remaining, int *last_err);

/**
 * Return true if a stored window covers the current GPS time (i.e. a subsequent
 * pgps_client_inject_now() would have ephemerides to write).
 */
bool pgps_client_have_window_now(void);

/**
 * Inject the stored window covering the current GPS time into the modem: writes
 * the system clock (from the device wall clock), an optional reference location
 * (when pos->have_pos), then each satellite's ephemeris. pos may be NULL to skip
 * the location element. Returns 0 on success, -ENOENT if no window covers now,
 * or a negative errno from the modem.
 */
int pgps_client_inject_now(const struct pgps_fetch_opts *pos);

/**
 * Describe the most recent successful injection. Returns 0 and fills out, or
 * -ENOENT if nothing has been injected this power cycle.
 */
int pgps_client_last_inject(struct pgps_inject_info *out);

#endif /* PGPS_CLIENT_H */
