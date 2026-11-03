/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Flash-backed ring store for predicted-GNSS (P-GPS) ephemeris windows.
 *
 * One 4 h window occupies one flash sector (PGPS_SLOT_SIZE), so a store update
 * is erase-one-sector + write-whole-slot: no read-modify-write, no page cache,
 * no stream_flash. The ring is indexed by the window number itself,
 *
 *     slot = (toe / PGPS_WINDOW_SPAN) % slot_count
 *
 * and since a window's toe is always k * 14400 + 7200 the division yields a
 * unique, monotonically increasing k per window. A slot_count of 84 therefore
 * spans exactly 14 days and expires naturally: a freshly downloaded window
 * lands on the sector holding the one that is 14 days old.
 * See pgps-implementation-plan.md section 8.1.
 *
 * The store keeps a small RAM index of the slot headers (built by a single scan
 * in pgps_store_init()) so window lookups do not touch flash until the
 * ephemerides are actually needed.
 */

#ifndef PGPS_STORE_H
#define PGPS_STORE_H

#include <stdbool.h>
#include <stdint.h>
#include <nrf_modem_gnss.h>

/* Kept in sync with pgps_client.c; a window covers [toe - HALF, toe + HALF). */
#define PGPS_WINDOW_SPAN 14400U
#define PGPS_WINDOW_HALF (PGPS_WINDOW_SPAN / 2U)

/* Maximum satellites per window (a full GPS constellation). */
#define PGPS_MAX_SV 32

/* One window as held in RAM (decode staging area and injection cache). */
struct pgps_window {
	uint32_t toe; /* GPS seconds, window centre */
	uint32_t gen; /* generation id the window was published under */
	uint8_t sv_count;
	struct nrf_modem_gnss_agnss_gps_data_ephemeris eph[PGPS_MAX_SV];
};

/** Summary of what the ring currently holds. */
struct pgps_store_stats {
	uint16_t slots;      /* ring length (CONFIG_OSCORE_CLOUD_PGPS_STORE_SLOTS) */
	uint16_t used;       /* slots holding a valid window */
	uint32_t first_toe;  /* oldest stored window centre, 0 if none */
	uint32_t last_toe;   /* newest stored window centre, 0 if none */
	uint32_t newest_gen; /* highest generation id stored, 0 if none */
};

/**
 * Open the P-GPS flash partition and scan every slot header into the RAM index.
 * Idempotent. Returns 0 on success, -ENODEV if the flash area is unavailable.
 */
int pgps_store_init(void);

/**
 * Write one window into its ring slot (erase + write, replacing whatever was
 * there). sv_count must be 1..PGPS_MAX_SV. Returns 0 on success or a negative
 * errno.
 */
int pgps_store_put(uint32_t toe, uint32_t gen, uint8_t sv_count,
		   const struct nrf_modem_gnss_agnss_gps_data_ephemeris *eph);

/**
 * Read the window whose 4 h span covers GPS second now_s into out. Returns 0 on
 * success, -ENOENT if no stored window covers now_s, or a negative errno on a
 * flash/CRC failure.
 */
int pgps_store_get_covering(uint64_t now_s, struct pgps_window *out);

/** True if a stored window covers GPS second now_s (RAM index only). */
bool pgps_store_have_covering(uint64_t now_s);

/** Fill stats from the RAM index. */
void pgps_store_get_stats(struct pgps_store_stats *stats);

/** Erase the whole ring. Returns 0 on success or a negative errno. */
int pgps_store_erase_all(void);

#endif /* PGPS_STORE_H */
