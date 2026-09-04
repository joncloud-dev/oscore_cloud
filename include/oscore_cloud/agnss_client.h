/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * OSCORE A-GNSS client: fetches GPS assistance from the OSCORE cloud (POST /a,
 * CBOR over Block2) and writes it to the modem. Replaces nRF Cloud A-GNSS.
 */

#ifndef AGNSS_CLIENT_H
#define AGNSS_CLIENT_H

#include <stdbool.h>
#include <stdint.h>
#include <nrf_modem_gnss.h>

/**
 * Optional per-fetch tuning for agnss_client_fetch_ex(). Zero-initialise and set
 * only the fields you need; the request-build code omits absent hints.
 *
 * The window/cap/encoding map to the agnss-schema.md 1.1 request keys w/n/e and
 * let the device pick a single-shot fetch (window_s = 0, small max_sv) or a
 * full look-ahead fetch. The position hint (coordinates preferred, else serving
 * cell) lets the server prune to the satellites the device can actually see.
 */
struct agnss_fetch_opts {
	uint32_t window_s; /* look-ahead window (s); 0 = single-shot / instant */
	uint8_t max_sv;    /* cap on returned satellites; 0 = uncapped */
	uint8_t encoding;  /* 0 = text-key maps, 1 = compact positional arrays */

	/* Coarse position hint (most precise). */
	bool have_pos;
	double lat;    /* degrees */
	double lon;    /* degrees */
	uint32_t unc_m; /* uncertainty, metres */

	/* Serving-cell hint (used when have_pos is false). */
	bool have_cell;
	uint16_t mcc;
	uint16_t mnc;
	uint32_t tac;
	uint32_t ci;
	int16_t rsrp;
	uint32_t ta;
};

/**
 * Fetch A-GNSS assistance for the modem's request and write it to the GNSS
 * core. Builds a CBOR request from the assistance-need frame, POSTs it to /a,
 * decodes the Block2 CBOR response (agnss-schema.md), and writes each element
 * via nrf_modem_gnss_agnss_write(). Must be called when the cloud client is
 * connected. Returns 0 on success or a negative errno.
 *
 * Uses the Kconfig defaults (OSCORE_CLOUD_AGNSS_WINDOW_S_DEFAULT / _MAX_SV_DEFAULT
 * / _COMPACT) and sends no position hint. For per-fetch control use
 * agnss_client_fetch_ex().
 */
int agnss_client_fetch(const struct nrf_modem_gnss_agnss_data_frame *req);

/**
 * Like agnss_client_fetch() but with per-fetch window/cap/encoding and an
 * optional position or serving-cell hint. Pass NULL opts for the defaults.
 */
int agnss_client_fetch_ex(const struct nrf_modem_gnss_agnss_data_frame *req,
			  const struct agnss_fetch_opts *opts);

#endif /* AGNSS_CLIENT_H */
