/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * OSCORE A-GNSS client: fetches GPS assistance from the OSCORE cloud (POST /a,
 * CBOR over Block2) and writes it to the modem. Replaces nRF Cloud A-GNSS.
 */

#ifndef AGNSS_CLIENT_H
#define AGNSS_CLIENT_H

#include <nrf_modem_gnss.h>

/**
 * Fetch A-GNSS assistance for the modem's request and write it to the GNSS
 * core. Builds a CBOR request from the assistance-need frame, POSTs it to /a,
 * decodes the Block2 CBOR response (agnss-schema.md), and writes each element
 * via nrf_modem_gnss_agnss_write(). Must be called when the cloud client is
 * connected. Returns 0 on success or a negative errno.
 */
int agnss_client_fetch(const struct nrf_modem_gnss_agnss_data_frame *req);

#endif /* AGNSS_CLIENT_H */
