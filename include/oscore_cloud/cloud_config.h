/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Runtime configuration and library-wide hooks for the oscore_cloud library.
 *
 * A consumer calls oscore_cloud_init() once (before connecting) to point the
 * library at a server and, optionally, supply OSCORE key material and tune the
 * reconnection backoff. Passing NULL keeps the compile-time defaults, so an
 * application that already provisions its OSCORE context out-of-band (as the
 * Asset-Tracker-Template does) needs no configuration at all.
 */

#ifndef OSCORE_CLOUD_CONFIG_H
#define OSCORE_CLOUD_CONFIG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Runtime configuration for the OSCORE cloud client.
 *
 * All fields are optional. Pointers are borrowed, not copied: they must remain
 * valid for the lifetime of the library (pass static / const storage). A zero
 * or NULL field selects the library default.
 */
struct oscore_cloud_config {
	/** Server IPv4 address as a string. NULL -> CONFIG_OSCORE_SERVER_IP. */
	const char *server_ip;
	/** CoAP UDP port. 0 -> 5683. */
	uint16_t server_port;

	/**
	 * Optional raw OSCORE key material for a self-contained ("hardcoded")
	 * application. When master_secret is non-NULL the library initialises
	 * the OSCORE context directly from these bytes; when it is NULL the
	 * library uses the PSA-provisioned context (opaque key + Protected
	 * Storage salt/IDs) loaded by oscore_provision, which is the default.
	 */
	const uint8_t *master_secret;
	size_t master_secret_len;
	const uint8_t *master_salt;
	size_t master_salt_len;
	const uint8_t *sender_id;
	size_t sender_id_len;
	const uint8_t *recipient_id;
	size_t recipient_id_len;

	/** Reconnection backoff bounds used by oscore_cloud_backoff_seconds().
	 *  0 -> the CONFIG_OSCORE_CLOUD_BACKOFF_* default. */
	uint32_t backoff_initial_s;
	uint32_t backoff_max_s;
};

/**
 * Configure the library. Safe to call once before the first connect; cfg may be
 * NULL to keep all defaults. The struct is shallow-copied, so the struct itself
 * need not persist, but any pointers it holds must (see the field docs).
 * Returns 0 on success.
 */
int oscore_cloud_init(const struct oscore_cloud_config *cfg);

/** Return the active configuration (never NULL; defaults applied). */
const struct oscore_cloud_config *oscore_cloud_get_config(void);

/**
 * Register a watchdog-feed callback. The library invokes it during long,
 * self-contained operations (FOTA image download, modem erase, coredump upload)
 * so a caller that runs OSCORE on a watchdog-guarded thread does not trip its
 * timer. Optional: with no callback registered the library simply does nothing.
 */
void oscore_cloud_set_watchdog_feed(void (*feed)(void));

/** Invoke the registered watchdog-feed callback, if any. Library-internal. */
void oscore_cloud_feed_wdt(void);

#ifdef __cplusplus
}
#endif

#endif /* OSCORE_CLOUD_CONFIG_H */
