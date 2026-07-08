/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Framework-free connection / session helper for the oscore_cloud library.
 *
 * This is the "batteries included" layer for a simple application: it wraps the
 * connect/reconnect lifecycle and turns a single telemetry post into a complete
 * check-in (post -> apply any shadow delta -> drive any pending FOTA job to
 * completion). It uses no zbus and no state-machine framework, so it can be
 * driven straight from a main() loop:
 *
 *     oscore_cloud_init(&cfg);
 *     uint32_t attempts = 0;
 *     while (1) {
 *         if (oscore_cloud_connect() != 0) {
 *             k_sleep(K_SECONDS(oscore_cloud_backoff_seconds(++attempts)));
 *             continue;
 *         }
 *         attempts = 0;
 *         struct cloud_telemetry t;
 *         cloud_telemetry_init(&t);
 *         cloud_telemetry_add_double(&t, 10, battery_percent());
 *         oscore_cloud_send_telemetry(&t, on_shadow_delta, NULL);
 *         k_sleep(interval);
 *     }
 *
 * All calls are synchronous and single-threaded; drive them from one context.
 */

#ifndef OSCORE_CLOUD_SESSION_H
#define OSCORE_CLOUD_SESSION_H

#include <stdint.h>

#include <oscore_cloud/cloud_client.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Establish the OSCORE transport (initialise the context and open the UDP
 * socket). The network link must already be up. Returns 0 on success or a
 * negative errno; on failure the caller typically sleeps for
 * oscore_cloud_backoff_seconds() and retries.
 */
int oscore_cloud_connect(void);

/**
 * Tear down the OSCORE transport, freeing the UDP socket. Safe to call when not
 * connected.
 */
void oscore_cloud_disconnect(void);

/**
 * Compute the reconnection backoff for the given (1-based) attempt count, using
 * the type selected in Kconfig (exponential / linear / none) and the bounds
 * from struct oscore_cloud_config (falling back to the CONFIG_OSCORE_CLOUD_-
 * BACKOFF_* defaults). Returns a delay in seconds, clamped to the maximum.
 */
uint32_t oscore_cloud_backoff_seconds(uint32_t attempts);

/**
 * Send one confirmable telemetry check-in and complete the resulting downlink:
 * a pending/inline shadow delta is applied (cb invoked, version acknowledged),
 * and a pending FOTA job is driven to completion (when CONFIG_OSCORE_CLOUD_FOTA
 * is enabled). cb/user may be NULL to ignore shadow deltas. Returns 0 on
 * success or a negative errno (e.g. a transport error, after which the caller
 * should reconnect).
 */
int oscore_cloud_send_telemetry(const struct cloud_telemetry *t,
				cloud_shadow_cb cb, void *user);

#ifdef __cplusplus
}
#endif

#endif /* OSCORE_CLOUD_SESSION_H */
