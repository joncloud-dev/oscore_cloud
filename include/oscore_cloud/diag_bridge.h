/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Bridge between the device observability collector (oscore_cloud/diag.h) and
 * the telemetry wire layer (oscore_cloud/cloud_client.h): it maps the collected
 * boot report (key 20), vitals heartbeat (key 21), crash report (key 22) and
 * static device info (key 23) onto a cloud_telemetry record so they ride the
 * ordinary telemetry uplink, and pushes the full coredump over Block1 after a
 * crash report has been delivered on a terrestrial bearer.
 *
 * When CONFIG_OSCORE_CLOUD_DIAG_AUTO_ATTACH is set (the default), the session
 * helper (oscore_cloud_send_telemetry) calls these for you, so an application
 * only has to call oscore_cloud_diag_init() once at boot. Set AUTO_ATTACH=n to
 * take manual control (e.g. to post observability on a slower cadence than the
 * rest of your telemetry) and call oscore_cloud_diag_attach()/_attach_clear()/
 * _after_send() yourself around your own cloud_client_post_telemetry() call.
 *
 * All functions are single-threaded; call from one context only.
 */

#ifndef OSCORE_CLOUD_DIAG_BRIDGE_H_
#define OSCORE_CLOUD_DIAG_BRIDGE_H_

#include <stdbool.h>

#include <oscore_cloud/cloud_client.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Process the retained diagnostics region + hwinfo (diag_boot_process) and arm
 * the one-shot device-info report. Call once, early in main(), before the
 * telemetry loop starts and ideally before the settings subsystem restore.
 */
void oscore_cloud_diag_init(void);

/**
 * Fold pending diagnostics into an outgoing telemetry record. A boot report
 * (key 20) and a crash report (key 22) are urgent one-shots and are always
 * attached when pending; the vitals heartbeat (key 21) is attached only every
 * CONFIG_OSCORE_CLOUD_DIAG_VITALS_INTERVAL calls to save uplink bandwidth; the
 * one-shot device-info report (key 23) is attached the first time after
 * oscore_cloud_diag_init(). If build-id support is enabled and t->fw_version is
 * unset, it is defaulted to app_fw_version(). Returns whether a one-shot
 * (boot/crash/device-info) was attached, so the caller clears it only after the
 * post succeeds.
 */
bool oscore_cloud_diag_attach(struct cloud_telemetry *t);

/**
 * Clear the one-shot diagnostics (boot report, crash snapshot, device-info) once
 * a telemetry post carrying them has been accepted, and stamp the diag heartbeat.
 * Call only after oscore_cloud_diag_attach() returned true and the post
 * succeeded.
 */
void oscore_cloud_diag_attach_clear(void);

/**
 * After a telemetry post that carried the minimal crash report, push the full
 * stored coredump to POST /c over Block1 — but only on a terrestrial bearer
 * (CLOUD_TRANSPORT_TN), so an NTN device is never asked to move the large blob.
 * No-op when there is no stored dump or coredump support is not built.
 */
void oscore_cloud_diag_after_send(enum cloud_transport transport);

#ifdef __cplusplus
}
#endif

#endif /* OSCORE_CLOUD_DIAG_BRIDGE_H_ */
