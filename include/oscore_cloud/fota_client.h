/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * OSCORE FOTA client for the Go platform (GET/POST /f, Block2 GET /f/i).
 */

#ifndef FOTA_CLIENT_H
#define FOTA_CLIENT_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* Image types from GET /f key 5 (matches server fotaTypeWire*). */
enum cloud_fota_image_type {
	CLOUD_FOTA_TYPE_APPLICATION  = 1,
	CLOUD_FOTA_TYPE_MODEM_DELTA  = 2,
	CLOUD_FOTA_TYPE_MODEM_FULL   = 3,
	CLOUD_FOTA_TYPE_BOOTLOADER   = 4,
};

/* FOTA job state codes for POST /f key 1. */
enum cloud_fota_state {
	CLOUD_FOTA_STATE_DOWNLOADING = 3,
	CLOUD_FOTA_STATE_DOWNLOADED  = 4,
	CLOUD_FOTA_STATE_APPLYING    = 5,
	CLOUD_FOTA_STATE_SUCCEEDED   = 6,
	CLOUD_FOTA_STATE_FAILED      = 7,
};

struct cloud_fota_notice {
	char job_id[16];
	char version[32];
	uint32_t size;
	uint8_t sha256[32];
	enum cloud_fota_image_type type;
};

/** Fetch the active job notice (GET /f). Returns -ENOENT when none pending. */
int fota_client_fetch_notice(struct cloud_fota_notice *notice);

/** Report job progress/state (POST /f). */
int fota_client_report(enum cloud_fota_state state, uint32_t progress_blocks,
		       const char *error);

/** Result of fota_client_step(); negative return values are errors. */
enum fota_step_result {
	FOTA_STEP_IDLE = 0, /* nothing pending; do not call again until next trigger */
	FOTA_STEP_MORE = 1, /* work in progress; call fota_client_step() again to continue */
	FOTA_STEP_DONE = 2, /* finished this unit of work (or about to reboot to apply) */
};

/**
 * Advance FOTA by one bounded unit of work and return. This is the cooperative
 * replacement for the old blocking run loop: a full image download is split
 * into many steps so the caller (the cloud module's message loop) regains
 * control between chunks and can service telemetry/shadow traffic.
 *
 * Drive it by calling once whenever a FOTA job is flagged pending, then again
 * for as long as it returns FOTA_STEP_MORE. The first call flushes any
 * boot-latched terminal report, then fetches a job notice and starts a download
 * session; subsequent calls each fetch a chunk and, on the last one, verify and
 * apply (an application image reboots from within and never returns).
 *
 * Returns an enum fota_step_result (>= 0) or a negative errno on failure.
 */
int fota_client_step(void);

/**
 * Boot-time FOTA reconciliation. Call once early in main(), before the network
 * is up. Logs MCUboot slot/swap state, and if a FOTA was applied before the
 * last reboot, determines the outcome from the running image's confirm state:
 *   - running image is UNCONFIRMED  -> the new image booted: confirm it and
 *     latch a pending SUCCEEDED report for the next fota_client_step().
 *   - running image is CONFIRMED    -> the swap did not take (MCUboot rejected
 *     or reverted the secondary): latch a pending FAILED report.
 * The latched result is sent to the server by the next fota_client_step(), which
 * is what stops the device from re-downloading the same job forever.
 */
void fota_client_boot_check(void);

#endif /* FOTA_CLIENT_H */
