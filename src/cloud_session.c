/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Framework-free connection / session helper. See cloud_session.h.
 *
 * The connect/backoff/downlink logic here is the plain-function equivalent of
 * what an application would otherwise build with zbus + the state machine
 * framework (as the Asset-Tracker-Template cloud module does).
 */

#include <oscore_cloud/cloud_session.h>
#include <oscore_cloud/cloud_client.h>
#include <oscore_cloud/cloud_config.h>

#ifdef CONFIG_OSCORE_CLOUD_FOTA
#include <oscore_cloud/fota_client.h>
#endif

#if defined(CONFIG_OSCORE_CLOUD_DIAG) && defined(CONFIG_OSCORE_CLOUD_DIAG_AUTO_ATTACH)
#include <oscore_cloud/diag_bridge.h>
#define OSCORE_CLOUD_DIAG_AUTO 1
#endif

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(oscore_cloud_session, CONFIG_OSCORE_CLOUD_LOG_LEVEL);

int oscore_cloud_connect(void)
{
	return cloud_client_init();
}

void oscore_cloud_disconnect(void)
{
	cloud_client_deinit();
}

uint32_t oscore_cloud_backoff_seconds(uint32_t attempts)
{
	const struct oscore_cloud_config *cfg = oscore_cloud_get_config();
	uint32_t initial = cfg->backoff_initial_s ?
			   cfg->backoff_initial_s :
			   CONFIG_OSCORE_CLOUD_BACKOFF_INITIAL_SECONDS;
	uint32_t max_s = cfg->backoff_max_s ?
			 cfg->backoff_max_s :
			 CONFIG_OSCORE_CLOUD_BACKOFF_MAX_SECONDS;
	uint32_t backoff = initial;

	if (attempts == 0) {
		attempts = 1;
	}

	if (IS_ENABLED(CONFIG_OSCORE_CLOUD_BACKOFF_TYPE_EXPONENTIAL)) {
		/* Cap the shift so the intermediate value cannot overflow before
		 * it is clamped to max_s below. */
		uint32_t shift = attempts - 1;

		if (shift > 31) {
			shift = 31;
		}
		if (shift >= 32 || (initial != 0 && (backoff << shift) / initial != (1U << shift))) {
			backoff = max_s;
		} else {
			backoff = initial << shift;
		}
	} else if (IS_ENABLED(CONFIG_OSCORE_CLOUD_BACKOFF_TYPE_LINEAR)) {
		backoff = initial +
			  ((attempts - 1) * CONFIG_OSCORE_CLOUD_BACKOFF_LINEAR_INCREMENT_SECONDS);
	}

	if (backoff > max_s) {
		backoff = max_s;
	}

	return backoff;
}

int oscore_cloud_send_telemetry(const struct cloud_telemetry *t,
				cloud_shadow_cb cb, void *user)
{
	struct cloud_downlink dl;
	int err;

	if (t == NULL) {
		return -EINVAL;
	}

#if defined(OSCORE_CLOUD_DIAG_AUTO)
	/* Fold any pending observability diagnostics (boot report / vitals / crash
	 * / device info) into a working copy so they ride the same telemetry packet
	 * (t is const; the caller's record is left untouched). The bridge honours
	 * the vitals cadence and defaults fw_version to the build-id version. */
	struct cloud_telemetry work = *t;

	(void)oscore_cloud_diag_attach(&work);
	t = &work;
#endif

	err = cloud_client_post_telemetry(t, &dl);
	if (err) {
		return err;
	}

#if defined(OSCORE_CLOUD_DIAG_AUTO)
	/* Post accepted: drop the one-shots (also stamps the diag heartbeat) and,
	 * after the minimal crash report, push the full coredump on a terrestrial
	 * bearer. Clearing when nothing was pending is a harmless no-op. */
	oscore_cloud_diag_attach_clear();
	oscore_cloud_diag_after_send(t->has_transport ? t->transport : CLOUD_TRANSPORT_NTN);
#endif

	if (dl.shadow_delta_pending || dl.has_inline_delta) {
		(void)cloud_client_process_downlink(&dl, cb, user);
	}

#ifdef CONFIG_OSCORE_CLOUD_FOTA
	if (dl.fota_job_pending) {
		/* Drive the interleaved FOTA pump to completion. Each step fetches
		 * a bounded chunk; an application image apply reboots from within
		 * fota_client_step() and never returns. */
		int step;

		do {
			step = fota_client_step();
		} while (step == FOTA_STEP_MORE);

		if (step < 0) {
			LOG_WRN("FOTA step failed: %d", step);
		}
	}
#endif

	return 0;
}
