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

	err = cloud_client_post_telemetry(t, &dl);
	if (err) {
		return err;
	}

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
