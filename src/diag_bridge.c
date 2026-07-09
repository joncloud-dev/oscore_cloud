/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * See oscore_cloud/diag_bridge.h. This is the glue that folds the observability
 * collector's signals into the telemetry wire layer; it was extracted from the
 * Asset-Tracker-Template cloud module so any oscore_cloud consumer gets fleet
 * health "for free" by enabling CONFIG_OSCORE_CLOUD_DIAG.
 */

#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#if defined(CONFIG_MODEM_INFO)
#include <modem/modem_info.h>
#endif

#include <oscore_cloud/diag.h>
#include <oscore_cloud/diag_bridge.h>
#include <oscore_cloud/cloud_client.h>
#if defined(CONFIG_OSCORE_CLOUD_DIAG_BUILD_ID)
#include <oscore_cloud/build_id.h>
#endif

LOG_MODULE_REGISTER(oscore_cloud_diag, CONFIG_OSCORE_CLOUD_DIAG_LOG_LEVEL);

/* One-shot device-info report, armed by oscore_cloud_diag_init() and cleared
 * once a telemetry post carrying it has been accepted. */
#if defined(CONFIG_OSCORE_CLOUD_DIAG_DEVICE_INFO)
static bool device_info_pending;
#endif

/* Counts calls to oscore_cloud_diag_attach() so the vitals heartbeat can be
 * folded in only every CONFIG_OSCORE_CLOUD_DIAG_VITALS_INTERVAL sends. */
#if defined(CONFIG_OSCORE_CLOUD_DIAG_VITALS)
static uint32_t vitals_tick;
#endif

void oscore_cloud_diag_init(void)
{
	diag_boot_process();

#if defined(CONFIG_OSCORE_CLOUD_DIAG_DEVICE_INFO)
	/* Report the static device identity once after boot; the server folds it
	 * onto the device record the same way it refreshes fw_version/transport. */
	device_info_pending = true;
#endif
}

#if defined(CONFIG_OSCORE_CLOUD_DIAG_DEVICE_INFO)
/* Fold the static device identity/metadata (board, modem firmware, IMEI, SIM
 * ICCID) into an outgoing telemetry record under key 23 when a report is armed.
 * Returns whether it was attached so the caller clears the one-shot only after
 * the post succeeds. */
static bool device_info_attach(struct cloud_telemetry *t)
{
	if (!device_info_pending) {
		return false;
	}

	struct cloud_telemetry_device_info di = { 0 };

	strncpy(di.board, CONFIG_BOARD, sizeof(di.board) - 1);

#if defined(CONFIG_MODEM_INFO)
	/* Best-effort: a getter that fails leaves its field the zero-initialised
	 * empty string, which the encoder omits from the wire map. */
	(void)modem_info_string_get(MODEM_INFO_FW_VERSION, di.modem_fw, sizeof(di.modem_fw));
	(void)modem_info_string_get(MODEM_INFO_IMEI, di.imei, sizeof(di.imei));
	(void)modem_info_string_get(MODEM_INFO_ICCID, di.iccid, sizeof(di.iccid));
#endif

	cloud_telemetry_set_device_info(t, &di);
	return true;
}
#endif /* CONFIG_OSCORE_CLOUD_DIAG_DEVICE_INFO */

#if defined(CONFIG_OSCORE_CLOUD_DIAG_VITALS)
/* True when this send should carry the vitals heartbeat, honouring the
 * bandwidth-saving cadence. Interval <= 1 means "every send". */
static bool vitals_due(void)
{
	uint32_t interval = CONFIG_OSCORE_CLOUD_DIAG_VITALS_INTERVAL;
	bool due = (interval <= 1U) || ((vitals_tick % interval) == 0U);

	vitals_tick++;
	return due;
}

static void vitals_attach(struct cloud_telemetry *t)
{
	struct diag_vitals v;
	struct cloud_telemetry_vitals tv = { 0 };

	/* Copy the diag sample list into the wire heartbeat verbatim. This bridge
	 * is metric-agnostic: new vitals added in diag_collect_vitals() need no
	 * change here. */
	diag_collect_vitals(&v);
	for (uint8_t i = 0; i < v.count; i++) {
		const struct diag_vital *it = &v.items[i];

		if (it->type == DIAG_VITAL_INT) {
			(void)cloud_telemetry_vitals_add_int(&tv, it->key, it->value.s);
		} else {
			(void)cloud_telemetry_vitals_add_uint(&tv, it->key, it->value.u);
		}
	}
	cloud_telemetry_set_vitals(t, &tv);
}
#endif /* CONFIG_OSCORE_CLOUD_DIAG_VITALS */

#if defined(CONFIG_OSCORE_CLOUD_DIAG_CRASH)
static void crash_attach(struct cloud_telemetry *t)
{
	const struct diag_crash_info *ci = diag_crash_get();

	if (ci == NULL) {
		return;
	}

	struct cloud_telemetry_crash c = {
		.fault_type = ci->fault_type,
		.pc = ci->pc,
		.lr = ci->lr,
		.reg_count = ci->reg_count,
		.stack_count = ci->stack_count,
	};

	memcpy(c.regs, ci->regs, sizeof(c.regs));
	memcpy(c.stack, ci->stack, sizeof(c.stack));

	/* Build-id of the crashing image (captured at fault time), hex-encoded for
	 * the wire so the server selects the exact symbol ELF. */
	if (ci->build_id_valid) {
		static const char digits[] = "0123456789abcdef";

		for (size_t i = 0; i < sizeof(ci->build_id); i++) {
			c.build_id[2 * i] = digits[ci->build_id[i] >> 4];
			c.build_id[2 * i + 1] = digits[ci->build_id[i] & 0xFU];
		}
		c.build_id[2 * sizeof(ci->build_id)] = '\0';
	}

	/* Inline the tail of the breadcrumb trail (most recent lines, closest to
	 * the fault) within the NTN-friendly cap; the full ring is recoverable
	 * from the coredump. */
	uint16_t bclen = 0;
	const char *bc = diag_breadcrumbs_get(&bclen);

	if (bc != NULL && bclen > 0) {
		uint16_t take = bclen;

		if (take > CLOUD_TELEMETRY_MAX_BREADCRUMB) {
			take = CLOUD_TELEMETRY_MAX_BREADCRUMB;
		}
		memcpy(c.breadcrumbs, bc + (bclen - take), take);
		c.breadcrumb_len = take;
	}

	cloud_telemetry_set_crash(t, &c);
}
#endif /* CONFIG_OSCORE_CLOUD_DIAG_CRASH */

bool oscore_cloud_diag_attach(struct cloud_telemetry *t)
{
	bool oneshot = false;

	if (t == NULL) {
		return false;
	}

#if defined(CONFIG_OSCORE_CLOUD_DIAG_BUILD_ID)
	/* Report the auto-generated (semver + build-id) firmware version unless the
	 * application already set one. */
	if (t->fw_version == NULL) {
		cloud_telemetry_set_fw_version(t, app_fw_version());
	}
#endif

	if (diag_boot_report_pending()) {
		const struct diag_boot_report *br = diag_boot_report_get();
		struct cloud_telemetry_reset r = {
			.hw_cause = br->hw_cause,
			.reason = br->reason,
			.prev_uptime_s = br->prev_uptime_s,
			.boot_count = br->boot_count,
			.crash_pending = br->crash_pending,
		};

		cloud_telemetry_set_reset(t, &r);
		oneshot = true;
	}

#if defined(CONFIG_OSCORE_CLOUD_DIAG_CRASH)
	if (diag_crash_pending()) {
		crash_attach(t);
		oneshot = true;
	}
#endif

#if defined(CONFIG_OSCORE_CLOUD_DIAG_DEVICE_INFO)
	if (device_info_attach(t)) {
		oneshot = true;
	}
#endif

#if defined(CONFIG_OSCORE_CLOUD_DIAG_VITALS)
	if (vitals_due()) {
		vitals_attach(t);
	}
#endif

	return oneshot;
}

void oscore_cloud_diag_attach_clear(void)
{
	diag_boot_report_clear();
#if defined(CONFIG_OSCORE_CLOUD_DIAG_CRASH)
	diag_crash_clear();
#endif
#if defined(CONFIG_OSCORE_CLOUD_DIAG_DEVICE_INFO)
	device_info_pending = false;
#endif
	diag_heartbeat();
}

#if defined(CONFIG_OSCORE_CLOUD_DIAG_CRASH) && defined(CONFIG_DEBUG_COREDUMP)
/* Block1 upload source: pull `want` bytes of the stored coredump at `offset`. */
static int coredump_block1_source(uint8_t *buf, size_t want, size_t offset, void *ctx)
{
	ARG_UNUSED(ctx);
	return diag_coredump_read(buf, want, offset);
}
#endif

void oscore_cloud_diag_after_send(enum cloud_transport transport)
{
#if defined(CONFIG_OSCORE_CLOUD_DIAG_CRASH) && defined(CONFIG_DEBUG_COREDUMP)
	/* Only move the large blob on a terrestrial bearer; on NTN it waits for the
	 * next terrestrial window. */
	if (transport != CLOUD_TRANSPORT_TN) {
		return;
	}

	int size = diag_coredump_size();

	if (size <= 0) {
		return;
	}

	LOG_INF("Uploading stored coredump (%d bytes) over Block1", size);

	/* SZX 6 == 1024-byte blocks, matching the FOTA download path. */
	int err = cloud_client_oscore_block1_post("c", (size_t)size, 6,
						  coredump_block1_source, NULL);
	if (err) {
		LOG_WRN("coredump upload failed: %d (will retry next session)", err);
		return;
	}

	diag_coredump_erase();
	LOG_INF("Coredump uploaded and erased from flash");
#else
	ARG_UNUSED(transport);
#endif
}
