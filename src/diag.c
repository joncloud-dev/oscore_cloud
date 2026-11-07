/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/hwinfo.h>
#include <zephyr/sys/crc.h>
#include <string.h>

#if defined(CONFIG_SYS_HEAP_RUNTIME_STATS)
#include <zephyr/sys/sys_heap.h>
#endif
#if defined(CONFIG_MODEM_INFO)
#include <modem/modem_info.h>
#endif
#if defined(CONFIG_LTE_LINK_CONTROL)
#include <modem/lte_lc.h>
#endif
#if defined(CONFIG_OSCORE_CLOUD_DIAG_CRASH)
#include <zephyr/fatal.h>
#endif
#include <zephyr/logging/log_ctrl.h>
#include <zephyr/logging/log_backend.h>
#include <zephyr/drivers/uart.h>
#if defined(CONFIG_OSCORE_CLOUD_DIAG_CRASH) || defined(CONFIG_OSCORE_CLOUD_DIAG_LIVENESS)
#include <zephyr/sys/reboot.h>
#endif
#if defined(CONFIG_DEBUG_COREDUMP)
#include <zephyr/debug/coredump.h>
#endif
#if defined(CONFIG_OSCORE_CLOUD_DIAG_BREADCRUMBS)
#include <zephyr/logging/log_backend.h>
#include <zephyr/logging/log_output.h>
#include <zephyr/logging/log_core.h>
#endif

#include <oscore_cloud/diag.h>
#include "diag_priv.h"

LOG_MODULE_REGISTER(diag, CONFIG_OSCORE_CLOUD_DIAG_LOG_LEVEL);

/* "DIAG" — marks the retained region as initialized by this firmware. A cold or
 * brown-out reset leaves SRAM indeterminate, so the magic + CRC together gate
 * whether the previous boot's state can be trusted. */
#define DIAG_MAGIC 0x44494147U

/* Sentinel pending_reason meaning "no planned reboot recorded". */
#define DIAG_REASON_NONE 0xFFU

/* Retained across a warm reset in the __noinit section (not zeroed at boot). The
 * trailing crc covers every field before it. */
struct diag_retained {
	uint32_t magic;
	uint32_t boot_count;
	uint8_t pending_reason;
	uint32_t uptime_s;
	struct diag_crash_info crash;
	uint32_t crc;
};

static __noinit struct diag_retained retained;

/* Module-local copies of what the previous boot left behind, exposed via the
 * getters. Kept separate from `retained` so re-arming the region for the next
 * cycle cannot clobber what we are about to upload. */
static struct diag_boot_report g_boot;
static struct diag_crash_info g_crash;
static bool g_boot_pending;

#if defined(CONFIG_OSCORE_CLOUD_DIAG_BREADCRUMBS)
/* "BCRB": the snapshot of the log ring is captured at crash time. */
#define BC_SNAP_MAGIC 0x42435242U
#define BC_SIZE       CONFIG_OSCORE_CLOUD_DIAG_BREADCRUMB_SIZE
#define LOG_RING_SIZE CONFIG_OSCORE_CLOUD_DIAG_LOG_RING_SIZE

/* Live log ring, plain .bss (zeroed every boot, so it only holds this boot's
 * log tail). Exported under a fixed name with a self-describing header so the
 * server can locate it in a RAM coredump via the ELF symbol table and decode it
 * without knowing this build's Kconfig. Layout is a wire contract (version 1):
 * buf[] is a byte ring, `head` = next write index, `len` = valid bytes. */
#define LOG_RING_MAGIC   0x474F4C4FU /* "OLOG" */
#define LOG_RING_VERSION 1U

struct oscore_diag_log_ring {
	uint32_t magic;
	uint16_t version;
	uint16_t hdr_size;   /* offsetof(buf) */
	uint32_t size;       /* sizeof(buf) */
	uint32_t head;
	uint32_t len;
	uint32_t boot_count; /* boot whose lines these are */
	uint8_t buf[LOG_RING_SIZE];
};

__used struct oscore_diag_log_ring oscore_diag_log_ring;

/* Crash snapshot, __noinit: the fatal handler copies the ring's tail in here
 * (oldest first) so it survives the warm reset and rides the inline crash report.
 * Independent of the live ring, so boot-time logging never clobbers it. */
static __noinit struct diag_bc_snap {
	uint32_t magic;
	uint16_t len;
	uint8_t buf[BC_SIZE];
	uint32_t crc;
} bc_snap;

static char g_breadcrumbs[BC_SIZE];
static uint16_t g_breadcrumbs_len;

static uint32_t bc_snap_crc(void)
{
	return crc32_ieee((const uint8_t *)&bc_snap, offsetof(struct diag_bc_snap, crc));
}
#endif /* CONFIG_OSCORE_CLOUD_DIAG_BREADCRUMBS */

/* Crash metadata (layout + wire contract in diag_priv.h). */
__used struct oscore_diag_crash_meta oscore_diag_crash_meta;

/* CRC over every byte of `retained` up to (not including) the crc field. */
static uint32_t retained_crc(void)
{
	return crc32_ieee((const uint8_t *)&retained,
			  offsetof(struct diag_retained, crc));
}

static bool retained_valid(void)
{
	return retained.magic == DIAG_MAGIC && retained.crc == retained_crc();
}

static void retained_commit(void)
{
	retained.magic = DIAG_MAGIC;
	retained.crc = retained_crc();
}

/* Best-effort mapping from a Zephyr hwinfo reset-cause bitmap to our reason enum
 * when no app intent was retained (an unplanned reset). */
static uint8_t reason_from_hwinfo(uint32_t cause)
{
	if (cause & RESET_WATCHDOG) {
		/* No intent was retained, so neither the task watchdog nor the
		 * pre-watchdog caught the hang before the HW WDT reset. */
		return DIAG_RESET_WATCHDOG_HW_SILENT;
	}
	if (cause & RESET_BROWNOUT) {
		return DIAG_RESET_BROWNOUT;
	}
	if (cause & RESET_POR) {
		return DIAG_RESET_POWER_ON;
	}
	if (cause & RESET_PIN) {
		return DIAG_RESET_PIN;
	}
	if (cause & RESET_DEBUG) {
		return DIAG_RESET_DEBUG;
	}
	if (cause & RESET_SOFTWARE) {
		return DIAG_RESET_SOFTWARE;
	}
	return (cause == 0U) ? DIAG_RESET_POWER_ON : DIAG_RESET_UNKNOWN;
}

#if defined(CONFIG_OSCORE_CLOUD_DIAG_BREADCRUMBS)
static void bc_boot_recover(bool crash_pending);
#endif

#if defined(CONFIG_OSCORE_CLOUD_DIAG_LIVENESS)
/* ---- Cloud-contact liveness watchdog ------------------------------------- */
/* A software watchdog that reboots the device if it goes too long without a
 * successful cloud contact (a diag_heartbeat(), posted by the telemetry path
 * after every accepted uplink). It is armed from boot and rescheduled on every
 * contact, so it catches the "alive but not progressing with the cloud" failure
 * mode that the per-thread task watchdog cannot see (threads keep running and
 * feeding their task watchdogs while the device makes no cloud progress). */
static void liveness_timeout_work_fn(struct k_work *work);
static K_WORK_DELAYABLE_DEFINE(liveness_work, liveness_timeout_work_fn);

static void liveness_timeout_work_fn(struct k_work *work)
{
	ARG_UNUSED(work);

	LOG_ERR("No successful cloud contact in %d s; rebooting to recover",
		CONFIG_OSCORE_CLOUD_DIAG_LIVENESS_TIMEOUT_SECONDS);

#if defined(CONFIG_OSCORE_CLOUD_DIAG_WATCHDOG)
	/* Through the fatal path, so the stall leaves a coredump + log ring. */
	diag_watchdog_liveness();
#endif
	/* Attribute the imminent reboot so the next boot report explains it. */
	diag_set_reboot_reason(DIAG_RESET_WATCHDOG);

	LOG_PANIC();
	sys_reboot(SYS_REBOOT_COLD);
}

/* (Re)start the liveness countdown. Called from boot and on every cloud
 * contact. k_work_reschedule replaces any pending timeout, so a steadily
 * reporting device never fires. */
static void liveness_kick(void)
{
	(void)k_work_reschedule(&liveness_work,
		K_SECONDS(CONFIG_OSCORE_CLOUD_DIAG_LIVENESS_TIMEOUT_SECONDS));
}
#endif /* CONFIG_OSCORE_CLOUD_DIAG_LIVENESS */

static void crash_meta_init(void)
{
	struct oscore_diag_crash_meta *m = &oscore_diag_crash_meta;

	memset(m, 0, sizeof(*m));
	m->magic = CRASH_META_MAGIC;
	m->version = CRASH_META_VERSION;
	m->size = sizeof(*m);
	m->boot_count = g_boot.boot_count;
	m->prev_reset_reason = g_boot.reason;
	m->wdt_channel = 0xFFU;
#if defined(CONFIG_OSCORE_CLOUD_DIAG_BUILD_ID)
	m->build_id_valid = (app_build_id_get(m->build_id) == 0);
	strncpy(m->fw_version, app_fw_version(), sizeof(m->fw_version) - 1);
#endif
#if defined(CONFIG_OSCORE_CLOUD_DIAG_BREADCRUMBS)
	oscore_diag_log_ring.boot_count = g_boot.boot_count;
#endif
}

uint32_t diag_boot_count_current(void)
{
	return oscore_diag_crash_meta.boot_count;
}

void diag_boot_process(void)
{
	uint32_t cause = 0;
	bool valid = retained_valid();

	if (hwinfo_get_reset_cause(&cause) != 0) {
		cause = 0;
	} else {
		/* Clear so the next boot reads only the next reset's cause. */
		(void)hwinfo_clear_reset_cause();
	}

	memset(&g_boot, 0, sizeof(g_boot));
	memset(&g_crash, 0, sizeof(g_crash));

	g_boot.valid = true;
	g_boot.hw_cause = cause;
	g_boot.boot_count = (valid ? retained.boot_count : 0U) + 1U;
	g_boot.prev_uptime_s = valid ? retained.uptime_s : 0U;

	if (valid && retained.pending_reason != DIAG_REASON_NONE) {
		g_boot.reason = retained.pending_reason;
	} else {
		g_boot.reason = reason_from_hwinfo(cause);
	}

	if (valid && retained.crash.valid) {
		g_crash = retained.crash;
		g_boot.crash_pending = true;
	}

#if defined(CONFIG_OSCORE_CLOUD_DIAG_BREADCRUMBS)
	/* Pull the crash-time log snapshot out of retained RAM before anything in
	 * this boot can overwrite the (separate) live ring. */
	bc_boot_recover(g_boot.crash_pending);
#endif

	g_boot_pending = true;
	crash_meta_init();

	LOG_INF("Boot #%u: hw_cause=0x%08x reason=%u prev_uptime=%us crash_pending=%d",
		g_boot.boot_count, g_boot.hw_cause, g_boot.reason,
		g_boot.prev_uptime_s, (int)g_boot.crash_pending);

	/* Re-arm the region for the next cycle: keep the (now-copied) boot counter,
	 * forget the consumed planned-reboot intent, reset the heartbeat uptime, and
	 * preserve the crash breadcrumb until it has actually been uploaded. */
	retained.boot_count = g_boot.boot_count;
	retained.pending_reason = DIAG_REASON_NONE;
	retained.uptime_s = 0;
	if (!g_boot.crash_pending) {
		memset(&retained.crash, 0, sizeof(retained.crash));
	}
	retained_commit();

#if defined(CONFIG_OSCORE_CLOUD_DIAG_LIVENESS)
	/* Arm the cloud-contact liveness watchdog from boot so a device that never
	 * establishes cloud contact after a reset is still recovered. Every
	 * successful contact (diag_heartbeat) reschedules it. */
	liveness_kick();
#endif
}

const struct diag_boot_report *diag_boot_report_get(void)
{
	return &g_boot;
}

bool diag_boot_report_pending(void)
{
	return g_boot_pending;
}

void diag_boot_report_clear(void)
{
	g_boot_pending = false;
}

void diag_set_reboot_reason(enum diag_reset_reason reason)
{
	/* diag_boot_process() runs first and leaves the region valid, but guard
	 * against a caller before init by re-establishing the magic. */
	diag_retained_set_reason((uint8_t)reason);
	LOG_DBG("Planned reboot reason set: %u", (unsigned int)reason);
}

void diag_retained_set_reason(uint8_t reason)
{
	if (!retained_valid()) {
		memset(&retained, 0, sizeof(retained));
		retained.pending_reason = DIAG_REASON_NONE;
	}
	retained.pending_reason = reason;
	/* prev_uptime in the next boot report is the uptime at the reset, not
	 * at the last cloud contact. */
	retained.uptime_s = (uint32_t)k_uptime_seconds();
	retained_commit();
}

void diag_heartbeat(void)
{
#if defined(CONFIG_OSCORE_CLOUD_DIAG_LIVENESS)
	/* A successful cloud contact just happened: defer the liveness reboot.
	 * Done unconditionally (independent of the retained region's validity). */
	liveness_kick();
#endif
	if (!retained_valid()) {
		return;
	}
	retained.uptime_s = (uint32_t)k_uptime_seconds();
	retained_commit();
	oscore_diag_crash_meta.last_contact_s = retained.uptime_s;
}

/* ---- Vitals (Phase 2) ---------------------------------------------------- */

#if defined(CONFIG_SYS_HEAP_RUNTIME_STATS)
/* The kernel's system heap backs k_malloc(); its runtime stats give a cheap,
 * always-available view of heap pressure. The symbol is kernel-internal but
 * stable, and reading it is guarded by the runtime-stats Kconfig. */
extern struct k_heap _system_heap;
#endif

#if defined(CONFIG_THREAD_MONITOR) && defined(CONFIG_THREAD_STACK_INFO)
struct stack_scan {
	uint32_t min_free;
};

static void stack_scan_cb(const struct k_thread *thread, void *user_data)
{
	struct stack_scan *s = user_data;
	size_t unused = 0;

	if (k_thread_stack_space_get(thread, &unused) == 0) {
		if (unused < s->min_free) {
			s->min_free = (uint32_t)unused;
		}
	}
}
#endif

/* ---- Generic vitals list --------------------------------------------------
 * The heartbeat is a small list of typed {key,value} samples so a new device
 * metric costs one add-call in diag_collect_vitals() below and nothing else. */

void diag_vitals_add_uint(struct diag_vitals *v, const char *key, uint32_t value)
{
	if (v->count >= DIAG_VITALS_MAX) {
		LOG_WRN("vitals list full, dropping '%s'", key);
		return;
	}
	v->items[v->count].key = key;
	v->items[v->count].type = DIAG_VITAL_UINT;
	v->items[v->count].value.u = value;
	v->count++;
}

void diag_vitals_add_int(struct diag_vitals *v, const char *key, int32_t value)
{
	if (v->count >= DIAG_VITALS_MAX) {
		LOG_WRN("vitals list full, dropping '%s'", key);
		return;
	}
	v->items[v->count].key = key;
	v->items[v->count].type = DIAG_VITAL_INT;
	v->items[v->count].value.s = value;
	v->count++;
}

#if defined(CONFIG_MODEM_INFO)
/* modem_info connectivity statistics (tx/rx byte counters) must be enabled once
 * before modem_info_get_connectivity_stats() returns non-zero values. */
static void modem_stats_ensure_init(void)
{
	static bool inited;

	if (!inited) {
		if (modem_info_connectivity_stats_init() == 0) {
			inited = true;
		}
	}
}
#endif

/* Sample the current device vitals into *out.
 *
 * >>> To add a new device metric: add ONE diag_vitals_add_uint()/_int() call
 *     below with a fresh 2-char wire key, then document the key in diag.h and
 *     OBSERVABILITY.md §3. No other file needs to change. <<< */
void diag_collect_vitals(struct diag_vitals *out)
{
	out->count = 0;

	/* up: always present, so the server records a heartbeat even when every
	 * optional source is unavailable. */
	diag_vitals_add_uint(out, "up", (uint32_t)k_uptime_seconds());

#if defined(CONFIG_SYS_HEAP_RUNTIME_STATS)
	{
		struct sys_memory_stats stats;

		if (sys_heap_runtime_stats_get(&_system_heap.heap, &stats) == 0) {
			diag_vitals_add_uint(out, "hf", (uint32_t)stats.free_bytes);
			diag_vitals_add_uint(out, "ha", (uint32_t)stats.allocated_bytes);
		}
	}
#endif

#if defined(CONFIG_THREAD_MONITOR) && defined(CONFIG_THREAD_STACK_INFO)
	{
		struct stack_scan s = { .min_free = UINT32_MAX };

		k_thread_foreach_unlocked(stack_scan_cb, &s);
		if (s.min_free != UINT32_MAX) {
			diag_vitals_add_uint(out, "sf", s.min_free);
		}
	}
#endif

#if defined(CONFIG_THREAD_RUNTIME_STATS)
	/* cu: CPU utilisation percent over the interval between heartbeats. The
	 * "all" stats expose execution_cycles (total elapsed) and total_cycles
	 * (non-idle); the ratio of their deltas is the busy fraction. */
	{
		static uint64_t prev_all, prev_busy;
		k_thread_runtime_stats_t rt;

		if (k_thread_runtime_stats_all_get(&rt) == 0) {
			uint64_t d_all = rt.execution_cycles - prev_all;
			uint64_t d_busy = rt.total_cycles - prev_busy;

			prev_all = rt.execution_cycles;
			prev_busy = rt.total_cycles;
			if (d_all > 0) {
				diag_vitals_add_uint(out, "cu",
						     (uint32_t)(d_busy * 100U / d_all));
			}
		}
	}
#endif

#if defined(CONFIG_MODEM_INFO)
	{
		int val = 0;
		uint8_t band = 0;
		int tx_kb = 0, rx_kb = 0;

		if (modem_info_get_rsrp(&val) == 0) {
			diag_vitals_add_int(out, "rp", val);
		}
		if (modem_info_get_snr(&val) == 0) {
			diag_vitals_add_int(out, "rq", val);
		}
		if (modem_info_get_temperature(&val) == 0) {
			diag_vitals_add_int(out, "mt", val);
		}
		if (modem_info_get_current_band(&band) == 0 && band > 0) {
			diag_vitals_add_uint(out, "bn", band);
		}

		/* tx/rx: cumulative modem data volume in kilobytes since power-on —
		 * directly ties fleet health to airtime cost and battery drain. */
		modem_stats_ensure_init();
		if (modem_info_get_connectivity_stats(&tx_kb, &rx_kb) == 0) {
			if (tx_kb >= 0) {
				diag_vitals_add_uint(out, "tx", (uint32_t)tx_kb);
			}
			if (rx_kb >= 0) {
				diag_vitals_add_uint(out, "rx", (uint32_t)rx_kb);
			}
		}
	}
#endif

#if defined(CONFIG_LTE_LINK_CONTROL)
	{
		enum lte_lc_lte_mode mode;
		int tau = 0, active = 0;

		/* lm: access technology (7 LTE-M, 9 NB-IoT, 14 NTN NB-IoT). */
		if (lte_lc_lte_mode_get(&mode) == 0 && mode != LTE_LC_LTE_MODE_NONE) {
			diag_vitals_add_uint(out, "lm", (uint32_t)mode);
		}

		/* pt/pa: negotiated PSM timers (TAU and active time, seconds) — the
		 * knobs that explain a device's power profile and reachability. A
		 * negative value means "not using PSM". */
		if (lte_lc_psm_get(&tau, &active) == 0) {
			if (tau >= 0) {
				diag_vitals_add_uint(out, "pt", (uint32_t)tau);
			}
			if (active >= 0) {
				diag_vitals_add_uint(out, "pa", (uint32_t)active);
			}
		}
	}
#endif
}

/* ---- Crash accessors (snapshot captured by the fatal handler, Phase 3) ---- */

const struct diag_crash_info *diag_crash_get(void)
{
	return g_crash.valid ? &g_crash : NULL;
}

bool diag_crash_pending(void)
{
	return g_crash.valid;
}

void diag_crash_clear(void)
{
	memset(&g_crash, 0, sizeof(g_crash));
	if (retained_valid()) {
		memset(&retained.crash, 0, sizeof(retained.crash));
		retained_commit();
	}
}

/* ---- Log breadcrumbs (Phase 4) ------------------------------------------- */

#if defined(CONFIG_OSCORE_CLOUD_DIAG_BREADCRUMBS)

/* Monotonic count of bytes ever appended (not part of the wire struct). */
static uint32_t bc_written;

/* Append formatted log bytes into the live ring, overwriting the oldest data
 * once full. Called from the log backend's output path (and, during a panic,
 * synchronously), so keep it short and interrupt-safe. */
static void bc_live_append(const uint8_t *data, size_t len)
{
	struct oscore_diag_log_ring *r = &oscore_diag_log_ring;
	unsigned int key = irq_lock();

	if (r->magic != LOG_RING_MAGIC) {
		r->version = LOG_RING_VERSION;
		r->hdr_size = offsetof(struct oscore_diag_log_ring, buf);
		r->size = LOG_RING_SIZE;
		r->head = 0;
		r->len = 0;
		r->magic = LOG_RING_MAGIC;
	}
	for (size_t i = 0; i < len; i++) {
		r->buf[r->head] = data[i];
		r->head = (r->head + 1U) % LOG_RING_SIZE;
	}
	r->len = MIN(r->len + len, (uint32_t)LOG_RING_SIZE);
	bc_written += len;
	irq_unlock(key);
}

/* Copy the ring's most recent BC_SIZE bytes into the retained snapshot, oldest
 * first, starting at a line boundary when possible. Fatal handler only. */
static void bc_capture(void)
{
	const struct oscore_diag_log_ring *r = &oscore_diag_log_ring;
	unsigned int key = irq_lock();
	uint32_t n = MIN(r->len, (uint32_t)BC_SIZE);
	uint32_t start = (r->head + LOG_RING_SIZE - n) % LOG_RING_SIZE;
	uint32_t skip = 0;

	/* Drop a leading partial line if a full one follows. */
	if (n < r->len) {
		while (skip < n && r->buf[(start + skip) % LOG_RING_SIZE] != '\n') {
			skip++;
		}
		skip = (skip < n) ? skip + 1U : 0U;
	}
	for (uint32_t i = skip; i < n; i++) {
		bc_snap.buf[i - skip] = r->buf[(start + i) % LOG_RING_SIZE];
	}
	bc_snap.len = (uint16_t)(n - skip);
	bc_snap.magic = BC_SNAP_MAGIC;
	bc_snap.crc = bc_snap_crc();
	irq_unlock(key);
}

/* Recover the crash-time breadcrumb snapshot at boot (called from
 * diag_boot_process). Copies it out for upload and invalidates it. */
static void bc_boot_recover(bool crash_pending)
{
	g_breadcrumbs_len = 0;

	if (crash_pending && bc_snap.magic == BC_SNAP_MAGIC &&
	    bc_snap.len <= BC_SIZE && bc_snap.crc == bc_snap_crc()) {
		memcpy(g_breadcrumbs, bc_snap.buf, bc_snap.len);
		g_breadcrumbs_len = bc_snap.len;
	}

	/* Invalidate so a later non-crash reboot does not resurrect stale crumbs. */
	bc_snap.magic = 0U;
}

static uint8_t bc_output_buf[64];

static int bc_output_func(uint8_t *data, size_t length, void *ctx)
{
	ARG_UNUSED(ctx);
	bc_live_append(data, length);
	return (int)length;
}

LOG_OUTPUT_DEFINE(bc_log_output, bc_output_func, bc_output_buf, sizeof(bc_output_buf));

static void bc_backend_process(const struct log_backend *const backend,
			       union log_msg_generic *msg)
{
	ARG_UNUSED(backend);
	/* Self-contained lines: uptime timestamp + level + module + message, no
	 * colour. The 8 KiB ring holds a few hundred lines. */
	uint32_t flags = LOG_OUTPUT_FLAG_LEVEL | LOG_OUTPUT_FLAG_TIMESTAMP |
			 LOG_OUTPUT_FLAG_FORMAT_TIMESTAMP;

	log_output_msg_process(&bc_log_output, &msg->log, flags);
}

static void bc_backend_init(const struct log_backend *const backend)
{
	ARG_UNUSED(backend);
}

static void bc_backend_panic(const struct log_backend *const backend)
{
	ARG_UNUSED(backend);
}

static void bc_backend_dropped(const struct log_backend *const backend, uint32_t cnt)
{
	ARG_UNUSED(backend);
	log_output_dropped_process(&bc_log_output, cnt);
}

static const struct log_backend_api bc_backend_api = {
	.process = bc_backend_process,
	.init = bc_backend_init,
	.panic = bc_backend_panic,
	.dropped = bc_backend_dropped,
};

LOG_BACKEND_DEFINE(diag_bc_backend, bc_backend_api, true);

#endif /* CONFIG_OSCORE_CLOUD_DIAG_BREADCRUMBS */

/* ---- Coredump pre-capture: logs into the ring, console after the dump ----- */

static bool g_precaptured;
#if defined(CONFIG_OSCORE_CLOUD_DIAG_BREADCRUMBS)
static uint32_t g_replay_from; /* bc_written when the flush started */
#endif

void diag_coredump_pre_capture(void)
{
	/* Runs from the coredump backend's start hook: inside the fatal path, before
	 * any memory is dumped and before k_sys_fatal_error_handler. Flush the
	 * deferred log queue so the last lines (incl. Zephyr's own fault report)
	 * land in the RAM log ring and therefore in the dump.
	 *
	 * Only the ring backend stays active for this flush. On nRF91 a BusFault is
	 * taken by TF-M first (which prints on the shared UART0) and then forwarded;
	 * a non-secure UARTE poll-out at that point faults again and TF-M resets the
	 * SoC, which would lose the dump. The console gets the same lines afterwards
	 * via diag_console_replay(), once the dump is safely stored. */
	diag_prewdt_disarm(); /* the dump write feeds the HW WDT itself */
#if defined(CONFIG_OSCORE_CLOUD_DIAG_BREADCRUMBS)
	STRUCT_SECTION_FOREACH(log_backend, b) {
		if (b != &diag_bc_backend) {
			log_backend_deactivate(b);
		}
	}
	g_replay_from = bc_written;
#endif
	LOG_PANIC();
	oscore_diag_crash_meta.captured = 1U;
	g_precaptured = true;
}

#if defined(CONFIG_OSCORE_CLOUD_DIAG_CRASH)
static void console_puts(const char *s, size_t n)
{
#if DT_HAS_CHOSEN(zephyr_console)
	const struct device *con = DEVICE_DT_GET(DT_CHOSEN(zephyr_console));

	if (!device_is_ready(con)) {
		return;
	}
	for (size_t i = 0; i < n; i++) {
		if (s[i] == '\n') {
			uart_poll_out(con, '\r');
		}
		uart_poll_out(con, s[i]);
	}
#else
	ARG_UNUSED(s);
	ARG_UNUSED(n);
#endif
}

/* Best-effort: echo the lines the pre-capture flush diverted into the ring. */
static void diag_console_replay(void)
{
#if defined(CONFIG_OSCORE_CLOUD_DIAG_BREADCRUMBS)
	const struct oscore_diag_log_ring *r = &oscore_diag_log_ring;
	uint32_t n = MIN(bc_written - g_replay_from, r->len);
	uint32_t start = (r->head + LOG_RING_SIZE - n) % LOG_RING_SIZE;

	for (uint32_t i = 0; i < n; i++) {
		console_puts((const char *)&r->buf[(start + i) % LOG_RING_SIZE], 1);
	}
#endif
}
#endif /* CONFIG_OSCORE_CLOUD_DIAG_CRASH */

const char *diag_breadcrumbs_get(uint16_t *len)
{
#if defined(CONFIG_OSCORE_CLOUD_DIAG_BREADCRUMBS)
	if (g_breadcrumbs_len > 0) {
		if (len) {
			*len = g_breadcrumbs_len;
		}
		return g_breadcrumbs;
	}
#endif
	if (len) {
		*len = 0;
	}
	return NULL;
}

/* ---- Crash capture: fatal handler (Phase 3) ------------------------------ */

#if defined(CONFIG_OSCORE_CLOUD_DIAG_CRASH)

#if defined(CONFIG_AT_MONITOR) && defined(CONFIG_CPU_CORTEX_M)
extern void at_monitor_dispatch(const char *notif);

/* at_monitor_dispatch runs in the modem IPC ISR; heap exhaustion trips
 * __ASSERT(at_notif, ...) (at_monitor.c:79) with lr pointing back into the
 * dispatch path. esf is often NULL for that panic, so fall back to the fault
 * stack's saved lr (see Zephyr arch_coredump z_arm_coredump_fault_sp). */
static bool fatal_is_at_monitor_heap(unsigned int reason, const struct arch_esf *esf)
{
	uint32_t lr = 0U;

	if (reason != K_ERR_KERNEL_PANIC) {
		return false;
	}

	if (esf != NULL) {
		lr = esf->basic.lr;
	}
#if defined(CONFIG_DEBUG_COREDUMP)
	/* z_arm_coredump_fault_sp only exists when the coredump subsystem is
	 * linked in; without it, a NULL esf simply cannot be classified. */
	else {
		extern uint32_t z_arm_coredump_fault_sp;
		const uint32_t *sp = (const uint32_t *)(uintptr_t)z_arm_coredump_fault_sp;

		if (sp != NULL) {
			lr = sp[0];
		}
	}
#endif

	{
		uintptr_t base = (uintptr_t)(void *)&at_monitor_dispatch;
		/* Wrapper + .part.0; generous for thumb/LTO layout drift. */
		const uintptr_t bound = base + 0x300U;

		return lr >= base && lr < bound;
	}
}
#else
static bool fatal_is_at_monitor_heap(unsigned int reason, const struct arch_esf *esf)
{
	ARG_UNUSED(reason);
	ARG_UNUSED(esf);
	return false;
}
#endif /* CONFIG_AT_MONITOR && CONFIG_CPU_CORTEX_M */

/* Snapshot the fault into the retained region: fault type, core registers from
 * the exception stack frame, and a slice of stack words (the server filters
 * these to code addresses and symbolicates them). Runs in fault context, so it
 * only touches the retained struct and the (valid) esf memory. */
static void diag_crash_capture(unsigned int reason, const struct arch_esf *esf)
{
	struct diag_crash_info ci;

	memset(&ci, 0, sizeof(ci));
	ci.valid = true;
	ci.fault_type = reason;
#if defined(CONFIG_OSCORE_CLOUD_DIAG_BUILD_ID)
	/* Reads only ROM, so safe in fault context. */
	ci.build_id_valid = (app_build_id_get(ci.build_id) == 0);
#endif

#if defined(CONFIG_CPU_CORTEX_M)
	if (esf != NULL) {
		ci.pc = esf->basic.pc;
		ci.lr = esf->basic.lr;
		ci.regs[0] = esf->basic.a1;
		ci.regs[1] = esf->basic.a2;
		ci.regs[2] = esf->basic.a3;
		ci.regs[3] = esf->basic.a4;
		ci.regs[4] = esf->basic.ip;
		ci.regs[5] = esf->basic.lr;
		ci.regs[6] = esf->basic.pc;
		ci.regs[7] = esf->basic.xpsr;
		ci.reg_count = 8;

		/* The exception stack frame sits at the fault-time stack pointer; the
		 * words above it are the pre-fault stack, a source of return-address
		 * candidates for an approximate backtrace. */
		const uint32_t *sp = (const uint32_t *)esf;

		for (uint8_t i = 0; i < DIAG_CRASH_MAX_STACK; i++) {
			ci.stack[i] = sp[i];
		}
		ci.stack_count = DIAG_CRASH_MAX_STACK;
	}
#else
	ARG_UNUSED(esf);
#endif

	retained.crash = ci;
	/* Keep a more specific reason if one was set just before the fault (e.g. a
	 * watchdog timeout), else attribute the reset to the fault itself. */
	if (retained.pending_reason == DIAG_REASON_NONE) {
		if (fatal_is_at_monitor_heap(reason, esf)) {
			retained.pending_reason = DIAG_RESET_AT_MONITOR_HEAP;
		} else {
			retained.pending_reason = DIAG_RESET_FATAL;
		}
	}
	retained.uptime_s = (uint32_t)k_uptime_seconds();
	retained_commit();

#if defined(CONFIG_OSCORE_CLOUD_DIAG_BREADCRUMBS)
	/* Freeze the log ring leading up to the fault so it ships with the report. */
	bc_capture();
#endif
}

/* Replace Zephyr's default fatal handler so a crash is captured to retained RAM
 * before the device resets. Mirrors the default's reset-on-fatal behaviour. */
void k_sys_fatal_error_handler(unsigned int reason, const struct arch_esf *esf)
{
	diag_crash_capture(reason, esf);
	if (g_precaptured) {
		/* The coredump is stored; the logs went only to the ring. */
		char line[48];
		int n = snprintk(line, sizeof(line), "diag: fatal error %u captured; rebooting\n",
				 reason);

		diag_console_replay();
		console_puts(line, MAX(n, 0));
	} else {
		LOG_PANIC();
		LOG_ERR("Fatal error %u captured; rebooting", reason);
	}
	sys_reboot(SYS_REBOOT_COLD);
	CODE_UNREACHABLE;
}

#endif /* CONFIG_OSCORE_CLOUD_DIAG_CRASH */

/* ---- Full coredump ------------------------------------------------------- */
/* Backend-agnostic: Zephyr's fatal path writes the dump to the configured
 * backend automatically; here we only read it back (next boot) via the generic
 * coredump_query/coredump_cmd API and stream it out over Block1. */

int diag_coredump_size(void)
{
#if defined(CONFIG_DEBUG_COREDUMP)
	int has = coredump_query(COREDUMP_QUERY_HAS_STORED_DUMP, NULL);

	if (has != 1) {
		return 0; /* none stored (or query unsupported) */
	}
	int sz = coredump_query(COREDUMP_QUERY_GET_STORED_DUMP_SIZE, NULL);

	return sz < 0 ? 0 : sz;
#else
	return 0;
#endif
}

int diag_coredump_read(uint8_t *buf, size_t want, size_t offset)
{
#if defined(CONFIG_DEBUG_COREDUMP)
	struct coredump_cmd_copy_arg arg = {
		.offset = offset,
		.buffer = buf,
		.length = want,
	};
	int rc = coredump_cmd(COREDUMP_CMD_COPY_STORED_DUMP, &arg);

	return rc < 0 ? rc : (int)want;
#else
	ARG_UNUSED(buf);
	ARG_UNUSED(want);
	ARG_UNUSED(offset);
	return -ENOTSUP;
#endif
}

void diag_coredump_erase(void)
{
#if defined(CONFIG_DEBUG_COREDUMP)
	(void)coredump_cmd(COREDUMP_CMD_ERASE_STORED_DUMP, NULL);
#endif
}

/* Backends that can describe their slot (coredump_backend_spi_nor.c) override. */
__weak int diag_coredump_info(struct diag_coredump_info *info)
{
	ARG_UNUSED(info);
	return -ENOTSUP;
}

/* ---- Shell: fault injection & inspection --------------------------------- */
/* Commands to exercise the observability pipeline from a serial console. The
 * fault triggers deliberately crash the device; the diag fatal handler captures
 * a snapshot to retained RAM and reboots, and the next boot uploads the crash
 * report (+ breadcrumbs, + coredump on terrestrial). Usage: `diag <cmd>`. */
#if defined(CONFIG_SHELL)
#include <zephyr/shell/shell.h>
#include <zephyr/sys/reboot.h>

/* Volatile sink so the optimiser cannot elide the faulting accesses below. */
static volatile uint32_t diag_sink;

static int cmd_diag_info(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	const struct diag_boot_report *b = diag_boot_report_get();

	if (b != NULL && b->valid) {
		shell_print(sh, "boot:   #%u reason=%u hw_cause=0x%08x prev_uptime=%us",
			    b->boot_count, b->reason, b->hw_cause, b->prev_uptime_s);
	} else {
		shell_print(sh, "boot:   <not processed>");
	}
#if defined(CONFIG_OSCORE_CLOUD_DIAG_BUILD_ID)
	shell_print(sh, "fw:     %s (build-id %s)", app_fw_version(),
		    app_build_id_hex()[0] != '\0' ? app_build_id_hex() : "<none>");
#endif
	shell_print(sh, "crash:  pending=%d", (int)diag_crash_pending());
#if defined(CONFIG_OSCORE_CLOUD_DIAG_BREADCRUMBS)
	{
		uint16_t bl = 0;
		const char *bc = diag_breadcrumbs_get(&bl);

		shell_print(sh, "crumbs: %u bytes%s", bl, (bc && bl) ? "" : " (none)");
	}
#endif
#if defined(CONFIG_DEBUG_COREDUMP)
	shell_print(sh, "dump:   %d bytes stored", diag_coredump_size());
#endif

	struct diag_vitals v;

	diag_collect_vitals(&v);
	shell_print(sh, "vitals: %u sample(s)", v.count);
	for (uint8_t i = 0; i < v.count; i++) {
		const struct diag_vital *it = &v.items[i];

		if (it->type == DIAG_VITAL_INT) {
			shell_print(sh, "  %s = %d", it->key, it->value.s);
		} else {
			shell_print(sh, "  %s = %u", it->key, it->value.u);
		}
	}
	return 0;
}

static int cmd_diag_reboot(const struct shell *sh, size_t argc, char **argv)
{
	enum diag_reset_reason reason = DIAG_RESET_SOFTWARE;

	if (argc >= 2) {
		if (strcmp(argv[1], "fota") == 0) {
			reason = DIAG_RESET_FOTA;
		} else if (strcmp(argv[1], "user") == 0) {
			reason = DIAG_RESET_USER;
		} else if (strcmp(argv[1], "software") == 0) {
			reason = DIAG_RESET_SOFTWARE;
		} else {
			shell_error(sh, "unknown reason '%s' (fota|user|software)", argv[1]);
			return -EINVAL;
		}
	}
	shell_print(sh, "rebooting (reason=%u)...", reason);
	diag_set_reboot_reason(reason);
	k_sleep(K_MSEC(50));
	sys_reboot(SYS_REBOOT_WARM);
	return 0;
}

/* Recurse with a per-frame buffer the optimiser must keep, to blow the thread
 * stack and trip the stack guard (PSPLIM). Each frame's buffer address is
 * passed to the callee and read again after the call returns, so the frame
 * must stay live: GCC can neither tail-call it nor turn it into an accumulator
 * loop (which the old `pad[0] + diag_recurse(depth + 1)` form allowed, making
 * `diag fault stack` spin forever instead of overflowing). */
static uint32_t __noinline diag_recurse(uint32_t depth, volatile uint32_t *prev)
{
	volatile uint32_t pad[16];

	for (size_t i = 0; i < ARRAY_SIZE(pad); i++) {
		pad[i] = depth + i + (prev != NULL ? prev[i] : 0U);
	}
	/* Never true at runtime; stops the optimiser proving infinite recursion. */
	if (diag_sink == 0xFFFFFFFFU) {
		return depth;
	}

	uint32_t r = diag_recurse(depth + 1, pad);

	return r ^ pad[r % ARRAY_SIZE(pad)];
}

/* Leaf handler: the fault kind is the subcommand name (argv[0]), e.g. the
 * command `diag fault null` invokes this with argv[0] == "null". */
static int cmd_diag_fault_do(const struct shell *sh, size_t argc, char **argv)
{
	const char *kind = argv[0];

	ARG_UNUSED(argc);
	shell_print(sh, "injecting fault '%s'; device will crash and reboot", kind);
	k_sleep(K_MSEC(50)); /* let the line flush before we fault */

	if (strcmp(kind, "null") == 0) {
		/* A write through address 0 is attributed to *secure* flash by the
		 * SAU, so it traps in TF-M as a SecureFault and never reaches this
		 * app's handler (no coredump). To exercise the non-secure capture
		 * path instead, write to a read-only address in *our* (non-secure)
		 * flash: the MPU marks the text/rodata region no-write, so the CPU
		 * takes a non-secure MemManage fault that Zephyr coredumps. Use
		 * `diag fault secure` for the genuine secure-region case. */
		volatile uint32_t *p =
			(volatile uint32_t *)((uintptr_t)&diag_recurse & ~0x3U);

		*p = 0xDEADBEEFU; /* store to read-only flash -> BusFault (forwarded by TF-M) */
	} else if (strcmp(kind, "badjump") == 0) {
		/* Jump into a non-secure RAM buffer (execute-never under the MPU) to
		 * model a corrupted function pointer. The thumb bit is set so the
		 * fault is a genuine XN/exec violation (non-secure MemManage), not an
		 * INVSTATE state error, and the captured PC points into RAM. */
		void (*fn)(void) = (void (*)(void))((uintptr_t)&diag_sink | 1U);

		fn(); /* execute from XN RAM -> NS MemManage, pc captured */
	} else if (strcmp(kind, "secure") == 0) {
		/* The one deliberately-secure case: a write to secure-attributed
		 * address 0 traps in TF-M. The app handler cannot run, so record the
		 * intent first; with CONFIG_TFM_HALT_ON_CORE_PANIC=n TF-M cold-resets
		 * and the next boot reports it. No coredump is possible here. */
		volatile uint32_t *p = (volatile uint32_t *)0;

		shell_warn(sh, "secure fault: TF-M will reset (no coredump)");
		diag_set_reboot_reason(DIAG_RESET_SECURE_FAULT);
		k_sleep(K_MSEC(50));
		*p = 0xDEADBEEFU; /* store to secure region -> SecureFault (TF-M) */
	} else if (strcmp(kind, "stack") == 0) {
		diag_sink = diag_recurse(0, NULL);
	} else if (strcmp(kind, "oops") == 0) {
		k_oops();
	} else if (strcmp(kind, "panic") == 0) {
		k_panic();
	} else if (strcmp(kind, "assert") == 0) {
#if defined(CONFIG_ASSERT)
		__ASSERT(false, "diag: forced assert");
#else
		shell_warn(sh, "CONFIG_ASSERT disabled; falling back to k_panic");
		k_panic();
#endif
	} else if (strcmp(kind, "unaligned") == 0) {
		/* Cortex-M33 performs unaligned LDR/STR unless CCR.UNALIGN_TRP is
		 * set, and setting it globally makes the fault handlers themselves
		 * fault (nested fault -> secure HardFault, no dump). LDRD always
		 * faults on an unaligned address, so use it on an odd address inside
		 * an NS RAM buffer (0x20000001 would be TF-M's secure RAM and give a
		 * forwarded SecureFault instead). */
		static volatile uint32_t buf[3];
		uintptr_t a = (uintptr_t)buf + 1U;
#if defined(CONFIG_CPU_CORTEX_M)
		uint32_t lo, hi;

		__asm__ volatile("ldrd %0, %1, [%2]" : "=r"(lo), "=r"(hi) : "r"(a) : "memory");
		diag_sink = lo ^ hi; /* -> UsageFault (UNALIGNED) */
#else
		diag_sink = *(volatile uint32_t *)a;
#endif
	}

	shell_warn(sh, "fault did not trip (config-dependent); try another");
	return 0;
}

static int cmd_diag_fault(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	shell_error(sh,
		    "usage: diag fault <null|badjump|stack|oops|panic|assert|unaligned|secure>");
	return -EINVAL;
}

#if defined(CONFIG_OSCORE_CLOUD_DIAG_WATCHDOG)
#include <zephyr/task_wdt/task_wdt.h>

/* Spare IRQ line for `diag hang isr`: TIMER2's vector, unless something owns
 * TIMER2. A board may mark the node "okay" with no driver behind it (the
 * Thingy:91 X enables all three TIMERs), so the test is "no driver uses it",
 * not "the node is disabled". Should another user connect the IRQ anyway, the
 * static ISR table rejects the duplicate at build time. */
#if DT_NODE_EXISTS(DT_NODELABEL(timer2)) && !defined(CONFIG_NRF_TIMER2_SECURE) && \
	!defined(CONFIG_NRFX_TIMER2) && \
	!(DT_NODE_HAS_STATUS_OKAY(DT_NODELABEL(timer2)) && defined(CONFIG_COUNTER))
#define DIAG_HANG_IRQ DT_IRQN(DT_NODELABEL(timer2))
#endif

static K_SEM_DEFINE(diag_hang_never, 0, 1);

static void diag_hang_wdt_cb(int channel_id, void *user_data)
{
	diag_watchdog_trigger(channel_id, user_data);
}

/* The spin the pre-watchdog must catch: no feed, no scheduler, no timer ISR. */
static void __noinline diag_hang_spin(void)
{
	for (;;) {
		diag_sink++;
	}
}

#if defined(DIAG_HANG_IRQ)
static void diag_hang_isr(const void *arg)
{
	ARG_UNUSED(arg);
	diag_hang_spin(); /* never returns: starves every lower-priority IRQ */
}
#endif

static int cmd_diag_hang_do(const struct shell *sh, size_t argc, char **argv)
{
	const char *kind = argv[0];

	ARG_UNUSED(argc);
	if (strcmp(kind, "thread") == 0) {
		int ch = task_wdt_add(CONFIG_TASK_WDT_MIN_TIMEOUT, diag_hang_wdt_cb,
				      (void *)k_current_get());

		if (ch < 0) {
			shell_error(sh, "task_wdt_add failed: %d", ch);
			return ch;
		}
		shell_print(sh, "hang 'thread': task_wdt channel %d, %u ms, never fed", ch,
			    CONFIG_TASK_WDT_MIN_TIMEOUT);
		LOG_WRN("diag hang thread: %s blocks forever on channel %d",
			k_thread_name_get(k_current_get()), ch);
		(void)k_sem_take(&diag_hang_never, K_FOREVER);
		return 0;
	}

	shell_print(sh, "hang '%s': the pre-watchdog must catch this", kind);
	LOG_WRN("diag hang %s: spinning", kind);
	k_sleep(K_MSEC(100)); /* let the lines reach the console and the ring */

	if (strcmp(kind, "irqlock") == 0) {
		unsigned int key = irq_lock();

		ARG_UNUSED(key);
		diag_hang_spin();
	}
#if defined(DIAG_HANG_IRQ)
	if (strcmp(kind, "isr") == 0) {
		IRQ_CONNECT(DIAG_HANG_IRQ, 0, diag_hang_isr, NULL, 0);
		irq_enable(DIAG_HANG_IRQ);
		NVIC_SetPendingIRQ(DIAG_HANG_IRQ);
		k_sleep(K_FOREVER);
	}
#endif
	shell_error(sh, "'%s' not available in this build", kind);
	return -ENOTSUP;
}

static int cmd_diag_hang(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	shell_error(sh, "usage: diag hang <thread|irqlock|isr>");
	return -EINVAL;
}

SHELL_STATIC_SUBCMD_SET_CREATE(
	diag_hang_sub,
	SHELL_CMD(thread, NULL, "Starve a task_wdt channel (task watchdog dump)", cmd_diag_hang_do),
	SHELL_CMD(irqlock, NULL, "Spin with IRQs locked (pre-watchdog dump)", cmd_diag_hang_do),
	SHELL_CMD(isr, NULL, "Spin in a high-priority ISR (pre-watchdog dump)", cmd_diag_hang_do),
	SHELL_SUBCMD_SET_END);
#endif /* CONFIG_OSCORE_CLOUD_DIAG_WATCHDOG */

#if defined(CONFIG_DEBUG_COREDUMP)
static int cmd_diag_coredump(const struct shell *sh, size_t argc, char **argv)
{
	if (argc >= 2 && strcmp(argv[1], "erase") == 0) {
		diag_coredump_erase();
		shell_print(sh, "coredump erased");
		return 0;
	}
	if (argc >= 2 && strcmp(argv[1], "verify") == 0) {
		int v = coredump_cmd(COREDUMP_CMD_VERIFY_STORED_DUMP, NULL);

		shell_print(sh, "coredump verify: %s (%d)", v == 1 ? "OK" : "FAIL", v);
		return 0;
	}

	struct diag_coredump_info ci;
	static const char *const st[] = {"clean", "pending", "dirty", "erasing"};

	if (diag_coredump_info(&ci) == 0) {
		shell_print(sh, "coredump: %s, %u / %u bytes%s, crc 0x%08x, write %u ms, dropped %u",
			    ci.state < ARRAY_SIZE(st) ? st[ci.state] : "?", ci.size,
			    ci.capacity, ci.truncated ? " (TRUNCATED)" : "", ci.crc, ci.write_ms,
			    ci.dropped);
		if (ci.state == DIAG_COREDUMP_PENDING) {
			shell_print(sh, "          boot #%u, reason %u, build-id %s", ci.boot_count,
				    ci.reason, ci.build_id_valid ? "set" : "none");
		}
	} else {
		shell_print(sh, "coredump: %d bytes stored", diag_coredump_size());
	}
	return 0;
}
#endif

SHELL_STATIC_SUBCMD_SET_CREATE(
	diag_fault_sub,
	SHELL_CMD(null, NULL, "Write read-only flash (BusFault via TF-M, coredump)", cmd_diag_fault_do),
	SHELL_CMD(badjump, NULL, "Execute from RAM (NS MemManage, coredump)", cmd_diag_fault_do),
	SHELL_CMD(stack, NULL, "Overflow the stack", cmd_diag_fault_do),
	SHELL_CMD(oops, NULL, "k_oops()", cmd_diag_fault_do),
	SHELL_CMD(panic, NULL, "k_panic()", cmd_diag_fault_do),
	SHELL_CMD(assert, NULL, "Forced __ASSERT", cmd_diag_fault_do),
	SHELL_CMD(unaligned, NULL, "Unaligned word load (UsageFault, coredump)", cmd_diag_fault_do),
	SHELL_CMD(secure, NULL, "Secure-region write (TF-M reset, no coredump)", cmd_diag_fault_do),
	SHELL_SUBCMD_SET_END);

SHELL_STATIC_SUBCMD_SET_CREATE(
	diag_sub,
	SHELL_CMD(info, NULL, "Show boot/crash/vitals state", cmd_diag_info),
	SHELL_CMD(fault, &diag_fault_sub, "Inject a fault (then reboot)", cmd_diag_fault),
#if defined(CONFIG_OSCORE_CLOUD_DIAG_WATCHDOG)
	SHELL_CMD(hang, &diag_hang_sub, "Inject a hang (watchdog dump, then reboot)", cmd_diag_hang),
#endif
	SHELL_CMD_ARG(reboot, NULL, "Reboot [fota|user|software]", cmd_diag_reboot, 1, 1),
#if defined(CONFIG_DEBUG_COREDUMP)
	SHELL_CMD_ARG(coredump, NULL, "Show, 'verify' or 'erase' stored coredump", cmd_diag_coredump, 1, 1),
#endif
	SHELL_SUBCMD_SET_END);

SHELL_CMD_REGISTER(diag, &diag_sub, "Device diagnostics & fault injection", NULL);

#endif /* CONFIG_SHELL */
