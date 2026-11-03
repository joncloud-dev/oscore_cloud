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
#if defined(CONFIG_OSCORE_CLOUD_DIAG_CRASH) || defined(CONFIG_OSCORE_CLOUD_DIAG_LIVENESS)
#include <zephyr/sys/reboot.h>
#include <zephyr/logging/log_ctrl.h>
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

/* Live ring, plain .bss: zeroed at every boot so it only ever holds the current
 * boot's log tail. A byte ring (head = next write, len = valid bytes). */
static uint8_t bc_live[BC_SIZE];
static uint16_t bc_head;
static uint16_t bc_len;

/* Crash snapshot, __noinit: the fatal handler linearises the live ring into here
 * (oldest first) so it survives the warm reset and the next boot can upload it.
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
		return DIAG_RESET_WATCHDOG;
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
	if (!retained_valid()) {
		memset(&retained, 0, sizeof(retained));
		retained.pending_reason = DIAG_REASON_NONE;
	}
	retained.pending_reason = (uint8_t)reason;
	retained_commit();
	LOG_DBG("Planned reboot reason set: %u", (unsigned int)reason);
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

/* Append formatted log bytes into the live ring, overwriting the oldest data
 * once full. Called from the log backend's output path (and, during a panic,
 * synchronously), so keep it short and interrupt-safe. */
static void bc_live_append(const uint8_t *data, size_t len)
{
	unsigned int key = irq_lock();

	for (size_t i = 0; i < len; i++) {
		bc_live[bc_head] = data[i];
		bc_head = (uint16_t)((bc_head + 1U) % BC_SIZE);
		if (bc_len < BC_SIZE) {
			bc_len++;
		}
	}
	irq_unlock(key);
}

/* Capture the live ring into the retained snapshot, linearised oldest-first, so
 * the next boot can read a contiguous breadcrumb trail. Invoked from the fatal
 * handler before the reset. */
static void bc_capture(void)
{
	unsigned int key = irq_lock();
	uint16_t n = bc_len;
	uint16_t start = (bc_len == BC_SIZE) ? bc_head : 0U;

	for (uint16_t i = 0; i < n; i++) {
		bc_snap.buf[i] = bc_live[(start + i) % BC_SIZE];
	}
	bc_snap.len = n;
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
	/* Compact, self-contained lines: level + module + message, no colour or
	 * timestamp, to stretch the small retained ring across more events. */
	uint32_t flags = LOG_OUTPUT_FLAG_LEVEL;

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
	LOG_PANIC();
	LOG_ERR("Fatal error %u captured; rebooting", reason);
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
 * stack and trip the MPU stack guard. */
static uint32_t diag_recurse(uint32_t depth)
{
	volatile uint32_t pad[16];

	for (size_t i = 0; i < ARRAY_SIZE(pad); i++) {
		pad[i] = depth + i;
	}
	diag_sink += pad[depth % ARRAY_SIZE(pad)];
	/* Never true at runtime, but stops the optimiser from proving the
	 * recursion is infinite (and tail-calling / warning about it). */
	if (diag_sink == 0xFFFFFFFFU) {
		return depth;
	}
	return pad[0] + diag_recurse(depth + 1);
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

		*p = 0xDEADBEEFU; /* store to read-only flash -> NS MemManage */
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
		diag_sink = diag_recurse(0);
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
		volatile uint32_t *p = (volatile uint32_t *)0x20000001U;

		diag_sink = *p; /* unaligned word access -> usage fault */
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

#if defined(CONFIG_DEBUG_COREDUMP)
static int cmd_diag_coredump(const struct shell *sh, size_t argc, char **argv)
{
	if (argc >= 2 && strcmp(argv[1], "erase") == 0) {
		diag_coredump_erase();
		shell_print(sh, "coredump erased");
		return 0;
	}
	shell_print(sh, "coredump: %d bytes stored", diag_coredump_size());
	return 0;
}
#endif

SHELL_STATIC_SUBCMD_SET_CREATE(
	diag_fault_sub,
	SHELL_CMD(null, NULL, "Write read-only flash (NS MemManage, coredump)", cmd_diag_fault_do),
	SHELL_CMD(badjump, NULL, "Execute from RAM (NS MemManage, coredump)", cmd_diag_fault_do),
	SHELL_CMD(stack, NULL, "Overflow the stack", cmd_diag_fault_do),
	SHELL_CMD(oops, NULL, "k_oops()", cmd_diag_fault_do),
	SHELL_CMD(panic, NULL, "k_panic()", cmd_diag_fault_do),
	SHELL_CMD(assert, NULL, "Forced __ASSERT", cmd_diag_fault_do),
	SHELL_CMD(unaligned, NULL, "Unaligned access", cmd_diag_fault_do),
	SHELL_CMD(secure, NULL, "Secure-region write (TF-M reset, no coredump)", cmd_diag_fault_do),
	SHELL_SUBCMD_SET_END);

SHELL_STATIC_SUBCMD_SET_CREATE(
	diag_sub,
	SHELL_CMD(info, NULL, "Show boot/crash/vitals state", cmd_diag_info),
	SHELL_CMD(fault, &diag_fault_sub, "Inject a fault (then reboot)", cmd_diag_fault),
	SHELL_CMD_ARG(reboot, NULL, "Reboot [fota|user|software]", cmd_diag_reboot, 1, 1),
#if defined(CONFIG_DEBUG_COREDUMP)
	SHELL_CMD_ARG(coredump, NULL, "Show or 'erase' stored coredump", cmd_diag_coredump, 1, 1),
#endif
	SHELL_SUBCMD_SET_END);

SHELL_CMD_REGISTER(diag, &diag_sub, "Device diagnostics & fault injection", NULL);

#endif /* CONFIG_SHELL */
