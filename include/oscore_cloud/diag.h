/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Device observability (Memfault-style), reported natively over the existing
 * OSCORE/CoAP/CBOR telemetry path. This module owns the device side of three
 * fleet-health signals, each folded into the ordinary telemetry uplink as a
 * nested CBOR map so no extra CoAP route is needed and an NTN device spends one
 * round-trip:
 *
 *   key 20  boot report    reboot reason (hwinfo cause + app intent)   Phase 1
 *   key 21  vitals         heap/stack/modem/battery heartbeat          Phase 2
 *   key 22  crash report   minimal fault snapshot (regs + stack)       Phase 3
 *
 * Persistence across a reset uses a __noinit "retained" RAM region validated by
 * a magic word + CRC32. nRF9151 SRAM keeps its contents across a warm reset
 * (software/watchdog/fault), so a boot can recover the previous shutdown's
 * intent and a crash breadcrumb; a cold/brown-out reset invalidates the region
 * and the reason falls back to the hwinfo cause.
 *
 * This is the raw collector API. Most applications never call it directly:
 * enable CONFIG_OSCORE_CLOUD_DIAG and let the session helper (or the bridge in
 * oscore_cloud/diag_bridge.h) fold these signals into telemetry automatically.
 */

#ifndef OSCORE_CLOUD_DIAG_H_
#define OSCORE_CLOUD_DIAG_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <oscore_cloud/build_id.h>

#ifdef __cplusplus
extern "C" {
#endif

/* App-level reboot reason. The numeric values are the wire contract with the
 * server (deviceapi resetReasonNames) and MUST stay in sync. */
enum diag_reset_reason {
	DIAG_RESET_POWER_ON = 0, /* cold boot, no retained intent */
	DIAG_RESET_WATCHDOG = 1, /* task/hardware watchdog timeout */
	DIAG_RESET_FOTA     = 2, /* planned reboot to apply an image */
	DIAG_RESET_FATAL    = 3, /* assert / fault / SEND_FATAL_ERROR() */
	DIAG_RESET_USER     = 4, /* operator/button-initiated */
	DIAG_RESET_BROWNOUT = 5, /* supply dipped */
	DIAG_RESET_PIN      = 6, /* external reset pin */
	DIAG_RESET_SOFTWARE = 7, /* sys_reboot() with no finer intent */
	DIAG_RESET_DEBUG    = 8, /* debugger-initiated */
	DIAG_RESET_UNKNOWN  = 9, /* indeterminate */
	DIAG_RESET_SECURE_FAULT = 10, /* TF-M core panic (secure-region fault); no
				       * NS crash capture is possible, so this is
				       * only recorded when the intent was set
				       * before the fault (e.g. `diag fault secure`) */
	DIAG_RESET_AT_MONITOR_HEAP = 11, /* at_monitor heap exhausted in the IPC ISR
					    * (__ASSERT at at_monitor.c heap alloc) */
};

/* Composed at boot from the hwinfo reset cause and the retained app intent. */
struct diag_boot_report {
	bool valid;
	uint32_t hw_cause;     /* Zephyr hwinfo reset-cause bitmap */
	uint8_t reason;        /* enum diag_reset_reason */
	uint32_t prev_uptime_s;/* uptime at the last heartbeat before reset */
	uint32_t boot_count;   /* monotonic boot counter */
	bool crash_pending;    /* a crash report is buffered for upload */
};

/* A minimal, NTN-friendly crash snapshot captured in the fatal handler and held
 * in retained RAM until the next boot uploads it (telemetry key 22). The server
 * symbolicates pc/lr/stack against the matching firmware ELF. */
#define DIAG_CRASH_MAX_REGS  16 /* r0-r12, sp, lr, pc, xpsr */
#define DIAG_CRASH_MAX_STACK 32 /* captured stack words from sp upward */

struct diag_crash_info {
	bool valid;
	uint32_t fault_type;                  /* Zephyr k_fatal_error reason */
	uint32_t pc;
	uint32_t lr;
	uint32_t regs[DIAG_CRASH_MAX_REGS];
	uint8_t reg_count;
	uint32_t stack[DIAG_CRASH_MAX_STACK]; /* return-address candidates */
	uint8_t stack_count;
	/* GNU build-id of the *crashing* image, captured at fault time so the
	 * report still selects the right symbol ELF if a FOTA lands between the
	 * crash and its upload. */
	bool build_id_valid;
	uint8_t build_id[APP_BUILD_ID_LEN];
};

/* Vitals heartbeat (telemetry key 21).
 *
 * The heartbeat is an *extensible list* of typed samples rather than a fixed
 * struct: each sample is a short (2-character) wire key and a value. This is the
 * single extension point for device metrics — adding a new vital is one line in
 * diag_collect_vitals() (see below), with no wire struct, CBOR encoder, or
 * backend schema change (the server stores the map verbatim as JSON).
 *
 * Wire keys in use (keep this list and OBSERVABILITY.md §3 in lockstep):
 *   up uptime_s   hf heap_free   ha heap_allocated   sf stack_min_free
 *   rp rsrp(dBm)  rq rsrq/snr    mt modem_temp(C)    bn band   bt battery_pct
 *   cu cpu_pct    tx modem_tx_kb rx modem_rx_kb      lm lte_mode
 *   pt psm_tau_s  pa psm_active_s
 */
enum diag_vital_type {
	DIAG_VITAL_UINT, /* unsigned value */
	DIAG_VITAL_INT,  /* signed value (e.g. RSRP, temperature) */
};

struct diag_vital {
	const char *key; /* 2-char static wire key, e.g. "hf" */
	enum diag_vital_type type;
	union {
		uint32_t u;
		int32_t s;
	} value;
};

/* Upper bound on the number of vitals in one heartbeat. Bump if you add many
 * new metrics; keep in step with CLOUD_TELEMETRY_MAX_VITALS and the CBOR budget
 * (CLOUD_TELEMETRY_VITALS_CBOR_MAX). */
#define DIAG_VITALS_MAX 24

struct diag_vitals {
	struct diag_vital items[DIAG_VITALS_MAX];
	uint8_t count;
};

/* Append a typed sample to the heartbeat. Silently dropped if the list is full.
 * These are the extension points used by diag_collect_vitals(); a source that is
 * unavailable simply does not call them, so the sample is omitted from the wire
 * map. */
void diag_vitals_add_uint(struct diag_vitals *v, const char *key, uint32_t value);
void diag_vitals_add_int(struct diag_vitals *v, const char *key, int32_t value);

/* ------------------------------------------------------------------------
 * Lifecycle
 * ------------------------------------------------------------------------ */

/* Process the retained region and hwinfo at boot: compose the boot report,
 * increment the boot counter, and re-arm the region for the next cycle (keeping
 * a pending crash breadcrumb so it survives until uploaded). Call once, early in
 * main(), before the state machine starts. */
void diag_boot_process(void);

/* The boot report composed by diag_boot_process(). Valid after that call. */
const struct diag_boot_report *diag_boot_report_get(void);

/* Whether a boot report is waiting to be folded into telemetry. */
bool diag_boot_report_pending(void);

/* Mark the boot report uploaded so it is not sent again. */
void diag_boot_report_clear(void);

/* Record the app's intent for an upcoming, planned reboot so the next boot
 * attributes the software reset correctly (FOTA/user/...). Persisted to the
 * retained region immediately. */
void diag_set_reboot_reason(enum diag_reset_reason reason);

/* Note that the device is alive: stamps the retained region with the current
 * uptime so an unexpected reset can still report how long the previous boot ran.
 * Cheap; call periodically (e.g. each telemetry send). */
void diag_heartbeat(void);

/* ------------------------------------------------------------------------
 * Vitals (Phase 2)
 * ------------------------------------------------------------------------ */

/* Sample the current device vitals into *out (list reset first). Each source is
 * best-effort: an unavailable source is simply omitted. To add a new metric, add
 * one diag_vitals_add_uint()/_int() call inside this function's implementation. */
void diag_collect_vitals(struct diag_vitals *out);

/* ------------------------------------------------------------------------
 * Crash (Phase 3)
 * ------------------------------------------------------------------------ */

/* The crash snapshot recovered from the previous boot, or NULL if none. Cleared
 * by diag_crash_clear() once uploaded. */
const struct diag_crash_info *diag_crash_get(void);

/* Whether a crash snapshot is pending upload. */
bool diag_crash_pending(void);

/* Mark the buffered crash snapshot uploaded and clear it from retained RAM. */
void diag_crash_clear(void);

/* ---- Log breadcrumbs (Phase 4) ------------------------------------------- */

/* The breadcrumb text recovered from the crashing boot's retained log ring, or
 * NULL if none. The bytes are the most recent log lines leading up to the fault,
 * oldest first; *len receives the length. Valid only while a crash is pending. */
const char *diag_breadcrumbs_get(uint16_t *len);

/* ---- Full coredump (flash-backed, pulled on demand over Block1) ----------- */

/* Size in bytes of a coredump stored in the flash backend, 0 if none, <0 on
 * error. The full coredump complements the minimal inline report and is uploaded
 * only over terrestrial LTE. */
int diag_coredump_size(void);

/* Copy up to `want` bytes of the stored coredump at `offset` into buf. Returns
 * the number of bytes read or <0 on error. Suitable as a block-upload source. */
int diag_coredump_read(uint8_t *buf, size_t want, size_t offset);

/* Erase the stored coredump after a successful upload so it is not re-sent. */
void diag_coredump_erase(void);

#ifdef __cplusplus
}
#endif

#endif /* OSCORE_CLOUD_DIAG_H_ */
