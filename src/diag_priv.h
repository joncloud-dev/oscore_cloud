/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Internal to the diag collector (diag.c) and its watchdog layer
 * (diag_watchdog.c). Not for application use.
 */

#ifndef OSCORE_CLOUD_DIAG_PRIV_H_
#define OSCORE_CLOUD_DIAG_PRIV_H_

#include <stddef.h>
#include <stdint.h>

#include <zephyr/toolchain.h>
#include <oscore_cloud/diag.h>

/* Crash metadata, plain RAM at a fixed symbol: filled at boot, so a RAM coredump
 * carries the identity of the crashing image and boot even when the inline
 * crash report (retained RAM) is lost to a power cycle. Wire contract, decoded
 * by the server (go/internal/platform/coredump/diag.go) at fixed offsets.
 *
 * v1: up to fw_version (72 B). v2 appends the watchdog block (120 B). */
#define CRASH_META_MAGIC   0x544D434FU /* "OCMT" */
#define CRASH_META_VERSION 2U

/* oscore_diag_crash_meta.wdt_kind */
enum diag_wdt_kind {
	DIAG_WDT_NONE = 0,
	DIAG_WDT_TASK = 1,     /* task_wdt channel expired (wdt_thread = starved) */
	DIAG_WDT_HW_PRE = 2,   /* hardware pre-watchdog (wdt_thread = interrupted) */
	DIAG_WDT_LIVENESS = 3, /* no cloud contact within the liveness timeout */
};

/* oscore_diag_crash_meta.wdt_flags */
#define DIAG_WDT_F_ISR    BIT(0) /* interrupted context was a handler (MSP) */
#define DIAG_WDT_F_SECURE BIT(1) /* interrupted context was secure (TF-M) code */
#define DIAG_WDT_F_FP     BIT(2) /* FP-extended exception frame */

#define DIAG_WDT_NAME_LEN 16

struct oscore_diag_crash_meta {
	uint32_t magic;
	uint16_t version;
	uint16_t size;
	uint32_t boot_count;       /* the boot that was running at the crash */
	uint32_t last_contact_s;   /* uptime at the last cloud contact */
	uint8_t prev_reset_reason; /* why the crashing boot itself started */
	uint8_t build_id_valid;
	uint8_t build_id[APP_BUILD_ID_LEN];
	uint8_t captured;          /* set by the coredump pre-capture hook */
	uint8_t reserved;
	char fw_version[32];
	/* ---- v2: watchdog culprit (all zero unless a watchdog fired) ---- */
	uint8_t wdt_kind;          /* enum diag_wdt_kind */
	uint8_t wdt_channel;       /* task_wdt channel, 0xFF if n/a */
	uint8_t wdt_flags;         /* DIAG_WDT_F_* */
	uint8_t wdt_reserved;
	uint32_t wdt_thread;       /* k_thread address of the culprit */
	char wdt_thread_name[DIAG_WDT_NAME_LEN];
	uint32_t wdt_pc;           /* HW_PRE: interrupted context's frame */
	uint32_t wdt_lr;
	uint32_t wdt_xpsr;
	uint32_t wdt_exc_return;
	uint32_t wdt_sp;           /* pre-exception SP of the interrupted context */
	uint32_t wdt_since_feed_ms; /* HW_PRE: time since the last HW WDT feed */
};

BUILD_ASSERT(offsetof(struct oscore_diag_crash_meta, fw_version) == 40, "crash meta v1 layout");
BUILD_ASSERT(offsetof(struct oscore_diag_crash_meta, wdt_kind) == 72, "crash meta v2 layout");
BUILD_ASSERT(offsetof(struct oscore_diag_crash_meta, wdt_thread) == 76, "crash meta v2 layout");
BUILD_ASSERT(offsetof(struct oscore_diag_crash_meta, wdt_pc) == 96, "crash meta v2 layout");
BUILD_ASSERT(sizeof(struct oscore_diag_crash_meta) == 120, "crash meta v2 layout");

extern struct oscore_diag_crash_meta oscore_diag_crash_meta;

/* Set the retained planned-reboot reason without logging (safe from the
 * pre-watchdog's zero-latency ISR, where kernel services are off limits). */
void diag_retained_set_reason(uint8_t reason);

#if defined(CONFIG_OSCORE_CLOUD_DIAG_PRE_WATCHDOG)
/* Stop the pre-watchdog: the fatal path is running (it feeds the HW WDT
 * itself while the dump is written). */
void diag_prewdt_disarm(void);
#else
static inline void diag_prewdt_disarm(void) {}
#endif

#if defined(CONFIG_OSCORE_CLOUD_DIAG_WATCHDOG)
/* Cloud-liveness expiry: dump + reboot via the fatal path. Does not return. */
FUNC_NORETURN void diag_watchdog_liveness(void);
#endif

#endif /* OSCORE_CLOUD_DIAG_PRIV_H_ */
