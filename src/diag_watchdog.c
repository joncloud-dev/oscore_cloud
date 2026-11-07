/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Watchdogs that end in a coredump (CONFIG_OSCORE_CLOUD_DIAG_WATCHDOG).
 *
 * Two layers, both finishing in Zephyr's fatal path, and so in coredump()
 * (full RAM + log ring) and the diag k_sys_fatal_error_handler (inline crash
 * report + reboot):
 *
 *  1. Task level. A task_wdt channel expired, but the scheduler and the system
 *     timer still run (the callback fires from the timer ISR).
 *     diag_watchdog_trigger() names the starved thread in the crash meta and
 *     raises ARCH_EXCEPT(DIAG_FATAL_WATCHDOG_TASK). The cloud liveness
 *     watchdog uses the same path.
 *
 *  2. Hardware pre-watchdog. IRQs are locked, an ISR spins, or the timer ISR is
 *     dead, so task_wdt never runs and the HW WDT would reset silently. A
 *     spare RTC runs as a zero-latency IRQ (above BASEPRI, so irq_lock() does
 *     not mask it). It is re-armed on every HW WDT feed through a wdt driver
 *     shim handed to task_wdt_init(), and it expires MARGIN ms before the HW
 *     WDT. Its handler copies the interrupted context's exception frame into
 *     an arch_esf and calls z_fatal_error(DIAG_FATAL_WATCHDOG_HW, &esf), as a
 *     CPU fault would.
 *
 * The nRF WDT TIMEOUT interrupt cannot do this job: it leaves 2 LFCLK cycles
 * (~61 us) before the reset.
 */

#include <zephyr/kernel.h>
#include <zephyr/init.h>
#include <zephyr/device.h>
#include <zephyr/fatal.h>
#include <zephyr/irq.h>
#include <zephyr/drivers/watchdog.h>
#include <zephyr/task_wdt/task_wdt.h>
#include <zephyr/logging/log.h>
#include <string.h>

#include <oscore_cloud/diag.h>
#include "diag_priv.h"

LOG_MODULE_DECLARE(diag, CONFIG_OSCORE_CLOUD_DIAG_LOG_LEVEL);

/* The board's watchdog0 alias, else the SoC's wdt0 (Thingy:91 X has no alias). */
#if DT_NODE_EXISTS(DT_ALIAS(watchdog0))
#define HW_WDT_NODE DT_ALIAS(watchdog0)
#else
#define HW_WDT_NODE DT_NODELABEL(wdt0)
#endif
BUILD_ASSERT(DT_NODE_HAS_STATUS_OKAY(HW_WDT_NODE),
	     "OSCORE_CLOUD_DIAG_WATCHDOG needs an enabled watchdog0 alias or wdt0");

static void meta_set_thread(struct oscore_diag_crash_meta *m, const struct k_thread *t)
{
	m->wdt_thread = (uint32_t)(uintptr_t)t;
	memset(m->wdt_thread_name, 0, sizeof(m->wdt_thread_name));
#if defined(CONFIG_THREAD_NAME)
	if (t != NULL) {
		/* Direct field read: k_thread_name_get() is a syscall wrapper and
		 * this also runs in the pre-watchdog ZLI. */
		strncpy(m->wdt_thread_name, t->name, sizeof(m->wdt_thread_name) - 1);
	}
#endif
}

/* ---- Task level ----------------------------------------------------------- */

void diag_watchdog_trigger(int channel, void *thread)
{
	struct oscore_diag_crash_meta *m = &oscore_diag_crash_meta;
	struct k_thread *t = thread;

	m->wdt_kind = DIAG_WDT_TASK;
	m->wdt_channel = (channel >= 0 && channel < 0xFF) ? (uint8_t)channel : 0xFFU;
	meta_set_thread(m, t);
	diag_retained_set_reason(DIAG_RESET_WATCHDOG_TASK);

	LOG_ERR("Task watchdog: channel %d, thread %p (%s) starved; capturing coredump",
		channel, (void *)t, m->wdt_thread_name);

	/* SVC from the timer ISR: the fatal path sees the ISR's frame, the
	 * starved thread is named in the crash meta. */
	ARCH_EXCEPT(DIAG_FATAL_WATCHDOG_TASK);
	CODE_UNREACHABLE;
}

FUNC_NORETURN void diag_watchdog_liveness(void)
{
	struct oscore_diag_crash_meta *m = &oscore_diag_crash_meta;

	m->wdt_kind = DIAG_WDT_LIVENESS;
	m->wdt_channel = 0xFFU;
	meta_set_thread(m, k_current_get());
	diag_retained_set_reason(DIAG_RESET_WATCHDOG);

	ARCH_EXCEPT(DIAG_FATAL_WATCHDOG_LIVENESS);
	CODE_UNREACHABLE;
}

/* ---- Hardware pre-watchdog ------------------------------------------------ */

#if defined(CONFIG_OSCORE_CLOUD_DIAG_PRE_WATCHDOG)
#include <hal/nrf_rtc.h>
#include <cmsis_core.h>

#if DT_HAS_CHOSEN(oscore_pre_watchdog_rtc)
#define PREWDT_RTC_NODE DT_CHOSEN(oscore_pre_watchdog_rtc)
#else
#define PREWDT_RTC_NODE DT_NODELABEL(rtc0)
#endif
BUILD_ASSERT(DT_NODE_EXISTS(PREWDT_RTC_NODE), "no RTC for the pre-watchdog");
/* The RTC is driven bare-metal; a Zephyr counter driver must not own it. */
BUILD_ASSERT(!DT_NODE_HAS_STATUS_OKAY(PREWDT_RTC_NODE),
	     "pre-watchdog RTC must be status = \"disabled\" (unused by drivers)");

/* task_wdt feeds the HW WDT at least every TASK_WDT_MIN_TIMEOUT and the HW
 * period is MIN_TIMEOUT + HW_FALLBACK_DELAY: the pre-watchdog must fire in
 * between, with 500 ms of slack for timer latency. */
BUILD_ASSERT(CONFIG_TASK_WDT_HW_FALLBACK_DELAY >= CONFIG_OSCORE_CLOUD_DIAG_PRE_WATCHDOG_MARGIN_MS + 500,
	     "TASK_WDT_HW_FALLBACK_DELAY must exceed the pre-watchdog margin by >= 500 ms");

#define PREWDT_RTC       ((NRF_RTC_Type *)DT_REG_ADDR(PREWDT_RTC_NODE))
#define PREWDT_IRQN      DT_IRQN(PREWDT_RTC_NODE)
#define PREWDT_HZ        32768U
#define PREWDT_CNT_MASK  NRF_RTC_COUNTER_MAX
#define MS_TO_RTC(ms)    ((uint32_t)(((uint64_t)(ms) * PREWDT_HZ) / 1000U))

static const struct device *const hw_wdt = DEVICE_DT_GET(HW_WDT_NODE);

static uint32_t prewdt_ticks;        /* fire this long after a feed */
static volatile uint32_t prewdt_fed; /* RTC count at the last feed */
static volatile bool prewdt_armed;

static void prewdt_kick(void)
{
	if (!prewdt_armed) {
		return;
	}
	uint32_t now = nrf_rtc_counter_get(PREWDT_RTC);

	prewdt_fed = now;
	nrf_rtc_cc_set(PREWDT_RTC, 0, (now + prewdt_ticks) & PREWDT_CNT_MASK);
}

static void prewdt_start(void)
{
	NRF_RTC_Type *rtc = PREWDT_RTC;

	if (prewdt_ticks == 0U) {
		return;
	}
	nrf_rtc_task_trigger(rtc, NRF_RTC_TASK_STOP);
	nrf_rtc_prescaler_set(rtc, 0); /* 30.5 us/tick, wraps after 512 s */
	nrf_rtc_int_disable(rtc, 0xFFFFFFFFU);
	nrf_rtc_event_clear(rtc, NRF_RTC_EVENT_COMPARE_0);
	nrf_rtc_task_trigger(rtc, NRF_RTC_TASK_START);
	prewdt_armed = true;
	prewdt_kick();
	nrf_rtc_int_enable(rtc, NRF_RTC_INT_COMPARE_0_MASK);
	NVIC_ClearPendingIRQ(PREWDT_IRQN);
	irq_enable(PREWDT_IRQN);
}

void diag_prewdt_disarm(void)
{
	prewdt_armed = false;
	nrf_rtc_int_disable(PREWDT_RTC, NRF_RTC_INT_COMPARE_0_MASK);
}

/* ZLI context: no kernel services, no logging, until z_fatal_error() (which
 * a CPU fault would call from the same priority). */
static struct arch_esf prewdt_esf;
static _callee_saved_t prewdt_callee;

#define PREWDT_EXC_SPSEL BIT(2) /* frame on PSP (thread mode) */
#define PREWDT_EXC_FTYPE BIT(4) /* 0: FP-extended frame */
#define PREWDT_EXC_S     BIT(6) /* 1: interrupted context was secure */

/* Called only from the prewdt_isr asm stub. */
void prewdt_handle(uint32_t msp, uint32_t psp, uint32_t exc_return, const uint32_t *r4_r11);

__used void prewdt_handle(uint32_t msp, uint32_t psp, uint32_t exc_return,
			  const uint32_t *r4_r11)
{
	NRF_RTC_Type *rtc = PREWDT_RTC;
	struct oscore_diag_crash_meta *m = &oscore_diag_crash_meta;

	nrf_rtc_event_clear(rtc, NRF_RTC_EVENT_COMPARE_0);
	uint32_t since = (nrf_rtc_counter_get(rtc) - prewdt_fed) & PREWDT_CNT_MASK;

	/* A compare that matched just before a feed moved CC is stale. */
	if (!prewdt_armed || since + MS_TO_RTC(100) < prewdt_ticks) {
		return;
	}
	diag_prewdt_disarm();

	bool secure = (exc_return & PREWDT_EXC_S) != 0U;
	bool on_psp = (exc_return & PREWDT_EXC_SPSEL) != 0U;
	bool fp = (exc_return & PREWDT_EXC_FTYPE) == 0U;
	uint32_t frame = on_psp ? psp : msp;
	uint32_t sp = frame;

	memset(&prewdt_esf, 0, sizeof(prewdt_esf));
	if (!secure) {
		/* The interrupted context's 8-word hardware frame. */
		memcpy(&prewdt_esf.basic, (const void *)frame, sizeof(prewdt_esf.basic));
		sp += sizeof(prewdt_esf.basic);
#if defined(CONFIG_FPU) && defined(CONFIG_FPU_SHARING)
		if (fp) {
			memcpy(&prewdt_esf.fpu, (const void *)(frame + sizeof(prewdt_esf.basic)),
			       sizeof(prewdt_esf.fpu));
		}
#endif
		if (fp) {
			sp += 18U * 4U; /* s0-s15, fpscr, reserved */
		}
		if (prewdt_esf.basic.xpsr & BIT(9)) {
			sp += 4U; /* realigned to 8 on entry */
		}
	} else {
		/* The frame is on the secure stack, which NS cannot read: report
		 * the NS thread that called into TF-M instead. */
		prewdt_esf.basic.xpsr = BIT(24); /* Thumb, thread mode */
		sp = psp;
	}

	memcpy(&prewdt_callee, r4_r11, 8U * sizeof(uint32_t));
	prewdt_callee.psp = psp;
#if defined(CONFIG_EXTRA_EXCEPTION_INFO)
	prewdt_esf.extra_info.callee = &prewdt_callee;
	prewdt_esf.extra_info.msp = msp;
	prewdt_esf.extra_info.exc_return = exc_return;
#endif
	z_arm_coredump_fault_sp = sp;

	m->wdt_kind = DIAG_WDT_HW_PRE;
	m->wdt_channel = 0xFFU;
	m->wdt_flags = (on_psp ? 0U : DIAG_WDT_F_ISR) | (secure ? DIAG_WDT_F_SECURE : 0U) |
		       (fp ? DIAG_WDT_F_FP : 0U);
	meta_set_thread(m, _current);
	m->wdt_pc = prewdt_esf.basic.pc;
	m->wdt_lr = prewdt_esf.basic.lr;
	m->wdt_xpsr = prewdt_esf.basic.xpsr;
	m->wdt_exc_return = exc_return;
	m->wdt_sp = sp;
	m->wdt_since_feed_ms = (uint32_t)(((uint64_t)since * 1000U) / PREWDT_HZ);
	diag_retained_set_reason(DIAG_RESET_WATCHDOG_HW_PRE);

	z_fatal_error(DIAG_FATAL_WATCHDOG_HW, &prewdt_esf);
	CODE_UNREACHABLE;
}

/* Vector entry. Captures MSP/PSP/EXC_RETURN and r4-r11 untouched by C code,
 * then calls prewdt_handle(). Returns normally only for a stale compare. Ten
 * registers keep the stack 8-byte aligned; r4-r11 start at sp+4. */
__attribute__((naked)) static void prewdt_isr(void)
{
	__asm__ volatile(
		"mrs   r0, msp\n"
		"mrs   r1, psp\n"
		"mov   r2, lr\n"
		"push  {r3-r11, lr}\n"
		"add   r3, sp, #4\n"
		"bl    prewdt_handle\n"
		"pop   {r3-r11, pc}\n");
}

/* ---- WDT shim: forwards to the HW WDT, re-arms the pre-watchdog per feed -- */

static int shim_setup(const struct device *dev, uint8_t options)
{
	ARG_UNUSED(dev);
	int rc = wdt_setup(hw_wdt, options);

	if (rc == 0) {
		prewdt_start();
	}
	return rc;
}

static int shim_disable(const struct device *dev)
{
	ARG_UNUSED(dev);
	diag_prewdt_disarm();
	return wdt_disable(hw_wdt);
}

static int shim_install_timeout(const struct device *dev, const struct wdt_timeout_cfg *cfg)
{
	ARG_UNUSED(dev);
	int ch = wdt_install_timeout(hw_wdt, cfg);

	if (ch >= 0 && cfg->window.max > CONFIG_OSCORE_CLOUD_DIAG_PRE_WATCHDOG_MARGIN_MS) {
		prewdt_ticks = MS_TO_RTC(cfg->window.max -
					 CONFIG_OSCORE_CLOUD_DIAG_PRE_WATCHDOG_MARGIN_MS);
	}
	return ch;
}

static int shim_feed(const struct device *dev, int channel_id)
{
	ARG_UNUSED(dev);
	int rc = wdt_feed(hw_wdt, channel_id);

	if (rc == 0) {
		prewdt_kick();
	}
	return rc;
}

static DEVICE_API(wdt, prewdt_shim_api) = {
	.setup = shim_setup,
	.disable = shim_disable,
	.install_timeout = shim_install_timeout,
	.feed = shim_feed,
};

static int prewdt_shim_init(const struct device *dev)
{
	ARG_UNUSED(dev);
	IRQ_DIRECT_CONNECT(PREWDT_IRQN, 0, prewdt_isr, IRQ_ZERO_LATENCY);
	return 0;
}

DEVICE_DEFINE(diag_prewdt_shim, "diag_prewdt", prewdt_shim_init, NULL, NULL, NULL,
	      POST_KERNEL, CONFIG_APPLICATION_INIT_PRIORITY, &prewdt_shim_api);

#define TASK_WDT_HW DEVICE_GET(diag_prewdt_shim)
#else
#define TASK_WDT_HW DEVICE_DT_GET(HW_WDT_NODE)
#endif /* CONFIG_OSCORE_CLOUD_DIAG_PRE_WATCHDOG */

/* ---- Boot: really arm task_wdt + the HW fallback -------------------------- */

static int diag_watchdog_init(void)
{
	const struct device *hw = TASK_WDT_HW;

	if (!device_is_ready(DEVICE_DT_GET(HW_WDT_NODE))) {
		LOG_ERR("HW watchdog not ready; task watchdog runs without fallback");
		hw = NULL;
	}
	int rc = task_wdt_init(hw);

	if (rc != 0) {
		LOG_ERR("task_wdt_init: %d", rc);
		return rc;
	}
#if defined(CONFIG_OSCORE_CLOUD_DIAG_PRE_WATCHDOG)
	LOG_INF("Watchdogs: HW WDT %u ms, pre-watchdog at %u ms (RTC IRQ %d, ZLI)",
		CONFIG_TASK_WDT_MIN_TIMEOUT + CONFIG_TASK_WDT_HW_FALLBACK_DELAY,
		CONFIG_TASK_WDT_MIN_TIMEOUT + CONFIG_TASK_WDT_HW_FALLBACK_DELAY -
			CONFIG_OSCORE_CLOUD_DIAG_PRE_WATCHDOG_MARGIN_MS,
		PREWDT_IRQN);
#else
	LOG_INF("Watchdogs: HW WDT %u ms (no pre-watchdog)",
		CONFIG_TASK_WDT_MIN_TIMEOUT + CONFIG_TASK_WDT_HW_FALLBACK_DELAY);
#endif
	return 0;
}

/* After the shim device (POST_KERNEL), before static threads add channels. */
SYS_INIT(diag_watchdog_init, APPLICATION, CONFIG_APPLICATION_INIT_PRIORITY);
