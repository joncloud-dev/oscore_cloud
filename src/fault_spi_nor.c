/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Fault-safe, bare-metal SPI NOR access (see fault_spi_nor.h).
 *
 * Why not the Zephyr drivers: spi_nor serialises with a k_sem and
 * spi_nrfx_spim completes transfers from the SPIM IRQ, so neither can run from
 * the fatal handler (IRQs locked, exception context). This is the same reason
 * the stock flash coredump backend deadlocks on nRF91 (soc_flash_nrf k_sem).
 * Memfault's rule for coredump storage applies: in fault context only
 * busy-polled register access, no RTOS. Everything below is register pokes on
 * the SPIM + a GPIO for chip-select, plus cycle-counted k_busy_wait() (on nRF91
 * arch_busy_wait is an nrfx coredep loop with no locks).
 *
 * Topology comes from devicetree: `coredump_partition` lives in the
 * fixed-partitions of a jedec,spi-nor device on an nordic,nrf-spim bus.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/devicetree.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/pinctrl.h>
#include <soc_nrf_common.h>

#include <hal/nrf_gpio.h>
#include <hal/nrf_spim.h>
#if DT_NODE_HAS_STATUS_OKAY(DT_NODELABEL(wdt0))
#include <hal/nrf_wdt.h>
#endif

#include "fault_spi_nor.h"

#define CD_NODE  DT_NODELABEL(coredump_partition)
#define NOR_NODE DT_GPARENT(CD_NODE)
#define SPI_NODE DT_BUS(NOR_NODE)

BUILD_ASSERT(DT_NODE_HAS_COMPAT(NOR_NODE, jedec_spi_nor),
	     "coredump_partition must be a partition of a jedec,spi-nor device");
BUILD_ASSERT(DT_NODE_HAS_COMPAT(SPI_NODE, nordic_nrf_spim),
	     "the coredump NOR must sit on an nordic,nrf-spim bus");

#define PART_OFF   ((uint32_t)DT_REG_ADDR(CD_NODE))
#define PART_SIZE  ((uint32_t)DT_REG_SIZE(CD_NODE))
#define NOR_BYTES  ((uint64_t)DT_PROP(NOR_NODE, size) / 8U) /* DT size is in bits */

BUILD_ASSERT(PART_OFF % FAULT_NOR_BLOCK_SIZE == 0, "coredump_partition must be 64 KiB aligned");
BUILD_ASSERT(PART_SIZE % FAULT_NOR_BLOCK_SIZE == 0, "coredump_partition size must be 64 KiB multiple");

/* >16 MiB parts: always use the dedicated 4-byte-address opcodes. They take a
 * 4-byte address regardless of the device's current address mode, so it does
 * not matter whether spi_nor switched the part into 4-byte mode (B7h) at init. */
#define USE_4B (NOR_BYTES > 0x1000000ULL)

#define CMD_WREN  0x06
#define CMD_RDSR  0x05
#define CMD_RDPD  0xAB /* release from deep power-down */
#define CMD_READ  (USE_4B ? 0x13 : 0x03)
#define CMD_PP    (USE_4B ? 0x12 : 0x02)
#define CMD_BE64  (USE_4B ? 0xDC : 0xD8)
#define SR_WIP    BIT(0)
#define ADDR_LEN  (USE_4B ? 4U : 3U)
#define HDR_LEN   (1U + ADDR_LEN)

/* Chip-select: the NOR's reg is its index into the bus's cs-gpios. */
#define CS_IDX       DT_PROP_BY_IDX(NOR_NODE, reg, 0)
#define CS_PSEL      NRF_DT_GPIOS_TO_PSEL_BY_IDX(SPI_NODE, cs_gpios, CS_IDX)
#define CS_ACT_LOW   ((DT_GPIO_FLAGS_BY_IDX(SPI_NODE, cs_gpios, CS_IDX) & GPIO_ACTIVE_LOW) != 0)

/* t-exit-dpd is in ns in the binding; default to a conservative 50 us. */
#define T_EXIT_DPD_US (DIV_ROUND_UP(DT_PROP_OR(NOR_NODE, t_exit_dpd, 50000), 1000) + 5)

#define NOR_HZ DT_PROP(NOR_NODE, spi_max_frequency)
#define SPIM_FREQ (NOR_HZ >= 8000000 ? NRF_SPIM_FREQ_8M : \
		   NOR_HZ >= 4000000 ? NRF_SPIM_FREQ_4M : \
		   NOR_HZ >= 2000000 ? NRF_SPIM_FREQ_2M : NRF_SPIM_FREQ_1M)

/* Worst-case waits (datasheet max: 64 KiB erase ~2 s, page program ~3 ms). */
#define ERASE_TIMEOUT_US   4000000U
#define PROGRAM_TIMEOUT_US 20000U
#define XFER_TIMEOUT_US    10000U

/* Private copy of the bus pin configuration (static in both translation units,
 * so no clash with the spi_nrfx_spim instance's own copy). */
PINCTRL_DT_DEFINE(SPI_NODE);

#define SPIM ((NRF_SPIM_Type *)DT_REG_ADDR(SPI_NODE))

/* EasyDMA buffers: must be in RAM. */
static uint8_t s_tx[HDR_LEN + FAULT_NOR_PAGE_SIZE];
static uint8_t s_rx[HDR_LEN + FAULT_NOR_PAGE_SIZE];

void fault_nor_feed_wdt(void)
{
#if DT_NODE_HAS_STATUS_OKAY(DT_NODELABEL(wdt0))
	NRF_WDT_Type *wdt = (NRF_WDT_Type *)DT_REG_ADDR(DT_NODELABEL(wdt0));

	if (!nrf_wdt_started_check(wdt)) {
		return;
	}
	for (int rr = 0; rr < NRF_WDT_CHANNEL_NUMBER; rr++) {
		if (nrf_wdt_reload_request_enable_check(wdt, (nrf_wdt_rr_register_t)rr)) {
			nrf_wdt_reload_request_set(wdt, (nrf_wdt_rr_register_t)rr);
		}
	}
#endif
}

static inline void cs(bool active)
{
	nrf_gpio_pin_write(CS_PSEL, (active == CS_ACT_LOW) ? 0 : 1);
}

/* Deassert every chip-select on the bus: on shared buses (e.g. Thingy:91 X,
 * NOR + nRF7002) a fault mid-transfer can leave another device selected,
 * which would then fight the NOR on MISO. */
#define CS_RELEASE(node, prop, idx)                                               \
	nrf_gpio_pin_write(NRF_DT_GPIOS_TO_PSEL_BY_IDX(node, prop, idx),          \
			   (DT_GPIO_FLAGS_BY_IDX(node, prop, idx) & GPIO_ACTIVE_LOW) ? 1 : 0); \
	nrf_gpio_cfg_output(NRF_DT_GPIOS_TO_PSEL_BY_IDX(node, prop, idx));

static void release_all_cs(void)
{
	DT_FOREACH_PROP_ELEM(SPI_NODE, cs_gpios, CS_RELEASE)
}

static int xfer(size_t txlen, size_t rxlen)
{
	cs(true);
	nrf_spim_tx_buffer_set(SPIM, s_tx, txlen);
	nrf_spim_rx_buffer_set(SPIM, s_rx, rxlen);
	nrf_spim_event_clear(SPIM, NRF_SPIM_EVENT_END);
	nrf_spim_task_trigger(SPIM, NRF_SPIM_TASK_START);

	uint32_t waited = 0;

	while (!nrf_spim_event_check(SPIM, NRF_SPIM_EVENT_END)) {
		if (waited++ >= XFER_TIMEOUT_US) {
			nrf_spim_task_trigger(SPIM, NRF_SPIM_TASK_STOP);
			cs(false);
			return -EIO;
		}
		k_busy_wait(1);
	}
	nrf_spim_event_clear(SPIM, NRF_SPIM_EVENT_END);
	cs(false);
	return 0;
}

static int cmd1(uint8_t op)
{
	s_tx[0] = op;
	return xfer(1, 0);
}

static void put_addr(uint8_t op, uint32_t abs)
{
	s_tx[0] = op;
	if (USE_4B) {
		s_tx[1] = (uint8_t)(abs >> 24);
		s_tx[2] = (uint8_t)(abs >> 16);
		s_tx[3] = (uint8_t)(abs >> 8);
		s_tx[4] = (uint8_t)abs;
	} else {
		s_tx[1] = (uint8_t)(abs >> 16);
		s_tx[2] = (uint8_t)(abs >> 8);
		s_tx[3] = (uint8_t)abs;
	}
}

static int wait_ready(uint32_t timeout_us)
{
	uint32_t waited = 0;

	for (;;) {
		s_tx[0] = CMD_RDSR;
		s_tx[1] = 0xFF;
		if (xfer(2, 2) != 0) {
			return -EIO;
		}
		if ((s_rx[1] & SR_WIP) == 0) {
			return 0;
		}
		if (waited >= timeout_us) {
			return -ETIMEDOUT;
		}
		k_busy_wait(50);
		waited += 50;
		if ((waited % 10000U) == 0U) {
			fault_nor_feed_wdt();
		}
	}
}

uint32_t fault_nor_capacity(void)
{
	return PART_SIZE;
}

int fault_nor_init(void)
{
	/* Silence the Zephyr driver's IRQ and abort whatever it was doing: the
	 * fault may have interrupted a settings/littlefs transfer mid-flight. */
	nrf_spim_int_disable(SPIM, NRF_SPIM_ALL_INTS_MASK);
	release_all_cs();

	/* STOP is harmless when idle; bound the wait in case SPIM is disabled
	 * (STOPPED never fires then). */
	nrf_spim_event_clear(SPIM, NRF_SPIM_EVENT_STOPPED);
	nrf_spim_task_trigger(SPIM, NRF_SPIM_TASK_STOP);
	for (int i = 0; i < 100 && !nrf_spim_event_check(SPIM, NRF_SPIM_EVENT_STOPPED); i++) {
		k_busy_wait(1);
	}

	nrf_spim_disable(SPIM);
	(void)pinctrl_apply_state(PINCTRL_DT_DEV_CONFIG_GET(SPI_NODE), PINCTRL_STATE_DEFAULT);
	nrf_spim_configure(SPIM, NRF_SPIM_MODE_0, NRF_SPIM_BIT_ORDER_MSB_FIRST);
	nrf_spim_frequency_set(SPIM, SPIM_FREQ);
	nrf_spim_orc_set(SPIM, 0xFF);
	nrf_spim_event_clear(SPIM, NRF_SPIM_EVENT_END);
	nrf_spim_event_clear(SPIM, NRF_SPIM_EVENT_STARTED);
	nrf_spim_enable(SPIM);
	k_busy_wait(2);

	/* The part may be in deep power-down (spi_nor PM suspend). RDPD is
	 * harmless when it is not. */
	if (cmd1(CMD_RDPD) != 0) {
		return -EIO;
	}
	k_busy_wait(T_EXIT_DPD_US);

	/* An erase/program interrupted by the fault keeps running in the part;
	 * wait it out before issuing new commands. */
	return wait_ready(ERASE_TIMEOUT_US) == 0 ? 0 : -EIO;
}

int fault_nor_read(uint32_t off, void *buf, size_t len)
{
	if (len > FAULT_NOR_PAGE_SIZE || off + len > PART_SIZE) {
		return -EINVAL;
	}
	put_addr(CMD_READ, PART_OFF + off);
	memset(&s_tx[HDR_LEN], 0xFF, len);
	if (xfer(HDR_LEN + len, HDR_LEN + len) != 0) {
		return -EIO;
	}
	memcpy(buf, &s_rx[HDR_LEN], len);
	return 0;
}

int fault_nor_program(uint32_t off, const void *buf, size_t len)
{
	if (len == 0) {
		return 0;
	}
	if (len > FAULT_NOR_PAGE_SIZE || off + len > PART_SIZE ||
	    (off / FAULT_NOR_PAGE_SIZE) != ((off + len - 1) / FAULT_NOR_PAGE_SIZE)) {
		return -EINVAL;
	}
	if (cmd1(CMD_WREN) != 0) {
		return -EIO;
	}
	put_addr(CMD_PP, PART_OFF + off);
	memcpy(&s_tx[HDR_LEN], buf, len);
	if (xfer(HDR_LEN + len, 0) != 0) {
		return -EIO;
	}
	return wait_ready(PROGRAM_TIMEOUT_US);
}

int fault_nor_erase_block(uint32_t off)
{
	if ((off % FAULT_NOR_BLOCK_SIZE) != 0 || off >= PART_SIZE) {
		return -EINVAL;
	}
	if (cmd1(CMD_WREN) != 0) {
		return -EIO;
	}
	put_addr(CMD_BE64, PART_OFF + off);
	if (xfer(HDR_LEN, 0) != 0) {
		return -EIO;
	}
	fault_nor_feed_wdt();
	return wait_ready(ERASE_TIMEOUT_US);
}
