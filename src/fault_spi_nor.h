/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Fault-safe, bare-metal SPI NOR access for the coredump path (internal).
 *
 * Drives the SPIM that hosts the `coredump_partition`'s NOR device directly
 * through the nrf_spim HAL with busy-polling: no RTOS primitives, no
 * interrupts, no driver locks. Usable with IRQs locked from the fatal handler,
 * where Zephyr's spi_nor/spi_nrfx_spim drivers (semaphores, IRQ completion)
 * cannot run. Never use it while the system is running normally: it takes the
 * SPIM away from the Zephyr driver without coordination.
 *
 * All addresses are byte offsets relative to the start of the coredump
 * partition; the functions bound-check against the partition size.
 */

#ifndef OSCORE_CLOUD_FAULT_SPI_NOR_H_
#define OSCORE_CLOUD_FAULT_SPI_NOR_H_

#include <stddef.h>
#include <stdint.h>

#define FAULT_NOR_PAGE_SIZE   256U
#define FAULT_NOR_BLOCK_SIZE  0x10000U /* 64 KiB erase block */

/* Take over the SPIM and wake the NOR: abort an interrupted transfer, re-apply
 * the default pin state, release deep power-down and wait for a pending
 * program/erase. Returns 0, or -EIO if the NOR stays busy / unresponsive. */
int fault_nor_init(void);

/* Read len bytes at off (len <= FAULT_NOR_PAGE_SIZE). */
int fault_nor_read(uint32_t off, void *buf, size_t len);

/* Program up to one page; [off, off+len) must not cross a page boundary. The
 * data is copied into a RAM bounce buffer first (EasyDMA cannot read flash). */
int fault_nor_program(uint32_t off, const void *buf, size_t len);

/* Erase the 64 KiB block at off (must be block aligned). */
int fault_nor_erase_block(uint32_t off);

/* Partition capacity in bytes. */
uint32_t fault_nor_capacity(void);

/* Reload every enabled hardware-watchdog channel (no-op if the WDT is not
 * running). Called from the long busy-wait loops so a large dump write cannot
 * be cut short by the HW watchdog. */
void fault_nor_feed_wdt(void);

#endif /* OSCORE_CLOUD_FAULT_SPI_NOR_H_ */
