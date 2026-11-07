/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Fault-safe external SPI NOR coredump backend (CONFIG_DEBUG_COREDUMP_BACKEND_OTHER).
 *
 * Capture (fatal handler, IRQs locked) goes through fault_spi_nor.c: polled
 * SPIM, no RTOS. Read-back, verify and erase (next boot, thread context) go
 * through the regular flash_area API / spi_nor driver.
 *
 * Slot layout (offsets relative to `coredump_partition`):
 *
 *   0x00  struct cd_hdr (64 B), fields programmed separately (NOR bits only
 *         go 1->0, so later fields can be written into the same erased page)
 *   0x40  Zephyr coredump stream (as emitted via buffer_output)
 *
 * Header state machine:
 *   magic == FF                      CLEAN    whole slot erased, program-only
 *   magic set, commit set, live      PENDING  complete dump awaiting upload
 *   anything else                    DIRTY    interrupted capture / discarded
 *
 * Invariant for CLEAN: the slot is erased from the last block down to block 0,
 * so an erased header implies an erased slot even if the erase was cut short.
 * That lets the fault path skip erasing (Memfault-style pre-erase) — writing a
 * ~200 KiB dump is then pure page programming. A DIRTY slot is erased lazily,
 * one 64 KiB block ahead of the write cursor, so only what the dump needs is
 * erased in the fault handler.
 *
 * Running out of space truncates (flag set, dump still valid) rather than
 * discarding everything as the old nvmc backend did.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/init.h>
#include <zephyr/debug/coredump.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/sys/crc.h>
#include <zephyr/logging/log.h>
#if defined(CONFIG_NRF_RTC_TIMER)
#include <hal/nrf_rtc.h>
#endif

#include <oscore_cloud/diag.h>

#include "fault_spi_nor.h"

LOG_MODULE_DECLARE(oscore_cloud_diag, CONFIG_OSCORE_CLOUD_DIAG_LOG_LEVEL);

#define CD_PARTITION PARTITION_ID(coredump_partition)

#define CD_MAGIC   0x32584443U /* "CDX2": header v2 (64 B) */
#define CD_COMMIT  0x54494D43U /* "CMIT" */
#define CD_LIVE    0xFFFFFFFFU
#define CD_ERASED  0xFFFFFFFFU

#define CD_FLAG_TRUNCATED BIT(0)

struct cd_hdr {
	uint32_t magic;    /* programmed first, when capture starts */
	uint32_t size;     /* payload bytes stored */
	uint32_t crc;      /* crc32_ieee over the stored payload */
	uint32_t flags;    /* CD_FLAG_* */
	uint32_t commit;   /* CD_COMMIT, programmed last */
	uint32_t discard;  /* CD_LIVE until uploaded/invalidated (then 0) */
	uint32_t write_ms; /* fault-handler write duration (diagnostic) */
	uint32_t boot_count; /* boot that crashed */
	uint32_t reason;     /* Zephyr fatal reason (from the stream's ZE header) */
	uint8_t build_id[APP_BUILD_ID_LEN]; /* image that crashed */
	uint32_t build_id_valid; /* 1 when build_id is set */
	uint32_t reserved;
};

#define CD_HDR_SIZE sizeof(struct cd_hdr)
BUILD_ASSERT(CD_HDR_SIZE == 64, "header must be 64 bytes");

#define CD_CAPACITY fault_nor_capacity()

/* ---- Retained across a warm reset: crash-loop accounting ------------------- */

#define CD_RET_MAGIC 0x43445254U /* "CDRT" */

static __noinit struct {
	uint32_t magic;
	uint32_t dropped; /* dumps not stored because one was already pending */
} cd_ret;

static void cd_ret_check(void)
{
	if (cd_ret.magic != CD_RET_MAGIC) {
		cd_ret.magic = CD_RET_MAGIC;
		cd_ret.dropped = 0;
	}
}

/* ---- Classification --------------------------------------------------------- */

static enum diag_coredump_state classify(const struct cd_hdr *h)
{
	if (h->magic == CD_ERASED) {
		return DIAG_COREDUMP_CLEAN;
	}
	if (h->magic == CD_MAGIC && h->commit == CD_COMMIT && h->discard == CD_LIVE &&
	    h->size > 0 && h->size <= CD_CAPACITY - CD_HDR_SIZE) {
		return DIAG_COREDUMP_PENDING;
	}
	return DIAG_COREDUMP_DIRTY;
}

/* ======================= Fault-context capture path ======================= */

static struct {
	bool active;
	int err;
	uint32_t woff;        /* next payload byte's slot offset */
	uint32_t erased_upto; /* slot offsets below this are known erased */
	uint32_t crc;
	uint32_t bytes;
	bool truncated;
	uint32_t t0;
	uint32_t reason;      /* bytes 8..11 of the Zephyr coredump header */
	uint8_t pg[FAULT_NOR_PAGE_SIZE];
	uint16_t pg_first;    /* first valid byte index in pg[] */
	uint16_t pg_fill;     /* one past the last valid byte in pg[] */
} cw;

static uint32_t now_ticks(void)
{
#if defined(CONFIG_NRF_RTC_TIMER)
	/* Read the system timer's RTC (RTC1, see nrf_rtc_timer.c) directly:
	 * sys_clock_cycle_get_32() takes a spinlock, which we avoid in fault
	 * context. 32768 Hz, 24-bit. */
	return nrf_rtc_counter_get(NRF_RTC1);
#else
	return 0;
#endif
}

static int ensure_erased(uint32_t off)
{
	while (off >= cw.erased_upto) {
		int rc = fault_nor_erase_block(cw.erased_upto);

		if (rc) {
			return rc;
		}
		cw.erased_upto += FAULT_NOR_BLOCK_SIZE;
	}
	return 0;
}

static int program(uint32_t off, const void *data, size_t len)
{
	int rc = ensure_erased(off + len - 1);

	return rc ? rc : fault_nor_program(off, data, len);
}

static void flush_page(void)
{
	if (cw.pg_fill <= cw.pg_first) {
		return;
	}
	uint32_t page_base = (cw.woff - 1U) & ~(FAULT_NOR_PAGE_SIZE - 1U);
	int rc = program(page_base + cw.pg_first, &cw.pg[cw.pg_first],
			 cw.pg_fill - cw.pg_first);

	if (rc) {
		cw.err = rc;
		cw.active = false;
	}
	cw.pg_first = 0;
	cw.pg_fill = 0;
	fault_nor_feed_wdt();
}

static void cd_start(void)
{
	struct cd_hdr h;

	/* Flush deferred logs into the RAM log ring first: the dump below then
	 * carries the last lines before the fault. */
	diag_coredump_pre_capture();

	memset(&cw, 0, sizeof(cw));
	cw.t0 = now_ticks();
	cd_ret_check();

	cw.err = fault_nor_init();
	if (cw.err == 0) {
		cw.err = fault_nor_read(0, &h, sizeof(h));
	}
	if (cw.err) {
		return;
	}

	enum diag_coredump_state st = classify(&h);

	if (st == DIAG_COREDUMP_PENDING && IS_ENABLED(CONFIG_OSCORE_CLOUD_DIAG_COREDUMP_KEEP_FIRST)) {
		/* Crash loop: keep the first (usually most telling) dump. */
		cd_ret.dropped++;
		cw.err = -EEXIST;
		return;
	}

	cw.erased_upto = (st == DIAG_COREDUMP_CLEAN) ? CD_CAPACITY : 0;

	uint32_t magic = CD_MAGIC;

	cw.err = program(0, &magic, sizeof(magic));
	if (cw.err) {
		return;
	}
	cw.woff = CD_HDR_SIZE;
	cw.pg_first = CD_HDR_SIZE % FAULT_NOR_PAGE_SIZE;
	cw.pg_fill = cw.pg_first;
	cw.crc = 0;
	cw.active = true;
}

static void cd_buffer_output(uint8_t *buf, size_t buflen)
{
	if (!cw.active) {
		return;
	}

	size_t room = CD_CAPACITY - cw.woff;

	if (buflen > room) {
		buflen = room;
		cw.truncated = true;
	}

	cw.bytes += buflen;

	while (buflen > 0 && cw.active) {
		uint16_t idx = cw.woff % FAULT_NOR_PAGE_SIZE;
		size_t n = MIN(buflen, FAULT_NOR_PAGE_SIZE - idx);

		memcpy(&cw.pg[idx], buf, n);
		/* Zephyr coredump header: id[2] ver u16 tgt u16 ptr u8 flag u8 reason u32 */
		for (size_t k = 0; k < n; k++) {
			uint32_t pos = cw.bytes - buflen + k;

			if (pos >= 8U && pos < 12U) {
				cw.reason |= (uint32_t)cw.pg[idx + k] << (8U * (pos - 8U));
			}
		}
		/* CRC the copy, not the source: the dump includes live memory (the
		 * interrupt stack this handler runs on), which our own call frames
		 * overwrite between reading and copying. */
		cw.crc = crc32_ieee_update(cw.crc, &cw.pg[idx], n);
		cw.pg_fill = idx + n;
		cw.woff += n;
		buf += n;
		buflen -= n;
		if ((cw.woff % FAULT_NOR_PAGE_SIZE) == 0) {
			flush_page();
		}
	}

	if (cw.truncated) {
		/* Slot full: stop accepting, keep what we have. */
		flush_page();
		cw.active = false;
	}
}

static void cd_end(void)
{
	if (cw.active) {
		flush_page();
	}
	if (cw.err || cw.bytes == 0) {
		/* Left DIRTY (magic set, no commit): next boot erases it. */
		return;
	}

	uint32_t t1 = now_ticks();
	struct {
		uint32_t size, crc, flags;
	} meta = {
		.size = cw.bytes,
		.crc = cw.crc,
		.flags = cw.truncated ? CD_FLAG_TRUNCATED : 0U,
	};
	uint32_t ms = (uint32_t)((((t1 - cw.t0) & 0xFFFFFFU) * 1000ULL) / 32768U);

	cw.err = fault_nor_program(offsetof(struct cd_hdr, size), &meta, sizeof(meta));
	struct {
		uint32_t write_ms, boot_count, reason;
		uint8_t build_id[APP_BUILD_ID_LEN];
		uint32_t build_id_valid;
	} id = {
		.write_ms = ms,
		.boot_count = diag_boot_count_current(),
		.reason = cw.reason,
	};
#if defined(CONFIG_OSCORE_CLOUD_DIAG_BUILD_ID)
	id.build_id_valid = (app_build_id_get(id.build_id) == 0) ? 1U : 0U;
#endif
	BUILD_ASSERT(sizeof(id) == offsetof(struct cd_hdr, reserved) -
					offsetof(struct cd_hdr, write_ms), "id block layout");
	if (cw.err == 0) {
		cw.err = fault_nor_program(offsetof(struct cd_hdr, write_ms), &id, sizeof(id));
	}
	if (cw.err == 0) {
		uint32_t commit = CD_COMMIT;

		cw.err = fault_nor_program(offsetof(struct cd_hdr, commit), &commit,
					   sizeof(commit));
	}
}

/* ======================= Thread-context path =============================== */

static atomic_t cd_erasing;
static K_THREAD_STACK_DEFINE(cd_erase_stack, 1024);
static struct k_work_q cd_erase_q;
static struct k_work cd_erase_work;

static int hdr_read(struct cd_hdr *h)
{
	const struct flash_area *fa;
	int rc = flash_area_open(CD_PARTITION, &fa);

	if (rc) {
		return rc;
	}
	rc = flash_area_read(fa, 0, h, sizeof(*h));
	flash_area_close(fa);
	return rc;
}

static void cd_erase_handler(struct k_work *work)
{
	ARG_UNUSED(work);

	const struct flash_area *fa;
	int64_t t0 = k_uptime_get();

	if (flash_area_open(CD_PARTITION, &fa) != 0) {
		atomic_clear(&cd_erasing);
		return;
	}

	/* Last block first, header block last: an erased header then guarantees
	 * an erased slot, even if this is interrupted by a reset. */
	for (int32_t off = (int32_t)fa->fa_size - FAULT_NOR_BLOCK_SIZE; off >= 0;
	     off -= FAULT_NOR_BLOCK_SIZE) {
		int rc = flash_area_erase(fa, off, FAULT_NOR_BLOCK_SIZE);

		if (rc) {
			LOG_ERR("coredump slot erase @0x%x failed: %d", off, rc);
			break;
		}
	}
	flash_area_close(fa);
	atomic_clear(&cd_erasing);
	LOG_INF("coredump slot erased (%u KiB in %lld ms)", (unsigned int)(CD_CAPACITY / 1024),
		k_uptime_get() - t0);
}

static void schedule_erase(void)
{
	if (atomic_cas(&cd_erasing, 0, 1)) {
		k_work_submit_to_queue(&cd_erase_q, &cd_erase_work);
	}
}

/* Mark a pending dump discarded (instant, one word) and erase in background so
 * the cloud thread does not stall for the seconds a 1 MiB erase takes. */
static int discard_and_erase(void)
{
	const struct flash_area *fa;
	struct cd_hdr h;
	int rc = flash_area_open(CD_PARTITION, &fa);

	if (rc) {
		return rc;
	}
	rc = flash_area_read(fa, 0, &h, sizeof(h));
	if (rc == 0 && h.magic != CD_ERASED && h.discard == CD_LIVE) {
		uint32_t zero = 0;

		rc = flash_area_write(fa, offsetof(struct cd_hdr, discard), &zero, sizeof(zero));
	}
	flash_area_close(fa);
	cd_ret_check();
	cd_ret.dropped = 0;
	if (h.magic != CD_ERASED) {
		schedule_erase();
	}
	return rc;
}

static int verify_crc(const struct cd_hdr *h)
{
	const struct flash_area *fa;
	uint8_t chunk[128];
	uint32_t crc = 0;
	int rc = flash_area_open(CD_PARTITION, &fa);

	if (rc) {
		return rc;
	}
	for (uint32_t off = 0; off < h->size; off += sizeof(chunk)) {
		size_t n = MIN(sizeof(chunk), h->size - off);

		rc = flash_area_read(fa, CD_HDR_SIZE + off, chunk, n);
		if (rc) {
			break;
		}
		crc = crc32_ieee_update(crc, chunk, n);
	}
	flash_area_close(fa);
	if (rc == 0 && crc != h->crc) {
		LOG_WRN("coredump crc mismatch: stored 0x%08x computed 0x%08x", h->crc, crc);
	}
	return rc ? rc : (crc == h->crc ? 1 : 0);
}

static int cd_query(enum coredump_query_id query_id, void *arg)
{
	ARG_UNUSED(arg);
	struct cd_hdr h;

	switch (query_id) {
	case COREDUMP_QUERY_GET_ERROR:
		return cw.err;
	case COREDUMP_QUERY_HAS_STORED_DUMP:
		if (hdr_read(&h) != 0) {
			return -EIO;
		}
		return classify(&h) == DIAG_COREDUMP_PENDING ? 1 : 0;
	case COREDUMP_QUERY_GET_STORED_DUMP_SIZE:
		if (hdr_read(&h) != 0) {
			return -EIO;
		}
		return classify(&h) == DIAG_COREDUMP_PENDING ? (int)h.size : 0;
	default:
		return -ENOTSUP;
	}
}

static int cd_cmd(enum coredump_cmd_id cmd_id, void *arg)
{
	struct cd_hdr h;

	switch (cmd_id) {
	case COREDUMP_CMD_CLEAR_ERROR:
		cw.err = 0;
		return 0;
	case COREDUMP_CMD_VERIFY_STORED_DUMP:
		if (hdr_read(&h) != 0 || classify(&h) != DIAG_COREDUMP_PENDING) {
			return 0;
		}
		return verify_crc(&h);
	case COREDUMP_CMD_COPY_STORED_DUMP: {
		struct coredump_cmd_copy_arg *cp = arg;
		const struct flash_area *fa;

		if (cp == NULL || cp->buffer == NULL) {
			return -EINVAL;
		}
		if (hdr_read(&h) != 0 || classify(&h) != DIAG_COREDUMP_PENDING) {
			return -ENODATA;
		}
		/* Bound against the slot, not the dump: the Block1 uploader may ask
		 * for a full final block; bytes past the dump read back as 0xFF. */
		if ((uint32_t)cp->offset + cp->length > CD_CAPACITY - CD_HDR_SIZE) {
			return -EINVAL;
		}
		int rc = flash_area_open(CD_PARTITION, &fa);

		if (rc) {
			return rc;
		}
		rc = flash_area_read(fa, CD_HDR_SIZE + cp->offset, cp->buffer, cp->length);
		flash_area_close(fa);
		return rc;
	}
	case COREDUMP_CMD_ERASE_STORED_DUMP:
	case COREDUMP_CMD_INVALIDATE_STORED_DUMP:
		return discard_and_erase();
	default:
		return -ENOTSUP;
	}
}

struct coredump_backend_api coredump_backend_other = {
	.start = cd_start,
	.end = cd_end,
	.buffer_output = cd_buffer_output,
	.query = cd_query,
	.cmd = cd_cmd,
};

int diag_coredump_info(struct diag_coredump_info *info)
{
	struct cd_hdr h;
	int rc;

	if (info == NULL) {
		return -EINVAL;
	}
	memset(info, 0, sizeof(*info));
	info->capacity = CD_CAPACITY - CD_HDR_SIZE;
	cd_ret_check();
	info->dropped = cd_ret.dropped;

	rc = hdr_read(&h);
	if (rc) {
		return rc;
	}
	info->state = atomic_get(&cd_erasing) ? DIAG_COREDUMP_ERASING : classify(&h);
	if (info->state == DIAG_COREDUMP_PENDING) {
		info->size = h.size;
		info->truncated = (h.flags & CD_FLAG_TRUNCATED) != 0;
		info->write_ms = h.write_ms;
		info->crc = h.crc;
		info->boot_count = h.boot_count;
		info->reason = h.reason;
		info->build_id_valid = (h.build_id_valid == 1U);
		memcpy(info->build_id, h.build_id, sizeof(info->build_id));
	}
	return 0;
}

/* Boot: start the erase queue; pre-erase a DIRTY slot so the next fault is
 * program-only. Runs after the spi_nor driver (POST_KERNEL) is up. */
static int cd_boot_init(void)
{
	struct cd_hdr h;

	k_work_queue_init(&cd_erase_q);
	k_work_queue_start(&cd_erase_q, cd_erase_stack, K_THREAD_STACK_SIZEOF(cd_erase_stack),
			   K_LOWEST_APPLICATION_THREAD_PRIO, NULL);
	k_thread_name_set(k_work_queue_thread_get(&cd_erase_q), "cd_erase");
	k_work_init(&cd_erase_work, cd_erase_handler);
	cd_ret_check();

	if (hdr_read(&h) == 0 && classify(&h) == DIAG_COREDUMP_DIRTY) {
		LOG_INF("coredump slot dirty, pre-erasing");
		schedule_erase();
	}
	return 0;
}

SYS_INIT(cd_boot_init, APPLICATION, CONFIG_APPLICATION_INIT_PRIORITY);
