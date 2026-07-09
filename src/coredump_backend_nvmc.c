/*
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Fault-safe flash coredump backend for nRF91 (non-secure).
 *
 * Zephyr's stock DEBUG_COREDUMP_BACKEND_FLASH_PARTITION cannot store a dump on
 * this SoC: it writes through the generic flash API, and soc_flash_nrf takes a
 * semaphore on every write (SYNC_LOCK = k_sem_take, K_FOREVER). Called from the
 * fatal handler (exception/ISR context) that __ASSERTs and escalates to a FORCED
 * HardFault, so the dump is never stored (and a stack-overflow fault hangs).
 *
 * This backend mirrors what the NCS Memfault port does: it programs the coredump
 * partition with nrfx_nvmc_* directly — a busy-poll on NVMC.READY with no RTOS
 * primitives — which is safe from fault context (CONFIG_SOC_FLASH_NRF_RADIO_SYNC_
 * NONE, so there is no timeslot arbitration to honour). Reads (query/copy for the
 * next-boot upload) run in thread context and just memcpy from memory-mapped
 * flash, which the coredump region is now attributed non-secure for (see the
 * `storage_partition` nodelabel in the consuming board's flash partitions).
 *
 * Selected via CONFIG_DEBUG_COREDUMP_BACKEND_OTHER; coredump_core.c binds to the
 * `coredump_backend_other` symbol defined here. Requires a `coredump_partition`
 * DT nodelabel in the internal flash, attributed non-secure.
 */

#include <zephyr/kernel.h>
#include <zephyr/debug/coredump.h>
#include <zephyr/devicetree.h>
#include <string.h>
#include <nrfx_nvmc.h>

/* Coredump storage partition (internal flash, memory-mapped at its offset). */
#define CD_NODE      DT_NODELABEL(coredump_partition)
#define CD_BASE      DT_REG_ADDR(CD_NODE)
#define CD_CAPACITY  DT_REG_SIZE(CD_NODE)

#define CD_WRITE_BLOCK 4U            /* nRF NVMC word */
#define CD_MAGIC       0x504d4443U   /* "CDMP" */

/* Storage-layer header at offset 0 (distinct from the coredump-core header that
 * arrives as the first buffer_output bytes). Word-multiple so nrfx word writes
 * land cleanly; written last, in end(), over the erased region. */
struct cd_hdr {
	uint32_t magic;
	uint32_t size;     /* payload bytes (excludes this header, excludes pad) */
	uint32_t checksum; /* sum of payload bytes */
	uint32_t flags;    /* 0 = valid, non-zero = capture error */
};

#define CD_HDR_SIZE ROUND_UP(sizeof(struct cd_hdr), CD_WRITE_BLOCK)

/* Capture state. Touched from fault context in start/buffer_output/end; only
 * plain memory, no locks. */
static size_t   cd_woff;     /* absolute flash write cursor for payload */
static uint32_t cd_checksum;
static uint32_t cd_bytes;    /* payload bytes accepted */
static int      cd_error;
static union {
	uint32_t w;
	uint8_t  b[CD_WRITE_BLOCK];
} cd_tail;
static uint8_t  cd_tail_len;

BUILD_ASSERT(CD_CAPACITY % 0x1000U == 0U, "coredump partition must be page-aligned in size");

static const volatile struct cd_hdr *cd_stored(void)
{
	return (const volatile struct cd_hdr *)(uintptr_t)CD_BASE;
}

/* ---- Fault-context path: erase + stream + finalize via nrfx_nvmc ---------- */

static void cd_start(void)
{
	cd_error = 0;
	cd_checksum = 0;
	cd_bytes = 0;
	cd_tail_len = 0;
	cd_woff = CD_BASE + CD_HDR_SIZE;

	/* Erase the whole region so word writes see 0xFF. Blocking busy-poll;
	 * a few hundred ms in the fatal handler is acceptable for a post-mortem. */
	uint32_t page = nrfx_nvmc_flash_page_size_get();

	for (uint32_t a = CD_BASE; a < CD_BASE + CD_CAPACITY; a += page) {
		(void)nrfx_nvmc_page_erase(a);
	}
}

static void cd_buffer_output(uint8_t *buf, size_t buflen)
{
	if (cd_error != 0) {
		return;
	}

	for (size_t i = 0; i < buflen; i++) {
		cd_checksum += buf[i];
		cd_bytes++;
		cd_tail.b[cd_tail_len++] = buf[i];

		if (cd_tail_len == CD_WRITE_BLOCK) {
			if (cd_woff + CD_WRITE_BLOCK > CD_BASE + CD_CAPACITY) {
				cd_error = -ENOSPC;
				return;
			}
			nrfx_nvmc_word_write(cd_woff, cd_tail.w);
			cd_woff += CD_WRITE_BLOCK;
			cd_tail_len = 0;
		}
	}
}

static void cd_end(void)
{
	/* Flush a partial trailing word, padded with the erased value. */
	if (cd_tail_len > 0U && cd_error == 0) {
		while (cd_tail_len < CD_WRITE_BLOCK) {
			cd_tail.b[cd_tail_len++] = 0xFFU;
		}
		if (cd_woff + CD_WRITE_BLOCK <= CD_BASE + CD_CAPACITY) {
			nrfx_nvmc_word_write(cd_woff, cd_tail.w);
			cd_woff += CD_WRITE_BLOCK;
		} else {
			cd_error = -ENOSPC;
		}
	}

	struct cd_hdr hdr = {
		.magic = CD_MAGIC,
		.size = cd_bytes,
		.checksum = cd_checksum,
		.flags = (cd_error != 0) ? 1U : 0U,
	};

	nrfx_nvmc_words_write(CD_BASE, &hdr, sizeof(hdr) / CD_WRITE_BLOCK);
}

/* ---- Thread-context path: query + read-back for the next-boot upload ------ */

static bool cd_valid(void)
{
	const volatile struct cd_hdr *h = cd_stored();

	return (h->magic == CD_MAGIC) && (h->flags == 0U) && (h->size > 0U) &&
	       (h->size <= CD_CAPACITY - CD_HDR_SIZE);
}

static uint32_t cd_verify_checksum(void)
{
	const volatile uint8_t *p = (const volatile uint8_t *)(uintptr_t)(CD_BASE + CD_HDR_SIZE);
	uint32_t sum = 0;
	uint32_t n = cd_stored()->size;

	for (uint32_t i = 0; i < n; i++) {
		sum += p[i];
	}
	return sum;
}

static int cd_query(enum coredump_query_id query_id, void *arg)
{
	ARG_UNUSED(arg);

	switch (query_id) {
	case COREDUMP_QUERY_GET_ERROR:
		return cd_error;
	case COREDUMP_QUERY_HAS_STORED_DUMP:
		return cd_valid() ? 1 : 0;
	case COREDUMP_QUERY_GET_STORED_DUMP_SIZE:
		return cd_valid() ? (int)cd_stored()->size : 0;
	default:
		return -ENOTSUP;
	}
}

static int cd_cmd(enum coredump_cmd_id cmd_id, void *arg)
{
	switch (cmd_id) {
	case COREDUMP_CMD_CLEAR_ERROR:
		cd_error = 0;
		return 0;
	case COREDUMP_CMD_VERIFY_STORED_DUMP:
		if (!cd_valid()) {
			return 0;
		}
		return (cd_verify_checksum() == cd_stored()->checksum) ? 1 : 0;
	case COREDUMP_CMD_COPY_STORED_DUMP: {
		struct coredump_cmd_copy_arg *cp = arg;

		if (cp == NULL || cp->buffer == NULL) {
			return -EINVAL;
		}
		if (!cd_valid()) {
			return -ENODATA;
		}
		/* Bound only against the physical partition (matching the stock flash
		 * backend): the Block1 uploader may ask for a full final block, and
		 * bytes past the dump read back as erased 0xFF rather than faulting. */
		if ((uint32_t)cp->offset + cp->length > CD_CAPACITY - CD_HDR_SIZE) {
			return -EINVAL;
		}
		const uint8_t *src =
			(const uint8_t *)(uintptr_t)(CD_BASE + CD_HDR_SIZE + cp->offset);

		memcpy(cp->buffer, src, cp->length);
		return 0;
	}
	case COREDUMP_CMD_ERASE_STORED_DUMP:
	case COREDUMP_CMD_INVALIDATE_STORED_DUMP: {
		/* Erase clears the magic; runs in thread context (after upload). */
		uint32_t page = nrfx_nvmc_flash_page_size_get();

		for (uint32_t a = CD_BASE; a < CD_BASE + CD_CAPACITY; a += page) {
			(void)nrfx_nvmc_page_erase(a);
		}
		return 0;
	}
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
