/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Flash-backed P-GPS window ring. See pgps_store.h.
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/sys/crc.h>
#include <string.h>
#include <errno.h>

#include <oscore_cloud/pgps_store.h>

LOG_MODULE_REGISTER(pgps_store, CONFIG_OSCORE_CLOUD_LOG_LEVEL);

/* One flash sector per window. 4096 B is the erase-block size of both the
 * nRF9151's internal NVMC and the DK's external GD25 SPI NOR
 * (CONFIG_SPI_NOR_FLASH_LAYOUT_PAGE_SIZE), so a slot write is a single erase
 * plus a single write with no read-modify-write. */
#define PGPS_SLOT_SIZE 4096U

#define PGPS_SLOT_MAGIC 0x31574750UL /* "PGW1" */

#define PGPS_SLOTS CONFIG_OSCORE_CLOUD_PGPS_STORE_SLOTS

/* Header at the start of each slot; the ephemeris body follows at
 * PGPS_SLOT_BODY_OFF. eph_size is an ABI guard: an NCS upgrade that changes the
 * modem ephemeris struct must invalidate everything already in flash rather
 * than inject garbage. */
struct pgps_slot_hdr {
	uint32_t magic;
	uint32_t toe;
	uint32_t gen;
	uint16_t sv_count;
	uint16_t eph_size;
	uint32_t crc; /* CRC32-IEEE over the sv_count ephemerides that follow */
};

/* Keep the body 4-byte aligned for flash write-block-size on either device. */
#define PGPS_SLOT_BODY_OFF ROUND_UP(sizeof(struct pgps_slot_hdr), 4)

BUILD_ASSERT(PGPS_SLOT_BODY_OFF +
		     PGPS_MAX_SV * sizeof(struct nrf_modem_gnss_agnss_gps_data_ephemeris) <=
	     PGPS_SLOT_SIZE,
	     "a full constellation must fit in one P-GPS flash slot");

/* RAM mirror of the slot headers, so window lookups never touch flash until the
 * ephemerides themselves are wanted. sv_count == 0 means the slot is empty. */
struct pgps_index_entry {
	uint32_t toe;
	uint32_t gen;
	uint16_t sv_count;
};

static struct pgps_index_entry slot_index[PGPS_SLOTS];
static const struct flash_area *store_fa;
static bool initialised;

/* Ring position of a window. toe is always k * PGPS_WINDOW_SPAN + HALF, so the
 * division recovers k and consecutive windows land on consecutive slots. */
static uint16_t slot_of(uint32_t toe)
{
	return (uint16_t)((toe / PGPS_WINDOW_SPAN) % PGPS_SLOTS);
}

static off_t slot_off(uint16_t slot)
{
	return (off_t)slot * PGPS_SLOT_SIZE;
}

/* Read and validate one slot header into ent. Leaves ent zeroed for an empty or
 * corrupt slot (both are simply "nothing stored here"). */
static void scan_slot(uint16_t slot, struct pgps_index_entry *ent)
{
	struct pgps_slot_hdr hdr;
	int err;

	memset(ent, 0, sizeof(*ent));

	err = flash_area_read(store_fa, slot_off(slot), &hdr, sizeof(hdr));
	if (err) {
		LOG_WRN("slot %u: header read failed: %d", slot, err);
		return;
	}
	if (hdr.magic != PGPS_SLOT_MAGIC) {
		return; /* erased or never written */
	}
	if (hdr.eph_size != sizeof(struct nrf_modem_gnss_agnss_gps_data_ephemeris)) {
		LOG_WRN("slot %u: ephemeris ABI changed (%u != %u); ignoring", slot, hdr.eph_size,
			(unsigned)sizeof(struct nrf_modem_gnss_agnss_gps_data_ephemeris));
		return;
	}
	if (hdr.sv_count == 0 || hdr.sv_count > PGPS_MAX_SV) {
		LOG_WRN("slot %u: bad sv_count %u; ignoring", slot, hdr.sv_count);
		return;
	}
	/* A toe that does not belong in this slot means a stale/garbled header. */
	if (slot_of(hdr.toe) != slot) {
		LOG_WRN("slot %u: toe %u belongs in slot %u; ignoring", slot, hdr.toe,
			slot_of(hdr.toe));
		return;
	}

	ent->toe = hdr.toe;
	ent->gen = hdr.gen;
	ent->sv_count = hdr.sv_count;
}

int pgps_store_init(void)
{
	uint16_t used = 0;
	int err;

	if (initialised) {
		return 0;
	}

	err = flash_area_open(PARTITION_ID(pgps_storage), &store_fa);
	if (err) {
		LOG_ERR("cannot open the pgps_storage partition: %d", err);
		store_fa = NULL;
		return -ENODEV;
	}

	if (store_fa->fa_size < (size_t)PGPS_SLOTS * PGPS_SLOT_SIZE) {
		LOG_ERR("pgps_storage is %zu B; %u slots need %u B", store_fa->fa_size,
			(unsigned)PGPS_SLOTS, (unsigned)(PGPS_SLOTS * PGPS_SLOT_SIZE));
		flash_area_close(store_fa);
		store_fa = NULL;
		return -ENOSPC;
	}

	for (uint16_t s = 0; s < PGPS_SLOTS; s++) {
		scan_slot(s, &slot_index[s]);
		if (slot_index[s].sv_count) {
			used++;
		}
	}

	initialised = true;
	LOG_INF("P-GPS store ready: %u slots x %u B (%u KiB), %u hold a window",
		(unsigned)PGPS_SLOTS, (unsigned)PGPS_SLOT_SIZE,
		(unsigned)(PGPS_SLOTS * PGPS_SLOT_SIZE / 1024), used);
	return 0;
}

int pgps_store_put(uint32_t toe, uint32_t gen, uint8_t sv_count,
		   const struct nrf_modem_gnss_agnss_gps_data_ephemeris *eph)
{
	struct pgps_slot_hdr hdr;
	uint16_t slot;
	size_t body_len;
	off_t off;
	int err;

	if (!initialised) {
		return -ENODEV;
	}
	if (sv_count == 0 || sv_count > PGPS_MAX_SV || eph == NULL) {
		return -EINVAL;
	}

	slot = slot_of(toe);
	off = slot_off(slot);
	body_len = (size_t)sv_count * sizeof(*eph);

	err = flash_area_erase(store_fa, off, PGPS_SLOT_SIZE);
	if (err) {
		LOG_ERR("slot %u: erase failed: %d", slot, err);
		slot_index[slot].sv_count = 0;
		return err;
	}

	/* Body first: until the header lands the slot reads as empty, so a power
	 * loss mid-write leaves an ignorable slot rather than a valid-looking
	 * header over a truncated body. */
	err = flash_area_write(store_fa, off + PGPS_SLOT_BODY_OFF, eph, body_len);
	if (err) {
		LOG_ERR("slot %u: body write failed: %d", slot, err);
		slot_index[slot].sv_count = 0;
		return err;
	}

	memset(&hdr, 0, sizeof(hdr));
	hdr.magic = PGPS_SLOT_MAGIC;
	hdr.toe = toe;
	hdr.gen = gen;
	hdr.sv_count = sv_count;
	hdr.eph_size = sizeof(*eph);
	hdr.crc = crc32_ieee((const uint8_t *)eph, body_len);

	err = flash_area_write(store_fa, off, &hdr, sizeof(hdr));
	if (err) {
		LOG_ERR("slot %u: header write failed: %d", slot, err);
		slot_index[slot].sv_count = 0;
		return err;
	}

	slot_index[slot].toe = toe;
	slot_index[slot].gen = gen;
	slot_index[slot].sv_count = sv_count;

	LOG_DBG("slot %u <- toe=%u gen=%u (%u SVs)", slot, toe, gen, sv_count);
	return 0;
}

/* Centre of the window covering GPS second now_s. */
static uint32_t covering_toe(uint64_t now_s)
{
	return (uint32_t)((now_s / PGPS_WINDOW_SPAN) * PGPS_WINDOW_SPAN + PGPS_WINDOW_HALF);
}

bool pgps_store_have_covering(uint64_t now_s)
{
	uint32_t toe;

	if (!initialised) {
		return false;
	}
	toe = covering_toe(now_s);

	const struct pgps_index_entry *ent = &slot_index[slot_of(toe)];

	return ent->sv_count != 0 && ent->toe == toe;
}

int pgps_store_get_covering(uint64_t now_s, struct pgps_window *out)
{
	struct pgps_index_entry *ent;
	uint32_t toe;
	uint16_t slot;
	size_t body_len;
	uint32_t crc;
	struct pgps_slot_hdr hdr;
	int err;

	if (!initialised) {
		return -ENODEV;
	}
	if (out == NULL) {
		return -EINVAL;
	}

	toe = covering_toe(now_s);
	slot = slot_of(toe);
	ent = &slot_index[slot];

	if (ent->sv_count == 0 || ent->toe != toe) {
		return -ENOENT;
	}

	err = flash_area_read(store_fa, slot_off(slot), &hdr, sizeof(hdr));
	if (err) {
		LOG_ERR("slot %u: header read failed: %d", slot, err);
		return err;
	}

	body_len = (size_t)ent->sv_count * sizeof(out->eph[0]);
	err = flash_area_read(store_fa, slot_off(slot) + PGPS_SLOT_BODY_OFF, out->eph, body_len);
	if (err) {
		LOG_ERR("slot %u: body read failed: %d", slot, err);
		return err;
	}

	crc = crc32_ieee((const uint8_t *)out->eph, body_len);
	if (crc != hdr.crc) {
		LOG_ERR("slot %u: CRC mismatch (%08x != %08x); dropping the window", slot, crc,
			hdr.crc);
		ent->sv_count = 0;
		return -EILSEQ;
	}

	out->toe = ent->toe;
	out->gen = ent->gen;
	out->sv_count = (uint8_t)ent->sv_count;
	return 0;
}

void pgps_store_get_stats(struct pgps_store_stats *stats)
{
	if (stats == NULL) {
		return;
	}

	memset(stats, 0, sizeof(*stats));
	stats->slots = PGPS_SLOTS;

	if (!initialised) {
		return;
	}

	for (uint16_t s = 0; s < PGPS_SLOTS; s++) {
		if (slot_index[s].sv_count == 0) {
			continue;
		}
		stats->used++;
		if (stats->first_toe == 0 || slot_index[s].toe < stats->first_toe) {
			stats->first_toe = slot_index[s].toe;
		}
		if (slot_index[s].toe > stats->last_toe) {
			stats->last_toe = slot_index[s].toe;
		}
		if (slot_index[s].gen > stats->newest_gen) {
			stats->newest_gen = slot_index[s].gen;
		}
	}
}

int pgps_store_erase_all(void)
{
	int err;

	if (!initialised) {
		return -ENODEV;
	}

	err = flash_area_erase(store_fa, 0, (size_t)PGPS_SLOTS * PGPS_SLOT_SIZE);
	if (err) {
		LOG_ERR("ring erase failed: %d", err);
		return err;
	}

	memset(slot_index, 0, sizeof(slot_index));
	LOG_INF("P-GPS store erased (%u slots)", (unsigned)PGPS_SLOTS);
	return 0;
}
