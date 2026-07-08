/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * OSCORE FOTA client for the Go platform (GET/POST /f, Block2 GET /f/i).
 *
 * State machine (matches go/internal/platform/deviceapi/fota.go):
 *
 *   GET  /f    -> {1:job_id, 2:version, 3:size, 4:sha256, 5:type}  (notified)
 *   POST /f    -> {1:state, 2:progress?, 3:error?}                 drives machine
 *   GET  /f/i  -> Block2 chunks of the active job's image
 *
 * The server treats only succeeded/failed/cancelled/timed_out as terminal. Any
 * non-terminal job keeps the FOTA-pending flag set, so the device MUST report a
 * terminal state once it is done — otherwise it re-downloads the same job after
 * every reboot. For an application/bootloader image the apply step reboots, so
 * the terminal report cannot happen inline; it is latched at boot time by
 * fota_client_boot_check() and flushed by the next fota_client_step().
 *
 * A modem delta image applies the same way: apply_image() schedules the update
 * (dfu_target_schedule_update) and cold-reboots. On the next boot the modem
 * applies the delta inside nrf_modem_lib_init() and reports the outcome to the
 * fota_modem_dfu_res() hook, which latches SUCCEEDED/FAILED for the next
 * fota_client_step() — exactly like the MCUboot boot reconciliation.
 *
 * Persisted progress (settings "fota/..."):
 *   fota/job_id : tstr  active job id (also used to detect resume vs new job)
 *   fota/phase  : u8    FOTA_PHASE_* — how far the active job got before reboot
 */

#include <oscore_cloud/fota_client.h>
#include <oscore_cloud/cloud_client.h>
#include <oscore_cloud/cloud_config.h>
#include <oscore_cloud/cbor.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/logging/log_ctrl.h>
#include <zephyr/net/coap.h>
#include <zephyr/sys/reboot.h>
#include <zephyr/dfu/mcuboot.h>
#include <dfu/dfu_target.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/settings/settings.h>
#include <nrf_modem.h>
#include <modem/nrf_modem_lib.h>
#include <psa/crypto.h>
#include <string.h>
#include <stdio.h>

#ifdef CONFIG_DFU_TARGET_MCUBOOT
#include <dfu/dfu_target_mcuboot.h>

#define MCUBOOT_STREAM_BUF_SZ 512
static uint8_t mcuboot_stream_buf[MCUBOOT_STREAM_BUF_SZ] __aligned(4);
static bool mcuboot_buf_ready;
#endif

LOG_MODULE_REGISTER(fota_client, LOG_LEVEL_INF);

#define FOTA_KEY_JOB_ID    1
#define FOTA_KEY_VERSION   2
#define FOTA_KEY_SIZE      3
#define FOTA_KEY_SHA256    4
#define FOTA_KEY_TYPE      5
#define FOTA_KEY_STATE     1
#define FOTA_KEY_PROGRESS  2
#define FOTA_KEY_ERROR     3

#define FOTA_LOG_BLOCK_INTERVAL 32
#define FOTA_REPORT_BLOCK_INTERVAL 64

/* Blocks fetched per fota_client_step() call. The download runs as a series of
 * these bounded chunks so the cloud thread returns to its zbus loop between
 * them and can service telemetry/shadow traffic — a full image is otherwise one
 * multi-minute blocking call that starves everything else.
 *
 * This is the cloud thread's worst-case yield latency: a STORAGE_BATCH_AVAILABLE
 * queued behind an in-flight step waits up to one whole step before the thread
 * picks it up, and the storage batch session times out
 * (APP_STORAGE_SESSION_TIMEOUT_SECONDS, 30 s) if that pickup never happens —
 * dropping the telemetry sample.
 *
 * Blocks are 1024 B (see g_block_szx; enabled by raising OSCORE_MAX_PLAINTEXT_LEN,
 * which previously overran uoscore's decrypt buffer at 1024 B). On a degraded
 * LTE-M link a block runs ~1.5 s and up to ~10 s on a single lost datagram
 * (BLOCK2_RECV_TIMEOUT_MS before retransmit). At 8 blocks/step that put a step
 * at 12-30+ s and routinely tripped the 30 s session timeout. Keeping it small
 * (2 blocks ≈ 1 KB, a few seconds even with one retransmit) keeps the pickup
 * latency comfortably under the session timeout; the extra zbus re-posts are
 * cheap and FOTA throughput is unchanged. */
#define FOTA_BLOCKS_PER_STEP 2

#define FOTA_SETTINGS_SUBTREE "fota"
#define FOTA_SETTINGS_JOB_ID  "job_id"
#define FOTA_SETTINGS_PHASE   "phase"

/* How far the active job progressed before the last reboot. */
#define FOTA_PHASE_NONE        0
#define FOTA_PHASE_DOWNLOADING 1 /* writing image to slot1, resumable */
#define FOTA_PHASE_APPLIED     2 /* boot_request_upgrade() done, awaiting swap */
#define FOTA_PHASE_REPORT_OK   3 /* swap confirmed at boot, owe SUCCEEDED report */
#define FOTA_PHASE_REPORT_FAIL 4 /* swap did not take, owe FAILED report */
#define FOTA_PHASE_MODEM_APPLIED 5 /* modem delta scheduled + rebooting; outcome
				    * comes from the modem DFU result on next init */

/* ---- Persisted job state (settings) ------------------------------------ */

static char fota_job_id[sizeof(((struct cloud_fota_notice *)0)->job_id)];
static uint8_t fota_phase;
static bool fota_loaded;

/* ---- Latched boot-time outcome, flushed by fota_client_step() ---------- */

static bool fota_boot_result_pending;
static enum cloud_fota_state fota_boot_result;
static char fota_boot_result_job[sizeof(fota_job_id)];

static int fota_settings_set(const char *name, size_t len, settings_read_cb read_cb,
			     void *cb_arg)
{
	ssize_t rc;

	if (strcmp(name, FOTA_SETTINGS_JOB_ID) == 0) {
		/* Clamp rather than reject: tolerate stale/odd-length values so
		 * a leftover record never wedges the load (was -EINVAL spam).
		 */
		rc = read_cb(cb_arg, fota_job_id, sizeof(fota_job_id) - 1);
		if (rc < 0) {
			return (int)rc;
		}
		fota_job_id[rc] = '\0';
		fota_loaded = true;
		return 0;
	}

	if (strcmp(name, FOTA_SETTINGS_PHASE) == 0) {
		uint8_t v = 0;

		rc = read_cb(cb_arg, &v, sizeof(v));
		if (rc < 0) {
			return (int)rc;
		}
		fota_phase = v;
		return 0;
	}

	return -ENOENT;
}

SETTINGS_STATIC_HANDLER_DEFINE(fota, FOTA_SETTINGS_SUBTREE, NULL, fota_settings_set, NULL,
			      NULL);

static void fota_settings_load(void)
{
	int err = settings_load_subtree(FOTA_SETTINGS_SUBTREE);

	if (err) {
		LOG_DBG("settings_load_subtree(%s): %d", FOTA_SETTINGS_SUBTREE, err);
	}
}

static int fota_settings_save(const char *job_id, uint8_t phase)
{
	int err;

	err = settings_save_one(FOTA_SETTINGS_SUBTREE "/" FOTA_SETTINGS_JOB_ID, job_id,
				strlen(job_id));
	if (err) {
		LOG_ERR("settings_save_one(fota/job_id) failed: %d", err);
		return err;
	}
	err = settings_save_one(FOTA_SETTINGS_SUBTREE "/" FOTA_SETTINGS_PHASE, &phase,
				sizeof(phase));
	if (err) {
		LOG_ERR("settings_save_one(fota/phase) failed: %d", err);
		return err;
	}

	strncpy(fota_job_id, job_id, sizeof(fota_job_id) - 1);
	fota_job_id[sizeof(fota_job_id) - 1] = '\0';
	fota_phase = phase;
	fota_loaded = true;
	LOG_DBG("FOTA persisted job=%s phase=%u", fota_job_id, phase);
	return 0;
}

static void fota_settings_clear(void)
{
	(void)settings_delete(FOTA_SETTINGS_SUBTREE "/" FOTA_SETTINGS_JOB_ID);
	(void)settings_delete(FOTA_SETTINGS_SUBTREE "/" FOTA_SETTINGS_PHASE);
	fota_job_id[0] = '\0';
	fota_phase = FOTA_PHASE_NONE;
	fota_loaded = false;
}

static bool fota_is_same_job(const struct cloud_fota_notice *notice)
{
	return fota_loaded && fota_job_id[0] != '\0' &&
	       strcmp(fota_job_id, notice->job_id) == 0;
}

/* ---- MCUboot / slot instrumentation ------------------------------------ */

static const char *mcuboot_swap_type_name(int swap_type)
{
	switch (swap_type) {
	case BOOT_SWAP_TYPE_NONE:
		return "none";
	case BOOT_SWAP_TYPE_TEST:
		return "test";
	case BOOT_SWAP_TYPE_PERM:
		return "perm";
	case BOOT_SWAP_TYPE_REVERT:
		return "revert";
	case BOOT_SWAP_TYPE_FAIL:
		return "fail";
	default:
		return "unknown";
	}
}

static void fota_log_slot_header(const char *label, uint8_t area_id)
{
	struct mcuboot_img_header hdr;
	int err;

	err = boot_read_bank_header(area_id, &hdr, sizeof(hdr));
	if (err) {
		LOG_INF("MCUboot %s (area %u): no valid header (%d)", label, area_id, err);
		return;
	}

	LOG_INF("MCUboot %s (area %u): ver %u.%u.%u+%u size %u",
		label, area_id,
		(unsigned)hdr.h.v1.sem_ver.major, (unsigned)hdr.h.v1.sem_ver.minor,
		(unsigned)hdr.h.v1.sem_ver.revision, (unsigned)hdr.h.v1.sem_ver.build_num,
		(unsigned)hdr.h.v1.image_size);
}

/*
 * Dump the tail of the secondary slot (the MCUboot image trailer / magic). On
 * external SPI-NOR with swap-using-move this is where boot_request_upgrade()
 * writes the "test" magic. If the swap never happens, comparing this before the
 * reboot and after the next boot tells us whether the magic was written and
 * whether the bootloader erased the slot (image rejected).
 */
static void fota_log_secondary_trailer(const char *when)
{
	const struct flash_area *fa;
	uint8_t tail[32];
	int err;

	err = flash_area_open(PARTITION_ID(slot1_partition), &fa);
	if (err) {
		LOG_WRN("trailer dump: flash_area_open(slot1) failed: %d", err);
		return;
	}

	err = flash_area_read(fa, fa->fa_size - sizeof(tail), tail, sizeof(tail));
	flash_area_close(fa);
	if (err) {
		LOG_WRN("trailer dump: flash_area_read failed: %d", err);
		return;
	}

	LOG_INF("MCUboot slot1 trailer (%s), last %u bytes:", when, (unsigned)sizeof(tail));
	LOG_HEXDUMP_INF(tail, sizeof(tail), "trailer");
}

static void fota_log_boot_state(const char *when)
{
	int swap_type = mcuboot_swap_type();

	LOG_INF("MCUboot %s: active_slot=%u swap_type=%s(%d) confirmed=%d",
		when, (unsigned)boot_fetch_active_slot(),
		mcuboot_swap_type_name(swap_type), swap_type, boot_is_img_confirmed());

	fota_log_slot_header("slot0", (uint8_t)PARTITION_ID(slot0_partition));
	fota_log_slot_header("slot1", (uint8_t)PARTITION_ID(slot1_partition));
}

static void fota_latch_result(enum cloud_fota_state state)
{
	fota_boot_result = state;
	strncpy(fota_boot_result_job, fota_job_id, sizeof(fota_boot_result_job) - 1);
	fota_boot_result_job[sizeof(fota_boot_result_job) - 1] = '\0';
	fota_boot_result_pending = true;
}

void fota_client_boot_check(void)
{
	bool confirmed;
	int err;

	fota_log_boot_state("boot");

	/* boot_check runs before shadow_config_load, so the settings subsystem
	 * may not be up yet. settings_subsys_init() is idempotent and guarded, so
	 * calling it here (and again later) is safe.
	 */
	err = settings_subsys_init();
	if (err) {
		LOG_WRN("settings_subsys_init in boot_check: %d", err);
	}
	fota_settings_load();

	confirmed = boot_is_img_confirmed();

	/* A reboot may interrupt us between confirming the new image and reporting
	 * SUCCEEDED. Persisting the *decided* phase (REPORT_OK / REPORT_FAIL) makes
	 * re-evaluation deterministic instead of re-reading confirmed state (which
	 * is true again after we confirm, and would otherwise look like a failure).
	 */
	if (fota_loaded && fota_phase == FOTA_PHASE_REPORT_OK) {
		LOG_INF("FOTA: resuming pending SUCCEEDED report for job %s", fota_job_id);
		fota_latch_result(CLOUD_FOTA_STATE_SUCCEEDED);
		return;
	}
	if (fota_loaded && fota_phase == FOTA_PHASE_REPORT_FAIL) {
		LOG_INF("FOTA: resuming pending FAILED report for job %s", fota_job_id);
		fota_latch_result(CLOUD_FOTA_STATE_FAILED);
		return;
	}

	if (fota_loaded && fota_phase == FOTA_PHASE_APPLIED && fota_job_id[0] != '\0') {
		if (!confirmed) {
			/* The new image was swapped in and is now running as the
			 * pending test image. Confirm it immediately so a reset
			 * before we reach the network does not revert it, then
			 * latch a SUCCEEDED report for the active job.
			 */
			err = boot_write_img_confirmed();
			LOG_INF("FOTA: new image booted (job %s), confirm=%d -> SUCCEEDED",
				fota_job_id, err);
			(void)fota_settings_save(fota_job_id, FOTA_PHASE_REPORT_OK);
			fota_latch_result(CLOUD_FOTA_STATE_SUCCEEDED);
		} else {
			/* We requested a test swap but came back running the old,
			 * already-confirmed image: the bootloader rejected or
			 * reverted the secondary. Report FAILED so the job stops.
			 */
			LOG_WRN("FOTA: applied job %s but running image is unchanged "
				"(swap did not take) -> FAILED", fota_job_id);
			fota_log_secondary_trailer("post-boot");
			(void)fota_settings_save(fota_job_id, FOTA_PHASE_REPORT_FAIL);
			fota_latch_result(CLOUD_FOTA_STATE_FAILED);
		}
		return;
	}

	if (fota_loaded && fota_phase == FOTA_PHASE_MODEM_APPLIED && fota_job_id[0] != '\0') {
		/* A modem delta update was scheduled before this reboot. The outcome
		 * is not known yet: it is delivered to fota_modem_dfu_res() when the
		 * network module calls nrf_modem_lib_init(), which happens after this
		 * boot check. Do not touch the (unchanged) application image here.
		 */
		LOG_INF("FOTA: awaiting modem DFU result for job %s", fota_job_id);
		return;
	}

	/* No FOTA in flight. Safety net: confirm any stray unconfirmed image so
	 * MCUboot does not revert it on the next reset.
	 */
	if (!confirmed) {
		err = boot_write_img_confirmed();
		LOG_INF("MCUboot: confirmed running image (no FOTA marker): %d", err);
	}
}

/*
 * Modem DFU result hook. nrf_modem_lib_init() (called by the network module on
 * boot) applies any scheduled modem firmware update and reports the outcome
 * here, before it returns. This is the modem-delta analogue of the MCUboot
 * reconciliation in fota_client_boot_check(): it maps the result to a terminal
 * FOTA state, persists the decision, and latches it so the next
 * fota_client_step() reports it to the server (which is what clears the pending
 * job and stops the device re-downloading the same delta).
 *
 * This may run before or after fota_client_boot_check() depending on module
 * thread start order, so it loads the persisted FOTA state itself rather than
 * relying on boot_check having run (settings_subsys_init() is idempotent).
 */
static void fota_modem_dfu_res(int dfu_res, void *ctx)
{
	ARG_UNUSED(ctx);

	(void)settings_subsys_init();
	fota_settings_load();

	if (!fota_loaded || fota_phase != FOTA_PHASE_MODEM_APPLIED ||
	    fota_job_id[0] == '\0') {
		LOG_INF("Modem DFU result 0x%x with no pending modem-delta job", dfu_res);
		return;
	}

	switch (dfu_res) {
	case NRF_MODEM_DFU_RESULT_OK:
		LOG_INF("FOTA: modem delta applied (job %s) -> SUCCEEDED", fota_job_id);
		(void)fota_settings_save(fota_job_id, FOTA_PHASE_REPORT_OK);
		fota_latch_result(CLOUD_FOTA_STATE_SUCCEEDED);
		break;
	case NRF_MODEM_DFU_RESULT_VOLTAGE_LOW:
		/* Not applied; the modem retries on the next reboot. Keep
		 * MODEM_APPLIED so we re-evaluate then, and report nothing.
		 */
		LOG_WRN("FOTA: modem delta deferred (low voltage); retry on reboot");
		break;
	case NRF_MODEM_DFU_RESULT_AUTH_ERROR:
	case NRF_MODEM_DFU_RESULT_UUID_ERROR:
	case NRF_MODEM_DFU_RESULT_HARDWARE_ERROR:
	case NRF_MODEM_DFU_RESULT_INTERNAL_ERROR:
	default:
		LOG_ERR("FOTA: modem delta apply failed (job %s, result 0x%x) -> FAILED",
			fota_job_id, dfu_res);
		(void)fota_settings_save(fota_job_id, FOTA_PHASE_REPORT_FAIL);
		fota_latch_result(CLOUD_FOTA_STATE_FAILED);
		break;
	}
}

NRF_MODEM_LIB_ON_DFU_RES(fota_modem_dfu_hook, fota_modem_dfu_res, NULL);

/* ---- Notice decode / status report ------------------------------------- */

static int decode_notice(const uint8_t *body, size_t body_len, struct cloud_fota_notice *out)
{
	struct cbor_reader r;
	uint8_t major;
	uint64_t nentries;
	bool have_job = false;

	memset(out, 0, sizeof(*out));
	cbor_reader_init(&r, body, body_len);
	if (cbor_read_head(&r, &major, &nentries) != 0 || major != CBOR_MAJOR_MAP) {
		return -EINVAL;
	}
	for (uint64_t i = 0; i < nentries; i++) {
		uint8_t kmaj;
		uint64_t key;

		if (cbor_read_head(&r, &kmaj, &key) != 0 || kmaj != CBOR_MAJOR_UINT) {
			return -EINVAL;
		}
		if (key == FOTA_KEY_JOB_ID) {
			uint8_t tmaj;
			uint64_t tlen;

			if (cbor_read_head(&r, &tmaj, &tlen) != 0 || tmaj != CBOR_MAJOR_TSTR) {
				return -EINVAL;
			}
			if (tlen >= sizeof(out->job_id) || r.pos + tlen > r.len) {
				return -EINVAL;
			}
			memcpy(out->job_id, &r.buf[r.pos], tlen);
			out->job_id[tlen] = '\0';
			r.pos += tlen;
			have_job = true;
		} else if (key == FOTA_KEY_VERSION) {
			uint8_t tmaj;
			uint64_t tlen;

			if (cbor_read_head(&r, &tmaj, &tlen) != 0 || tmaj != CBOR_MAJOR_TSTR) {
				return -EINVAL;
			}
			if (tlen >= sizeof(out->version) || r.pos + tlen > r.len) {
				return -EINVAL;
			}
			memcpy(out->version, &r.buf[r.pos], tlen);
			out->version[tlen] = '\0';
			r.pos += tlen;
		} else if (key == FOTA_KEY_SIZE) {
			uint8_t vmaj;
			uint64_t v;

			if (cbor_read_head(&r, &vmaj, &v) != 0 || vmaj != CBOR_MAJOR_UINT) {
				return -EINVAL;
			}
			out->size = (uint32_t)v;
		} else if (key == FOTA_KEY_SHA256) {
			uint8_t bmaj;
			uint64_t blen;

			if (cbor_read_head(&r, &bmaj, &blen) != 0 || bmaj != CBOR_MAJOR_BSTR) {
				return -EINVAL;
			}
			if (blen != sizeof(out->sha256) || r.pos + blen > r.len) {
				return -EINVAL;
			}
			memcpy(out->sha256, &r.buf[r.pos], blen);
			r.pos += blen;
		} else if (key == FOTA_KEY_TYPE) {
			uint8_t vmaj;
			uint64_t v;

			if (cbor_read_head(&r, &vmaj, &v) != 0 || vmaj != CBOR_MAJOR_UINT) {
				return -EINVAL;
			}
			out->type = (enum cloud_fota_image_type)v;
		} else {
			if (cbor_skip(&r) != 0) {
				return -EINVAL;
			}
		}
	}
	return have_job ? 0 : -EINVAL;
}

int fota_client_fetch_notice(struct cloud_fota_notice *notice)
{
	struct coap_oscore_response resp;
	int err;

	if (!notice) {
		return -EINVAL;
	}

	err = cloud_client_oscore_get("f", &resp);
	if (err) {
		return err;
	}
	if (!resp.payload || resp.payload_len == 0) {
		return -ENOENT;
	}
	return decode_notice(resp.payload, resp.payload_len, notice);
}

int fota_client_report(enum cloud_fota_state state, uint32_t progress_blocks,
		       const char *error)
{
	uint8_t cbor[96];
	size_t map_entries = 1;
	size_t n = 0;
	int err;

	if (progress_blocks > 0) {
		map_entries++;
	}
	if (error) {
		map_entries++;
	}

	n += cbor_write_map_header(cbor + n, map_entries);
	n += cbor_write_uint(cbor + n, FOTA_KEY_STATE);
	n += cbor_write_uint(cbor + n, (uint64_t)state);
	if (progress_blocks > 0) {
		n += cbor_write_uint(cbor + n, FOTA_KEY_PROGRESS);
		n += cbor_write_uint(cbor + n, progress_blocks);
	}
	if (error) {
		size_t elen = strlen(error);

		if (elen >= 24) {
			return -ENOMEM;
		}
		n += cbor_write_uint(cbor + n, FOTA_KEY_ERROR);
		n += cbor_write_tstr(cbor + n, error, elen);
	}

	err = cloud_client_oscore_post("f", cbor, n, NULL);
	if (err) {
		LOG_ERR("POST /f report (state %d) failed: %d", state, err);
	}
	return err;
}

/* ---- Download + apply --------------------------------------------------- */

/*
 * dfu_target event callback. MUST be non-NULL: dfu_target_modem_delta_init()
 * stores this pointer and, when the modem scratch area is dirty/erase-pending,
 * calls it unconditionally (callback(DFU_TARGET_EVT_ERASE_PENDING)) with no NULL
 * guard. Passing NULL there is a call through a NULL function pointer, which on
 * the nRF91 (TF-M) faults as a SecureFault (branch into the secure region at
 * address 0, SFSR.INVEP). The MCUboot target never invokes the callback during
 * init, which is why the application-FOTA path tolerated a NULL callback.
 *
 * The modem erase blocks inside dfu_target_init() for minutes (it polls the
 * modem every second), and we run on the cloud SMF thread, which must feed its
 * task watchdog (180 s) or the device resets. The erase loop invokes this
 * callback once up front (ERASE_PENDING) and then every CONFIG_DFU_TARGET_MODEM_
 * TIMEOUT seconds (60 s) with TIMEOUT, so feeding the watchdog here keeps it
 * alive across the whole erase.
 */
static void fota_dfu_target_cb(enum dfu_target_evt_id evt_id)
{
	switch (evt_id) {
	case DFU_TARGET_EVT_ERASE_PENDING:
		LOG_INF("dfu_target: modem scratch erase pending (can take minutes)");
		oscore_cloud_feed_wdt();
		break;
	case DFU_TARGET_EVT_TIMEOUT:
		LOG_WRN("dfu_target: erase still in progress");
		oscore_cloud_feed_wdt();
		break;
	case DFU_TARGET_EVT_ERASE_DONE:
		LOG_INF("dfu_target: erase done");
		oscore_cloud_feed_wdt();
		break;
	default:
		break;
	}
}

static enum dfu_target_image_type fota_type_to_dfu(enum cloud_fota_image_type type)
{
	switch (type) {
	case CLOUD_FOTA_TYPE_APPLICATION:
	case CLOUD_FOTA_TYPE_BOOTLOADER:
		return DFU_TARGET_IMAGE_TYPE_MCUBOOT;
	case CLOUD_FOTA_TYPE_MODEM_DELTA:
		return DFU_TARGET_IMAGE_TYPE_MODEM_DELTA;
	case CLOUD_FOTA_TYPE_MODEM_FULL:
		return DFU_TARGET_IMAGE_TYPE_FULL_MODEM;
	default:
		return DFU_TARGET_IMAGE_TYPE_NONE;
	}
}

struct fota_dl_ctx {
	const struct cloud_fota_notice *notice;
	size_t block_size;
	size_t base_offset;
	size_t bytes;
	uint32_t last_log_block;
	uint32_t last_report_block;
	psa_hash_operation_t hash;
	bool hashing;
};

/* ---- Active (interleaved) download session ----------------------------- */
/* A download is driven across many fota_client_step() calls, so its context
 * must outlive a single call. g_dl_active gates whether a session is in flight;
 * g_notice is the live job (g_dl.notice points at it). */
static bool g_dl_active;
static struct cloud_fota_notice g_notice;
static struct fota_dl_ctx g_dl;
static uint8_t g_block_szx;
static size_t g_block_size;
static uint32_t g_next_block;

static int fota_dl_sink(const uint8_t *data, size_t len, void *ctx)
{
	struct fota_dl_ctx *dl = ctx;
	uint32_t block;
	int err;

	if (!dl) {
		return -EINVAL;
	}

	err = dfu_target_write(data, len);
	if (err < 0) {
		LOG_ERR("dfu_target_write failed at %u: %d",
			(unsigned)(dl->base_offset + dl->bytes), err);
		return err;
	}

	if (dl->hashing) {
		psa_status_t s = psa_hash_update(&dl->hash, data, len);

		if (s != PSA_SUCCESS) {
			LOG_ERR("psa_hash_update failed: %d", (int)s);
			dl->hashing = false;
		}
	}

	dl->bytes += len;
	block = (uint32_t)((dl->base_offset + dl->bytes) / dl->block_size);

	if (block >= dl->last_log_block + FOTA_LOG_BLOCK_INTERVAL) {
		if (dl->notice && dl->notice->size > 0) {
			LOG_INF("FOTA download %u/%u bytes (block %u)",
				(unsigned)(dl->base_offset + dl->bytes),
				dl->notice->size, block);
		} else {
			LOG_INF("FOTA download %u bytes (block %u)",
				(unsigned)(dl->base_offset + dl->bytes), block);
		}
		dl->last_log_block = block;
	}

	if (block >= dl->last_report_block + FOTA_REPORT_BLOCK_INTERVAL) {
		(void)fota_client_report(CLOUD_FOTA_STATE_DOWNLOADING, block, NULL);
		dl->last_report_block = block;
	}

	return 0;
}

#ifdef CONFIG_DFU_TARGET_MCUBOOT
static int ensure_mcuboot_stream_buf(void)
{
	int err;

	if (mcuboot_buf_ready) {
		return 0;
	}

	err = dfu_target_mcuboot_set_buf(mcuboot_stream_buf, sizeof(mcuboot_stream_buf));
	if (err) {
		return err;
	}

	mcuboot_buf_ready = true;
	return 0;
}

/*
 * Erase the secondary-slot trailer page before a fresh MCUboot download.
 * stream_flash only erases the pages it writes to; since the image is smaller
 * than the slot, the trailer page is never touched and may still hold a stale
 * magic from a previous swap. boot_request_upgrade() then cannot write a clean
 * magic (NOR cannot set bits 0->1), so the swap silently fails.
 */
static void erase_secondary_trailer(void)
{
	const struct flash_area *fa;
	int err;

	err = flash_area_open(PARTITION_ID(slot1_partition), &fa);
	if (err) {
		LOG_WRN("flash_area_open(slot1) failed: %d, skipping trailer erase", err);
		return;
	}

	const size_t page_size = CONFIG_SPI_NOR_FLASH_LAYOUT_PAGE_SIZE;
	const off_t trailer_off = fa->fa_size - page_size;

	err = flash_area_erase(fa, trailer_off, page_size);
	if (err) {
		LOG_WRN("flash_area_erase(slot1 trailer) failed: %d", err);
	} else {
		LOG_INF("Erased slot1 MCUboot trailer page at offset 0x%lx",
			(long)trailer_off);
	}

	flash_area_close(fa);
}
#endif

/* Verify the freshly written image against the server-provided SHA-256.
 * Returns 0 on match, -EIO on mismatch, -ENOTSUP if hashing was unavailable.
 */
static int fota_verify_hash(struct fota_dl_ctx *dl, const struct cloud_fota_notice *notice)
{
	uint8_t digest[32];
	size_t dlen = 0;
	psa_status_t s;

	if (!dl->hashing) {
		LOG_WRN("FOTA sha256 not computed (hashing unavailable); skipping verify");
		return -ENOTSUP;
	}

	s = psa_hash_finish(&dl->hash, digest, sizeof(digest), &dlen);
	if (s != PSA_SUCCESS || dlen != sizeof(digest)) {
		LOG_ERR("psa_hash_finish failed: %d", (int)s);
		return -ENOTSUP;
	}

	if (memcmp(digest, notice->sha256, sizeof(digest)) != 0) {
		LOG_ERR("FOTA sha256 MISMATCH for job %s", notice->job_id);
		LOG_HEXDUMP_ERR(digest, sizeof(digest), "computed");
		LOG_HEXDUMP_ERR(notice->sha256, sizeof(notice->sha256), "expected");
		return -EIO;
	}

	LOG_INF("FOTA sha256 verified OK for job %s", notice->job_id);
	return 0;
}

static int apply_image(enum cloud_fota_image_type type)
{
	int err;

	LOG_INF("FOTA finalizing download (dfu_target_done)...");
	fota_log_slot_header("slot1 before finalize",
			     (uint8_t)PARTITION_ID(slot1_partition));

	err = dfu_target_done(true);
	if (err) {
		LOG_ERR("dfu_target_done failed: %d", err);
		fota_log_slot_header("slot1 after failed finalize",
				     (uint8_t)PARTITION_ID(slot1_partition));
		return err;
	}

	LOG_INF("FOTA finalize OK");
	fota_log_slot_header("slot1 after finalize",
			     (uint8_t)PARTITION_ID(slot1_partition));

	switch (type) {
	case CLOUD_FOTA_TYPE_APPLICATION:
	case CLOUD_FOTA_TYPE_BOOTLOADER:
		LOG_INF("MCUboot: requesting test upgrade for image 0");
		err = boot_request_upgrade(BOOT_UPGRADE_TEST);
		if (err) {
			LOG_ERR("boot_request_upgrade failed: %d", err);
			return err;
		}
		/* Persist that we reached the apply step, so the next boot can
		 * reconcile the outcome and report a terminal state.
		 */
		(void)fota_settings_save(fota_job_id, FOTA_PHASE_APPLIED);
		fota_log_secondary_trailer("after boot_request_upgrade");
		LOG_INF("MCUboot: pending swap_type=%s(%d), rebooting to apply",
			mcuboot_swap_type_name(mcuboot_swap_type()), mcuboot_swap_type());
		log_panic();
		k_msleep(100);
		sys_reboot(SYS_REBOOT_COLD);
		break;
	case CLOUD_FOTA_TYPE_MODEM_DELTA:
		/* dfu_target_done(true) above finalized the write into the modem
		 * scratch area. Scheduling tells the modem to apply the delta the
		 * next time it boots; a cold reset then re-runs nrf_modem_lib_init(),
		 * which applies it and reports the outcome via the DFU-result hook
		 * below. Persist MODEM_APPLIED first so the outcome can be reconciled
		 * into a terminal report even across an unexpected reset.
		 */
		LOG_INF("Scheduling modem delta update");
		err = dfu_target_schedule_update(0);
		if (err) {
			LOG_ERR("dfu_target_schedule_update failed: %d", err);
			return err;
		}
		(void)fota_settings_save(fota_job_id, FOTA_PHASE_MODEM_APPLIED);
		LOG_INF("Modem delta scheduled; rebooting to apply");
		log_panic();
		k_msleep(100);
		sys_reboot(SYS_REBOOT_COLD);
		break;
	case CLOUD_FOTA_TYPE_MODEM_FULL:
		LOG_INF("Full modem image downloaded; reboot to apply");
		sys_reboot(SYS_REBOOT_COLD);
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

/* Set up dfu_target, resume detection, trailer erase and the streaming hash for
 * a fresh download session. On success g_dl_active is set and the per-chunk
 * pump can run. Mirrors the head of the old monolithic download routine. */
static int fota_dl_begin(const struct cloud_fota_notice *notice)
{
	enum dfu_target_image_type dfu_type;
	size_t offset;
	bool resume_job;
	int err;

	dfu_type = fota_type_to_dfu(notice->type);
	if (dfu_type == DFU_TARGET_IMAGE_TYPE_NONE) {
		return -EINVAL;
	}

	resume_job = fota_is_same_job(notice);
	if (!resume_job) {
		LOG_INF("FOTA new job %s (previous %s), clearing download progress",
			notice->job_id, fota_loaded ? fota_job_id : "none");
		fota_settings_clear();
		/* Any stale dfu_target progress is discarded after init below, once
		 * a target exists (dfu_target_reset before init returns -EACCES).
		 */
	} else {
		LOG_INF("FOTA resuming job %s (phase %u)", notice->job_id, fota_phase);
	}

#ifdef CONFIG_DFU_TARGET_MCUBOOT
	if (dfu_type == DFU_TARGET_IMAGE_TYPE_MCUBOOT) {
		err = ensure_mcuboot_stream_buf();
		if (err) {
			LOG_ERR("dfu_target_mcuboot_set_buf failed: %d", err);
			return err;
		}
	}
#endif

	LOG_INF("MCUboot state before download:");
	fota_log_boot_state("pre-download");

	err = dfu_target_init(dfu_type, 0, notice->size, fota_dfu_target_cb);
	if (err) {
		LOG_ERR("dfu_target_init failed: %d", err);
		return err;
	}

	err = dfu_target_offset_get(&offset);
	if (err) {
		LOG_ERR("dfu_target_offset_get failed: %d", err);
		return err;
	}

	if (!resume_job && offset != 0) {
		LOG_WRN("FOTA stale offset %u after new job, forcing reset", (unsigned)offset);
		(void)dfu_target_reset();
		err = dfu_target_init(dfu_type, 0, notice->size, fota_dfu_target_cb);
		if (err) {
			LOG_ERR("dfu_target_init (forced fresh) failed: %d", err);
			return err;
		}
		offset = 0;
	}

#ifdef CONFIG_DFU_TARGET_MCUBOOT
	if (dfu_type == DFU_TARGET_IMAGE_TYPE_MCUBOOT && offset == 0) {
		erase_secondary_trailer();
	}
#endif

	if (!resume_job) {
		/* Persist job id now so an interrupted download can resume. */
		err = fota_settings_save(notice->job_id, FOTA_PHASE_DOWNLOADING);
		if (err) {
			return err;
		}
	}

	/* SZX 6 = 1024 B blocks, halving the round-trips vs 512 B. This earlier
	 * failed with psa_aead_decrypt -> unexpected_result_from_ext_lib: that was
	 * PSA returning BUFFER_TOO_SMALL because uoscore's plaintext output buffer
	 * (OSCORE_MAX_PLAINTEXT_LEN, default 1064) couldn't hold a 1024 B body plus
	 * the inner CoAP frame. Raised to 1536 in CMakeLists, so 1024 B now fits.
	 * (Independently, the server no longer re-reads the image from byte 0 per
	 * block, O(N^2) -> O(1), removing the progressive per-block slowdown.)
	 */
	g_block_szx = 6;
	g_block_size = 1U << (g_block_szx + 4);
	g_next_block = (uint32_t)(offset / g_block_size);

	memset(&g_dl, 0, sizeof(g_dl));
	g_dl.notice = &g_notice;
	g_dl.block_size = g_block_size;
	g_dl.base_offset = offset;
	g_dl.last_log_block = g_next_block;
	g_dl.last_report_block = g_next_block;

	/* SHA-256 verification is only possible for a full (non-resumed) download,
	 * since we hash the bytes as they stream past. Resumed downloads rely on
	 * the dfu_target size check and MCUboot's own validation.
	 */
	if (offset == 0) {
		psa_status_t s = psa_hash_setup(&g_dl.hash, PSA_ALG_SHA_256);

		g_dl.hashing = (s == PSA_SUCCESS);
		if (!g_dl.hashing) {
			LOG_WRN("psa_hash_setup failed: %d (sha256 verify disabled)", (int)s);
		}
	}

	if (offset > 0) {
		LOG_INF("FOTA resuming job %s at offset %u (block %u)", notice->job_id,
			(unsigned)offset, g_next_block);
	} else {
		LOG_INF("FOTA downloading %u bytes in %u-byte blocks",
			notice->size, (unsigned)g_block_size);
	}

	g_dl_active = true;
	return 0;
}

/* Finalize a completed download: size/hash verification, terminal reports, and
 * apply. For MCUboot images apply_image() reboots and never returns; the
 * terminal state is reported from fota_client_boot_check()/fota_client_step()
 * after the swap. Returns FOTA_STEP_DONE on success, negative on error. */
static int fota_dl_finish(void)
{
	const struct cloud_fota_notice *notice = &g_notice;
	size_t offset = g_dl.base_offset;
	size_t total = g_dl.bytes;
	int err;

	g_dl_active = false;

	LOG_INF("FOTA download complete: %u bytes this session (%u total)",
		(unsigned)total, (unsigned)(offset + total));
	fota_log_slot_header("slot1 after download",
			     (uint8_t)PARTITION_ID(slot1_partition));

	if (notice->size > 0) {
		size_t downloaded = 0;

		if (dfu_target_offset_get(&downloaded) != 0) {
			downloaded = offset + total;
		}
		if (downloaded != notice->size) {
			LOG_ERR("FOTA size mismatch: got %u want %u",
				(unsigned)downloaded, notice->size);
			if (g_dl.hashing) {
				psa_hash_abort(&g_dl.hash);
			}
			(void)dfu_target_done(false);
			(void)fota_client_report(CLOUD_FOTA_STATE_FAILED, 0, "size mismatch");
			return -EIO;
		}
	}

	/* Verify integrity BEFORE asking MCUboot to swap. A corrupt download is
	 * the most common reason the bootloader silently refuses the secondary
	 * image; catching it here turns a mystifying boot loop into a clear error.
	 */
	if (offset == 0) {
		err = fota_verify_hash(&g_dl, notice);
		if (err == -EIO) {
			(void)dfu_target_done(false);
			fota_settings_clear();
			(void)fota_client_report(CLOUD_FOTA_STATE_FAILED, 0, "sha256 mismatch");
			return err;
		}
		/* -ENOTSUP (hashing unavailable) falls through: rely on MCUboot. */
	}

	if (dfu_target_offset_get(&offset) == 0) {
		(void)fota_client_report(CLOUD_FOTA_STATE_DOWNLOADED,
					 (uint32_t)(offset / g_block_size), NULL);
	} else {
		(void)fota_client_report(CLOUD_FOTA_STATE_DOWNLOADED,
					 (uint32_t)(total / g_block_size), NULL);
	}
	(void)fota_client_report(CLOUD_FOTA_STATE_APPLYING, 0, NULL);

	err = apply_image(notice->type);
	if (err) {
		fota_settings_clear();
		(void)fota_client_report(CLOUD_FOTA_STATE_FAILED, 0, "apply failed");
		return err;
	}

	/* Reached only for image types that apply without a reboot (modem delta). */
	fota_settings_clear();
	(void)fota_client_report(CLOUD_FOTA_STATE_SUCCEEDED, 0, NULL);
	return FOTA_STEP_DONE;
}

/* Fetch the next bounded chunk of the active download. Returns FOTA_STEP_MORE
 * if more chunks remain, FOTA_STEP_DONE when finished, negative on error. */
static int fota_dl_pump(void)
{
	uint32_t next = g_next_block;
	size_t chunk_bytes = 0;
	bool more = false;
	int err;

	err = cloud_client_oscore_block2_get("f/i", g_block_szx, fota_dl_sink, &g_dl,
					     g_next_block, FOTA_BLOCKS_PER_STEP, g_notice.size,
					     &next, &chunk_bytes, &more);
	if (err) {
		if (g_dl.hashing) {
			psa_hash_abort(&g_dl.hash);
		}
		(void)dfu_target_done(false);
		(void)fota_client_report(CLOUD_FOTA_STATE_FAILED, 0, "download failed");
		g_dl_active = false;
		return err;
	}

	g_next_block = next;
	if (more) {
		return FOTA_STEP_MORE;
	}
	return fota_dl_finish();
}

int fota_client_step(void)
{
	int err;

	/* First, flush any terminal outcome latched at boot. This is what stops
	 * the device from re-downloading an already-applied job.
	 */
	if (fota_boot_result_pending) {
		const char *errstr =
			fota_boot_result == CLOUD_FOTA_STATE_FAILED ? "swap did not apply" : NULL;

		LOG_INF("FOTA: reporting post-boot result %d for job %s",
			fota_boot_result, fota_boot_result_job);
		err = fota_client_report(fota_boot_result, 0, errstr);
		if (err) {
			/* Keep it pending; retry on the next downlink. The image
			 * is already confirmed, so this is purely server bookkeeping.
			 */
			return FOTA_STEP_DONE;
		}
		fota_settings_clear();
		fota_boot_result_pending = false;
		return FOTA_STEP_DONE;
	}

	/* A download already in flight: pump the next chunk and yield. */
	if (g_dl_active) {
		return fota_dl_pump();
	}

	/* No session yet: look for a job to start. */
	err = fota_client_fetch_notice(&g_notice);
	if (err) {
		return (err == -ENOENT) ? FOTA_STEP_IDLE : FOTA_STEP_DONE;
	}

	LOG_INF("FOTA job %s version %s type %u size %u", g_notice.job_id, g_notice.version,
		(unsigned)g_notice.type, g_notice.size);

	(void)fota_client_report(CLOUD_FOTA_STATE_DOWNLOADING, 0, NULL);

	err = fota_dl_begin(&g_notice);
	if (err) {
		/* Setup failed before any image bytes were written. Leave the job
		 * non-terminal (no FAILED report) so it retries on the next downlink
		 * or reboot, matching the previous behaviour. */
		LOG_ERR("FOTA begin failed: %d", err);
		return FOTA_STEP_DONE;
	}
	return FOTA_STEP_MORE;
}
