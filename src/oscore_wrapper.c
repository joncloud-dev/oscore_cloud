/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * OSCORE wrapper for uoscore-uedhoc: owns the device's OSCORE security
 * contexts, their durable state, their epochs and the move from PSK to EDHOC.
 *
 * Contexts ("lanes"):
 *   psk        the provisioned key (PLAN-NTN-SECURITY B1). Epoch e is a plain
 *              RFC 8613 context with ID Context idctx(base, e) = base ||
 *              minimal big-endian(e) (epoch 0 = base).
 *   edhoc-a/b  two A/B slots for contexts from an EDHOC run (B3/B4). The
 *              master secret is a persistent PSA key per slot; salt, IDs and
 *              epoch state live in settings. They extend by epochs too, with
 *              ID Context idctx(empty, e) (docs/NTN-SECURITY-A6.md §2).
 *
 * At most one lane is *active* (carries the traffic) and at most one EDHOC
 * lane is *pending* (a completed run the server has not confirmed yet). The
 * transition follows docs/NTN-SECURITY-A6.md §4:
 *   1. After a run (message_4 verified) the new context is stored pending,
 *      before any request uses it. CON requests go under it; the first verified
 *      response confirms it: it becomes active, the old EDHOC slot (if any) is
 *      erased and the PSK lane is parked. NON requests stay on the active lane
 *      until then (nothing acknowledges them, so they do not go under a context
 *      the server may not hold), unless the active context was refused while
 *      pending: then the server has most likely switched and NONs follow.
 *   3. A CON under the pending context without a verified response is followed
 *      by one CON under the active context. Whatever that returns, the next
 *      CON goes back to pending. Misses in this phase do not count toward K.
 *      If the active context keeps answering (twice), the server no longer
 *      holds the pending one; on TN the device asks for a newer run.
 *   4. A parked PSK lane is never used again unless the EDHOC context is lost;
 *      then the device rejoins PSK at the recorded epoch + 1 (works once an
 *      operator ran psk-reenable).
 *   5. A rekey (option 65000, or the SSN limit) on TN with EDHOC provisioned
 *      runs EDHOC (forward secrecy); otherwise, and for K misses, the active
 *      lane moves to its next epoch.
 *   6. A pending context is only ever replaced by a newer run.
 *
 * Epochs (docs/NTN-SECURITY-A3.md): the active lane moves to e+1 on its own
 * authority, with no round trip:
 *   - when a verified response carries the rekey option (65000),
 *   - after K consecutive CON requests with no verified response (and a time
 *     floor), because a server whose limit_v is spent cannot ask any more,
 *   - when its sender sequence number nears 2^16 (keeps the PIV at <= 2 B),
 *   - on the "oscore epoch bump" shell command (testing).
 * It never goes past confirmed + W, where confirmed is the newest epoch a
 * verified response has proven, because the server derives only
 * active+1 .. active+W. The kid context is sent while the epoch is
 * unconfirmed and left out afterwards.
 */

#include <oscore_cloud/oscore_wrapper.h>
#include <oscore_cloud/oscore_provision.h>
#include <oscore_cloud/cloud_client.h>
#if defined(CONFIG_OSCORE_CLOUD_EDHOC)
#include <oscore_cloud/oscore_edhoc.h>
#endif

#include <zephyr/kernel.h>
#include <zephyr/net/coap.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/sys/reboot.h>
#include <zephyr/sys/util.h>

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <oscore.h>
#include <psa/crypto.h>
#include <zephyr/logging/log.h>
#include <zephyr/logging/log_ctrl.h>

#if defined(OSCORE_NVM_SUPPORT)
#include <zephyr/settings/settings.h>
#endif

LOG_MODULE_REGISTER(oscore_wrapper, LOG_LEVEL_INF);

/* Inner (Class E) option the server adds to a protected response to ask for
 * the next epoch (go/internal/oscore OptionRekey). */
#define OSCORE_OPTION_REKEY 65000

/* uoscore accepts ID Contexts up to 8 bytes; the epoch takes up to 4. */
#define ID_CONTEXT_MAX      8
#define ID_CONTEXT_BASE_MAX (ID_CONTEXT_MAX - sizeof(uint32_t))

/* Sender/Recipient IDs: provisioned IDs are 1 byte, an EDHOC C_R is 1 byte
 * from this server; 8 is uoscore's limit. */
#define LANE_ID_MAX 8

/* EDHOC A/B slots. Their master secrets are persistent PSA keys next to the
 * PSK (+0) and the EDHOC static key (+1). Lost on ERASE_ALL like those. */
#define EDHOC_SLOTS          2
#define EDHOC_SLOT_KEY_ID(i) ((psa_key_id_t)(OSCORE_MASTER_SECRET_KEY_ID + 2U + (i)))
#define EDHOC_SECRET_LEN     16
#define EDHOC_SALT_LEN       8

enum lane_kind {
	LANE_PSK,
	LANE_EDHOC,
};

enum slot_state {
	SLOT_EMPTY = 0,
	SLOT_PENDING = 1,
	SLOT_ACTIVE = 2,
};

struct lane {
	const char *name;
	uint8_t kind;
	uint8_t slot;  /* EDHOC slot index */
	uint8_t state; /* EDHOC: enum slot_state */
	bool ready;    /* ctx holds a derived context */
	struct context ctx;

	/* Durable (the PSK epoch record, or the EDHOC slot record). */
	uint32_t epoch;
	uint32_t confirmed;
	uint32_t seq; /* EDHOC: run number; a newer slot wins */
	uint8_t misses;
	uint64_t ssn;
	uint8_t fp[4]; /* EDHOC: SHA-256(secret || salt)[0..3], for logs */

	/* Derivation inputs; uoscore keeps pointers into these. */
	psa_key_id_t key_id;
	const uint8_t *raw_secret; /* oscore_wrapper_init_with_keys() only */
	size_t raw_secret_len;
	bool fresh;
	uint8_t salt[OSCORE_MASTER_SALT_MAX];
	size_t salt_len;
	uint8_t sid[LANE_ID_MAX];
	size_t sid_len;
	uint8_t rid[LANE_ID_MAX];
	size_t rid_len;
	uint8_t idc[ID_CONTEXT_MAX];
	size_t idc_len;

	/* Runtime only. */
	int64_t first_miss_ms;
	bool cap_logged;
	bool rekey_requested;
};

/* Zero-initialised (.bss); lanes_init() names them. */
static struct lane psk_lane;
static struct lane ed_lane[EDHOC_SLOTS];

static struct lane *active = &psk_lane; /* carries the traffic */
static struct lane *pending;            /* EDHOC run awaiting confirmation */
static struct lane *tx_lane;            /* lane of the last protected request */
static struct lane *con_lane;           /* last CON still without a verified response */
static struct lane *hook_lane;          /* lane inside a uoscore call (NVM hooks) */
static bool fallback;                   /* next CON goes under active (rule 3) */
static bool pending_likely;             /* active refused while pending: NONs follow */
static uint8_t pending_stale;           /* fallbacks the active context still answered */
static bool psk_parked;                 /* an EDHOC context was confirmed */
static bool wrapper_ready;
static bool epochs_enabled; /* provisioned contexts with NVM persistence */

static uint8_t id_ctx_base[ID_CONTEXT_BASE_MAX];
static size_t id_ctx_base_len; /* provisioning has no base yet: always 0 */

/* Raw, caller-supplied master secret (oscore_wrapper_init_with_keys). */
static uint8_t raw_master_secret[32];

static atomic_t bump_forced; /* shell request, applied before the next request */
static bool edhoc_inflight;  /* a rekey asked for an EDHOC run */
static bool edhoc_failed;    /* that run failed: use an epoch instead */

#if defined(CONFIG_OSCORE_CLOUD_TEST_IMPAIR)
static bool fault_drop_confirm;
static bool fault_reboot_pending;
#endif

static void lanes_init(void)
{
	static const char *const names[EDHOC_SLOTS] = { "edhoc-a", "edhoc-b" };

	psk_lane.name = "psk";
	psk_lane.kind = LANE_PSK;
	for (int i = 0; i < EDHOC_SLOTS; i++) {
		ed_lane[i].name = names[i];
		ed_lane[i].kind = LANE_EDHOC;
		ed_lane[i].slot = (uint8_t)i;
	}
}

static int oscore_status_to_errno(enum err status)
{
	return (status == ok) ? 0 : -(int)status;
}

static void print_id(char *out, size_t cap, const uint8_t *id, size_t len)
{
	size_t n = 0;

	out[0] = '\0';
	for (size_t i = 0; i < len && n + 3 <= cap; i++) {
		n += (size_t)snprintf(&out[n], cap - n, "%02x", id[i]);
	}
	if (len == 0 && cap > 1) {
		snprintf(out, cap, "-");
	}
}

/* Tear down a lane's context: destroy its volatile PSA key handles (the
 * derived sender/recipient keys) and wipe it. The master key is left alone. */
static void lane_teardown(struct lane *l)
{
#if defined(OSCORE_PSA_OPAQUE_KEYS)
	if (l->ctx.sc.sender_key_id != PSA_KEY_ID_NULL) {
		(void)psa_destroy_key(l->ctx.sc.sender_key_id);
	}
	if (l->ctx.rc.recipient_key_id != PSA_KEY_ID_NULL) {
		(void)psa_destroy_key(l->ctx.rc.recipient_key_id);
	}
#endif
	memset(&l->ctx, 0, sizeof(l->ctx));
	l->ready = false;
}

void oscore_wrapper_deinit(void)
{
	lane_teardown(&psk_lane);
	for (int i = 0; i < EDHOC_SLOTS; i++) {
		lane_teardown(&ed_lane[i]);
	}
	tx_lane = NULL;
	con_lane = NULL;
	wrapper_ready = false;
}

/* Build idctx(base, epoch) into the lane. EDHOC lanes have an empty base. */
static void lane_build_id_context(struct lane *l)
{
	size_t n = 0;

	if (l->kind == LANE_PSK) {
		memcpy(l->idc, id_ctx_base, id_ctx_base_len);
		n = id_ctx_base_len;
	}
	if (l->epoch != 0) {
		int shift = 24;

		while (shift > 0 && ((l->epoch >> shift) & 0xff) == 0) {
			shift -= 8;
		}
		for (; shift >= 0; shift -= 8) {
			l->idc[n++] = (uint8_t)(l->epoch >> shift);
		}
	}
	l->idc_len = n;
}

static void apply_kid_context_policy(struct lane *l)
{
#if defined(OSCORE_KID_CONTEXT_OMIT)
	/* Send the kid context until a verified response confirms the epoch. */
	l->ctx.cc.omit_kid_context = (l->confirmed == l->epoch);
#else
	ARG_UNUSED(l);
#endif
}

/* ─────────────────────────── Durable records ────────────────────────────────
 *
 * PSK: one settings record "oscore/ep" (B1, layout unchanged):
 *
 *   ssn        next sender sequence number of the current epoch. uoscore
 *              persists it through nvm_write_ssn() before the number is used
 *              (on the client it writes on every request: the echo state never
 *              leaves ECHO_REBOOT), and adds K + F (20) to it at boot.
 *   epoch      current epoch. A bump writes epoch+1 with ssn 0 *before* the new
 *              context is derived or used, so no (epoch, ssn) pair is reused.
 *   confirmed  newest epoch a verified response has proven.
 *   misses     consecutive CON requests without a verified response (capped
 *              at K so an outage does not keep writing flash).
 *   slot       B4: 1 = parked (an EDHOC context was confirmed), 0 = in use.
 *   fp         fingerprint of the provisioned key and IDs. A mismatch means the
 *              device was re-provisioned with new material: epochs restart at 0
 *              and any EDHOC context is dropped (the server deleted it).
 *
 * Legacy "oscore/ssn": kept in step while the epoch is 0 (every 10th SSN, which
 * is what the old firmware's +20 boot jump assumes), so a FOTA rollback to a
 * pre-B1 image stays nonce-safe. Before the first bump it is set to a value the
 * old firmware refuses to send with (>= OSCORE_SSN_OVERFLOW_VALUE after its
 * jump): such an image would otherwise reuse epoch-0 nonces the server has
 * retired anyway.
 *
 * EDHOC: one record per slot, "oscore/e0" and "oscore/e1" (struct slot_rec),
 * with the same epoch fields plus state, run number, salt and IDs. A slot
 * record is written before its PSA key is used and erased before its key is
 * destroyed, so a torn update leaves either a usable slot or an empty one.
 */
#define EPOCH_REC_VERSION 1
#define SLOT_REC_VERSION  1

struct epoch_rec {
	uint8_t ver;
	uint8_t slot;
	uint8_t misses;
	uint8_t rsvd0;
	uint32_t epoch;
	uint32_t confirmed;
	uint8_t fp[8];
	uint8_t rsvd1[4];
	uint64_t ssn;
};
BUILD_ASSERT(sizeof(struct epoch_rec) == 32, "epoch record layout changed");

struct slot_rec {
	uint8_t ver;
	uint8_t state;
	uint8_t misses;
	uint8_t sid_len;
	uint8_t rid_len;
	uint8_t salt_len;
	uint8_t rsvd[2];
	uint32_t seq;
	uint32_t epoch;
	uint32_t confirmed;
	uint8_t sid[LANE_ID_MAX];
	uint8_t rid[LANE_ID_MAX];
	uint8_t salt[EDHOC_SALT_LEN];
	uint8_t fp[4];
	uint64_t ssn;
};
BUILD_ASSERT(sizeof(struct slot_rec) == 56, "EDHOC slot record layout changed");

static struct epoch_rec rec; /* PSK record: ver, fp, and the last written copy */

#if defined(OSCORE_NVM_SUPPORT)

#define OSCORE_CFG_SUBTREE  "oscore"
#define OSCORE_CFG_EP       "ep"
#define OSCORE_CFG_SSN      "ssn"
#define OSCORE_CFG_PATH_EP  OSCORE_CFG_SUBTREE "/" OSCORE_CFG_EP
#define OSCORE_CFG_PATH_SSN OSCORE_CFG_SUBTREE "/" OSCORE_CFG_SSN
/* Old firmware adds 20 at boot, then refuses to send at >= 0x7FFFFF. */
#define LEGACY_SSN_POISON   ((uint64_t)OSCORE_SSN_OVERFLOW_VALUE)

static struct epoch_rec loaded_rec;
static bool loaded_rec_present;
static bool loaded_rec_bad;
static uint64_t legacy_ssn;
static bool legacy_present;
static struct slot_rec loaded_slot[EDHOC_SLOTS];
static bool loaded_slot_present[EDHOC_SLOTS];

static int oscore_cfg_set(const char *name, size_t len, settings_read_cb read_cb, void *cb_arg)
{
	const char *next;
	ssize_t rc;

	if (settings_name_steq(name, OSCORE_CFG_EP, &next) && !next) {
		if (len != sizeof(loaded_rec)) {
			LOG_ERR("Stored epoch record has size %zu, expected %zu", len,
				sizeof(loaded_rec));
			loaded_rec_bad = true;
			return 0;
		}
		rc = read_cb(cb_arg, &loaded_rec, sizeof(loaded_rec));
		if (rc < 0) {
			LOG_ERR("Failed to read epoch record: %d", (int)rc);
			return (int)rc;
		}
		loaded_rec_present = true;
		return 0;
	}

	if (settings_name_steq(name, OSCORE_CFG_SSN, &next) && !next) {
		if (len != sizeof(legacy_ssn)) {
			return 0;
		}
		rc = read_cb(cb_arg, &legacy_ssn, sizeof(legacy_ssn));
		if (rc < 0) {
			return (int)rc;
		}
		legacy_present = true;
		return 0;
	}

	for (int i = 0; i < EDHOC_SLOTS; i++) {
		char key[3] = { 'e', (char)('0' + i), '\0' };

		if (settings_name_steq(name, key, &next) && !next) {
			if (len != sizeof(loaded_slot[i]) ||
			    read_cb(cb_arg, &loaded_slot[i], sizeof(loaded_slot[i])) !=
				    sizeof(loaded_slot[i])) {
				/* Unreadable: treated as empty (lost) below. */
				LOG_ERR("EDHOC slot record %s unreadable (%zu B)", key, len);
				return 0;
			}
			loaded_slot_present[i] = true;
			return 0;
		}
	}

	LOG_WRN("Unknown oscore key '%s' in NVS, ignoring", name);
	return -ENOENT;
}

SETTINGS_STATIC_HANDLER_DEFINE(oscore_cfg, OSCORE_CFG_SUBTREE, NULL, oscore_cfg_set, NULL, NULL);

static int psk_rec_save(const struct lane *l)
{
	struct epoch_rec r = rec;
	int err;

	r.epoch = l->epoch;
	r.confirmed = l->confirmed;
	r.misses = l->misses;
	r.ssn = l->ssn;
	r.slot = psk_parked ? 1 : 0;
	err = settings_save_one(OSCORE_CFG_PATH_EP, &r, sizeof(r));
	if (err) {
		LOG_ERR("settings_save_one(%s) failed: %d", OSCORE_CFG_PATH_EP, err);
		return err;
	}
	rec = r;
	return 0;
}

static void slot_key(const struct lane *l, char *key, size_t cap)
{
	snprintf(key, cap, OSCORE_CFG_SUBTREE "/e%u", l->slot);
}

static int slot_save(const struct lane *l)
{
	struct slot_rec r = {
		.ver = SLOT_REC_VERSION,
		.state = l->state,
		.misses = l->misses,
		.sid_len = (uint8_t)l->sid_len,
		.rid_len = (uint8_t)l->rid_len,
		.salt_len = (uint8_t)l->salt_len,
		.seq = l->seq,
		.epoch = l->epoch,
		.confirmed = l->confirmed,
		.ssn = l->ssn,
	};
	char key[16];
	int err;

	memcpy(r.sid, l->sid, l->sid_len);
	memcpy(r.rid, l->rid, l->rid_len);
	memcpy(r.salt, l->salt, l->salt_len);
	memcpy(r.fp, l->fp, sizeof(r.fp));
	slot_key(l, key, sizeof(key));
	err = settings_save_one(key, &r, sizeof(r));
	if (err) {
		LOG_ERR("settings_save_one(%s) failed: %d", key, err);
	}
	return err;
}

static int slot_delete(const struct lane *l)
{
	char key[16];
	int err;

	slot_key(l, key, sizeof(key));
	err = settings_delete(key);
	if (err) {
		LOG_ERR("settings_delete(%s) failed: %d", key, err);
	}
	return err;
}

static int legacy_save(uint64_t v)
{
	int err = settings_save_one(OSCORE_CFG_PATH_SSN, &v, sizeof(v));

	if (err) {
		LOG_ERR("settings_save_one(%s) failed: %d", OSCORE_CFG_PATH_SSN, err);
		return err;
	}
	legacy_ssn = v;
	legacy_present = true;
	return 0;
}

static int legacy_poison(void)
{
	if (legacy_present && legacy_ssn == LEGACY_SSN_POISON) {
		return 0;
	}
	return legacy_save(LEGACY_SSN_POISON);
}

#else /* !OSCORE_NVM_SUPPORT */

static int psk_rec_save(const struct lane *l)
{
	ARG_UNUSED(l);
	return 0;
}

static int slot_save(const struct lane *l)
{
	ARG_UNUSED(l);
	return 0;
}

static int slot_delete(const struct lane *l)
{
	ARG_UNUSED(l);
	return 0;
}

static int legacy_poison(void)
{
	return 0;
}

#endif /* OSCORE_NVM_SUPPORT */

static int lane_save(const struct lane *l)
{
	return (l->kind == LANE_PSK) ? psk_rec_save(l) : slot_save(l);
}

/* Persist a new SSN; the RAM copy moves only if the write succeeded. */
static int lane_save_ssn(struct lane *l, uint64_t ssn)
{
	uint64_t old = l->ssn;
	int err;

	l->ssn = ssn;
	err = lane_save(l);
	if (err) {
		l->ssn = old;
	}
	return err;
}

static bool psa_key_exists(psa_key_id_t id)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t st = psa_get_key_attributes(id, &attr);

	psa_reset_key_attributes(&attr);
	return st == PSA_SUCCESS;
}

/* Drop an EDHOC slot: record first, then the key, so a torn erase leaves an
 * empty record (and at worst a stray key the next install destroys). */
static void slot_erase(struct lane *l)
{
	lane_teardown(l);
	(void)slot_delete(l);
	(void)psa_destroy_key(EDHOC_SLOT_KEY_ID(l->slot));
	l->state = SLOT_EMPTY;
	l->epoch = 0;
	l->confirmed = 0;
	l->misses = 0;
	l->ssn = 0;
	l->sid_len = 0;
	l->rid_len = 0;
	l->salt_len = 0;
	l->rekey_requested = false;
	memset(l->fp, 0, sizeof(l->fp));
	if (con_lane == l) {
		con_lane = NULL;
	}
	if (tx_lane == l) {
		tx_lane = NULL;
	}
}

/* Derive the lane's context for its current epoch. Any previous context is
 * torn down first, so this is also the re-init path for an epoch bump. */
static int lane_setup(struct lane *l)
{
	enum err status;

	lane_teardown(l);
	lane_build_id_context(l);

	struct oscore_init_params params = {
		.master_secret = {
			.ptr = (uint8_t *)l->raw_secret,
			.len = (uint32_t)l->raw_secret_len,
		},
		.master_secret_id = l->key_id,
		.sender_id = {
			.ptr = l->sid,
			.len = (uint32_t)l->sid_len,
		},
		.recipient_id = {
			.ptr = l->rid,
			.len = (uint32_t)l->rid_len,
		},
		.id_context = {
			.ptr = l->idc_len ? l->idc : NULL,
			.len = (uint32_t)l->idc_len,
		},
		.master_salt = {
			.ptr = l->salt,
			.len = (uint32_t)l->salt_len,
		},
		.aead_alg = OSCORE_AES_CCM_16_64_128,
		.hkdf = OSCORE_SHA_256,
		/*
		 * A provisioned or stored master secret/salt is the same on every
		 * boot, so the context is NOT fresh: the library restores the SSN
		 * through nvm_read_ssn() and persists it through nvm_write_ssn().
		 */
		.fresh_master_secret_salt = l->fresh,
	};

	hook_lane = l;
	status = oscore_context_init(&params, &l->ctx);
	hook_lane = NULL;
	if (status != ok) {
		LOG_ERR("oscore_context_init (%s epoch %" PRIu32 ") returned: %d", l->name,
			l->epoch, (int)status);
		lane_teardown(l);
		return oscore_status_to_errno(status);
	}

	apply_kid_context_policy(l);
	l->ready = true;
	return 0;
}

/* ───────────────────────────── NVM hooks ───────────────────────────────────── */

#if defined(OSCORE_NVM_SUPPORT)

static bool nvm_key_matches(const struct lane *l, const struct nvm_key_t *k)
{
	return k != NULL && k->sender_id.len == l->sid_len &&
	       (l->sid_len == 0 || memcmp(k->sender_id.ptr, l->sid, l->sid_len) == 0) &&
	       k->id_context.len == l->idc_len &&
	       (l->idc_len == 0 || memcmp(k->id_context.ptr, l->idc, l->idc_len) == 0);
}

/* uoscore hook: persist the next SSN of the lane being protected. Called from
 * coap2oscore() before the PIV it follows is put on the wire; a failure aborts
 * the protect. */
enum err nvm_write_ssn(const struct nvm_key_t *nvm_key, uint64_t ssn)
{
	struct lane *l = hook_lane;

	if (!epochs_enabled || l == NULL || !nvm_key_matches(l, nvm_key)) {
		LOG_ERR("nvm_write_ssn for a context that is not the current one");
		return wrong_parameter;
	}
	if (lane_save_ssn(l, ssn)) {
		return unexpected_result_from_ext_lib;
	}

	/* Pre-B1 rollback image: same cadence its own uoscore used. */
	if (l->kind == LANE_PSK && l->epoch == 0 && (ssn % K_SSN_NVM_STORE_INTERVAL) == 0) {
		(void)legacy_save(ssn);
	}
	LOG_DBG("Persisted OSCORE %s epoch %" PRIu32 " SSN %" PRIu64, l->name, l->epoch, ssn);
	return ok;
}

/* uoscore hook: called from oscore_context_init() (ssn_init), which adds
 * K_SSN_NVM_STORE_INTERVAL + F_NVM_MAX_WRITE_FAILURE to the value. */
enum err nvm_read_ssn(const struct nvm_key_t *nvm_key, uint64_t *ssn)
{
	struct lane *l = hook_lane;

	if (ssn == NULL || nvm_key == NULL) {
		return wrong_parameter;
	}
	if (!epochs_enabled || l == NULL || !nvm_key_matches(l, nvm_key)) {
		LOG_ERR("nvm_read_ssn for a context that is not the current one");
		return wrong_parameter;
	}
	*ssn = l->ssn;
	return ok;
}

#endif /* OSCORE_NVM_SUPPORT */

/* ─────────────────────────────── Epochs ────────────────────────────────────── */

/* Move a lane to epoch+1: durable record first, then the new context. force
 * skips the confirmed + W cap (the PSK rejoin of rule 4, which the operator's
 * psk-reenable opens at max + 1). */
static int epoch_advance(struct lane *l, const char *why, bool force)
{
	uint32_t epoch = l->epoch;
	uint8_t misses = l->misses;
	uint64_t ssn = l->ssn;
	int err;

	if (!force && l->epoch >= l->confirmed + CONFIG_OSCORE_CLOUD_EPOCH_WINDOW) {
		if (!l->cap_logged) {
			LOG_WRN("OSCORE %s epoch %" PRIu32 " is confirmed + %d; not advancing (%s)",
				l->name, l->epoch, CONFIG_OSCORE_CLOUD_EPOCH_WINDOW, why);
			l->cap_logged = true;
		}
		return -EALREADY;
	}
	if (l->epoch == UINT32_MAX) {
		return -EOVERFLOW;
	}

	if (l->kind == LANE_PSK && l->epoch == 0) {
		err = legacy_poison();
		if (err) {
			return err;
		}
	}

	l->epoch = epoch + 1;
	l->ssn = 0;
	l->misses = 0;
	err = lane_save(l);
	if (err) {
		l->epoch = epoch;
		l->ssn = ssn;
		l->misses = misses;
		return err;
	}
	l->first_miss_ms = 0;
	l->cap_logged = false;

	LOG_INF("OSCORE %s epoch %" PRIu32 " -> %" PRIu32 " (%s)", l->name, epoch, l->epoch, why);
	return lane_setup(l);
}

static bool is_con_request(const uint8_t *buf, size_t len)
{
	if (len < 4 || (buf[0] >> 6) != 1) {
		return false;
	}
	/* Type CON (0), code class 0 and not Empty. */
	return ((buf[0] >> 4) & 0x3) == 0 && buf[1] != 0 && (buf[1] >> 5) == 0;
}

static void note_miss(struct lane *l)
{
	if (l->misses < UINT8_MAX) {
		l->misses++;
	}
	if (l->misses == 1 || l->first_miss_ms == 0) {
		l->first_miss_ms = k_uptime_get();
	}
	/* Persist up to K only: beyond it the value no longer changes a decision. */
	if (l->misses <= MAX(CONFIG_OSCORE_CLOUD_EPOCH_SELF_BUMP_MISSES, 1)) {
		(void)lane_save(l);
	}
}

static bool self_bump_due(const struct lane *l)
{
	if (CONFIG_OSCORE_CLOUD_EPOCH_SELF_BUMP_MISSES == 0 ||
	    l->misses < CONFIG_OSCORE_CLOUD_EPOCH_SELF_BUMP_MISSES) {
		return false;
	}
	return k_uptime_get() - l->first_miss_ms >=
	       (int64_t)CONFIG_OSCORE_CLOUD_EPOCH_SELF_BUMP_MIN_SECONDS * MSEC_PER_SEC;
}

/* Rule 5: a rekey on TN with EDHOC provisioned runs EDHOC. */
static bool edhoc_rekey_possible(void)
{
#if defined(CONFIG_OSCORE_CLOUD_EDHOC_AUTO_REKEY)
	return epochs_enabled && !edhoc_failed && oscore_edhoc_ready() &&
	       cloud_client_transport() != CLOUD_TRANSPORT_NTN;
#else
	return false;
#endif
}

/* The previous CON on lane l got no verified response. */
static void account_miss(struct lane *l)
{
	if (l == pending) {
		/* Rule 3: one CON under the active context next. */
		fallback = true;
		LOG_INF("OSCORE pending %s unanswered; next CON under %s", l->name, active->name);
	} else if (pending != NULL) {
		/* The fallback was refused: the server has most likely switched
		 * (confirmation disables the old context in the same step). Not
		 * counted toward K; back to the pending context, and NONs follow
		 * it so they are not sent under a context the server retired. */
		pending_likely = true;
		LOG_INF("OSCORE %s unanswered while %s is pending", l->name, pending->name);
	} else if (l == active) {
		note_miss(l);
	}
}

/* Apply a due rekey to the active lane (only while nothing is pending: a
 * pending EDHOC context is the rekey). */
static void active_rekey(void)
{
	struct lane *l = active;
	const char *why = NULL;
	bool edhoc_ok = false;
	int err;

	if (atomic_cas(&bump_forced, 1, 0)) {
		why = "shell";
	} else if (l->rekey_requested) {
		why = "server request";
		edhoc_ok = true;
	} else if (self_bump_due(l)) {
		why = "no verified response";
	} else if (l->ctx.sc.ssn >= CONFIG_OSCORE_CLOUD_EPOCH_SSN_LIMIT) {
		why = "sequence number";
		edhoc_ok = true;
	}
	if (why == NULL) {
		return;
	}

	if (edhoc_ok && edhoc_rekey_possible()) {
#if defined(CONFIG_OSCORE_CLOUD_EDHOC)
		if (!edhoc_inflight) {
			LOG_INF("OSCORE rekey (%s) on %s: EDHOC run on the next request", why,
				l->name);
			(void)oscore_edhoc_request_run(false);
			edhoc_inflight = true;
		}
#endif
		return;
	}

	err = epoch_advance(l, why, false);
	if (err == 0 || err == -EALREADY) {
		l->rekey_requested = false;
		edhoc_failed = false;
	} else {
		LOG_ERR("OSCORE epoch advance failed: %d", err);
	}
}

/* Before each request: account for the previous one, apply any rekey, then
 * pick the lane this request goes under. */
static int before_request(const uint8_t *buf, size_t len, struct lane **out)
{
	bool con = is_con_request(buf, len);
	int err;

	if (!epochs_enabled) {
		*out = active;
		return active->ready ? 0 : -EINVAL;
	}

	if (!active->ready) {
		/* A previous re-derivation failed after the record moved on. */
		err = lane_setup(active);
		if (err) {
			return err;
		}
	}
	if (pending != NULL && !pending->ready) {
		err = lane_setup(pending);
		if (err) {
			LOG_ERR("pending %s: context setup failed: %d", pending->name, err);
		}
	}

	if (con_lane != NULL) {
		account_miss(con_lane);
		con_lane = NULL;
	}

	if (pending == NULL) {
		active_rekey();
		if (!active->ready) {
			return -EINVAL;
		}
	}

	if (pending != NULL && pending->ready &&
	    ((con && !fallback) || (!con && pending_likely))) {
		*out = pending;
	} else {
		if (con) {
			fallback = false;
		}
		*out = active;
	}
	return 0;
}

static bool has_rekey_option(uint8_t *buf, size_t len)
{
	struct coap_packet pkt;
	struct coap_option opt;

	if (coap_packet_parse(&pkt, buf, len, NULL, 0) != 0) {
		return false;
	}
	return coap_find_options(&pkt, OSCORE_OPTION_REKEY, &opt, 1) > 0;
}

/* Rule 1: the pending context answered. Make it active; erase the EDHOC slot
 * it replaces and park the PSK lane. Order: new slot active, PSK parked, old
 * slot erased. Boot repairs a torn sequence (newest active slot wins). */
static void confirm_pending(void)
{
	struct lane *old = active;
	struct lane *l = pending;
	char kid[2 * LANE_ID_MAX + 1];

	l->state = SLOT_ACTIVE;
	l->confirmed = l->epoch;
	l->misses = 0;
	l->first_miss_ms = 0;
	apply_kid_context_policy(l);
	(void)slot_save(l);

	if (!psk_parked) {
		psk_parked = true;
		(void)psk_rec_save(&psk_lane);
	}

	if (old->kind == LANE_EDHOC) {
		slot_erase(old);
	} else {
		lane_teardown(old); /* the PSK key and epoch record stay (rule 4) */
		old->rekey_requested = false;
	}

	active = l;
	pending = NULL;
	fallback = false;
	pending_likely = false;
	pending_stale = 0;
	print_id(kid, sizeof(kid), l->sid, l->sid_len);
	LOG_INF("OSCORE EDHOC context %s (kid %s, run %" PRIu32 ") confirmed; %s retired",
		l->name, kid, l->seq, old->name);
}

/* After a response verified under lane l. */
static void after_verified(struct lane *l, uint8_t *buf, size_t len)
{
	bool dirty = false;

	if (!epochs_enabled) {
		return;
	}
	if (con_lane == l) {
		con_lane = NULL;
	}

	if (l == pending) {
		confirm_pending();
	} else if (pending != NULL) {
		/* Rule 3: the server has not confirmed the pending context yet. */
		pending_likely = false;
		if (pending_stale < UINT8_MAX) {
			pending_stale++;
		}
		LOG_INF("OSCORE %s still accepted; next CON under %s", l->name, pending->name);
		/* A pending context the server no longer holds (a later run whose
		 * message_4 was lost replaced it there) would keep every other CON
		 * wasted. Rule 6 lets only a newer run replace it: ask for one. */
		if (pending_stale >= 2 && !edhoc_inflight && edhoc_rekey_possible()) {
#if defined(CONFIG_OSCORE_CLOUD_EDHOC)
			LOG_WRN("OSCORE pending %s still unconfirmed after %u fallbacks; "
				"EDHOC run on the next request", pending->name, pending_stale);
			(void)oscore_edhoc_request_run(false);
			edhoc_inflight = true;
			pending_stale = 0;
#endif
		}
		return;
	}

	l->first_miss_ms = 0;
	if (l->misses != 0) {
		l->misses = 0;
		dirty = true;
	}
	if (l->confirmed != l->epoch) {
		LOG_INF("OSCORE %s epoch %" PRIu32 " confirmed", l->name, l->epoch);
		l->confirmed = l->epoch;
		apply_kid_context_policy(l);
		dirty = true;
	}
	if (dirty) {
		/* A failed write only means the kid context is sent again after a
		 * reboot, or K restarts a little high: both harmless. */
		(void)lane_save(l);
	}

	if (!l->rekey_requested && has_rekey_option(buf, len)) {
		LOG_INF("Server requested a rekey of %s (epoch %" PRIu32 ")", l->name, l->epoch);
		l->rekey_requested = true;
	}
}

/* ─────────────────────────────── Boot ──────────────────────────────────────── */

#if defined(OSCORE_NVM_SUPPORT)

/* Fingerprint of (master key, salt, sender ID, recipient ID, base): 8 bytes of
 * HKDF-SHA256 output under a label of our own, computed inside PSA. It never
 * matches anything on the wire and reveals nothing about the key. */
static int key_fingerprint(uint8_t out[8])
{
	static const char label[] = "oscore_cloud epoch fp v1";
	const struct lane *p = &psk_lane;
	uint8_t info[sizeof(label) - 1 + 3 + LANE_ID_MAX + LANE_ID_MAX + ID_CONTEXT_BASE_MAX];
	psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
	psa_status_t st;
	size_t n = 0;

	memcpy(info, label, sizeof(label) - 1);
	n += sizeof(label) - 1;
	info[n++] = (uint8_t)p->sid_len;
	memcpy(&info[n], p->sid, p->sid_len);
	n += p->sid_len;
	info[n++] = (uint8_t)p->rid_len;
	memcpy(&info[n], p->rid, p->rid_len);
	n += p->rid_len;
	info[n++] = (uint8_t)id_ctx_base_len;
	memcpy(&info[n], id_ctx_base, id_ctx_base_len);
	n += id_ctx_base_len;

	st = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
	if (st == PSA_SUCCESS && p->salt_len > 0) {
		st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, p->salt,
						    p->salt_len);
	}
	if (st == PSA_SUCCESS) {
		st = psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
						  OSCORE_MASTER_SECRET_KEY_ID);
	}
	if (st == PSA_SUCCESS) {
		st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO, info, n);
	}
	if (st == PSA_SUCCESS) {
		st = psa_key_derivation_output_bytes(&op, out, 8);
	}
	(void)psa_key_derivation_abort(&op);

	if (st != PSA_SUCCESS) {
		LOG_ERR("key fingerprint failed: %d", (int)st);
		return -EIO;
	}
	return 0;
}

static void psk_lane_from_rec(void)
{
	psk_lane.epoch = rec.epoch;
	psk_lane.confirmed = rec.confirmed;
	psk_lane.misses = rec.misses;
	psk_lane.ssn = rec.ssn;
	psk_parked = rec.slot != 0;
	if (psk_lane.misses > 0) {
		psk_lane.first_miss_ms = k_uptime_get();
	}
}

/* Load (or create / migrate) the PSK record. Returns 1 when the key material
 * changed (re-provisioned), 0 otherwise, or a negative errno. */
static int psk_state_load(void)
{
	uint8_t fp[8];
	int changed = 0;
	int err;

	/* Never overwrite a record this image does not understand: a newer image
	 * wrote it, and rewriting it in this format could reuse nonces. */
	if (loaded_rec_bad || (loaded_rec_present && loaded_rec.ver != EPOCH_REC_VERSION)) {
		LOG_ERR("OSCORE epoch record version %u not supported by this image (want %u); "
			"refusing to start OSCORE", loaded_rec_present ? loaded_rec.ver : 0,
			EPOCH_REC_VERSION);
		return -ENOTSUP;
	}

	err = key_fingerprint(fp);
	if (err) {
		return err;
	}

	if (loaded_rec_present) {
		rec = loaded_rec;
		if (memcmp(rec.fp, fp, sizeof(fp)) != 0) {
			/* New key material: the server starts this generation at epoch 0
			 * and has deleted every context of the old one, EDHOC included.
			 * The SSN is carried over, not reset: under a new key that only
			 * costs PIV bytes, and it keeps a false mismatch nonce-safe. */
			LOG_WRN("OSCORE key material changed: epoch %" PRIu32 " -> 0", rec.epoch);
			rec.epoch = 0;
			rec.confirmed = 0;
			rec.misses = 0;
			rec.slot = 0;
			memcpy(rec.fp, fp, sizeof(fp));
			err = settings_save_one(OSCORE_CFG_PATH_EP, &rec, sizeof(rec));
			if (err) {
				return err;
			}
			/* Epoch 0 again: a rollback image may use the new key too. */
			(void)legacy_save(rec.ssn);
			changed = 1;
		}
	} else {
		if (legacy_present && legacy_ssn >= LEGACY_SSN_POISON) {
			/* The legacy key is retired only after an epoch record was
			 * written, so that record is lost: epoch and SSN are unknown and
			 * any guess could reuse a nonce. */
			LOG_ERR("OSCORE epoch record missing but %s is retired; "
				"re-provision this device", OSCORE_CFG_PATH_SSN);
			return -EIO;
		}
		/* First boot of this image: migrate the pre-B1 SSN (epoch 0). */
		memset(&rec, 0, sizeof(rec));
		rec.ver = EPOCH_REC_VERSION;
		memcpy(rec.fp, fp, sizeof(fp));
		if (legacy_present) {
			rec.ssn = legacy_ssn;
			LOG_INF("Migrating OSCORE SSN %" PRIu64 " from %s", legacy_ssn,
				OSCORE_CFG_PATH_SSN);
		}
		err = settings_save_one(OSCORE_CFG_PATH_EP, &rec, sizeof(rec));
		if (err) {
			return err;
		}
	}

	/* Repair an interrupted first bump (poison write is the step before it). */
	if (rec.epoch > 0) {
		err = legacy_poison();
		if (err) {
			return err;
		}
	}

	psk_lane_from_rec();
	return changed;
}

/* Fill an EDHOC lane from its record. False if the record is unusable. */
static bool slot_from_rec(struct lane *l, const struct slot_rec *r)
{
	if (r->ver != SLOT_REC_VERSION ||
	    (r->state != SLOT_PENDING && r->state != SLOT_ACTIVE) || r->sid_len == 0 ||
	    r->sid_len > LANE_ID_MAX || r->rid_len > LANE_ID_MAX ||
	    r->salt_len > EDHOC_SALT_LEN) {
		return false;
	}
	l->state = r->state;
	l->misses = r->misses;
	l->seq = r->seq;
	l->epoch = r->epoch;
	l->confirmed = r->confirmed;
	l->ssn = r->ssn;
	l->sid_len = r->sid_len;
	l->rid_len = r->rid_len;
	l->salt_len = r->salt_len;
	memcpy(l->sid, r->sid, r->sid_len);
	memcpy(l->rid, r->rid, r->rid_len);
	memcpy(l->salt, r->salt, r->salt_len);
	memcpy(l->fp, r->fp, sizeof(l->fp));
	l->key_id = EDHOC_SLOT_KEY_ID(l->slot);
	l->raw_secret = NULL;
	l->raw_secret_len = 0;
	l->fresh = false;
	if (l->misses > 0) {
		l->first_miss_ms = k_uptime_get();
	}
	return true;
}

/* Resolve which lane is active and which is pending after a reboot. */
static int lanes_resolve(bool reprovisioned)
{
	struct lane *act = NULL;
	struct lane *pend = NULL;
	char kid[2 * LANE_ID_MAX + 1];
	int err;

	for (int i = 0; i < EDHOC_SLOTS; i++) {
		struct lane *l = &ed_lane[i];
		bool have_key = psa_key_exists(EDHOC_SLOT_KEY_ID(i));

		l->state = SLOT_EMPTY;
		if (!loaded_slot_present[i]) {
			if (have_key) {
				/* Torn erase or install: the record went first. */
				(void)psa_destroy_key(EDHOC_SLOT_KEY_ID(i));
			}
			continue;
		}
		if (reprovisioned) {
			LOG_WRN("dropping %s: the PSK was re-provisioned", l->name);
			slot_erase(l);
			continue;
		}
		if (!slot_from_rec(l, &loaded_slot[i]) || !have_key) {
			LOG_ERR("%s unusable (%s); erasing it", l->name,
				have_key ? "bad record" : "master key missing");
			slot_erase(l);
			continue;
		}
		if (l->state == SLOT_ACTIVE) {
			if (act == NULL || l->seq > act->seq) {
				if (act != NULL) {
					slot_erase(act);
				}
				act = l;
			} else {
				slot_erase(l);
			}
		} else {
			if (pend == NULL || l->seq > pend->seq) {
				if (pend != NULL) {
					slot_erase(pend);
				}
				pend = l;
			} else {
				slot_erase(l);
			}
		}
	}
	/* A pending run older than the active context was superseded. */
	if (pend != NULL && act != NULL && pend->seq < act->seq) {
		slot_erase(pend);
		pend = NULL;
	}

	if (act != NULL) {
		active = act;
		if (!psk_parked) {
			/* Torn confirmation: the slot went active, the park did not. */
			psk_parked = true;
			(void)psk_rec_save(&psk_lane);
		}
	} else {
		active = &psk_lane;
		if (psk_parked && pend == NULL) {
			/* Rule 4: the EDHOC context is lost. Rejoin PSK at a fresh epoch:
			 * the recorded one may have spent sequence numbers. The server
			 * accepts it after an operator ran psk-reenable. */
			LOG_ERR("OSCORE EDHOC context lost; rejoining PSK at epoch %" PRIu32
				" (needs psk-reenable on the server)", psk_lane.epoch + 1);
			psk_parked = false;
			err = epoch_advance(&psk_lane, "EDHOC context lost", true);
			if (err) {
				return err;
			}
		}
	}
	pending = pend;

	if (active->kind == LANE_EDHOC) {
		print_id(kid, sizeof(kid), active->sid, active->sid_len);
		LOG_INF("OSCORE active: %s kid %s run %" PRIu32 " epoch %" PRIu32
			" (confirmed %" PRIu32 "), ssn %" PRIu64 "; PSK parked at epoch %" PRIu32,
			active->name, kid, active->seq, active->epoch, active->confirmed,
			active->ssn, psk_lane.epoch);
	} else {
		LOG_INF("OSCORE active: psk epoch %" PRIu32 " (confirmed %" PRIu32
			"), ssn %" PRIu64 ", misses %u", psk_lane.epoch, psk_lane.confirmed,
			psk_lane.ssn, psk_lane.misses);
	}
	if (pending != NULL) {
		print_id(kid, sizeof(kid), pending->sid, pending->sid_len);
		LOG_INF("OSCORE pending: %s kid %s run %" PRIu32 ", ssn %" PRIu64, pending->name,
			kid, pending->seq, pending->ssn);
	}
	return 0;
}

static int epoch_state_load(void)
{
	int err;
	int changed;

	err = settings_subsys_init();
	if (err) {
		LOG_ERR("settings_subsys_init failed: %d", err);
		return err;
	}

	loaded_rec_present = false;
	loaded_rec_bad = false;
	legacy_present = false;
	memset(loaded_slot_present, 0, sizeof(loaded_slot_present));
	err = settings_load_subtree(OSCORE_CFG_SUBTREE);
	if (err) {
		LOG_ERR("settings_load_subtree(%s) failed: %d", OSCORE_CFG_SUBTREE, err);
		return err;
	}

	changed = psk_state_load();
	if (changed < 0) {
		return changed;
	}
	return lanes_resolve(changed == 1);
}

#endif /* OSCORE_NVM_SUPPORT */

int oscore_wrapper_init(void)
{
	struct oscore_ps_material material;
	int err;

	if (wrapper_ready) {
		return 0;
	}
	if (!epochs_enabled) {
		lanes_init();
	}

	psa_status_t psa_ret = psa_crypto_init();
	if (psa_ret != PSA_SUCCESS) {
		LOG_ERR("psa_crypto_init failed: %d", (int)psa_ret);
		return -EIO;
	}
	LOG_INF("psa_crypto_init OK");

	/* Refuse to start OSCORE on an unprovisioned device. */
	if (!oscore_provision_has_key()) {
		LOG_ERR("OSCORE not provisioned: master-secret key 0x%08x missing. "
			"Run 'oscore provision <secret> <salt> <sender_id> <recipient_id>' "
			"over the shell, then reboot.",
			(unsigned int)OSCORE_MASTER_SECRET_KEY_ID);
		return -ENOENT;
	}

	err = oscore_provision_load(&material);
	if (err != 0) {
		LOG_ERR("OSCORE salt/IDs not in Protected Storage (%d). "
			"Run 'oscore provision ...' then reboot.", err);
		return err;
	}

	struct lane *p = &psk_lane;

	memcpy(p->salt, material.salt, material.salt_len);
	p->salt_len = material.salt_len;
	memcpy(p->sid, material.sender_id, material.sender_id_len);
	p->sid_len = material.sender_id_len;
	memcpy(p->rid, material.recipient_id, material.recipient_id_len);
	p->rid_len = material.recipient_id_len;
	p->key_id = OSCORE_MASTER_SECRET_KEY_ID;
	p->raw_secret = NULL;
	p->raw_secret_len = 0;
	id_ctx_base_len = 0;

#if defined(OSCORE_NVM_SUPPORT)
	p->fresh = false;
	if (!epochs_enabled) {
		err = epoch_state_load();
		if (err) {
			return err;
		}
		epochs_enabled = true;
	}
#else
	/* Unit tests: a per-boot session. */
	p->fresh = true;
	active = p;
#endif

	err = lane_setup(active);
	if (err) {
		return err;
	}
	if (pending != NULL) {
		err = lane_setup(pending);
		if (err) {
			/* Kept (rule 6): retried before the next request. */
			LOG_ERR("pending %s: context setup failed: %d", pending->name, err);
		}
	}

	wrapper_ready = true;
	LOG_INF("OSCORE context ready (%s, epoch %" PRIu32 "%s)", active->name, active->epoch,
		pending ? ", EDHOC pending" : "");
	return 0;
}

int oscore_wrapper_init_with_keys(const uint8_t *master_secret, size_t master_secret_len,
				  const uint8_t *master_salt_in, size_t master_salt_in_len,
				  const uint8_t *sender_id_in, size_t sender_id_in_len,
				  const uint8_t *recipient_id_in, size_t recipient_id_in_len)
{
	struct lane *p = &psk_lane;
	psa_status_t psa_ret;
	int err;

	if (wrapper_ready) {
		return 0;
	}
	lanes_init();

	if (master_secret == NULL || master_secret_len == 0 ||
	    master_secret_len > sizeof(raw_master_secret) ||
	    master_salt_in_len > sizeof(p->salt) || sender_id_in_len > sizeof(p->sid) ||
	    recipient_id_in_len > sizeof(p->rid)) {
		return -EINVAL;
	}

	psa_ret = psa_crypto_init();
	if (psa_ret != PSA_SUCCESS) {
		LOG_ERR("psa_crypto_init failed: %d", (int)psa_ret);
		return -EIO;
	}

	memcpy(raw_master_secret, master_secret, master_secret_len);
	p->raw_secret = raw_master_secret;
	p->raw_secret_len = master_secret_len;
	p->key_id = PSA_KEY_ID_NULL;
	if (master_salt_in_len > 0) {
		memcpy(p->salt, master_salt_in, master_salt_in_len);
	}
	p->salt_len = master_salt_in_len;
	memcpy(p->sid, sender_id_in, sender_id_in_len);
	p->sid_len = sender_id_in_len;
	memcpy(p->rid, recipient_id_in, recipient_id_in_len);
	p->rid_len = recipient_id_in_len;
	p->epoch = 0;
	p->fresh = true;
	active = p;
	pending = NULL;

	err = lane_setup(p);
	if (err) {
		return err;
	}
	LOG_INF("OSCORE context ready (raw key material)");
	wrapper_ready = true;
	return 0;
}

int oscore_wrapper_protect(uint8_t *buf, size_t *len, size_t max_len)
{
	uint8_t protected_buf[OSCORE_MAX_PLAINTEXT_LEN + AUTH_TAG_LEN];
	uint32_t protected_len = sizeof(protected_buf);
	struct lane *l = NULL;
	enum err status;
	int err;

	if (!buf || !len) {
		return -EINVAL;
	}

	if (*len > UINT32_MAX) {
		return -EOVERFLOW;
	}

	int64_t t0 = k_uptime_get();

	err = before_request(buf, *len, &l);
	if (err) {
		return err;
	}
	if (l == NULL || !l->ready) {
		return -EINVAL;
	}

	hook_lane = l;
	status = coap2oscore(buf, (uint32_t)*len, protected_buf, &protected_len, &l->ctx);
	hook_lane = NULL;
	if (status != ok) {
		return oscore_status_to_errno(status);
	}
	if (k_uptime_get() - t0 > 500) {
		/* SSN persistence (a settings write per request until B5) stalls. */
		LOG_WRN("OSCORE protect under %s took %lld ms", l->name, k_uptime_get() - t0);
	}

	if (protected_len > max_len) {
		return -ENOBUFS;
	}

	tx_lane = l;
	con_lane = is_con_request(buf, *len) ? l : NULL;
	memcpy(buf, protected_buf, protected_len);
	*len = protected_len;

	return 0;
}

void oscore_wrapper_request_not_sent(void)
{
	con_lane = NULL;
}

int oscore_wrapper_unprotect(uint8_t *buf, size_t *len, size_t max_len)
{
	uint8_t plaintext_buf[OSCORE_MAX_PLAINTEXT_LEN];
	uint32_t plaintext_len = sizeof(plaintext_buf);
	struct lane *l = tx_lane;
	enum err status;

	if (!buf || !len || l == NULL || !l->ready) {
		return -EINVAL;
	}

	if (*len > UINT32_MAX) {
		return -EOVERFLOW;
	}

#if defined(CONFIG_OSCORE_CLOUD_TEST_IMPAIR)
	if (l == pending && fault_reboot_pending) {
		/* The request reached the server; die before the response is used. */
		LOG_WRN("fault: rebooting before the pending response is processed");
		LOG_PANIC();
		sys_reboot(SYS_REBOOT_COLD);
	}
	if (l == pending && fault_drop_confirm) {
		fault_drop_confirm = false;
		LOG_WRN("fault: dropping the response to the pending %s request", l->name);
		return -EBADMSG;
	}
#endif

	hook_lane = l;
	status = oscore2coap(buf, (uint32_t)*len, plaintext_buf, &plaintext_len, &l->ctx);
	hook_lane = NULL;
	if (status != ok) {
		return oscore_status_to_errno(status);
	}

	if (plaintext_len > max_len) {
		return -ENOBUFS;
	}

	memcpy(buf, plaintext_buf, plaintext_len);
	*len = plaintext_len;

	after_verified(l, buf, *len);
	return 0;
}

/* ───────────────────────── EDHOC install (B4) ──────────────────────────────── */

int oscore_wrapper_edhoc_install(const uint8_t *secret, size_t secret_len, const uint8_t *salt,
				 size_t salt_len, const uint8_t *sender_id, size_t sender_id_len,
				 const uint8_t *recipient_id, size_t recipient_id_len,
				 const uint8_t fp[4])
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t id;
	struct lane *l;
	uint32_t seq = 0;
	char kid[2 * LANE_ID_MAX + 1];
	psa_status_t st;
	int err;

	if (!epochs_enabled) {
		return -ENOTSUP;
	}
	if (secret_len != EDHOC_SECRET_LEN || salt_len > EDHOC_SALT_LEN || sender_id_len == 0 ||
	    sender_id_len > LANE_ID_MAX || recipient_id_len > LANE_ID_MAX) {
		return -EINVAL;
	}
	if (psk_lane.sid_len == sender_id_len &&
	    memcmp(psk_lane.sid, sender_id, sender_id_len) == 0) {
		/* The server keeps C_R unique against every kid; never alias. */
		return -EEXIST;
	}

	/* Rule 6: a newer run replaces the pending one in its slot. Otherwise use
	 * the slot the active EDHOC context does not hold. */
	if (pending != NULL) {
		l = pending;
	} else if (active->kind == LANE_EDHOC) {
		l = &ed_lane[active->slot ^ 1];
	} else {
		l = &ed_lane[0];
	}
	for (int i = 0; i < EDHOC_SLOTS; i++) {
		seq = MAX(seq, ed_lane[i].seq);
	}

	/* Invalidate the slot (record first), then replace its key. */
	slot_erase(l);
	if (pending == l) {
		pending = NULL;
	}
	fallback = false;

	id = EDHOC_SLOT_KEY_ID(l->slot);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attr, PSA_ALG_HKDF(PSA_ALG_SHA_256));
	psa_set_key_type(&attr, PSA_KEY_TYPE_DERIVE);
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_PERSISTENT);
	psa_set_key_id(&attr, id);
	st = psa_import_key(&attr, secret, secret_len, &id);
	psa_reset_key_attributes(&attr);
	if (st != PSA_SUCCESS) {
		LOG_ERR("%s: importing the EDHOC master secret: %d", l->name, (int)st);
		return -EIO;
	}

	l->key_id = id;
	l->raw_secret = NULL;
	l->raw_secret_len = 0;
	l->fresh = false;
	memcpy(l->salt, salt, salt_len);
	l->salt_len = salt_len;
	memcpy(l->sid, sender_id, sender_id_len);
	l->sid_len = sender_id_len;
	memcpy(l->rid, recipient_id, recipient_id_len);
	l->rid_len = recipient_id_len;
	memcpy(l->fp, fp, sizeof(l->fp));
	l->epoch = 0;
	l->confirmed = 0;
	l->misses = 0;
	l->ssn = 0;
	l->seq = seq + 1;
	l->state = SLOT_PENDING;
	l->rekey_requested = false;

	/* Durable before the first request under it. */
	err = slot_save(l);
	if (err) {
		slot_erase(l);
		return err;
	}
	err = lane_setup(l);
	if (err) {
		slot_erase(l);
		return err;
	}

	pending = l;
	pending_likely = false;
	pending_stale = 0;
	active->rekey_requested = false; /* the run is the rekey */
	edhoc_failed = false;
	print_id(kid, sizeof(kid), l->sid, l->sid_len);
	LOG_INF("OSCORE EDHOC context stored pending in %s (kid %s, run %" PRIu32
		"); next CON goes under it", l->name, kid, l->seq);
	return 0;
}

void oscore_wrapper_edhoc_run_done(int err)
{
	if (!edhoc_inflight) {
		return;
	}
	edhoc_inflight = false;
	if (err) {
		edhoc_failed = true;
		LOG_WRN("EDHOC rekey run failed (%d); the next request moves %s to a new epoch",
			err, active->name);
	}
}

/* ─────────────────────────────── Status ────────────────────────────────────── */

int oscore_wrapper_epoch_status(struct oscore_epoch_status *out)
{
	const struct lane *l = active;

	if (out == NULL) {
		return -EINVAL;
	}
	if (!epochs_enabled) {
		return -ENOTSUP;
	}
	memset(out, 0, sizeof(*out));
	out->epoch = l->epoch;
	out->confirmed = l->confirmed;
	out->ssn = l->ready ? l->ctx.sc.ssn : l->ssn;
	out->misses = l->misses;
	out->ready = l->ready;
	out->rekey_requested = l->rekey_requested;
#if defined(OSCORE_KID_CONTEXT_OMIT)
	out->kid_context_sent = l->ready && l->idc_len > 0 && !l->ctx.cc.omit_kid_context;
#else
	out->kid_context_sent = l->idc_len > 0;
#endif
	out->lane = l->name;
	out->edhoc = l->kind == LANE_EDHOC;
	out->run = l->seq;
	out->kid_len = (uint8_t)l->sid_len;
	memcpy(out->kid, l->sid, l->sid_len);
	out->psk_parked = psk_parked;
	out->psk_epoch = psk_lane.epoch;
	out->fallback = fallback;
	out->edhoc_rekey_inflight = edhoc_inflight;
	if (pending != NULL) {
		out->pending = pending->name;
		out->pending_run = pending->seq;
		out->pending_ssn = pending->ready ? pending->ctx.sc.ssn : pending->ssn;
		out->pending_kid_len = (uint8_t)pending->sid_len;
		memcpy(out->pending_kid, pending->sid, pending->sid_len);
	}
	return 0;
}

int oscore_wrapper_epoch_request_bump(void)
{
	if (!epochs_enabled) {
		return -ENOTSUP;
	}
	if (active->epoch >= active->confirmed + CONFIG_OSCORE_CLOUD_EPOCH_WINDOW) {
		return -EALREADY;
	}
	atomic_set(&bump_forced, 1);
	return 0;
}

#if defined(CONFIG_OSCORE_CLOUD_TEST_IMPAIR)
int oscore_wrapper_test_fault(const char *name)
{
	if (strcmp(name, "confirm") == 0) {
		fault_drop_confirm = true;
	} else if (strcmp(name, "reboot") == 0) {
		fault_reboot_pending = true;
	} else if (strcmp(name, "none") == 0) {
		fault_drop_confirm = false;
		fault_reboot_pending = false;
	} else {
		return -EINVAL;
	}
	return 0;
}

int oscore_wrapper_test_forget_edhoc(void)
{
	if (!epochs_enabled) {
		return -ENOTSUP;
	}
	for (int i = 0; i < EDHOC_SLOTS; i++) {
		if (ed_lane[i].state != SLOT_EMPTY || psa_key_exists(EDHOC_SLOT_KEY_ID(i))) {
			slot_erase(&ed_lane[i]);
		}
	}
	pending = NULL;
	fallback = false;
	active = &psk_lane;
	if (!psk_parked) {
		return lane_setup(active);
	}
	/* Rule 4, as at boot: the EDHOC context is lost while PSK is parked. */
	LOG_ERR("OSCORE EDHOC context lost; rejoining PSK at epoch %" PRIu32
		" (needs psk-reenable on the server)", psk_lane.epoch + 1);
	psk_parked = false;
	return epoch_advance(&psk_lane, "EDHOC context lost", true);
}
#endif
