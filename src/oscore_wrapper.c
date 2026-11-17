/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * OSCORE wrapper for uoscore-uedhoc: owns the device's single OSCORE security
 * context, its durable state and its PSK epochs.
 *
 * PSK epochs (PLAN-NTN-SECURITY B1, protocol in docs/NTN-SECURITY-A3.md):
 * epoch e of the provisioned key is a plain RFC 8613 context whose ID Context
 * is idctx(base, e) = base || minimal big-endian(e) (epoch 0 = base). The
 * device moves to e+1 on its own authority, with no round trip:
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

#include <zephyr/kernel.h>
#include <zephyr/net/coap.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/sys/util.h>

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <string.h>

#include <oscore.h>
#include <psa/crypto.h>
#include <zephyr/logging/log.h>

#if defined(OSCORE_NVM_SUPPORT)
#include <zephyr/settings/settings.h>
#endif

LOG_MODULE_REGISTER(oscore_wrapper, LOG_LEVEL_INF);

/*
 * The master secret lives as a persistent, opaque PSA key in the secure domain
 * (OSCORE_MASTER_SECRET_KEY_ID); the non-secret salt and sender/recipient IDs
 * come from protected storage. Both are written once via "oscore provision"
 * (oscore_provision.c).
 *
 * Device-side ID convention: sender_id is what this device puts on the wire
 * (= the server's Recipient ID); recipient_id identifies the server
 * (= the server's Sender ID).
 */
static uint8_t master_salt[OSCORE_MASTER_SALT_MAX];
static size_t master_salt_len;
/* 8 bytes: the EDHOC path stores a C_R of up to 8 bytes here; provisioned
 * IDs are 1 byte. */
static uint8_t sender_id_buf[8];
static uint8_t recipient_id_buf[8];
static size_t sender_id_len;
static size_t recipient_id_len;
static struct context oscore_ctx;
/* True while oscore_ctx holds a usable context. */
static bool initialized;

/* Staging for a raw, caller-supplied master secret (oscore_wrapper_init_with_keys).
 * Held for the lifetime of the OSCORE context, which references it by pointer. */
static uint8_t raw_master_secret[32];
static size_t raw_master_secret_len;

/* Inner (Class E) option the server adds to a protected response to ask for
 * the next epoch (go/internal/oscore OptionRekey). */
#define OSCORE_OPTION_REKEY 65000

/* uoscore accepts ID Contexts up to 8 bytes; the epoch takes up to 4. */
#define ID_CONTEXT_MAX     8
#define ID_CONTEXT_BASE_MAX (ID_CONTEXT_MAX - sizeof(uint32_t))

static int oscore_status_to_errno(enum err status)
{
	return (status == ok) ? 0 : -(int)status;
}

/* Tear down the live context: destroy its volatile PSA key handles (the
 * derived sender/recipient keys) and wipe it. The provisioned master key is
 * app-owned and persistent, so it is left alone. */
static void ctx_teardown(void)
{
#if defined(OSCORE_PSA_OPAQUE_KEYS)
	if (oscore_ctx.sc.sender_key_id != PSA_KEY_ID_NULL) {
		(void)psa_destroy_key(oscore_ctx.sc.sender_key_id);
	}
	if (oscore_ctx.rc.recipient_key_id != PSA_KEY_ID_NULL) {
		(void)psa_destroy_key(oscore_ctx.rc.recipient_key_id);
	}
#endif
	memset(&oscore_ctx, 0, sizeof(oscore_ctx));
	initialized = false;
}

void oscore_wrapper_deinit(void)
{
	ctx_teardown();
}

/* ─────────────────────── Durable epoch record ───────────────────────────────
 *
 * One settings record holds everything that must survive a reboot. It replaces
 * the pre-B1 "oscore/ssn" key and is written atomically (one settings entry):
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
 *   slot       reserved for B4 (A/B key slots); 0 = provisioned PSK.
 *   fp         fingerprint of the provisioned key and IDs. A mismatch means the
 *              device was re-provisioned with new material: epochs restart at 0.
 *
 * Legacy "oscore/ssn": kept in step while the epoch is 0 (every 10th SSN, which
 * is what the old firmware's +20 boot jump assumes), so a FOTA rollback to a
 * pre-B1 image stays nonce-safe. Before the first bump it is set to a value the
 * old firmware refuses to send with (>= OSCORE_SSN_OVERFLOW_VALUE after its
 * jump): such an image would otherwise reuse epoch-0 nonces the server has
 * retired anyway.
 */
#define EPOCH_REC_VERSION 1

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

static struct epoch_rec rec; /* RAM copy of the durable record */
static bool epochs_enabled;  /* provisioned-PSK context with NVM persistence */

static uint8_t id_ctx_base[ID_CONTEXT_BASE_MAX];
static size_t id_ctx_base_len; /* provisioning has no base yet: always 0 */
static uint8_t id_ctx_buf[ID_CONTEXT_MAX];
static size_t id_ctx_len;

static bool awaiting_response;   /* last CON request has no verified response */
static bool rekey_requested;     /* a verified response carried option 65000 */
static atomic_t bump_forced;     /* shell request, applied before the next request */
static int64_t first_miss_ms;    /* uptime of the first miss in the current run */
static bool cap_logged;

/* Build idctx(base, epoch) into id_ctx_buf. */
static void build_id_context(uint32_t epoch)
{
	size_t n = id_ctx_base_len;

	memcpy(id_ctx_buf, id_ctx_base, id_ctx_base_len);
	if (epoch != 0) {
		int shift = 24;

		while (shift > 0 && ((epoch >> shift) & 0xff) == 0) {
			shift -= 8;
		}
		for (; shift >= 0; shift -= 8) {
			id_ctx_buf[n++] = (uint8_t)(epoch >> shift);
		}
	}
	id_ctx_len = n;
}

static void apply_kid_context_policy(void)
{
#if defined(OSCORE_KID_CONTEXT_OMIT)
	/* Send the kid context until a verified response confirms the epoch. */
	oscore_ctx.cc.omit_kid_context = (rec.confirmed == rec.epoch);
#endif
}

#if defined(OSCORE_NVM_SUPPORT)

#define OSCORE_CFG_SUBTREE     "oscore"
#define OSCORE_CFG_EP          "ep"
#define OSCORE_CFG_SSN         "ssn"
#define OSCORE_CFG_PATH_EP     OSCORE_CFG_SUBTREE "/" OSCORE_CFG_EP
#define OSCORE_CFG_PATH_SSN    OSCORE_CFG_SUBTREE "/" OSCORE_CFG_SSN
/* Old firmware adds 20 at boot, then refuses to send at >= 0x7FFFFF. */
#define LEGACY_SSN_POISON      ((uint64_t)OSCORE_SSN_OVERFLOW_VALUE)

static struct epoch_rec loaded_rec;
static bool loaded_rec_present;
static bool loaded_rec_bad;
static uint64_t legacy_ssn;
static bool legacy_present;

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

	LOG_WRN("Unknown oscore key '%s' in NVS, ignoring", name);
	return -ENOENT;
}

SETTINGS_STATIC_HANDLER_DEFINE(oscore_cfg, OSCORE_CFG_SUBTREE, NULL, oscore_cfg_set, NULL, NULL);

static int rec_save(const struct epoch_rec *r)
{
	int err = settings_save_one(OSCORE_CFG_PATH_EP, r, sizeof(*r));

	if (err) {
		LOG_ERR("settings_save_one(%s) failed: %d", OSCORE_CFG_PATH_EP, err);
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

/* Fingerprint of (master key, salt, sender ID, recipient ID, base): 8 bytes of
 * HKDF-SHA256 output under a label of our own, computed inside PSA. It never
 * matches anything on the wire and reveals nothing about the key. */
static int key_fingerprint(uint8_t out[8])
{
	static const char label[] = "oscore_cloud epoch fp v1";
	uint8_t info[sizeof(label) - 1 + 3 + sizeof(sender_id_buf) + sizeof(recipient_id_buf) +
		     ID_CONTEXT_BASE_MAX];
	psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
	psa_status_t st;
	size_t n = 0;

	memcpy(info, label, sizeof(label) - 1);
	n += sizeof(label) - 1;
	info[n++] = (uint8_t)sender_id_len;
	memcpy(&info[n], sender_id_buf, sender_id_len);
	n += sender_id_len;
	info[n++] = (uint8_t)recipient_id_len;
	memcpy(&info[n], recipient_id_buf, recipient_id_len);
	n += recipient_id_len;
	info[n++] = (uint8_t)id_ctx_base_len;
	memcpy(&info[n], id_ctx_base, id_ctx_base_len);
	n += id_ctx_base_len;

	st = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
	if (st == PSA_SUCCESS && master_salt_len > 0) {
		st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT,
						    master_salt, master_salt_len);
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

/* Load (or create / migrate) the durable record before the first context is
 * derived. */
static int epoch_state_load(void)
{
	uint8_t fp[8];
	int err;

	err = settings_subsys_init();
	if (err) {
		LOG_ERR("settings_subsys_init failed: %d", err);
		return err;
	}

	loaded_rec_present = false;
	loaded_rec_bad = false;
	legacy_present = false;
	err = settings_load_subtree(OSCORE_CFG_SUBTREE);
	if (err) {
		LOG_ERR("settings_load_subtree(%s) failed: %d", OSCORE_CFG_SUBTREE, err);
		return err;
	}

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
			/* New key material: the server starts this generation at epoch 0.
			 * The SSN is carried over, not reset: under a new key that only
			 * costs PIV bytes, and it keeps a false mismatch nonce-safe. */
			LOG_WRN("OSCORE key material changed: epoch %" PRIu32 " -> 0",
				rec.epoch);
			rec.epoch = 0;
			rec.confirmed = 0;
			rec.misses = 0;
			rec.slot = 0;
			memcpy(rec.fp, fp, sizeof(fp));
			err = rec_save(&rec);
			if (err) {
				return err;
			}
			/* Epoch 0 again: a rollback image may use the new key too. */
			(void)legacy_save(rec.ssn);
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
		err = rec_save(&rec);
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

	if (rec.misses > 0) {
		first_miss_ms = k_uptime_get();
	}

	LOG_INF("OSCORE epoch %" PRIu32 " (confirmed %" PRIu32 "), ssn %" PRIu64
		", misses %u", rec.epoch, rec.confirmed, rec.ssn, rec.misses);
	return 0;
}

/* uoscore hook: persist the next SSN of the current epoch. Called from
 * coap2oscore() before the PIV it follows is put on the wire; a failure aborts
 * the protect. */
enum err nvm_write_ssn(const struct nvm_key_t *nvm_key, uint64_t ssn)
{
	struct epoch_rec next;

	if (!epochs_enabled || nvm_key == NULL || nvm_key->id_context.len != id_ctx_len ||
	    (id_ctx_len > 0 && memcmp(nvm_key->id_context.ptr, id_ctx_buf, id_ctx_len) != 0)) {
		LOG_ERR("nvm_write_ssn for a context that is not the current epoch");
		return wrong_parameter;
	}

	next = rec;
	next.ssn = ssn;
	if (rec_save(&next)) {
		return unexpected_result_from_ext_lib;
	}
	rec = next;

	/* Pre-B1 rollback image: same cadence its own uoscore used. */
	if (rec.epoch == 0 && (ssn % K_SSN_NVM_STORE_INTERVAL) == 0) {
		(void)legacy_save(ssn);
	}
	LOG_DBG("Persisted OSCORE epoch %" PRIu32 " SSN %" PRIu64, rec.epoch, ssn);
	return ok;
}

/* uoscore hook: called from oscore_context_init() (ssn_init), which adds
 * K_SSN_NVM_STORE_INTERVAL + F_NVM_MAX_WRITE_FAILURE to the value. */
enum err nvm_read_ssn(const struct nvm_key_t *nvm_key, uint64_t *ssn)
{
	if (ssn == NULL || nvm_key == NULL) {
		return wrong_parameter;
	}
	if (!epochs_enabled || nvm_key->id_context.len != id_ctx_len ||
	    (id_ctx_len > 0 && memcmp(nvm_key->id_context.ptr, id_ctx_buf, id_ctx_len) != 0)) {
		LOG_ERR("nvm_read_ssn for a context that is not the current epoch");
		return wrong_parameter;
	}
	*ssn = rec.ssn;
	return ok;
}

#else /* !OSCORE_NVM_SUPPORT */

static int rec_save(const struct epoch_rec *r)
{
	ARG_UNUSED(r);
	return 0;
}

static int legacy_poison(void)
{
	return 0;
}

#endif /* OSCORE_NVM_SUPPORT */

/* Derive the provisioned-key context for rec.epoch. Any previous context is
 * torn down first, so this is also the re-init path for an epoch bump. */
static int ctx_setup_provisioned(void)
{
	enum err status;

	ctx_teardown();
	build_id_context(rec.epoch);

	struct oscore_init_params params = {
		/* Opaque persistent key; raw secret bytes are not provided here. */
		.master_secret = {
			.ptr = NULL,
			.len = 0,
		},
		.master_secret_id = OSCORE_MASTER_SECRET_KEY_ID,
		.sender_id = {
			.ptr = sender_id_buf,
			.len = sender_id_len,
		},
		.recipient_id = {
			.ptr = recipient_id_buf,
			.len = recipient_id_len,
		},
		.id_context = {
			.ptr = id_ctx_len ? id_ctx_buf : NULL,
			.len = id_ctx_len,
		},
		.master_salt = {
			.ptr = master_salt,
			.len = master_salt_len,
		},
		.aead_alg = OSCORE_AES_CCM_16_64_128,
		.hkdf = OSCORE_SHA_256,
		/*
		 * The provisioned master secret/salt are identical on every boot,
		 * so the context is NOT fresh: the library restores the SSN through
		 * nvm_read_ssn() and persists it through nvm_write_ssn(). Without
		 * OSCORE_NVM_SUPPORT (unit tests) fall back to a per-boot session.
		 */
#if defined(OSCORE_NVM_SUPPORT)
		.fresh_master_secret_salt = false,
#else
		.fresh_master_secret_salt = true,
#endif
	};

	status = oscore_context_init(&params, &oscore_ctx);
	if (status != ok) {
		LOG_ERR("oscore_context_init (epoch %" PRIu32 ") returned: %d", rec.epoch,
			(int)status);
		ctx_teardown();
		return oscore_status_to_errno(status);
	}

	apply_kid_context_policy();
	initialized = true;
	return 0;
}

/* Move to epoch+1: durable record first, then the new context. */
static int epoch_advance(const char *why)
{
	struct epoch_rec next = rec;
	int err;

	if (rec.epoch >= rec.confirmed + CONFIG_OSCORE_CLOUD_EPOCH_WINDOW) {
		if (!cap_logged) {
			LOG_WRN("OSCORE epoch %" PRIu32 " is confirmed + %d; not advancing (%s)",
				rec.epoch, CONFIG_OSCORE_CLOUD_EPOCH_WINDOW, why);
			cap_logged = true;
		}
		return -EALREADY;
	}
	if (rec.epoch == UINT32_MAX) {
		return -EOVERFLOW;
	}

	if (rec.epoch == 0) {
		err = legacy_poison();
		if (err) {
			return err;
		}
	}

	next.epoch = rec.epoch + 1;
	next.ssn = 0;
	next.misses = 0;
	err = rec_save(&next);
	if (err) {
		return err;
	}
	rec = next;
	first_miss_ms = 0;
	cap_logged = false;

	LOG_INF("OSCORE epoch %" PRIu32 " -> %" PRIu32 " (%s)", rec.epoch - 1, rec.epoch, why);
	return ctx_setup_provisioned();
}

static bool is_con_request(const uint8_t *buf, size_t len)
{
	if (len < 4 || (buf[0] >> 6) != 1) {
		return false;
	}
	/* Type CON (0), code class 0 and not Empty. */
	return ((buf[0] >> 4) & 0x3) == 0 && buf[1] != 0 && (buf[1] >> 5) == 0;
}

static void note_miss(void)
{
	if (rec.misses < UINT8_MAX) {
		rec.misses++;
	}
	if (rec.misses == 1 || first_miss_ms == 0) {
		first_miss_ms = k_uptime_get();
	}
	/* Persist up to K only: beyond it the value no longer changes a decision. */
	if (rec.misses <= MAX(CONFIG_OSCORE_CLOUD_EPOCH_SELF_BUMP_MISSES, 1)) {
		(void)rec_save(&rec);
	}
}

static bool self_bump_due(void)
{
	if (CONFIG_OSCORE_CLOUD_EPOCH_SELF_BUMP_MISSES == 0 ||
	    rec.misses < CONFIG_OSCORE_CLOUD_EPOCH_SELF_BUMP_MISSES) {
		return false;
	}
	return k_uptime_get() - first_miss_ms >=
	       (int64_t)CONFIG_OSCORE_CLOUD_EPOCH_SELF_BUMP_MIN_SECONDS * MSEC_PER_SEC;
}

/* Before each request: account for the previous one, then apply any bump. */
static int epoch_before_request(const uint8_t *buf, size_t len)
{
	const char *why = NULL;
	bool con = is_con_request(buf, len);
	int err;

	if (!epochs_enabled) {
		return 0;
	}

	if (!initialized) {
		/* A previous re-derivation failed after the record moved on. */
		err = ctx_setup_provisioned();
		if (err) {
			return err;
		}
	}

	if (con && awaiting_response) {
		note_miss();
	}
	awaiting_response = false;

	if (atomic_cas(&bump_forced, 1, 0)) {
		why = "shell";
	} else if (rekey_requested) {
		why = "server request";
	} else if (self_bump_due()) {
		why = "no verified response";
	} else if (oscore_ctx.sc.ssn >= CONFIG_OSCORE_CLOUD_EPOCH_SSN_LIMIT) {
		why = "sequence number";
	}

	if (why != NULL) {
		err = epoch_advance(why);
		if (err == 0 || err == -EALREADY) {
			rekey_requested = false;
		} else {
			LOG_ERR("OSCORE epoch advance failed: %d", err);
			if (!initialized) {
				return err;
			}
		}
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

/* After a response verified under the current context. */
static void epoch_after_verified(uint8_t *buf, size_t len)
{
	bool dirty = false;

	if (!epochs_enabled) {
		return;
	}

	awaiting_response = false;
	first_miss_ms = 0;
	if (rec.misses != 0) {
		rec.misses = 0;
		dirty = true;
	}
	if (rec.confirmed != rec.epoch) {
		LOG_INF("OSCORE epoch %" PRIu32 " confirmed", rec.epoch);
		rec.confirmed = rec.epoch;
		apply_kid_context_policy();
		dirty = true;
	}
	if (dirty) {
		/* A failed write only means the kid context is sent again after a
		 * reboot, or K restarts a little high: both harmless. */
		(void)rec_save(&rec);
	}

	if (!rekey_requested && has_rekey_option(buf, len)) {
		LOG_INF("Server requested OSCORE epoch %" PRIu32, rec.epoch + 1);
		rekey_requested = true;
	}
}

int oscore_wrapper_init(void)
{
	struct oscore_ps_material material;
	int err;

	if (initialized) {
		return 0;
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

	memcpy(master_salt, material.salt, material.salt_len);
	master_salt_len = material.salt_len;
	memcpy(sender_id_buf, material.sender_id, material.sender_id_len);
	sender_id_len = material.sender_id_len;
	memcpy(recipient_id_buf, material.recipient_id, material.recipient_id_len);
	recipient_id_len = material.recipient_id_len;
	id_ctx_base_len = 0;

#if defined(OSCORE_NVM_SUPPORT)
	if (!epochs_enabled) {
		err = epoch_state_load();
		if (err) {
			return err;
		}
		epochs_enabled = true;
	}
#else
	memset(&rec, 0, sizeof(rec));
#endif

	err = ctx_setup_provisioned();
	if (err) {
		return err;
	}

	LOG_INF("OSCORE context ready (opaque key 0x%08x, epoch %" PRIu32 ")",
		(unsigned int)OSCORE_MASTER_SECRET_KEY_ID, rec.epoch);
	return 0;
}

int oscore_wrapper_init_with_keys(const uint8_t *master_secret, size_t master_secret_len,
				  const uint8_t *master_salt_in, size_t master_salt_in_len,
				  const uint8_t *sender_id_in, size_t sender_id_in_len,
				  const uint8_t *recipient_id_in, size_t recipient_id_in_len)
{
	enum err status;
	psa_status_t psa_ret;

	if (initialized) {
		return 0;
	}

	if (master_secret == NULL || master_secret_len == 0 ||
	    master_secret_len > sizeof(raw_master_secret) ||
	    master_salt_in_len > sizeof(master_salt) ||
	    sender_id_in_len > sizeof(sender_id_buf) ||
	    recipient_id_in_len > sizeof(recipient_id_buf)) {
		return -EINVAL;
	}

	psa_ret = psa_crypto_init();
	if (psa_ret != PSA_SUCCESS) {
		LOG_ERR("psa_crypto_init failed: %d", (int)psa_ret);
		return -EIO;
	}

	memcpy(raw_master_secret, master_secret, master_secret_len);
	raw_master_secret_len = master_secret_len;
	if (master_salt_in_len > 0) {
		memcpy(master_salt, master_salt_in, master_salt_in_len);
	}
	master_salt_len = master_salt_in_len;
	memcpy(sender_id_buf, sender_id_in, sender_id_in_len);
	sender_id_len = sender_id_in_len;
	memcpy(recipient_id_buf, recipient_id_in, recipient_id_in_len);
	recipient_id_len = recipient_id_in_len;

	struct oscore_init_params params = {
		.master_secret = {
			.ptr = raw_master_secret,
			.len = raw_master_secret_len,
		},
		.master_secret_id = PSA_KEY_ID_NULL,
		.sender_id = {
			.ptr = sender_id_buf,
			.len = sender_id_len,
		},
		.recipient_id = {
			.ptr = recipient_id_buf,
			.len = recipient_id_len,
		},
		.id_context = {
			.ptr = NULL,
			.len = 0,
		},
		.master_salt = {
			.ptr = master_salt,
			.len = master_salt_len,
		},
		.aead_alg = OSCORE_AES_CCM_16_64_128,
		.hkdf = OSCORE_SHA_256,
		.fresh_master_secret_salt = true,
	};

	ctx_teardown();

	status = oscore_context_init(&params, &oscore_ctx);
	if (status != ok) {
		LOG_ERR("oscore_context_init (raw keys) returned: %d", (int)status);
		ctx_teardown();
		return oscore_status_to_errno(status);
	}

	LOG_INF("OSCORE context ready (raw key material)");
	initialized = true;
	return 0;
}

int oscore_wrapper_protect(uint8_t *buf, size_t *len, size_t max_len)
{
	uint8_t protected_buf[OSCORE_MAX_PLAINTEXT_LEN + AUTH_TAG_LEN];
	uint32_t protected_len = sizeof(protected_buf);
	enum err status;
	int err;

	if (!buf || !len) {
		return -EINVAL;
	}

	if (*len > UINT32_MAX) {
		return -EOVERFLOW;
	}

	err = epoch_before_request(buf, *len);
	if (err) {
		return err;
	}
	if (!initialized) {
		return -EINVAL;
	}

	status = coap2oscore(buf, (uint32_t)*len, protected_buf, &protected_len,
			     &oscore_ctx);
	if (status != ok) {
		return oscore_status_to_errno(status);
	}

	if (protected_len > max_len) {
		return -ENOBUFS;
	}

	awaiting_response = is_con_request(buf, *len);
	memcpy(buf, protected_buf, protected_len);
	*len = protected_len;

	return 0;
}

void oscore_wrapper_request_not_sent(void)
{
	awaiting_response = false;
}

int oscore_wrapper_unprotect(uint8_t *buf, size_t *len, size_t max_len)
{
	uint8_t plaintext_buf[OSCORE_MAX_PLAINTEXT_LEN];
	uint32_t plaintext_len = sizeof(plaintext_buf);
	enum err status;

	if (!buf || !len || !initialized) {
		return -EINVAL;
	}

	if (*len > UINT32_MAX) {
		return -EOVERFLOW;
	}

	status = oscore2coap(buf, (uint32_t)*len, plaintext_buf, &plaintext_len,
			     &oscore_ctx);
	if (status != ok) {
		return oscore_status_to_errno(status);
	}

	if (plaintext_len > max_len) {
		return -ENOBUFS;
	}

	memcpy(buf, plaintext_buf, plaintext_len);
	*len = plaintext_len;

	epoch_after_verified(buf, *len);
	return 0;
}

int oscore_wrapper_epoch_status(struct oscore_epoch_status *out)
{
	if (out == NULL) {
		return -EINVAL;
	}
	if (!epochs_enabled) {
		return -ENOTSUP;
	}
	out->epoch = rec.epoch;
	out->confirmed = rec.confirmed;
	out->ssn = initialized ? oscore_ctx.sc.ssn : rec.ssn;
	out->misses = rec.misses;
	out->ready = initialized;
	out->rekey_requested = rekey_requested;
#if defined(OSCORE_KID_CONTEXT_OMIT)
	out->kid_context_sent = id_ctx_len > 0 && !oscore_ctx.cc.omit_kid_context;
#else
	out->kid_context_sent = id_ctx_len > 0;
#endif
	return 0;
}

int oscore_wrapper_epoch_request_bump(void)
{
	if (!epochs_enabled) {
		return -ENOTSUP;
	}
	if (rec.epoch >= rec.confirmed + CONFIG_OSCORE_CLOUD_EPOCH_WINDOW) {
		return -EALREADY;
	}
	atomic_set(&bump_forced, 1);
	return 0;
}

