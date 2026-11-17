/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * EDHOC initiator for the device (NTN security B3). See oscore_edhoc.h.
 *
 * Profile (docs/NTN-SECURITY-A5.md §2): method 3, suite 2 (AES-CCM-16-64-128,
 * SHA-256, P-256), ID_CRED_x = { 4 : kid } sent compact, CRED_x = a CCS,
 * forward flow over CoAP (RFC 9528 App. A.2), message_4 always processed.
 */

#include <oscore_cloud/oscore_edhoc.h>
#include <oscore_cloud/oscore_provision.h>
#include <oscore_cloud/cloud_client.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <psa/crypto.h>
#include <edhoc.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/settings/settings.h>
#include <zephyr/sys/atomic.h>
#ifdef CONFIG_SHELL
#include <zephyr/shell/shell.h>
#endif

LOG_MODULE_REGISTER(oscore_edhoc, LOG_LEVEL_INF);

/* Persistent PSA id of the device's static EDHOC key, next to the OSCORE
 * master secret. Like that key, it is lost on ERASE_ALL. */
#define EDHOC_STATIC_KEY_ID (OSCORE_MASTER_SECRET_KEY_ID + 1)

#define EDHOC_KID_MAX  4
#define EDHOC_CRED_MAX 160
#define P256_PUB_LEN   65

/* C_I: a one-byte CBOR int is the cheapest message_1 (A5 §7). It becomes the
 * server's OSCORE Sender ID, i.e. this device's Recipient ID. -24. */
#define EDHOC_C_I 0x37

#define COAP_CODE_CHANGED 0x44

/* ───────────────────────── Credentials in settings ────────────────────────── */

#define EDHOC_REC_VERSION 1

struct edhoc_cred_rec {
	uint8_t ver;
	uint8_t kid_len;
	uint8_t cred_len;
	uint8_t kid[EDHOC_KID_MAX];
	uint8_t cred[EDHOC_CRED_MAX];
};

static struct edhoc_cred_rec cred_i; /* this device, exactly as the server built it */
static struct edhoc_cred_rec cred_r; /* the server, pinned */
static bool creds_loaded;

static int edhoc_cfg_set(const char *key, size_t len, settings_read_cb read_cb, void *cb_arg)
{
	struct edhoc_cred_rec *dst;
	struct edhoc_cred_rec tmp;

	if (strcmp(key, "i") == 0) {
		dst = &cred_i;
	} else if (strcmp(key, "r") == 0) {
		dst = &cred_r;
	} else {
		return -ENOENT;
	}
	if (len != sizeof(tmp) || read_cb(cb_arg, &tmp, sizeof(tmp)) != sizeof(tmp) ||
	    tmp.ver != EDHOC_REC_VERSION || tmp.kid_len == 0 || tmp.kid_len > EDHOC_KID_MAX ||
	    tmp.cred_len == 0 || tmp.cred_len > EDHOC_CRED_MAX) {
		LOG_WRN("ignoring malformed edhoc/%s record", key);
		return 0;
	}
	*dst = tmp;
	return 0;
}

SETTINGS_STATIC_HANDLER_DEFINE(edhoc_cfg, "edhoc", NULL, edhoc_cfg_set, NULL, NULL);

static int creds_load(void)
{
	int err;

	if (creds_loaded) {
		return 0;
	}
	err = settings_subsys_init();
	if (err == 0) {
		err = settings_load_subtree("edhoc");
	}
	if (err) {
		LOG_ERR("loading EDHOC credentials: %d", err);
		return err;
	}
	creds_loaded = true;
	return 0;
}

/* ID_CRED_x = { 4 : h'kid' } (RFC 9528 §3.5.3.2; the uedhoc fork compacts it
 * on the wire). */
static size_t id_cred_build(const struct edhoc_cred_rec *r, uint8_t *out)
{
	out[0] = 0xa1;
	out[1] = 0x04;
	out[2] = 0x40 | r->kid_len;
	memcpy(&out[3], r->kid, r->kid_len);
	return 3U + r->kid_len;
}

/* Pull the COSE_Key x (-2) and y (-3) out of a CCS. Both are 32-byte bstrs,
 * encoded 21 58 20 / 22 58 20 in the deterministic CBOR the server writes. */
static int ccs_point(const struct edhoc_cred_rec *r, uint8_t pub[P256_PUB_LEN])
{
	static const uint8_t tag_x[] = { 0x21, 0x58, 0x20 };
	static const uint8_t tag_y[] = { 0x22, 0x58, 0x20 };
	bool have_x = false;
	bool have_y = false;

	for (size_t i = 0; i + 3 + 32 <= r->cred_len; i++) {
		if (!have_x && memcmp(&r->cred[i], tag_x, 3) == 0) {
			memcpy(&pub[1], &r->cred[i + 3], 32);
			have_x = true;
		} else if (!have_y && memcmp(&r->cred[i], tag_y, 3) == 0) {
			memcpy(&pub[33], &r->cred[i + 3], 32);
			have_y = true;
		}
	}
	pub[0] = 0x04;
	return (have_x && have_y) ? 0 : -EINVAL;
}

/* ───────────────────────── PSA keys behind uedhoc ─────────────────────────── */

/* A byte_array that stands for a PSA key handle rather than key bytes. uedhoc
 * only passes private keys on to shared_secret_derive(), so the handle never
 * has to be dereferenced elsewhere. */
#define PSA_KEY_REF_MAGIC 0x50534b52u /* "PSKR" */

struct psa_key_ref {
	uint32_t magic;
	psa_key_id_t id;
};

static bool key_ref_get(const struct byte_array *sk, psa_key_id_t *id)
{
	struct psa_key_ref ref;

	if (sk == NULL || sk->ptr == NULL || sk->len != sizeof(ref)) {
		return false;
	}
	memcpy(&ref, sk->ptr, sizeof(ref));
	if (ref.magic != PSA_KEY_REF_MAGIC) {
		return false;
	}
	*id = ref.id;
	return true;
}

/* uedhoc's point decompression (src/common/crypto_p256.c); takes x only. */
int crypto_p256_uncompress_point(const uint8_t *input, size_t ilen, uint8_t *output,
				 size_t *olen, size_t osize);

/*
 * Strong override of uedhoc's weak ECDH (src/common/crypto_wrapper.c). Same
 * contract; additionally accepts a struct psa_key_ref as sk, so the static and
 * ephemeral private keys stay inside PSA. The peer key may be x only (32 B,
 * as G_X / G_Y travel), 02/03 ‖ x (33 B, uedhoc's form of a credential key) or
 * 04 ‖ x ‖ y (65 B). ECDH on P-256 uses only the x-coordinate of the result,
 * so the sign of y does not matter.
 */
enum err shared_secret_derive(enum ecdh_alg alg, const struct byte_array *sk,
			      const struct byte_array *pk, uint8_t *shared_secret)
{
	uint8_t peer[P256_PUB_LEN];
	size_t peer_len = 0;
	psa_key_id_t key = PSA_KEY_ID_NULL;
	bool imported = false;
	size_t out_len = 0;
	psa_status_t st;

	if (alg != P256) {
		return crypto_operation_not_implemented;
	}

	if (pk->len == P256_PUB_LEN && pk->ptr[0] == 0x04) {
		memcpy(peer, pk->ptr, P256_PUB_LEN);
		peer_len = P256_PUB_LEN;
	} else if (pk->len == 33 || pk->len == 32) {
		const uint8_t *x = (pk->len == 33) ? &pk->ptr[1] : pk->ptr;

		if (crypto_p256_uncompress_point(x, 32, peer, &peer_len, sizeof(peer)) != 0) {
			return unexpected_result_from_ext_lib;
		}
	} else {
		return wrong_parameter;
	}

	if (!key_ref_get(sk, &key)) {
		/* Raw private key bytes (uedhoc's own callers, tests). */
		psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;

		psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
		psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
		psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
		psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
		st = psa_import_key(&attr, sk->ptr, sk->len, &key);
		if (st != PSA_SUCCESS) {
			return unexpected_result_from_ext_lib;
		}
		imported = true;
	}

	st = psa_raw_key_agreement(PSA_ALG_ECDH, key, peer, peer_len, shared_secret, 32,
				   &out_len);
	if (imported) {
		(void)psa_destroy_key(key);
	}
	if (st != PSA_SUCCESS || out_len != 32) {
		LOG_ERR("ECDH failed: %d", (int)st);
		return unexpected_result_from_ext_lib;
	}
	return ok;
}

static bool static_key_present(void)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t st = psa_get_key_attributes(EDHOC_STATIC_KEY_ID, &attr);

	psa_reset_key_attributes(&attr);
	return st == PSA_SUCCESS;
}

static int static_key_public(uint8_t pub[P256_PUB_LEN])
{
	size_t len = 0;
	psa_status_t st = psa_export_public_key(EDHOC_STATIC_KEY_ID, pub, P256_PUB_LEN, &len);

	return (st == PSA_SUCCESS && len == P256_PUB_LEN) ? 0 : -EIO;
}

/* P-256 ECDH key pair; persistent for the static key, volatile for the
 * ephemeral one. Neither is exportable. */
static int ecdh_key_generate(bool persistent, psa_key_id_t *id)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t st;

	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
	psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attr, 256);
	if (persistent) {
		psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_PERSISTENT);
		psa_set_key_id(&attr, EDHOC_STATIC_KEY_ID);
	} else {
		psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	}
	st = psa_generate_key(&attr, id);
	psa_reset_key_attributes(&attr);
	if (st != PSA_SUCCESS) {
		LOG_ERR("psa_generate_key(%s): %d", persistent ? "static" : "ephemeral", (int)st);
		return -EIO;
	}
	return 0;
}

/* ───────────────────────────── Transport ──────────────────────────────────── */

struct edhoc_transport {
	const struct byte_array *c_r; /* filled by uedhoc before message_3 */
	uint8_t tx_count;
	uint8_t resp[256];
	size_t resp_len;
	uint32_t bytes_up;
	uint32_t bytes_down;
};

/* message_1 goes as true ‖ message_1, message_3 as C_R ‖ message_3. The
 * response (message_2 / message_4) is kept for the rx callback. */
static enum err edhoc_tx(void *sock, struct byte_array *data)
{
	struct edhoc_transport *t = sock;
	uint8_t body[256];
	size_t n = 0;
	uint8_t code = 0;
	int err;

	if (t->tx_count == 0) {
		body[n++] = 0xf5;
	} else {
		const struct byte_array *c_r = t->c_r;

		if (c_r == NULL || c_r->len == 0 || c_r->len > 23) {
			LOG_ERR("message_3 without a usable C_R");
			return wrong_parameter;
		}
		if (c_r->len == 1 && (c_r->ptr[0] <= 0x17 ||
				      (c_r->ptr[0] >= 0x20 && c_r->ptr[0] <= 0x37))) {
			body[n++] = c_r->ptr[0];
		} else {
			body[n++] = 0x40 | (uint8_t)c_r->len;
			memcpy(&body[n], c_r->ptr, c_r->len);
			n += c_r->len;
		}
	}
	if (n + data->len > sizeof(body)) {
		return buffer_to_small;
	}
	memcpy(&body[n], data->ptr, data->len);
	n += data->len;
	t->tx_count++;

	t->resp_len = sizeof(t->resp);
	err = cloud_client_edhoc_post(body, n, &code, t->resp, &t->resp_len);
	if (err) {
		LOG_ERR("EDHOC message_%u exchange: %d", t->tx_count == 1 ? 1 : 3, err);
		return unexpected_result_from_ext_lib;
	}
	t->bytes_up += (uint32_t)n;
	t->bytes_down += (uint32_t)t->resp_len;
	if (code != COAP_CODE_CHANGED) {
		/* 4.00 / 5.00 / 5.03 carry an EDHOC error message: ERR_CODE, ERR_INFO. */
		LOG_ERR("EDHOC message_%u refused: %u.%02u (%zu B error message)",
			t->tx_count == 1 ? 1 : 3, code >> 5, code & 0x1f, t->resp_len);
		LOG_HEXDUMP_WRN(t->resp, t->resp_len, "EDHOC error");
		return error_message_received;
	}
	return ok;
}

static enum err edhoc_rx(void *sock, struct byte_array *data)
{
	struct edhoc_transport *t = sock;

	if (t->resp_len > data->len) {
		return buffer_to_small;
	}
	memcpy(data->ptr, t->resp, t->resp_len);
	data->len = (uint32_t)t->resp_len;
	return ok;
}

static enum err edhoc_ead_process(void *params, struct byte_array *ead)
{
	ARG_UNUSED(params);
	ARG_UNUSED(ead);
	return ok;
}

/* ─────────────────────────────── The run ──────────────────────────────────── */

static atomic_t run_requested;
static atomic_t run_forced;

static struct {
	int result;         /* 0 ok, else the error of the last run; 1 = never ran */
	uint32_t runs;
	uint32_t duration_ms;
	uint32_t bytes_up;
	uint32_t bytes_down;
	uint8_t c_r[8];
	uint8_t c_r_len;
	uint8_t key_fp[4];  /* SHA-256(secret ‖ salt), first 4 bytes */
} last = { .result = 1 };

static int edhoc_run(void)
{
	struct psa_key_ref static_ref = { .magic = PSA_KEY_REF_MAGIC, .id = EDHOC_STATIC_KEY_ID };
	struct psa_key_ref eph_ref = { .magic = PSA_KEY_REF_MAGIC, .id = PSA_KEY_ID_NULL };
	uint8_t g_i[P256_PUB_LEN];
	uint8_t g_r[P256_PUB_LEN];
	uint8_t g_x_full[P256_PUB_LEN];
	uint8_t id_cred_i[3 + EDHOC_KID_MAX];
	uint8_t id_cred_r[3 + EDHOC_KID_MAX];
	uint8_t suites[] = { 0x02 };
	uint8_t c_i_byte = EDHOC_C_I;
	uint8_t c_r_buf[8];
	uint8_t prk_out_buf[32];
	uint8_t prk_exp_buf[32];
	uint8_t secret[16];
	uint8_t salt[8];
	uint8_t err_buf[64];
	struct byte_array c_r = { .ptr = c_r_buf, .len = sizeof(c_r_buf) };
	struct byte_array prk_out = { .ptr = prk_out_buf, .len = sizeof(prk_out_buf) };
	struct byte_array prk_exp = { .ptr = prk_exp_buf, .len = sizeof(prk_exp_buf) };
	struct byte_array err_msg = { .ptr = err_buf, .len = sizeof(err_buf) };
	struct edhoc_transport t = { .c_r = &c_r };
	struct edhoc_initiator_context c = { 0 };
	struct other_party_cred other = { 0 };
	struct cred_array creds = { .len = 1, .ptr = &other };
	int64_t start = k_uptime_get();
	size_t len = 0;
	enum err st;
	int err;

	err = creds_load();
	if (err) {
		return err;
	}
	if (!static_key_present()) {
		LOG_ERR("no EDHOC static key (edhoc keygen)");
		return -ENODEV;
	}
	if (cred_i.cred_len == 0 || cred_r.cred_len == 0) {
		LOG_ERR("EDHOC credentials missing (edhoc cred / edhoc server)");
		return -ENOENT;
	}
	if (static_key_public(g_i) || ccs_point(&cred_r, g_r)) {
		LOG_ERR("cannot read the static public keys");
		return -EIO;
	}

	err = ecdh_key_generate(false, &eph_ref.id);
	if (err) {
		return err;
	}
	if (psa_export_public_key(eph_ref.id, g_x_full, sizeof(g_x_full), &len) != PSA_SUCCESS ||
	    len != P256_PUB_LEN) {
		err = -EIO;
		goto out;
	}

	c.c_i = (struct byte_array){ .ptr = &c_i_byte, .len = 1 };
	c.method = INITIATOR_SDHK_RESPONDER_SDHK;
	c.suites_i = (struct byte_array){ .ptr = suites, .len = sizeof(suites) };
	c.id_cred_i = (struct byte_array){ .ptr = id_cred_i,
					   .len = (uint32_t)id_cred_build(&cred_i, id_cred_i) };
	c.cred_i = (struct byte_array){ .ptr = cred_i.cred, .len = cred_i.cred_len };
	/* G_X travels as its x-coordinate only. */
	c.g_x = (struct byte_array){ .ptr = &g_x_full[1], .len = 32 };
	c.x = (struct byte_array){ .ptr = (uint8_t *)&eph_ref, .len = sizeof(eph_ref) };
	c.g_i = (struct byte_array){ .ptr = g_i, .len = sizeof(g_i) };
	c.i = (struct byte_array){ .ptr = (uint8_t *)&static_ref, .len = sizeof(static_ref) };
	c.sock = &t;

	other.id_cred = (struct byte_array){ .ptr = id_cred_r,
					     .len = (uint32_t)id_cred_build(&cred_r, id_cred_r) };
	other.cred = (struct byte_array){ .ptr = cred_r.cred, .len = cred_r.cred_len };
	other.g = (struct byte_array){ .ptr = g_r, .len = sizeof(g_r) };

	LOG_INF("EDHOC run (kid I %02x, kid R %02x, C_I %02x)", cred_i.kid[0], cred_r.kid[0],
		c_i_byte);
	st = edhoc_initiator_run_extended(&c, &creds, &err_msg, &c_r, &prk_out, edhoc_tx,
					  edhoc_rx, edhoc_ead_process);
	if (st != ok) {
		LOG_ERR("EDHOC initiator: %d (after %u message(s) sent)", (int)st, t.tx_count);
		err = -EACCES;
		goto out;
	}

	/* RFC 9528 App. A.1: OSCORE Master Secret / Salt from the exporter. */
	struct byte_array secret_out = { .ptr = secret, .len = sizeof(secret) };
	struct byte_array salt_out = { .ptr = salt, .len = sizeof(salt) };

	if (prk_out2exporter(SHA_256, &prk_out, &prk_exp) != ok ||
	    edhoc_exporter(SHA_256, OSCORE_MASTER_SECRET, &prk_exp, &secret_out) != ok ||
	    edhoc_exporter(SHA_256, OSCORE_MASTER_SALT, &prk_exp, &salt_out) != ok) {
		LOG_ERR("EDHOC exporter failed");
		err = -EIO;
		goto out;
	}

	uint8_t ks[sizeof(secret) + sizeof(salt)];
	uint8_t digest[32];

	memcpy(ks, secret, sizeof(secret));
	memcpy(&ks[sizeof(secret)], salt, sizeof(salt));
	(void)psa_hash_compute(PSA_ALG_SHA_256, ks, sizeof(ks), digest, sizeof(digest), &len);
	memcpy(last.key_fp, digest, sizeof(last.key_fp));
	memset(ks, 0, sizeof(ks));

	last.c_r_len = (uint8_t)MIN(c_r.len, sizeof(last.c_r));
	memcpy(last.c_r, c_r.ptr, last.c_r_len);
	LOG_INF("EDHOC done: message_4 verified, C_R %02x (%u B), OSCORE key fp %02x%02x%02x%02x, "
		"%u B up / %u B down, %lld ms",
		last.c_r[0], last.c_r_len, last.key_fp[0], last.key_fp[1], last.key_fp[2],
		last.key_fp[3], t.bytes_up, t.bytes_down, k_uptime_get() - start);
	/* B4 stores the context as pending and switches to it; until then the
	 * keys are dropped and the PSK context stays in use. */
	err = 0;

out:
	(void)psa_destroy_key(eph_ref.id);
	memset(secret, 0, sizeof(secret));
	memset(salt, 0, sizeof(salt));
	memset(prk_out_buf, 0, sizeof(prk_out_buf));
	memset(prk_exp_buf, 0, sizeof(prk_exp_buf));
	last.result = err;
	last.runs++;
	last.duration_ms = (uint32_t)(k_uptime_get() - start);
	last.bytes_up = t.bytes_up;
	last.bytes_down = t.bytes_down;
	return err;
}

void oscore_edhoc_service(void)
{
	if (!atomic_cas(&run_requested, 1, 0)) {
		return;
	}
	if (!atomic_cas(&run_forced, 1, 0) && cloud_client_transport() == CLOUD_TRANSPORT_NTN) {
		LOG_WRN("EDHOC run skipped: bearer is NTN (edhoc run force overrides)");
		return;
	}
	(void)edhoc_run();
}

int oscore_edhoc_request_run(bool force)
{
	atomic_set(&run_forced, force ? 1 : 0);
	atomic_set(&run_requested, 1);
	return 0;
}

/* ─────────────────────────────── Shell ────────────────────────────────────── */

#ifdef CONFIG_SHELL

static int hexval(char c)
{
	if (c >= '0' && c <= '9') {
		return c - '0';
	}
	c |= 0x20;
	return (c >= 'a' && c <= 'f') ? c - 'a' + 10 : -1;
}

static int hex2bin_str(const char *hex, uint8_t *out, size_t cap, size_t *out_len)
{
	size_t n = strlen(hex);

	if (n == 0 || (n % 2) != 0 || n / 2 > cap) {
		return -EINVAL;
	}
	for (size_t i = 0; i < n / 2; i++) {
		int hi = hexval(hex[2 * i]);
		int lo = hexval(hex[2 * i + 1]);

		if (hi < 0 || lo < 0) {
			return -EINVAL;
		}
		out[i] = (uint8_t)((hi << 4) | lo);
	}
	*out_len = n / 2;
	return 0;
}

static void print_hex(const struct shell *sh, const char *label, const uint8_t *b, size_t n)
{
	char line[2 * EDHOC_CRED_MAX + 1];
	size_t i;

	for (i = 0; i < n && i < EDHOC_CRED_MAX; i++) {
		static const char d[] = "0123456789abcdef";

		line[2 * i] = d[b[i] >> 4];
		line[2 * i + 1] = d[b[i] & 0xf];
	}
	line[2 * i] = '\0';
	shell_print(sh, "%s%s", label, line);
}

static int cmd_status(const struct shell *sh, size_t argc, char **argv)
{
	uint8_t pub[P256_PUB_LEN];

	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	(void)creds_load();
	if (static_key_present() && static_key_public(pub) == 0) {
		print_hex(sh, "static key: ", pub, sizeof(pub));
	} else {
		shell_print(sh, "static key: none (edhoc keygen)");
	}
	if (cred_i.cred_len) {
		shell_print(sh, "CRED_I: kid %02x, %u B", cred_i.kid[0], cred_i.cred_len);
	} else {
		shell_print(sh, "CRED_I: none (edhoc cred <kid> <cred>)");
	}
	if (cred_r.cred_len) {
		shell_print(sh, "CRED_R: kid %02x, %u B", cred_r.kid[0], cred_r.cred_len);
	} else {
		shell_print(sh, "CRED_R: none (edhoc server <kid> <cred>)");
	}
	if (last.result == 1) {
		shell_print(sh, "last run: never");
	} else {
		shell_print(sh, "last run: %d after %u ms (%u B up, %u B down), runs %u%s",
			    last.result, last.duration_ms, last.bytes_up, last.bytes_down,
			    last.runs, last.result == 0 ? "" : " (see log)");
		if (last.c_r_len) {
			shell_print(sh, "last success: C_R %02x, key fp %02x%02x%02x%02x",
				    last.c_r[0], last.key_fp[0], last.key_fp[1], last.key_fp[2],
				    last.key_fp[3]);
		}
	}
	return 0;
}

static int cmd_keygen(const struct shell *sh, size_t argc, char **argv)
{
	uint8_t pub[P256_PUB_LEN];
	psa_key_id_t id;

	if (static_key_present()) {
		if (argc < 2 || strcmp(argv[1], "replace") != 0) {
			shell_error(sh, "a static key exists; 'edhoc keygen replace' makes a new "
					"one (the server credential must then be re-registered)");
			return -EEXIST;
		}
		(void)psa_destroy_key(EDHOC_STATIC_KEY_ID);
	}
	if (ecdh_key_generate(true, &id) || static_key_public(pub)) {
		shell_error(sh, "key generation failed");
		return -EIO;
	}
	print_hex(sh, "edhoc_pub: ", pub, sizeof(pub));
	return 0;
}

static int store_cred(const struct shell *sh, const char *which, struct edhoc_cred_rec *dst,
		      const char *kid_hex, const char *cred_hex)
{
	struct edhoc_cred_rec r = { .ver = EDHOC_REC_VERSION };
	size_t kid_len;
	size_t cred_len;
	char key[8];
	int err;

	if (hex2bin_str(kid_hex, r.kid, sizeof(r.kid), &kid_len) ||
	    hex2bin_str(cred_hex, r.cred, sizeof(r.cred), &cred_len)) {
		shell_error(sh, "kid (<= %d B) and cred (<= %d B) must be hex", EDHOC_KID_MAX,
			    EDHOC_CRED_MAX);
		return -EINVAL;
	}
	r.kid_len = (uint8_t)kid_len;
	r.cred_len = (uint8_t)cred_len;

	uint8_t pt[P256_PUB_LEN];

	if (ccs_point(&r, pt)) {
		shell_error(sh, "cred is not a CCS with a P-256 COSE_Key");
		return -EINVAL;
	}
	if (dst == &cred_i) {
		uint8_t pub[P256_PUB_LEN];

		if (!static_key_present() || static_key_public(pub) ||
		    memcmp(pub, pt, sizeof(pub)) != 0) {
			shell_error(sh, "CRED_I does not hold this device's static key");
			return -EINVAL;
		}
	}
	snprintf(key, sizeof(key), "edhoc/%s", which);
	err = settings_save_one(key, &r, sizeof(r));
	if (err) {
		shell_error(sh, "settings_save_one(%s): %d", key, err);
		return err;
	}
	*dst = r;
	shell_print(sh, "stored %s: kid %02x, %u B", key, r.kid[0], r.cred_len);
	return 0;
}

static int cmd_cred(const struct shell *sh, size_t argc, char **argv)
{
	(void)creds_load();
	return store_cred(sh, "i", &cred_i, argv[1], argv[2]);
}

static int cmd_server(const struct shell *sh, size_t argc, char **argv)
{
	(void)creds_load();
	return store_cred(sh, "r", &cred_r, argv[1], argv[2]);
}

static int cmd_run(const struct shell *sh, size_t argc, char **argv)
{
	bool force = argc > 1 && strcmp(argv[1], "force") == 0;

	oscore_edhoc_request_run(force);
	shell_print(sh, "EDHOC run queued for the next cloud request%s",
		    force ? " (forced)" : "");
	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(
	edhoc_cmds,
	SHELL_CMD_ARG(keygen, NULL, "Create the static P-256 key: [replace]", cmd_keygen, 1, 1),
	SHELL_CMD_ARG(cred, NULL, "Store CRED_I: <edhoc_kid> <edhoc_cred> (hex)", cmd_cred, 3,
		      0),
	SHELL_CMD_ARG(server, NULL, "Pin CRED_R: <kid> <cred> (hex)", cmd_server, 3, 0),
	SHELL_CMD_ARG(run, NULL, "Run EDHOC on the next cloud request: [force]", cmd_run, 1, 1),
	SHELL_SUBCMD_SET_END);

SHELL_CMD_REGISTER(edhoc, &edhoc_cmds, "EDHOC (method 3, suite 2) credentials and runs",
		   cmd_status);

#endif /* CONFIG_SHELL */
