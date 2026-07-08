/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * OSCORE bench provisioning (Phase 3): a shell command that loads device
 * identity + OSCORE key material once, plus the loaders used by
 * oscore_wrapper_init() at boot.
 *
 * The master secret is imported as a persistent, opaque PSA derive key in the
 * TF-M secure domain (id OSCORE_MASTER_SECRET_KEY_ID). The non-secret salt and
 * sender/recipient IDs go to PSA Protected Storage. The raw master secret only
 * transits a volatile staging buffer in NS RAM during this one-time step, which
 * is wiped immediately after import.
 */

#include <oscore_cloud/oscore_provision.h>

#include <errno.h>
#include <string.h>

#include <psa/crypto.h>
#include <psa/protected_storage.h>

#include <zephyr/logging/log.h>
#include <zephyr/sys/barrier.h>

#ifdef CONFIG_SHELL
#include <zephyr/shell/shell.h>
#endif

LOG_MODULE_REGISTER(oscore_provision, LOG_LEVEL_INF);

/* Protected Storage UID for the OSCORE material record ("OSCORE" + version). */
#define OSCORE_PS_UID_MATERIAL ((psa_storage_uid_t)0x4f53434f52450001ULL)

bool oscore_provision_has_key(void)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t status = psa_get_key_attributes(OSCORE_MASTER_SECRET_KEY_ID,
						     &attr);

	psa_reset_key_attributes(&attr);
	return status == PSA_SUCCESS;
}

int oscore_provision_load(struct oscore_ps_material *out)
{
	size_t got = 0;
	psa_status_t status;

	if (out == NULL) {
		return -EINVAL;
	}

	status = psa_ps_get(OSCORE_PS_UID_MATERIAL, 0, sizeof(*out), out, &got);
	if (status == PSA_ERROR_DOES_NOT_EXIST) {
		return -ENOENT;
	}
	if (status != PSA_SUCCESS || got != sizeof(*out)) {
		LOG_ERR("psa_ps_get(material) failed: status=%d len=%zu",
			(int)status, got);
		return -EIO;
	}
	if (out->salt_len > OSCORE_MASTER_SALT_MAX ||
	    out->sender_id_len > OSCORE_ID_MAX ||
	    out->recipient_id_len > OSCORE_ID_MAX) {
		LOG_ERR("Provisioned material has invalid lengths");
		return -EINVAL;
	}
	return 0;
}

#ifdef CONFIG_SHELL

static int hex_nibble(char c)
{
	if ((c >= '0') && (c <= '9')) {
		return c - '0';
	}
	if ((c >= 'a') && (c <= 'f')) {
		return 10 + (c - 'a');
	}
	if ((c >= 'A') && (c <= 'F')) {
		return 10 + (c - 'A');
	}
	return -1;
}

/* Decode an even-length hex string into up to out_cap bytes. */
static int hex_decode(const char *hex, uint8_t *out, size_t out_cap,
		      size_t *out_len)
{
	size_t hlen = strlen(hex);
	size_t blen = hlen / 2;

	if ((hlen % 2) != 0 || blen > out_cap) {
		return -EINVAL;
	}
	for (size_t i = 0; i < blen; i++) {
		int hi = hex_nibble(hex[2 * i]);
		int lo = hex_nibble(hex[(2 * i) + 1]);

		if (hi < 0 || lo < 0) {
			return -EINVAL;
		}
		out[i] = (uint8_t)((hi << 4) | lo);
	}
	*out_len = blen;
	return 0;
}

/* Import the master secret as a persistent, opaque PSA derive key at the fixed
 * id, replacing any previously provisioned key (re-provisioning). */
static int store_master_secret(const uint8_t *secret, size_t len)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t kid;
	psa_status_t status;

	/* Best-effort drop of any existing key at this id (re-provisioning). On a
	 * first-ever provisioning there is nothing to destroy; if a key does exist
	 * and the delete genuinely fails, the import below reports ALREADY_EXISTS. */
	(void)psa_destroy_key(OSCORE_MASTER_SECRET_KEY_ID);

	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attr, PSA_ALG_HKDF(PSA_ALG_SHA_256));
	psa_set_key_type(&attr, PSA_KEY_TYPE_DERIVE);
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_PERSISTENT);
	psa_set_key_id(&attr, OSCORE_MASTER_SECRET_KEY_ID);

	status = psa_import_key(&attr, secret, len, &kid);
	if (status != PSA_SUCCESS) {
		LOG_ERR("psa_import_key(master secret) failed: %d", (int)status);
		return -EIO;
	}

	/* Evict the volatile copy from the crypto cache; the key lives in ITS. */
	(void)psa_purge_key(OSCORE_MASTER_SECRET_KEY_ID);
	return 0;
}

static int store_material(const struct oscore_ps_material *m)
{
	psa_status_t status = psa_ps_set(OSCORE_PS_UID_MATERIAL, sizeof(*m), m,
					 PSA_STORAGE_FLAG_NONE);

	if (status != PSA_SUCCESS) {
		LOG_ERR("psa_ps_set(material) failed: %d", (int)status);
		return -EIO;
	}
	return 0;
}

static int cmd_oscore_provision(const struct shell *sh, size_t argc,
				char **argv)
{
	/* Single staging buffer for the secret; wiped via a volatile pointer on
	 * every exit path so the zeroization is never optimised away and no
	 * plaintext copy lingers in NS RAM after this one-time step. */
	static uint8_t secret_staging[OSCORE_MASTER_SECRET_LEN];
	struct oscore_ps_material m = { 0 };
	size_t secret_len = 0;
	size_t salt_len = 0;
	size_t sid_len = 0;
	size_t rid_len = 0;
	psa_status_t psa_ret;
	int err = 0;

	ARG_UNUSED(argc);

	psa_ret = psa_crypto_init();
	if (psa_ret != PSA_SUCCESS) {
		shell_error(sh, "psa_crypto_init failed: %d", (int)psa_ret);
		return -EIO;
	}

	/* Parse the non-secret arguments first; on a bad arg we return before any
	 * secret material is placed in RAM. */
	if (hex_decode(argv[2], m.salt, sizeof(m.salt), &salt_len) != 0 ||
	    salt_len == 0) {
		shell_error(sh, "salt must be 1..%d hex bytes",
			    OSCORE_MASTER_SALT_MAX);
		return -EINVAL;
	}
	m.salt_len = (uint8_t)salt_len;
	if (hex_decode(argv[3], m.sender_id, sizeof(m.sender_id), &sid_len) != 0 ||
	    sid_len == 0) {
		shell_error(sh, "sender_id must be 1..%d hex bytes", OSCORE_ID_MAX);
		return -EINVAL;
	}
	m.sender_id_len = (uint8_t)sid_len;
	if (hex_decode(argv[4], m.recipient_id, sizeof(m.recipient_id), &rid_len) != 0 ||
	    rid_len == 0) {
		shell_error(sh, "recipient_id must be 1..%d hex bytes", OSCORE_ID_MAX);
		return -EINVAL;
	}
	m.recipient_id_len = (uint8_t)rid_len;

	if (hex_decode(argv[1], secret_staging, sizeof(secret_staging),
		       &secret_len) != 0 ||
	    secret_len != OSCORE_MASTER_SECRET_LEN) {
		shell_error(sh, "secret must be %d hex bytes",
			    OSCORE_MASTER_SECRET_LEN);
		err = -EINVAL;
		goto wipe;
	}

	err = store_master_secret(secret_staging, secret_len);
	if (err != 0) {
		shell_error(sh, "Failed to store master secret: %d", err);
		goto wipe;
	}

	err = store_material(&m);
	if (err != 0) {
		shell_error(sh, "Failed to store salt/IDs: %d", err);
		goto wipe;
	}

	shell_print(sh,
		    "OSCORE provisioned: secret -> PSA key 0x%08x, salt/IDs -> Protected Storage.",
		    (unsigned int)OSCORE_MASTER_SECRET_KEY_ID);
	shell_print(sh, "Reboot to start OSCORE with the new context.");

wipe:
	{
		volatile uint8_t *p = secret_staging;

		for (size_t i = 0; i < sizeof(secret_staging); i++) {
			p[i] = 0;
		}
	}
	barrier_dmem_fence_full();
	return err;
}

/* Opacity check: the master-secret key is imported without PSA_KEY_USAGE_EXPORT,
 * so psa_export_key() must be refused. A success here would mean the secret is
 * readable from NS — i.e. the opacity guarantee is broken. */
static int cmd_oscore_verify(const struct shell *sh, size_t argc, char **argv)
{
	uint8_t buf[OSCORE_MASTER_SECRET_LEN];
	size_t out_len = 0;
	psa_status_t st;
	int ret;

	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	(void)psa_crypto_init();

	if (!oscore_provision_has_key()) {
		shell_warn(sh, "No master-secret key at 0x%08x (device not provisioned).",
			   (unsigned int)OSCORE_MASTER_SECRET_KEY_ID);
		return -ENOENT;
	}

	st = psa_export_key(OSCORE_MASTER_SECRET_KEY_ID, buf, sizeof(buf), &out_len);
	if (st == PSA_SUCCESS) {
		shell_error(sh,
			    "OPACITY FAILURE: master secret exported (%zu bytes) - key is readable from NS!",
			    out_len);
		ret = -EPERM;
	} else {
		shell_print(sh,
			    "Opacity OK: psa_export_key(0x%08x) refused (status %d); master secret is non-exportable.",
			    (unsigned int)OSCORE_MASTER_SECRET_KEY_ID, (int)st);
		ret = 0;
	}

	/* Wipe the buffer regardless (it holds the secret only on the failure path). */
	{
		volatile uint8_t *p = buf;

		for (size_t i = 0; i < sizeof(buf); i++) {
			p[i] = 0;
		}
	}
	barrier_dmem_fence_full();
	return ret;
}

SHELL_STATIC_SUBCMD_SET_CREATE(
	oscore_subcmds,
	SHELL_CMD_ARG(provision, NULL,
		      "Provision OSCORE identity + keys (then reboot):\n"
		      "  oscore provision <secret_hex(16B)> <salt_hex> <sender_id_hex> <recipient_id_hex>",
		      cmd_oscore_provision, 5, 0),
	SHELL_CMD(verify, NULL,
		  "Prove the provisioned master secret is non-exportable (opacity check)",
		  cmd_oscore_verify),
	SHELL_SUBCMD_SET_END);

SHELL_CMD_REGISTER(oscore, &oscore_subcmds, "OSCORE provisioning", NULL);

#endif /* CONFIG_SHELL */
