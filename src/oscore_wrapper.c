/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * OSCORE wrapper for uoscore-uedhoc (hardcoded context, Phase 1).
 *
 * NCS pulls in the uoscore-uedhoc Zephyr module when CONFIG_UOSCORE=y.
 * This file must call the module's API to protect/unprotect CoAP messages.
 * The exact API and include path depend on the module version in your NCS.
 *
 * After "west update", inspect the uoscore-uedhoc module (in your west
 * workspace) for headers and symbols, e.g.:
 *   oscore_ctx_t, oscore_context_init, oscore_protect_request, oscore_unprotect_response
 * Then add the correct #include and replace the stub implementations below.
 */

#include <oscore_cloud/oscore_wrapper.h>
#include <oscore_cloud/oscore_provision.h>

#include <zephyr/kernel.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <oscore.h>
#include <psa/crypto.h>
#include <zephyr/logging/log.h>

#if defined(OSCORE_NVM_SUPPORT)
#include <inttypes.h>
#include <zephyr/settings/settings.h>
#endif

LOG_MODULE_REGISTER(oscore_wrapper, LOG_LEVEL_INF);

/*
 * OSCORE context (Phase 3: bench-provisioned, opaque keys).
 *
 * The master secret lives as a persistent, opaque PSA key in the TF-M secure
 * domain (OSCORE_MASTER_SECRET_KEY_ID); the non-secret salt and sender/
 * recipient IDs come from PSA Protected Storage. Both are written once via the
 * "oscore provision ..." shell command (see oscore_provision.c) and loaded
 * here at boot. master_secret[] below is only used by the EDHOC path, which
 * derives the secret at runtime and passes it as bytes.
 *
 * Device-side ID convention: sender_id is what this device puts on the wire
 * (= the server's Recipient ID); recipient_id identifies the server
 * (= the server's Sender ID).
 */
#ifdef CONFIG_OSCORE_USE_EDHOC
static uint8_t master_secret[16]; /* EDHOC derives the secret into this buffer */
#endif
static uint8_t master_salt[OSCORE_MASTER_SALT_MAX];
static size_t master_salt_len;
/* 8 bytes: the EDHOC path stores a C_R of up to 8 bytes here; provisioned
 * IDs are 1 byte. */
static uint8_t sender_id_buf[8];
static uint8_t recipient_id_buf[8];
static size_t sender_id_len;
static size_t recipient_id_len;
static struct context oscore_ctx;
static bool initialized;

/* Staging for a raw, caller-supplied master secret (oscore_wrapper_init_with_keys).
 * Held for the lifetime of the OSCORE context, which references it by pointer. */
static uint8_t raw_master_secret[32];
static size_t raw_master_secret_len;

static int oscore_status_to_errno(enum err status)
{
	return (status == ok) ? 0 : -(int)status;
}

/* ───────────────────── OSCORE replay-counter (SSN) persistence ──────────────
 *
 * The Phase 1 context reuses the same master secret/salt across every reboot
 * (see oscore_wrapper_init). To stop the server from rejecting our requests as
 * replays after a device reboot, the Sender Sequence Number (the OSCORE replay
 * counter) must survive reboots. RFC 8613 Appendix B.1.1 describes exactly this:
 * the SSN is written to non-volatile memory periodically and, on the next boot,
 * restored and advanced past any sequence numbers that might have been used
 * since the last successful write.
 *
 * The uoscore-uedhoc library implements that logic for us when the module is
 * built with OSCORE_NVM_SUPPORT defined (see app/CMakeLists.txt) and the OSCORE
 * context is initialized with fresh_master_secret_salt = false. It then calls
 * the two weak hooks below, which we override here:
 *   - nvm_read_ssn()  once at oscore_context_init() time (via ssn_init), and
 *   - nvm_write_ssn() from coap2oscore() every K_SSN_NVM_STORE_INTERVAL packets.
 *
 * Both hooks are backed by the Zephyr settings subsystem (NVS on the external
 * "settings_storage" partition) — the same persistence path the device shadow
 * configuration uses in main.c. The counter is stored as a single uint64_t
 * under the "oscore/ssn" key; this PoC has exactly one OSCORE context, so the
 * nvm_key (sender/recipient/id-context) is not used to select a slot.
 */
#if defined(OSCORE_NVM_SUPPORT)

#define OSCORE_CFG_SUBTREE  "oscore"
#define OSCORE_CFG_SSN      "ssn"
#define OSCORE_CFG_PATH_SSN OSCORE_CFG_SUBTREE "/" OSCORE_CFG_SSN

/* RAM mirror of the SSN stored in NVS, populated by oscore_cfg_set() when the
 * settings subsystem replays the stored "oscore/ssn" key back to us.
 */
static uint64_t ssn_mirror;
static bool ssn_mirror_loaded;

/* settings "set" handler: invoked by settings_load_subtree() for each stored
 * key under the OSCORE_CFG_SUBTREE subtree. Copies the value into ssn_mirror.
 */
static int oscore_cfg_set(const char *name, size_t len, settings_read_cb read_cb, void *cb_arg)
{
	const char *next;
	ssize_t rc;

	if (settings_name_steq(name, OSCORE_CFG_SSN, &next) && !next) {
		if (len != sizeof(ssn_mirror)) {
			LOG_ERR("Stored '%s' has size %zu, expected %zu", OSCORE_CFG_SSN, len,
				sizeof(ssn_mirror));
			return -EINVAL;
		}

		rc = read_cb(cb_arg, &ssn_mirror, sizeof(ssn_mirror));
		if (rc < 0) {
			LOG_ERR("Failed to read '%s' from NVS: %d", OSCORE_CFG_SSN, (int)rc);
			return (int)rc;
		}

		ssn_mirror_loaded = true;
		return 0;
	}

	LOG_WRN("Unknown oscore key '%s' in NVS, ignoring", name);
	return -ENOENT;
}

SETTINGS_STATIC_HANDLER_DEFINE(oscore_cfg, OSCORE_CFG_SUBTREE, NULL, oscore_cfg_set, NULL, NULL);

/* Override of the library weak symbol: persist the current SSN to NVS. Called
 * periodically by the library from coap2oscore(); a failure here is reported so
 * the library can count it against F_NVM_MAX_WRITE_FAILURE.
 */
enum err nvm_write_ssn(const struct nvm_key_t *nvm_key, uint64_t ssn)
{
	ARG_UNUSED(nvm_key);

	int err = settings_save_one(OSCORE_CFG_PATH_SSN, &ssn, sizeof(ssn));

	if (err) {
		LOG_ERR("settings_save_one('%s', %" PRIu64 ") failed: %d", OSCORE_CFG_PATH_SSN,
			ssn, err);
		return unexpected_result_from_ext_lib;
	}

	ssn_mirror = ssn;
	ssn_mirror_loaded = true;
	LOG_DBG("Persisted OSCORE SSN %" PRIu64 " to NVS", ssn);
	return ok;
}

/* Override of the library weak symbol: restore the last persisted SSN from NVS.
 * Called once at oscore_context_init() time. A first-ever boot (nothing stored
 * yet) is not an error: report SSN 0 and let the library advance from there.
 */
enum err nvm_read_ssn(const struct nvm_key_t *nvm_key, uint64_t *ssn)
{
	ARG_UNUSED(nvm_key);

	if (ssn == NULL) {
		return wrong_parameter;
	}

	/* Make sure the static handler can run even if the cloud module is the
	 * first user of the settings subsystem (settings_subsys_init is idempotent).
	 */
	int err = settings_subsys_init();

	if (err) {
		LOG_ERR("settings_subsys_init failed: %d", err);
		return unexpected_result_from_ext_lib;
	}

	ssn_mirror_loaded = false;
	err = settings_load_subtree(OSCORE_CFG_PATH_SSN);
	if (err) {
		LOG_ERR("settings_load_subtree('%s') failed: %d", OSCORE_CFG_PATH_SSN, err);
		return unexpected_result_from_ext_lib;
	}

	if (!ssn_mirror_loaded) {
		*ssn = 0;
		LOG_INF("No OSCORE SSN stored yet; starting replay counter fresh");
		return ok;
	}

	*ssn = ssn_mirror;
	LOG_INF("Restored OSCORE SSN %" PRIu64 " from NVS", *ssn);
	return ok;
}

#endif /* OSCORE_NVM_SUPPORT */

int oscore_wrapper_init(void)
{
	struct oscore_ps_material material;
	enum err status;
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
			.ptr = NULL,
			.len = 0,
		},
		.master_salt = {
			.ptr = master_salt,
			.len = master_salt_len,
		},
		.aead_alg = OSCORE_AES_CCM_16_64_128,
		.hkdf = OSCORE_SHA_256,
		/*
		 * The provisioned master secret/salt are identical on every boot,
		 * so the context is NOT fresh: the library restores the sender
		 * sequence number (replay counter) from NVM via nvm_read_ssn() and
		 * persists it via nvm_write_ssn(), letting the device reboot without
		 * a server-side counter reset. When OSCORE_NVM_SUPPORT is not
		 * compiled in (e.g. unit tests), fall back to a fresh per-boot session.
		 */
#if defined(OSCORE_NVM_SUPPORT)
		.fresh_master_secret_salt = false,
#else
		.fresh_master_secret_salt = true,
#endif
	};

	memset(&oscore_ctx, 0, sizeof(oscore_ctx));

	status = oscore_context_init(&params, &oscore_ctx);
	if (status != ok) {
		LOG_ERR("oscore_context_init returned: %d", (int)status);
		return oscore_status_to_errno(status);
	}

	LOG_INF("OSCORE context ready (opaque key 0x%08x)",
		(unsigned int)OSCORE_MASTER_SECRET_KEY_ID);
	initialized = true;
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

	memset(&oscore_ctx, 0, sizeof(oscore_ctx));

	status = oscore_context_init(&params, &oscore_ctx);
	if (status != ok) {
		LOG_ERR("oscore_context_init (raw keys) returned: %d", (int)status);
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

	if (!buf || !len || !initialized) {
		return -EINVAL;
	}

	if (*len > UINT32_MAX) {
		return -EOVERFLOW;
	}

	status = coap2oscore(buf, (uint32_t)*len, protected_buf, &protected_len,
			     &oscore_ctx);
	if (status != ok) {
		return oscore_status_to_errno(status);
	}

	if (protected_len > max_len) {
		return -ENOBUFS;
	}

	memcpy(buf, protected_buf, protected_len);
	*len = protected_len;

	return 0;
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

	return 0;
}

#ifdef CONFIG_OSCORE_USE_EDHOC

static int edhoc_sockfd = -1;

#include <edhoc.h>
#include <edhoc/suites.h>
#include "edhoc_credentials.h"

#include <zephyr/net/coap.h>
#include <zephyr/net/socket.h>

#define COAP_EDHOC_PORT 5683
#define EDHOC_COAP_BUFFER_SIZE 512
#define EDHOC_RX_MAX_MESSAGES 4
#define COAP_CONTENT_FORMAT_EDHOC_CBOR_SEQ 64
#define COAP_CONTENT_FORMAT_CID_EDHOC_CBOR_SEQ 65

struct edhoc_transport_ctx {
	int sockfd;
	struct byte_array *c_r;
	uint8_t tx_count;
};

/* EDHOC tx: build CoAP POST /.well-known/edhoc and send payload */
static enum err edhoc_tx(void *sock, struct byte_array *data)
{
	struct edhoc_transport_ctx *transport = sock;
	uint8_t coap_buf[EDHOC_COAP_BUFFER_SIZE];
	uint8_t payload_buf[EDHOC_COAP_BUFFER_SIZE];
	struct coap_packet request;
	int err;
	ssize_t sent;
	struct sockaddr_in server;
	size_t payload_len;
	size_t prefix_len;

	if ((transport == NULL) || (data == NULL)) {
		return wrong_parameter;
	}

	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_port = htons(COAP_EDHOC_PORT);
	zsock_inet_pton(AF_INET, CONFIG_OSCORE_SERVER_IP, &server.sin_addr);

	err = coap_packet_init(&request, coap_buf, sizeof(coap_buf),
			       COAP_VERSION_1, COAP_TYPE_CON, 8,
			       coap_next_token(), COAP_METHOD_POST, coap_next_id());
	if (err) {
		LOG_ERR("edhoc_tx coap_packet_init: %d", err);
		return (enum err)(-err);
	}

	err = coap_packet_append_option(&request, COAP_OPTION_URI_PATH,
				       ".well-known", 11);
	if (err) {
		LOG_ERR("edhoc_tx URI_PATH .well-known: %d", err);
		return (enum err)(-err);
	}
	err = coap_packet_append_option(&request, COAP_OPTION_URI_PATH,
				       "edhoc", 5);
	if (err) {
		LOG_ERR("edhoc_tx URI_PATH edhoc: %d", err);
		return (enum err)(-err);
	}

	err = coap_append_option_int(&request, COAP_OPTION_CONTENT_FORMAT,
				     COAP_CONTENT_FORMAT_CID_EDHOC_CBOR_SEQ);
	if (err) {
		LOG_ERR("edhoc_tx CONTENT_FORMAT: %d", err);
		return (enum err)(-err);
	}

	err = coap_append_option_int(&request, COAP_OPTION_ACCEPT,
				     COAP_CONTENT_FORMAT_EDHOC_CBOR_SEQ);
	if (err) {
		LOG_ERR("edhoc_tx ACCEPT: %d", err);
		return (enum err)(-err);
	}

	if (transport->tx_count == 0U) {
		payload_buf[0] = 0xf5; /* "true" indicates a new EDHOC session */
		prefix_len = 1U;
	} else {
		if (transport->c_r == NULL) {
			LOG_ERR("edhoc_tx missing C_R for message_3");
			return wrong_parameter;
		}
		/* Empty C_R (zero-length bstr) is valid. For EDHOC-over-CoAP
		 * correlation we must prepend the CBOR encoding of empty bstr,
		 * i.e., 0x40, not "no prefix".
		 */
		if (transport->c_r->len > 0U) {
			if (transport->c_r->ptr == NULL) {
				LOG_ERR("edhoc_tx invalid C_R buffer for message_3");
				return wrong_parameter;
			}
			memcpy(payload_buf, transport->c_r->ptr, transport->c_r->len);
			prefix_len = transport->c_r->len;
		} else {
			payload_buf[0] = 0x40;
			prefix_len = 1U;
		}
	}

	payload_len = prefix_len + data->len;
	if (payload_len > sizeof(payload_buf)) {
		LOG_ERR("edhoc_tx payload too large");
		return buffer_to_small;
	}
	memcpy(payload_buf + prefix_len, data->ptr, data->len);

	err = coap_packet_append_payload_marker(&request);
	if (err) {
		LOG_ERR("edhoc_tx append_payload_marker: %d", err);
		return (enum err)(-err);
	}
	err = coap_packet_append_payload(&request, payload_buf, payload_len);
	if (err) {
		LOG_ERR("edhoc_tx append_payload: %d", err);
		return (enum err)(-err);
	}

	sent = zsock_sendto(transport->sockfd, coap_buf, request.offset, 0,
			    (struct sockaddr *)&server, sizeof(server));
	if (sent != (ssize_t)request.offset) {
		LOG_ERR("edhoc_tx sendto: %zd", sent);
		return (enum err)(sent < 0 ? -errno : -EIO);
	}

	transport->tx_count++;
	return ok;
}

/* EDHOC rx: receive CoAP response and copy payload into data */
static enum err edhoc_rx(void *sock, struct byte_array *data)
{
	struct edhoc_transport_ctx *transport = sock;
	uint8_t recv_buf[EDHOC_COAP_BUFFER_SIZE];
	struct coap_packet response;
	ssize_t received;
	const uint8_t *payload;
	uint16_t payload_len;
	struct sockaddr_in from;
	socklen_t fromlen = sizeof(from);
	int parse_err;
	uint8_t code;
	uint8_t type;

	if ((transport == NULL) || (data == NULL)) {
		return wrong_parameter;
	}

	for (int attempt = 0; attempt < EDHOC_RX_MAX_MESSAGES; attempt++) {
		fromlen = sizeof(from);
		received = zsock_recvfrom(transport->sockfd, recv_buf,
					  sizeof(recv_buf), 0,
					  (struct sockaddr *)&from, &fromlen);
		if (received < 0) {
			LOG_ERR("edhoc_rx recvfrom: %d", -errno);
			return (enum err)(-errno);
		}

		parse_err = coap_packet_parse(&response, recv_buf, (uint16_t)received,
					      NULL, 0);
		if (parse_err) {
			LOG_ERR("edhoc_rx coap_packet_parse: %d", parse_err);
			return (enum err)(-parse_err);
		}

		type = coap_header_get_type(&response);
		code = coap_header_get_code(&response);
		payload = coap_packet_get_payload(&response, &payload_len);

		if (payload && payload_len > 0) {
			if (payload_len > data->len) {
				LOG_ERR("edhoc_rx payload too large");
				return buffer_to_small;
			}

			LOG_INF("edhoc_rx CoAP type=%u code=%u payload=%u",
				type, code, payload_len);
			memcpy(data->ptr, payload, payload_len);
			data->len = payload_len;
			return ok;
		}

		/* A confirmable request may be acknowledged first, with the
		 * payload-bearing EDHOC response arriving as a separate message.
		 */
		if ((type == COAP_TYPE_ACK) && (code == COAP_CODE_EMPTY)) {
			LOG_DBG("edhoc_rx empty ACK, waiting for separate response");
			continue;
		}

		LOG_ERR("edhoc_rx empty CoAP response: type=%u code=%u", type, code);
		return (enum err)(-EINVAL);
	}

	LOG_ERR("edhoc_rx timed out waiting for payload response");
	return (enum err)(-ETIMEDOUT);
}

static enum err edhoc_ead_process(void *params, struct byte_array *ead24)
{
	ARG_UNUSED(params);
	ARG_UNUSED(ead24);
	return ok;
}

static enum err edhoc_wait_for_msg3_response(struct edhoc_transport_ctx *transport)
{
	uint8_t recv_buf[EDHOC_COAP_BUFFER_SIZE];
	struct coap_packet response;
	struct zsock_pollfd pfd = {
		.fd = transport->sockfd,
		.events = ZSOCK_POLLIN,
	};
	struct sockaddr_in from;
	socklen_t fromlen = sizeof(from);
	ssize_t received;
	uint16_t payload_len = 0;
	const uint8_t *payload;
	uint8_t code;
	uint8_t type;
	int err;

	if (transport == NULL) {
		return wrong_parameter;
	}

	err = zsock_poll(&pfd, 1, 5000);
	if (err < 0) {
		LOG_ERR("msg3 response poll failed: %d", -errno);
		return (enum err)(-errno);
	}
	if (err == 0) {
		LOG_ERR("timed out waiting for EDHOC message_3 response");
		return (enum err)(-ETIMEDOUT);
	}

	received = zsock_recvfrom(transport->sockfd, recv_buf, sizeof(recv_buf), 0,
				  (struct sockaddr *)&from, &fromlen);
	if (received < 0) {
		LOG_ERR("msg3 response recvfrom failed: %d", -errno);
		return (enum err)(-errno);
	}

	err = coap_packet_parse(&response, recv_buf, (uint16_t)received, NULL, 0);
	if (err) {
		LOG_ERR("msg3 response parse failed: %d", err);
		return (enum err)(-err);
	}

	type = coap_header_get_type(&response);
	code = coap_header_get_code(&response);
	payload = coap_packet_get_payload(&response, &payload_len);

	LOG_INF("message_3 response CoAP type=%u code=%u payload=%u",
		type, code, payload_len);

	/* RFC 9528 over CoAP completes with a 2.04 Changed response
	 * after message_3 when no EDHOC message_4 is used.
	 */
	if ((code == COAP_RESPONSE_CODE_CHANGED) && (payload_len == 0U)) {
		return ok;
	}

	if (payload && payload_len > 0U) {
		LOG_HEXDUMP_INF(payload, payload_len, "unexpected message_3 response payload");
	}

	LOG_ERR("unexpected EDHOC message_3 response: type=%u code=%u", type, code);
	return (enum err)(-EPROTO);
}

int edhoc_oscore_init(void)
{
	int sockfd;
	uint8_t ephemeral_x[32];
	uint8_t ephemeral_g_x[64];
	/* Use a non-small-int C_I so EDHOC encodes it as bstr (not int),
	 * avoiding responder-side ambiguity when mapping C_I to OSCORE Sender ID.
	 */
	uint8_t c_i_byte = 0x41;
	uint8_t prk_out_buf[32];
	uint8_t prk_exporter_buf[32];
	uint8_t oscore_secret[16];
	uint8_t oscore_salt[8];
	uint8_t c_r_buf[8];
	size_t c_r_len;
	struct byte_array prk_out = { .ptr = prk_out_buf, .len = sizeof(prk_out_buf) };
	struct byte_array prk_exporter = { .ptr = prk_exporter_buf, .len = sizeof(prk_exporter_buf) };
	struct byte_array err_msg = { .ptr = NULL, .len = 0 };
	struct byte_array c_r_bytes = { .ptr = c_r_buf, .len = sizeof(c_r_buf) };
	struct edhoc_transport_ctx transport = { 0 };
	struct edhoc_initiator_context c_i;
	struct other_party_cred cred_r;
	struct cred_array cred_r_array = { .len = 1, .ptr = &cred_r };
	enum err status;
	uint32_t seed;
	int err;

	if (initialized) {
		return 0;
	}

	err = psa_crypto_init();
	if (err != PSA_SUCCESS) {
		LOG_ERR("edhoc_oscore_init psa_crypto_init: %d", err);
		return -EIO;
	}

	/* Secure random seed for ephemeral DH */
	if (psa_generate_random((uint8_t *)&seed, sizeof(seed)) != PSA_SUCCESS) {
		LOG_ERR("edhoc_oscore_init psa_generate_random failed");
		return -EIO;
	}

	/* Build client static DH public key g_i (x || y) */
	static uint8_t g_i_buf[64];

	memcpy(g_i_buf, edhoc_client_g_x, 32);
	memcpy(g_i_buf + 32, edhoc_client_g_y, 32);

	c_i.sock = &transport;
	c_i.method = INITIATOR_SDHK_RESPONDER_SDHK;
	c_i.suites_i.ptr = (uint8_t *)"\x02";
	c_i.suites_i.len = 1;
	c_i.ead_1.ptr = NULL;
	c_i.ead_1.len = 0;
	c_i.ead_3.ptr = NULL;
	c_i.ead_3.len = 0;
	c_i.id_cred_i.ptr = (uint8_t *)edhoc_client_id_cred;
	c_i.id_cred_i.len = EDHOC_CLIENT_ID_CRED_LEN;
	c_i.cred_i.ptr = (uint8_t *)edhoc_client_cred;
	c_i.cred_i.len = EDHOC_CLIENT_CRED_LEN;
	c_i.g_x.ptr = ephemeral_g_x;
	c_i.g_x.len = sizeof(ephemeral_g_x);
	c_i.x.ptr = ephemeral_x;
	c_i.x.len = sizeof(ephemeral_x);
	c_i.g_i.ptr = g_i_buf;
	c_i.g_i.len = sizeof(g_i_buf);
	c_i.i.ptr = (uint8_t *)edhoc_client_priv;
	c_i.i.len = EDHOC_CLIENT_PRIV_LEN;
	c_i.sk_i.ptr = NULL;
	c_i.sk_i.len = 0;
	c_i.pk_i.ptr = NULL;
	c_i.pk_i.len = 0;
	c_i.c_i.ptr = &c_i_byte;
	c_i.c_i.len = 1;
	c_i.params_ead_process = NULL;

	cred_r.id_cred.ptr = (uint8_t *)edhoc_server_id_cred;
	cred_r.id_cred.len = EDHOC_SERVER_ID_CRED_LEN;
	cred_r.cred.ptr = (uint8_t *)edhoc_server_cred;
	cred_r.cred.len = EDHOC_SERVER_CRED_LEN;
	cred_r.g.ptr = (uint8_t *)edhoc_server_g;
	cred_r.g.len = EDHOC_SERVER_G_LEN;
	cred_r.pk.ptr = NULL;
	cred_r.pk.len = 0;
	cred_r.ca.ptr = NULL;
	cred_r.ca.len = 0;
	cred_r.ca_pk.ptr = NULL;
	cred_r.ca_pk.len = 0;

	status = ephemeral_dh_key_gen(P256, seed, &c_i.x, &c_i.g_x);
	if (status != ok) {
		LOG_ERR("edhoc_oscore_init ephemeral_dh_key_gen: %d", (int)status);
		return oscore_status_to_errno(status);
	}

	sockfd = zsock_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sockfd < 0) {
		LOG_ERR("edhoc_oscore_init socket: %d", -errno);
		return -errno;
	}

	transport.sockfd = sockfd;
	transport.c_r = &c_r_bytes;
	transport.tx_count = 0U;

	status = edhoc_initiator_run_extended(&c_i, &cred_r_array, &err_msg,
					      &c_r_bytes, &prk_out,
					      edhoc_tx, edhoc_rx, edhoc_ead_process);

	if (status != ok) {
		zsock_close(sockfd);
		LOG_ERR("edhoc_oscore_init edhoc_initiator_run: %d", (int)status);
		return oscore_status_to_errno(status);
	}

	status = edhoc_wait_for_msg3_response(&transport);
	if (status != ok) {
		zsock_close(sockfd);
		LOG_ERR("edhoc_oscore_init message_3 response: %d", (int)status);
		return oscore_status_to_errno(status);
	}

	LOG_INF("EDHOC exchange OK");

	c_r_len = c_r_bytes.len;
	if (c_r_len > sizeof(c_r_buf)) {
		c_r_len = sizeof(c_r_buf);
	}

	status = prk_out2exporter(SHA_256, &prk_out, &prk_exporter);
	if (status != ok) {
		LOG_ERR("edhoc_oscore_init prk_out2exporter: %d", (int)status);
		return oscore_status_to_errno(status);
	}

	struct byte_array secret_out = { .ptr = oscore_secret, .len = sizeof(oscore_secret) };
	struct byte_array salt_out = { .ptr = oscore_salt, .len = sizeof(oscore_salt) };

	status = edhoc_exporter(SHA_256, OSCORE_MASTER_SECRET, &prk_exporter, &secret_out);
	if (status != ok) {
		LOG_ERR("edhoc_oscore_init edhoc_exporter SECRET: %d", (int)status);
		return oscore_status_to_errno(status);
	}
	status = edhoc_exporter(SHA_256, OSCORE_MASTER_SALT, &prk_exporter, &salt_out);
	if (status != ok) {
		LOG_ERR("edhoc_oscore_init edhoc_exporter SALT: %d", (int)status);
		return oscore_status_to_errno(status);
	}

	memcpy(master_secret, oscore_secret, sizeof(oscore_secret));
	memcpy(master_salt, oscore_salt, sizeof(oscore_salt));
	sender_id_buf[0] = c_i_byte;
	sender_id_len = 1;
	memcpy(recipient_id_buf, c_r_buf, c_r_len);
	recipient_id_len = c_r_len;

	memset(&oscore_ctx, 0, sizeof(oscore_ctx));
	struct oscore_init_params params = {
		.master_secret = { .ptr = master_secret, .len = sizeof(master_secret) },
		/* EDHOC derives the secret at runtime: pass it as bytes, no opaque key. */
		.master_secret_id = PSA_KEY_ID_NULL,
		.sender_id = { .ptr = sender_id_buf, .len = sender_id_len },
		.recipient_id = { .ptr = recipient_id_buf, .len = recipient_id_len },
		.id_context = { .ptr = NULL, .len = 0 },
		.master_salt = { .ptr = master_salt, .len = sizeof(master_salt) },
		.aead_alg = OSCORE_AES_CCM_16_64_128,
		.hkdf = OSCORE_SHA_256,
		.fresh_master_secret_salt = true,
	};

	status = oscore_context_init(&params, &oscore_ctx);
	if (status != ok) {
		LOG_ERR("edhoc_oscore_init oscore_context_init: %d", (int)status);
		return oscore_status_to_errno(status);
	}

	initialized = true;
	edhoc_sockfd = sockfd;
	LOG_INF("EDHOC+OSCORE context ready");
	return 0;
}

int oscore_wrapper_get_socket(void)
{
	return edhoc_sockfd;
}

#endif /* CONFIG_OSCORE_USE_EDHOC */
