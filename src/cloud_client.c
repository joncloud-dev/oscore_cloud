/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Cloud client for the OSCORE platform (ATT integration).
 * Network/LTE is owned by the ATT network module; init only sets up OSCORE + UDP.
 */

#include <oscore_cloud/cloud_client.h>
#include <oscore_cloud/cbor.h>
#include <oscore_cloud/oscore_wrapper.h>
#include <oscore_cloud/cloud_config.h>
#if defined(CONFIG_OSCORE_CLOUD_EDHOC)
#include <oscore_cloud/oscore_edhoc.h>
#endif

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/socket.h>
#include <zephyr/random/random.h>
#include <zephyr/sys/byteorder.h>
#if defined(CONFIG_LTE_LINK_CONTROL)
#include <modem/lte_lc.h>
#endif
#if defined(CONFIG_SHELL)
#include <zephyr/shell/shell.h>
#endif
#if defined(CONFIG_OSCORE_CLOUD_RAI)
#include <zephyr/net/socket_ncs.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

LOG_MODULE_REGISTER(cloud_client, LOG_LEVEL_INF);

#ifndef COAP_TYPE_NON
#define COAP_TYPE_NON 1
#endif
#ifndef COAP_CONTENT_FORMAT_APPLICATION_CBOR
#define COAP_CONTENT_FORMAT_APPLICATION_CBOR 60
#endif

#ifndef CONFIG_OSCORE_SERVER_IP
#define CONFIG_OSCORE_SERVER_IP "192.168.1.100"
#endif

#define COAP_PORT     5683
#define COAP_BUF_SIZE 2048
#define RECV_BUF_SIZE 2048

#ifndef COAP_OPTION_BLOCK2
#define COAP_OPTION_BLOCK2 23
#endif
#ifndef COAP_OPTION_BLOCK1
#define COAP_OPTION_BLOCK1 27
#endif

#define ENVELOPE_FLAG_SHADOW_DELTA 0x01
#define ENVELOPE_FLAG_FOTA_JOB     0x02

#define SHADOW_KEY_VERSION 1
#define SHADOW_KEY_DIFF    2
#define ENVELOPE_KEY_FLAGS 1
#define ENVELOPE_KEY_DELTA 2

static uint8_t coap_buf[COAP_BUF_SIZE];
static uint8_t recv_buf[RECV_BUF_SIZE];
static int g_sock = -1;

static struct cloud_shadow_delta g_inline_delta;

/* ------------------------------------------------------------------------
 * Runtime configuration + library hooks (cloud_config.h)
 * ------------------------------------------------------------------------ */

static struct oscore_cloud_config g_cfg = {
	.server_ip = CONFIG_OSCORE_SERVER_IP,
	.server_port = COAP_PORT,
};

static void (*g_wdt_feed)(void);

int oscore_cloud_init(const struct oscore_cloud_config *cfg)
{
	if (cfg == NULL) {
		/* Keep the compile-time defaults. */
		return 0;
	}

	g_cfg = *cfg;
	if (g_cfg.server_ip == NULL) {
		g_cfg.server_ip = CONFIG_OSCORE_SERVER_IP;
	}
	if (g_cfg.server_port == 0) {
		g_cfg.server_port = COAP_PORT;
	}
	return 0;
}

const struct oscore_cloud_config *oscore_cloud_get_config(void)
{
	return &g_cfg;
}

void oscore_cloud_set_watchdog_feed(void (*feed)(void))
{
	g_wdt_feed = feed;
}

void oscore_cloud_feed_wdt(void)
{
	if (g_wdt_feed != NULL) {
		g_wdt_feed();
	}
}

static void server_addr(struct sockaddr_in *server)
{
	memset(server, 0, sizeof(*server));
	server->sin_family = AF_INET;
	server->sin_port = htons(g_cfg.server_port);
	zsock_inet_pton(AF_INET, g_cfg.server_ip, &server->sin_addr);
}

static void rai_reset(void);
static void bearer_refresh(void);

int cloud_client_init(void)
{
	int err;

	if (g_cfg.master_secret != NULL) {
		/* Self-contained app: initialise OSCORE from raw key material. */
		err = oscore_wrapper_init_with_keys(g_cfg.master_secret, g_cfg.master_secret_len,
						    g_cfg.master_salt, g_cfg.master_salt_len,
						    g_cfg.sender_id, g_cfg.sender_id_len,
						    g_cfg.recipient_id, g_cfg.recipient_id_len);
	} else {
		/* Default: PSA-provisioned opaque key + Protected Storage salt/IDs. */
		err = oscore_wrapper_init();
	}
	if (err) {
		LOG_ERR("OSCORE context init failed: %d", err);
		return err;
	}

	/* Close any socket left over from a previous connection. Without this each
	 * reconnect (e.g. after repeated coverage loss) opens a new UDP socket and
	 * orphans the old fd, eventually exhausting the modem's socket descriptors
	 * and wedging the cloud connection permanently. */
	if (g_sock >= 0) {
		(void)zsock_close(g_sock);
		g_sock = -1;
	}

	g_sock = zsock_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (g_sock < 0) {
		LOG_ERR("socket: %d", -errno);
		return -errno;
	}

	/* Connect the UDP socket to the (fixed) server so every request is a plain
	 * zsock_send(). connect() on a datagram socket only sets the default peer:
	 * no packet is sent. It also makes the modem drop datagrams from any other
	 * source, and it is required for SO_RAI = RAI_NO_DATA (explicit release
	 * without sending), which cloud_client_rai_release() uses. */
	struct sockaddr_in server;

	server_addr(&server);
	if (zsock_connect(g_sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
		err = -errno;
		LOG_ERR("connect %s:%u: %d", g_cfg.server_ip, g_cfg.server_port, err);
		(void)zsock_close(g_sock);
		g_sock = -1;
		return err;
	}

	/* A hint queued for the previous socket must not leak onto the new one. */
	rai_reset();

	bearer_refresh();

	return 0;
}

void cloud_client_deinit(void)
{
	if (g_sock >= 0) {
		(void)zsock_close(g_sock);
		g_sock = -1;
	}
	rai_reset();
}

/* ------------------------------------------------------------------------
 * Release Assistance Indication (SO_RAI)
 *
 * The caller (the cloud module) knows whether more traffic follows a send, so
 * it queues a one-shot hint with cloud_client_rai_next(); the next request send
 * consumes it and the hint resets to CLOUD_RAI_NONE (no setsockopt at all).
 * Block1/Block2 transfers apply RAI_ONGOING to every block request instead, so
 * a multi-block transfer never releases mid-way; the library never releases at
 * the end of a transfer, the caller decides (cloud_client_rai_release()).
 *
 * RAI is advisory: a setsockopt failure is logged once and never fails a send.
 * Everything compiles to no-ops when CONFIG_OSCORE_CLOUD_RAI=n.
 * ------------------------------------------------------------------------ */

#if defined(CONFIG_OSCORE_CLOUD_RAI)
static enum cloud_rai_hint g_rai_next = CLOUD_RAI_NONE;
static bool g_rai_warned;

static const char *rai_name(int so_rai)
{
	switch (so_rai) {
	case RAI_NO_DATA:
		return "NO_DATA";
	case RAI_LAST:
		return "LAST";
	case RAI_ONE_RESP:
		return "ONE_RESP";
	case RAI_ONGOING:
		return "ONGOING";
	default:
		return "?";
	}
}

static int rai_setsockopt(int so_rai)
{
	if (g_sock < 0) {
		return -ENOTCONN;
	}
	if (zsock_setsockopt(g_sock, SOL_SOCKET, SO_RAI, &so_rai, sizeof(so_rai)) < 0) {
		int err = -errno;

		if (!g_rai_warned) {
			LOG_WRN("setsockopt(SO_RAI, %s): %d (RAI hints ignored)",
				rai_name(so_rai), err);
			g_rai_warned = true;
		}
		return err;
	}
	LOG_DBG("SO_RAI %s", rai_name(so_rai));
	return 0;
}

static int rai_hint_to_so(enum cloud_rai_hint hint)
{
	switch (hint) {
	case CLOUD_RAI_LAST:
		return RAI_LAST;
	case CLOUD_RAI_ONE_RESP:
		return RAI_ONE_RESP;
	case CLOUD_RAI_ONGOING:
		return RAI_ONGOING;
	case CLOUD_RAI_NONE:
	default:
		return 0;
	}
}

static void rai_reset(void)
{
	g_rai_next = CLOUD_RAI_NONE;
}

/* Consume the queued one-shot hint right before a request send. */
static void apply_rai_hint(void)
{
	enum cloud_rai_hint hint = g_rai_next;

	g_rai_next = CLOUD_RAI_NONE;
	if (hint != CLOUD_RAI_NONE) {
		(void)rai_setsockopt(rai_hint_to_so(hint));
	}
}

/* Before each Block1/Block2 block request: keep the link up. A pending one-shot
 * hint is dropped, since a bulk transfer always continues past this send. */
static void apply_rai_ongoing(void)
{
	g_rai_next = CLOUD_RAI_NONE;
	(void)rai_setsockopt(RAI_ONGOING);
}

void cloud_client_rai_next(enum cloud_rai_hint hint)
{
	g_rai_next = hint;
}

static inline enum cloud_rai_hint rai_peek(void)
{
	return g_rai_next;
}

int cloud_client_rai_release(void)
{
	g_rai_next = CLOUD_RAI_NONE;
	return rai_setsockopt(RAI_NO_DATA);
}
#else
static void rai_reset(void)
{
}

static void apply_rai_hint(void)
{
}

static void apply_rai_ongoing(void)
{
}

void cloud_client_rai_next(enum cloud_rai_hint hint)
{
	ARG_UNUSED(hint);
}

static inline enum cloud_rai_hint rai_peek(void)
{
	return CLOUD_RAI_NONE;
}

int cloud_client_rai_release(void)
{
	return 0;
}
#endif /* CONFIG_OSCORE_CLOUD_RAI */

/* Send one protected request on the connected socket. */
static int sock_send(const char *what, const char *path, uint32_t block_num, size_t len)
{
	ssize_t sent = zsock_send(g_sock, coap_buf, len, 0);

	if (sent != (ssize_t)len) {
		LOG_ERR("%s send %s blk %u: %zd (errno %d)", what, path, block_num, sent,
			sent < 0 ? errno : 0);
		/* Never reached the modem: its missing response is no epoch miss. */
		oscore_wrapper_request_not_sent();
		return -EIO;
	}
	return 0;
}

static int append_uri_path(struct coap_packet *req, const char *path)
{
	const char *seg = path;
	int err;

	while (*seg) {
		const char *slash = strchr(seg, '/');
		size_t seglen = slash ? (size_t)(slash - seg) : strlen(seg);

		if (seglen > 0) {
			err = coap_packet_append_option(req, COAP_OPTION_URI_PATH,
							(const uint8_t *)seg, seglen);
			if (err) {
				return err;
			}
		}
		if (!slash) {
			break;
		}
		seg = slash + 1;
	}
	return 0;
}

/* Discard any datagrams already queued on the socket before issuing a request.
 *
 * OSCORE matches each response to its request by CoAP token (uoscore's
 * "interactions" table). The server only ever speaks in response to us, so any
 * datagram sitting in the RX queue when we are about to send is a stale or
 * duplicated response to an earlier request. If we don't drop it, the next
 * recvfrom() returns that old datagram instead of our real response: its token
 * no longer matches the current interaction (oscore_interaction_not_found,
 * -222) or its nonce doesn't match (decrypt failure, -3). Worse, the queue then
 * stays permanently offset by one, so every later exchange — telemetry, shadow,
 * FOTA — fails the same way and never recovers (observed after a long Block2
 * download hit one duplicate around block 622). Draining before each send keeps
 * every request/response self-contained and lets a wedged context self-heal on
 * the very next request.
 */
static void flush_rx(void)
{
	int count = 0;

	/* poll(timeout=0) to test readability rather than MSG_DONTWAIT: the nRF91
	 * offloaded socket mishandles non-blocking recv flags the same way it does
	 * SO_RCVTIMEO (see wait_readable()). When poll reports data the
	 * recvfrom returns immediately. */
	while (count < 16) {
		struct zsock_pollfd pfd = { .fd = g_sock, .events = ZSOCK_POLLIN };
		int pr = zsock_poll(&pfd, 1, 0);

		if (pr <= 0 || !(pfd.revents & ZSOCK_POLLIN)) {
			break;
		}
		if (zsock_recv(g_sock, recv_buf, sizeof(recv_buf), 0) < 0) {
			break;
		}
		count++;
	}
	if (count > 0) {
		LOG_WRN("flushed %d stale datagram(s) before request", count);
	}
}

/* ------------------------------------------------------------------------
 * Bearer (TN / NTN) and CoAP transmission parameters (NTN security B2)
 *
 * The bearer comes from the modem's LTE mode (+CEREG AcT 14 = NTN NB-IoT) and
 * selects one of two RFC 7252 transmission profiles. A shell override forces
 * either profile, which is how the NTN timings are exercised without a
 * satellite link.
 * ------------------------------------------------------------------------ */

enum bearer_override {
	BEARER_AUTO = 0,
	BEARER_FORCE_TN,
	BEARER_FORCE_NTN,
};

static enum bearer_override g_bearer_override;
static enum cloud_transport g_bearer_detected = CLOUD_TRANSPORT_TN;

static void log_bearer(void);

struct xmit_profile {
	uint32_t ack_timeout_ms;
	uint8_t max_retransmit;
};

static const struct xmit_profile xmit_tn = {
	.ack_timeout_ms = CONFIG_OSCORE_CLOUD_COAP_ACK_TIMEOUT_MS,
	.max_retransmit = CONFIG_OSCORE_CLOUD_COAP_MAX_RETRANSMIT,
};

static const struct xmit_profile xmit_ntn = {
	.ack_timeout_ms = CONFIG_OSCORE_CLOUD_COAP_NTN_ACK_TIMEOUT_MS,
	.max_retransmit = CONFIG_OSCORE_CLOUD_COAP_NTN_MAX_RETRANSMIT,
};

/* Counters for the shell and for the B2 measurements. */
static struct {
	uint32_t requests;     /* first transmissions (CON and NON) */
	uint32_t retransmits;  /* identical-byte retransmissions */
	uint32_t timeouts;     /* exchanges that ran out of retransmissions */
	uint32_t stale;        /* datagrams dropped for a foreign token/MID */
	uint32_t empty_acks;   /* separate-response ACKs seen */
	uint32_t con_acked;    /* CON responses we acknowledged */
	uint32_t last_rtt_ms;  /* first send to verified response */
	uint32_t max_rtt_ms;
} g_xstats;

#if defined(CONFIG_LTE_LINK_CONTROL)
static enum cloud_transport transport_from_lte_mode(enum lte_lc_lte_mode mode)
{
	return mode == LTE_LC_LTE_MODE_NTN_NBIOT ? CLOUD_TRANSPORT_NTN : CLOUD_TRANSPORT_TN;
}

static void bearer_lte_handler(const struct lte_lc_evt *const evt)
{
	if (evt->type == LTE_LC_EVT_LTE_MODE_UPDATE) {
		enum cloud_transport t = transport_from_lte_mode(evt->lte_mode);

		if (t != g_bearer_detected) {
			LOG_INF("bearer %s (LTE mode %d)", t == CLOUD_TRANSPORT_NTN ? "NTN" : "TN",
				(int)evt->lte_mode);
		}
		g_bearer_detected = t;
	}
}

/* Register for LTE mode updates once, and read the current mode: the cloud
 * client is initialised after the network is up, so the attach-time update has
 * usually already been delivered to the other handlers. */
static void bearer_refresh(void)
{
	static bool registered;
	enum lte_lc_lte_mode mode;

	if (!registered) {
		lte_lc_register_handler(bearer_lte_handler);
		registered = true;
	}
	if (lte_lc_lte_mode_get(&mode) == 0) {
		g_bearer_detected = transport_from_lte_mode(mode);
	}
	log_bearer();
}
#else
static void bearer_refresh(void)
{
	log_bearer();
}
#endif

enum cloud_transport cloud_client_transport(void)
{
	switch (g_bearer_override) {
	case BEARER_FORCE_TN:
		return CLOUD_TRANSPORT_TN;
	case BEARER_FORCE_NTN:
		return CLOUD_TRANSPORT_NTN;
	default:
		return g_bearer_detected;
	}
}

static const struct xmit_profile *xmit_profile(void)
{
	return cloud_client_transport() == CLOUD_TRANSPORT_NTN ? &xmit_ntn : &xmit_tn;
}

static void log_bearer(void)
{
	const struct xmit_profile *p = xmit_profile();

	LOG_INF("bearer %s%s: ACK timeout %u ms, %u retransmission(s)",
		cloud_client_transport() == CLOUD_TRANSPORT_NTN ? "NTN" : "TN",
		g_bearer_override == BEARER_AUTO ? "" : " (forced)", p->ack_timeout_ms,
		p->max_retransmit);
}

/* CoAP tokens (A1 F2). OSCORE binds a response to its request through the
 * request's kid and PIV, not the token, so the token only has to tell this
 * exchange's datagrams from stale ones. A 2-byte counter, seeded at random per
 * boot, cannot repeat within 65536 exchanges; flush_rx() and the token check
 * below drop anything older. Saves 6 B in every request and every response
 * against the 8 B random tokens used before. */
#define COAP_TOKEN_LEN 2

static uint16_t g_token_ctr;
static uint8_t g_token[COAP_TOKEN_LEN];

static const uint8_t *next_token(void)
{
	static bool seeded;

	if (!seeded) {
		g_token_ctr = (uint16_t)sys_rand32_get();
		seeded = true;
	}
	g_token_ctr++;
	sys_put_be16(g_token_ctr, g_token);
	return g_token;
}

/* ------------------------------------------------------------------------
 * Test-only link impairment (CONFIG_OSCORE_CLOUD_TEST_IMPAIR)
 *
 * Emulates a lossy, slow bearer on the device side so the retransmission and
 * NTN timeouts can be tested on TN: a dropped TX is reported as sent but never
 * reaches the modem (uplink loss), a dropped RX is read and discarded
 * (downlink loss), and the delay hides every response until delay_ms after
 * the request's first transmission (a minimum RTT) while the retransmission
 * timer keeps running.
 * ------------------------------------------------------------------------ */
#if defined(CONFIG_OSCORE_CLOUD_TEST_IMPAIR)
static struct {
	uint8_t tx_drop_pct;
	uint8_t rx_drop_pct;
	uint32_t delay_ms;
	uint32_t tx_dropped;
	uint32_t rx_dropped;
	uint32_t burst_skip; /* coap burst: let this many datagrams pass, */
	uint32_t burst_drop; /* then drop this many */
} g_impair;

static bool impair_roll(uint8_t pct)
{
	return pct > 0 && (sys_rand32_get() % 100U) < pct;
}
#endif

/* Write one datagram from coap_buf. first marks the first transmission of a
 * request: only then does a failed send mean the request never left (and is
 * therefore no epoch miss). */
static int xmit(const char *what, const char *path, uint32_t block_num, size_t len, bool first)
{
#if defined(CONFIG_OSCORE_CLOUD_TEST_IMPAIR)
	bool burst = false;

	if (g_impair.burst_skip > 0) {
		g_impair.burst_skip--;
	} else if (g_impair.burst_drop > 0) {
		g_impair.burst_drop--;
		burst = true;
	}
	if (burst || impair_roll(g_impair.tx_drop_pct)) {
		g_impair.tx_dropped++;
		LOG_WRN("impair: dropped %s %s blk %u (%zu B)", what, path, block_num, len);
		return 0;
	}
#endif
	if (first) {
		return sock_send(what, path, block_num, len);
	}

	ssize_t sent = zsock_send(g_sock, coap_buf, len, 0);

	if (sent != (ssize_t)len) {
		LOG_ERR("%s retransmit %s blk %u: %zd (errno %d)", what, path, block_num, sent,
			sent < 0 ? errno : 0);
		return -EIO;
	}
	return 0;
}

/* Wait until the socket is readable or deadline (uptime ms) passes, feeding
 * the watchdog: NTN waits run to minutes. Returns 1 readable, 0 timeout. */
static int wait_readable(int64_t deadline)
{
	for (;;) {
		int64_t left = deadline - k_uptime_get();

		if (left <= 0) {
			return 0;
		}
		oscore_cloud_feed_wdt();

		struct zsock_pollfd pfd = { .fd = g_sock, .events = ZSOCK_POLLIN };
		int pr = zsock_poll(&pfd, 1, (int)MIN(left, 5000));

		if (pr < 0) {
			return -errno;
		}
		if (pr > 0) {
			if (!(pfd.revents & ZSOCK_POLLIN)) {
				LOG_ERR("poll revents 0x%x", pfd.revents);
				return -EIO;
			}
			return 1;
		}
	}
}

/* Acknowledge a CON response (a separate response) with an empty ACK. */
static void send_empty_ack(uint16_t mid)
{
	uint8_t ack[4] = { 0x60, 0x00, (uint8_t)(mid >> 8), (uint8_t)mid };

	(void)zsock_send(g_sock, ack, sizeof(ack), 0);
	g_xstats.con_acked++;
}

/* Verify and parse the response sitting in recv_buf. */
static int process_response(const char *path, size_t received, bool plain,
			    struct coap_oscore_response *resp, struct coap_packet *parsed)
{
	size_t recv_len = received;
	struct coap_packet local;
	int err;

	if (!plain) {
		err = oscore_wrapper_unprotect(recv_buf, &recv_len, sizeof(recv_buf));
		if (err) {
			LOG_ERR("oscore unprotect %s (%zu B wire): %d", path, received, err);
			return err;
		}
	}

	if (!resp && !parsed) {
		return 0;
	}

	err = coap_packet_parse(parsed ? parsed : &local, recv_buf, recv_len, NULL, 0);
	if (err) {
		LOG_ERR("coap_packet_parse %s: %d", path, err);
		return err;
	}

	if (resp) {
		resp->code = coap_header_get_code(parsed ? parsed : &local);
		resp->payload = coap_packet_get_payload(parsed ? parsed : &local, &resp->payload_len);
	}
	return 0;
}

/* Send the protected request in coap_buf[0, len) and, for a CON, wait for its
 * response, retransmitting the same bytes per RFC 7252 §4.2 (A1 F3): timeout
 * ACK_TIMEOUT x [1, 1.5), doubled per retransmission, up to MAX_RETRANSMIT.
 * A retransmission costs no SSN, and the server answers a copy of a request
 * it already processed from its response cache (A4 F1) instead of running the
 * handler again. A datagram with another token or message ID is a stale
 * response to an earlier exchange and is dropped without touching OSCORE.
 *
 * Returns 0 with the verified response, -EAGAIN when every transmission timed
 * out, *send_failed set (and -EIO) when the socket refused a datagram, or the
 * OSCORE/CoAP error of the first matching response. plain skips OSCORE (the
 * EDHOC messages, which are protected by EDHOC itself).
 */
static int exchange_ex(const char *what, const char *path, uint32_t block_num, size_t len,
		       bool rai_ongoing, bool plain, struct coap_oscore_response *resp,
		       struct coap_packet *parsed, bool *send_failed);

static int exchange(const char *what, const char *path, uint32_t block_num, size_t len,
		    bool rai_ongoing, struct coap_oscore_response *resp,
		    struct coap_packet *parsed, bool *send_failed)
{
	return exchange_ex(what, path, block_num, len, rai_ongoing, false, resp, parsed,
			   send_failed);
}

static int exchange_ex(const char *what, const char *path, uint32_t block_num, size_t len,
		       bool rai_ongoing, bool plain, struct coap_oscore_response *resp,
		       struct coap_packet *parsed, bool *send_failed)
{
	const struct xmit_profile *p = xmit_profile();
	uint8_t type = (coap_buf[0] >> 4) & 0x03;
	uint8_t tkl = coap_buf[0] & 0x0f;
	uint16_t mid = sys_get_be16(&coap_buf[2]);
	uint8_t token[COAP_TOKEN_LEN];
	uint32_t timeout;
	uint8_t tx = 0;
	uint8_t max_rt;
	bool acked = false;
	int64_t start;
	int64_t deadline;
	int err;

	*send_failed = false;
	if (tkl != COAP_TOKEN_LEN || len < 4U + tkl) {
		return -EINVAL;
	}
	memcpy(token, &coap_buf[4], tkl);

	flush_rx();
	if (rai_ongoing) {
		apply_rai_ongoing();
	} else {
		apply_rai_hint();
	}

	start = k_uptime_get();
	err = xmit(what, path, block_num, len, true);
	if (err) {
		*send_failed = true;
		return err;
	}
	g_xstats.requests++;

	/* NON requests have no response. */
	if (type == COAP_TYPE_NON && !resp && !parsed) {
		return 0;
	}

	max_rt = (type == COAP_TYPE_NON) ? 0 : p->max_retransmit;
	timeout = p->ack_timeout_ms + (sys_rand32_get() % (p->ack_timeout_ms / 2U + 1U));
	deadline = start + timeout;

	for (;;) {
#if defined(CONFIG_OSCORE_CLOUD_TEST_IMPAIR)
		/* Minimum RTT: no response is visible before delay_ms after the
		 * first transmission; the retransmission timer keeps running. */
		while (g_impair.delay_ms > 0 &&
		       k_uptime_get() < MIN(start + g_impair.delay_ms, deadline)) {
			oscore_cloud_feed_wdt();
			k_msleep((int32_t)MIN(MIN(start + g_impair.delay_ms, deadline) -
					      k_uptime_get(), 1000));
		}
#endif
		int r = wait_readable(deadline);

		if (r < 0) {
			LOG_ERR("%s poll %s blk %u: %d", what, path, block_num, r);
			return r;
		}
		if (r == 0) {
			if (acked || tx >= max_rt) {
				g_xstats.timeouts++;
				LOG_WRN("%s %s blk %u: no response after %u transmission(s), %lld ms",
					what, path, block_num, tx + 1U, k_uptime_get() - start);
				return -EAGAIN;
			}
			tx++;
			timeout *= 2U;
			deadline = k_uptime_get() + timeout;
			g_xstats.retransmits++;
			LOG_WRN("%s %s blk %u: retransmit %u/%u (next wait %u ms)", what, path,
				block_num, tx, max_rt, timeout);
			err = xmit(what, path, block_num, len, false);
			if (err) {
				*send_failed = true;
				return err;
			}
			continue;
		}

		ssize_t received = zsock_recv(g_sock, recv_buf, sizeof(recv_buf), 0);

		if (received < 0) {
			LOG_ERR("recv %s: %d", path, -errno);
			return -errno;
		}
#if defined(CONFIG_OSCORE_CLOUD_TEST_IMPAIR)
		if (impair_roll(g_impair.rx_drop_pct)) {
			g_impair.rx_dropped++;
			LOG_WRN("impair: dropped response to %s %s blk %u", what, path, block_num);
			continue;
		}
#endif
		if (received < 4 || (recv_buf[0] >> 6) != 1) {
			g_xstats.stale++;
			continue;
		}

		uint8_t rtype = (recv_buf[0] >> 4) & 0x03;
		uint8_t rtkl = recv_buf[0] & 0x0f;
		uint16_t rmid = sys_get_be16(&recv_buf[2]);
		bool mid_match = (rtype == COAP_TYPE_ACK || rtype == COAP_TYPE_RESET) && rmid == mid;

		if (rtype == COAP_TYPE_RESET && mid_match) {
			LOG_WRN("%s %s blk %u: reset by peer", what, path, block_num);
			return -ECONNRESET;
		}
		if (recv_buf[1] == 0 && mid_match) {
			/* Empty ACK: the response follows separately. Stop
			 * retransmitting and wait out the rest of the span. */
			g_xstats.empty_acks++;
			acked = true;
			continue;
		}
		if (rtkl != tkl || received < 4 + rtkl || memcmp(&recv_buf[4], token, tkl) != 0) {
			g_xstats.stale++;
			LOG_DBG("%s %s: dropped stale datagram (%zd B)", what, path, received);
			continue;
		}
		if (rtype == COAP_TYPE_CON) {
			send_empty_ack(rmid);
		}

		uint32_t rtt = (uint32_t)(k_uptime_get() - start);

		g_xstats.last_rtt_ms = rtt;
		g_xstats.max_rtt_ms = MAX(g_xstats.max_rtt_ms, rtt);
		if (tx > 0) {
			LOG_INF("%s %s blk %u: response after %u retransmission(s), %u ms", what,
				path, block_num, tx, rtt);
		}
		return process_response(path, (size_t)received, plain, resp, parsed);
	}
}

static int coap_oscore_request(uint8_t method, uint8_t coap_type, const char *path,
			       const uint8_t *payload, size_t payload_len,
			       struct coap_oscore_response *resp)
{
	struct coap_packet request;
	ssize_t len;
	bool send_failed;
	int err;

#if defined(CONFIG_OSCORE_CLOUD_EDHOC)
	/* A shell-requested EDHOC run happens here, on the cloud thread, before
	 * coap_buf is filled: the run reuses the socket and the buffers. */
	oscore_edhoc_service();
#endif

	err = coap_packet_init(&request, coap_buf, sizeof(coap_buf), COAP_VERSION_1,
			       coap_type, COAP_TOKEN_LEN, next_token(), method, coap_next_id());
	if (err) {
		LOG_ERR("coap_packet_init %s: %d", path, err);
		return err;
	}

	err = append_uri_path(&request, path);
	if (err) {
		LOG_ERR("append URI_PATH %s: %d", path, err);
		return err;
	}

	if (payload && payload_len > 0) {
		err = coap_append_option_int(&request, COAP_OPTION_CONTENT_FORMAT,
					     COAP_CONTENT_FORMAT_APPLICATION_CBOR);
		if (err) {
			LOG_ERR("append CONTENT_FORMAT %s: %d (off=%u/%u)", path, err,
				request.offset, (unsigned int)sizeof(coap_buf));
			return err;
		}
		err = coap_packet_append_payload_marker(&request);
		if (err) {
			LOG_ERR("append payload marker %s: %d (off=%u/%u)", path, err,
				request.offset, (unsigned int)sizeof(coap_buf));
			return err;
		}
		err = coap_packet_append_payload(&request, payload, payload_len);
		if (err) {
			LOG_ERR("append payload %s: %d (off=%u payload=%u max=%u)", path,
				err, request.offset, (unsigned int)payload_len,
				(unsigned int)sizeof(coap_buf));
			return err;
		}
	}

	len = request.offset;
	err = oscore_wrapper_protect(coap_buf, (size_t *)&len, sizeof(coap_buf));
	if (err) {
		LOG_ERR("oscore protect %s: %d", path, err);
		return err;
	}

	/* On timeout the caller treats it as a network error and rebuilds the
	 * connection. */
	return exchange("request", path, 0, (size_t)len, false, resp, NULL, &send_failed);
}

#if defined(CONFIG_OSCORE_CLOUD_EDHOC)
int cloud_client_edhoc_post(const uint8_t *body, size_t body_len, uint8_t *code, uint8_t *out,
			    size_t *out_len)
{
	struct coap_packet request;
	struct coap_packet response;
	struct coap_oscore_response resp;
	bool send_failed;
	int err;

	if (g_sock < 0) {
		return -ENOTCONN;
	}
	err = coap_packet_init(&request, coap_buf, sizeof(coap_buf), COAP_VERSION_1,
			       COAP_TYPE_CON, COAP_TOKEN_LEN, next_token(), COAP_METHOD_POST,
			       coap_next_id());
	if (err) {
		return err;
	}
	err = append_uri_path(&request, ".well-known/edhoc");
	if (err) {
		return err;
	}
	/* RFC 9528 Appendix A.2: the request carries C_x ahead of the message. */
	err = coap_append_option_int(&request, COAP_OPTION_CONTENT_FORMAT, 65);
	if (err) {
		return err;
	}
	err = coap_packet_append_payload_marker(&request);
	if (err) {
		return err;
	}
	err = coap_packet_append_payload(&request, body, body_len);
	if (err) {
		return err;
	}

	/* The run happens inside the application's next request: keep the link
	 * up between message_1 and message_3, and leave the one-shot RAI hint the
	 * application queued for that request untouched. */
	enum cloud_rai_hint hint = rai_peek();

	err = exchange_ex("edhoc", ".well-known/edhoc", 0, request.offset, true, true, &resp,
			  &response, &send_failed);
	cloud_client_rai_next(hint);
	if (err) {
		return err;
	}
	*code = resp.code;
	if (resp.payload_len > *out_len) {
		return -ENOBUFS;
	}
	if (resp.payload_len > 0) {
		memcpy(out, resp.payload, resp.payload_len);
	}
	*out_len = resp.payload_len;
	return 0;
}
#endif /* CONFIG_OSCORE_CLOUD_EDHOC */

int cloud_client_oscore_get(const char *path, struct coap_oscore_response *resp)
{
	return coap_oscore_request(COAP_METHOD_GET, COAP_TYPE_CON, path, NULL, 0, resp);
}

int cloud_client_oscore_post(const char *path, const uint8_t *payload, size_t payload_len,
			     struct coap_oscore_response *resp)
{
	return coap_oscore_request(COAP_METHOD_POST, COAP_TYPE_CON, path, payload, payload_len,
				   resp);
}

static int append_block2_option(struct coap_packet *req, uint32_t block_num, uint8_t szx)
{
	uint32_t opt = (block_num << 4) | (szx & 0x07);
	uint8_t enc[3];
	uint8_t elen = 0;

	if (opt <= 0xff) {
		enc[0] = (uint8_t)opt;
		elen = 1;
	} else if (opt <= 0xffff) {
		enc[0] = (uint8_t)(opt >> 8);
		enc[1] = (uint8_t)opt;
		elen = 2;
	} else {
		enc[0] = (uint8_t)(opt >> 16);
		enc[1] = (uint8_t)(opt >> 8);
		enc[2] = (uint8_t)opt;
		elen = 3;
	}
	return coap_packet_append_option(req, COAP_OPTION_BLOCK2, enc, elen);
}

/* A block exchange that fails (every CoAP retransmission timed out, or the
 * response did not verify) is retried as a new, freshly protected request up
 * to this many times in all. The CoAP layer already retransmits identical
 * bytes inside each attempt (exchange()), so this only covers a lost context
 * sync or a long outage. */
#define BLOCK_MAX_ATTEMPTS 3

/* Run one block exchange: build + protect (a new SSN per attempt) through
 * build(), then exchange(). Returns 0 with the verified response, the send or
 * build error, or the last attempt's error (-ETIMEDOUT for timeouts). */
static int block_exchange(const char *what, const char *path, uint32_t block_num,
			  int (*build)(const void *arg, size_t *len), const void *arg,
			  struct coap_oscore_response *resp, struct coap_packet *parsed)
{
	int err = 0;

	for (int attempt = 1; attempt <= BLOCK_MAX_ATTEMPTS; attempt++) {
		size_t len;
		bool send_failed;

		err = build(arg, &len);
		if (err) {
			LOG_ERR("%s build %s blk %u: %d", what, path, block_num, err);
			return err;
		}
		err = exchange(what, path, block_num, len, true, resp, parsed, &send_failed);
		if (err == 0 || send_failed) {
			return err;
		}
		if (attempt < BLOCK_MAX_ATTEMPTS) {
			LOG_WRN("%s %s blk %u: attempt %d failed (%d), new request", what, path,
				block_num, attempt, err);
		}
	}
	LOG_ERR("%s %s blk %u: failed after %d attempts: %d", what, path, block_num,
		BLOCK_MAX_ATTEMPTS, err);
	return err == -EAGAIN ? -ETIMEDOUT : err;
}

struct block2_get_args {
	const char *path;
	uint32_t block_num;
	uint8_t szx;
};

/* Build and OSCORE-protect one Block2 GET request into coap_buf. */
static int block2_build_request(const void *arg, size_t *out_len)
{
	const struct block2_get_args *a = arg;
	struct coap_packet request;
	ssize_t len;
	int err;

	err = coap_packet_init(&request, coap_buf, sizeof(coap_buf), COAP_VERSION_1,
			       COAP_TYPE_CON, COAP_TOKEN_LEN, next_token(), COAP_METHOD_GET,
			       coap_next_id());
	if (err) {
		return err;
	}
	err = append_uri_path(&request, a->path);
	if (err) {
		return err;
	}
	err = append_block2_option(&request, a->block_num, a->szx);
	if (err) {
		return err;
	}

	len = request.offset;
	err = oscore_wrapper_protect(coap_buf, (size_t *)&len, sizeof(coap_buf));
	if (err) {
		LOG_ERR("oscore protect block2 %s blk %u: %d", a->path, a->block_num, err);
		return err;
	}
	*out_len = (size_t)len;
	return 0;
}

int cloud_client_oscore_block2_get(const char *path, uint8_t szx,
				   int (*sink)(const uint8_t *data, size_t len, void *ctx),
				   void *ctx, uint32_t start_block, uint32_t max_blocks,
				   size_t expected_size, uint32_t *next_block_out,
				   size_t *total_out, bool *more_out)
{
	uint32_t block_num = start_block;
	uint32_t blocks_done = 0;
	bool more = true;
	size_t total = 0;
	const size_t block_size = 1U << (szx + 4);
	int err;

	if (!path || !sink) {
		return -EINVAL;
	}

	/* max_blocks == 0 means "download to completion in one call". A non-zero
	 * limit downloads at most that many blocks and returns with *more_out set,
	 * so the caller can yield the thread (e.g. to service telemetry) between
	 * chunks and resume from *next_block_out. */
	while (more && (max_blocks == 0 || blocks_done < max_blocks)) {
		struct coap_packet response;
		struct coap_oscore_response resp;
		struct block2_get_args args = { .path = path, .block_num = block_num, .szx = szx };

		err = block_exchange("block2", path, block_num, block2_build_request, &args,
				     &resp, &response);
		if (err) {
			return err;
		}
		if (resp.code != COAP_RESPONSE_CODE_CONTENT) {
			LOG_ERR("block2 GET %s blk %u: code 0x%02x", path, block_num, resp.code);
			return -EIO;
		}

		bool has_more = false;
		uint32_t block_number = 0;
		int block2_err;

		block2_err = coap_get_block2_option(&response, &has_more, &block_number);
		if (block2_err < 0) {
			LOG_DBG("block2 option missing on blk %u", block_num);
		}

		if (resp.payload && resp.payload_len > 0) {
			err = sink(resp.payload, resp.payload_len, ctx);
			if (err) {
				LOG_ERR("block2 sink blk %u: %d", block_num, err);
				return err;
			}
			total += resp.payload_len;
		}

		if (expected_size > 0) {
			size_t absolute = ((size_t)start_block * block_size) + total;

			more = absolute < expected_size;
			block_num++;
		} else if (block2_err >= 0) {
			more = has_more;
			block_num = block_number + 1;
		} else {
			more = false;
		}

		blocks_done++;

		if (!more) {
			break;
		}
	}

	if (next_block_out) {
		*next_block_out = block_num;
	}
	if (total_out) {
		*total_out = total;
	}
	if (more_out) {
		*more_out = more;
	}
	return 0;
}

struct block2_post_args {
	const char *path;
	uint32_t block_num;
	uint8_t szx;
	const uint8_t *body;
	size_t body_len;
};

/* Build and OSCORE-protect one Block2 POST request. The CBOR request body is
 * included only on block 0 (matching the server, which decodes the request on
 * the first POST and serves continuation blocks from its per-device cache);
 * later blocks are empty POSTs carrying just the incremented Block2 option. */
static int block2_post_build_request(const void *arg, size_t *out_len)
{
	const struct block2_post_args *a = arg;
	struct coap_packet request;
	ssize_t len;
	int err;

	err = coap_packet_init(&request, coap_buf, sizeof(coap_buf), COAP_VERSION_1,
			       COAP_TYPE_CON, COAP_TOKEN_LEN, next_token(), COAP_METHOD_POST,
			       coap_next_id());
	if (err) {
		return err;
	}
	err = append_uri_path(&request, a->path);
	if (err) {
		return err;
	}
	err = append_block2_option(&request, a->block_num, a->szx);
	if (err) {
		return err;
	}

	if (a->block_num == 0 && a->body && a->body_len > 0) {
		err = coap_append_option_int(&request, COAP_OPTION_CONTENT_FORMAT,
					     COAP_CONTENT_FORMAT_APPLICATION_CBOR);
		if (err) {
			return err;
		}
		err = coap_packet_append_payload_marker(&request);
		if (err) {
			return err;
		}
		err = coap_packet_append_payload(&request, a->body, a->body_len);
		if (err) {
			return err;
		}
	}

	len = request.offset;
	err = oscore_wrapper_protect(coap_buf, (size_t *)&len, sizeof(coap_buf));
	if (err) {
		LOG_ERR("oscore protect block2 post %s blk %u: %d", a->path, a->block_num, err);
		return err;
	}
	*out_len = (size_t)len;
	return 0;
}

int cloud_client_oscore_block2_post(const char *path, const uint8_t *body, size_t body_len,
				    uint8_t szx,
				    int (*sink)(const uint8_t *data, size_t len, void *ctx),
				    void *ctx)
{
	uint32_t block_num = 0;
	bool more = true;
	int err;

	if (!path || !sink) {
		return -EINVAL;
	}

	while (more) {
		struct coap_packet response;
		struct coap_oscore_response resp;
		struct block2_post_args args = {
			.path = path, .block_num = block_num, .szx = szx,
			.body = body, .body_len = body_len,
		};

		err = block_exchange("block2 post", path, block_num, block2_post_build_request,
				     &args, &resp, &response);
		if (err) {
			return err;
		}
		if (resp.code != COAP_RESPONSE_CODE_CONTENT &&
		    resp.code != COAP_RESPONSE_CODE_CHANGED) {
			LOG_ERR("block2 POST %s blk %u: code 0x%02x", path, block_num, resp.code);
			return -EIO;
		}

		bool has_more = false;
		uint32_t block_number = 0;
		int block2_err = coap_get_block2_option(&response, &has_more, &block_number);

		if (resp.payload && resp.payload_len > 0) {
			err = sink(resp.payload, resp.payload_len, ctx);
			if (err) {
				LOG_ERR("block2 post sink blk %u: %d", block_num, err);
				return err;
			}
		}

		if (block2_err >= 0) {
			more = has_more;
			block_num = block_number + 1;
		} else {
			more = false;
		}
	}

	return 0;
}

/* Append a Block1 request option: (num << 4) | (more << 3) | szx. Mirrors
 * append_block2_option but on the upload (request-payload) side. */
static int append_block1_option(struct coap_packet *req, uint32_t block_num, uint8_t szx,
				bool more)
{
	uint32_t opt = (block_num << 4) | (more ? 0x08U : 0U) | (szx & 0x07U);
	uint8_t enc[3];
	uint8_t elen;

	if (opt <= 0xff) {
		enc[0] = (uint8_t)opt;
		elen = 1;
	} else if (opt <= 0xffff) {
		enc[0] = (uint8_t)(opt >> 8);
		enc[1] = (uint8_t)opt;
		elen = 2;
	} else {
		enc[0] = (uint8_t)(opt >> 16);
		enc[1] = (uint8_t)(opt >> 8);
		enc[2] = (uint8_t)opt;
		elen = 3;
	}
	return coap_packet_append_option(req, COAP_OPTION_BLOCK1, enc, elen);
}

struct block1_args {
	const char *path;
	uint32_t block_num;
	uint8_t szx;
	bool more;
	const uint8_t *chunk;
	size_t chunk_len;
};

/* Build and OSCORE-protect one Block1 POST carrying [chunk, chunk_len). */
static int block1_build_request(const void *arg, size_t *out_len)
{
	const struct block1_args *a = arg;
	struct coap_packet request;
	ssize_t len;
	int err;

	err = coap_packet_init(&request, coap_buf, sizeof(coap_buf), COAP_VERSION_1,
			       COAP_TYPE_CON, COAP_TOKEN_LEN, next_token(), COAP_METHOD_POST,
			       coap_next_id());
	if (err) {
		return err;
	}
	err = append_uri_path(&request, a->path);
	if (err) {
		return err;
	}
	err = append_block1_option(&request, a->block_num, a->szx, a->more);
	if (err) {
		return err;
	}
	if (a->chunk && a->chunk_len > 0) {
		err = coap_append_option_int(&request, COAP_OPTION_CONTENT_FORMAT,
					     COAP_CONTENT_FORMAT_APPLICATION_CBOR);
		if (err) {
			return err;
		}
		err = coap_packet_append_payload_marker(&request);
		if (err) {
			return err;
		}
		err = coap_packet_append_payload(&request, a->chunk, a->chunk_len);
		if (err) {
			return err;
		}
	}

	len = request.offset;
	err = oscore_wrapper_protect(coap_buf, (size_t *)&len, sizeof(coap_buf));
	if (err) {
		LOG_ERR("oscore protect block1 %s blk %u: %d", a->path, a->block_num, err);
		return err;
	}
	*out_len = (size_t)len;
	return 0;
}

int cloud_client_oscore_block1_post(const char *path, size_t total_len, uint8_t szx,
				    cloud_block1_source source, void *ctx)
{
	return cloud_client_oscore_block1_post_from(path, total_len, szx, 0, source, ctx);
}

int cloud_client_oscore_block1_post_from(const char *path, size_t total_len, uint8_t szx,
					 uint32_t start_block, cloud_block1_source source,
					 void *ctx)
{
	const size_t block_size = (size_t)16U << (szx & 0x07U);
	static uint8_t chunk[1024];
	uint32_t block_num = start_block;
	size_t offset = (size_t)start_block * block_size;
	int err;

	if (!path || !source || total_len == 0 || block_size > sizeof(chunk) ||
	    offset >= total_len) {
		return -EINVAL;
	}

	while (offset < total_len) {
		size_t want = MIN(block_size, total_len - offset);
		int got = source(chunk, want, offset, ctx);

		if (got <= 0) {
			LOG_ERR("block1 source %s @%zu: %d", path, offset, got);
			return got < 0 ? got : -EIO;
		}

		struct coap_oscore_response resp;
		struct block1_args args = {
			.path = path, .block_num = block_num, .szx = szx,
			.more = (offset + (size_t)got) < total_len,
			.chunk = chunk, .chunk_len = (size_t)got,
		};

		err = block_exchange("block1", path, block_num, block1_build_request, &args,
				     &resp, NULL);
		if (err) {
			return err;
		}
		/* 2.31 Continue while more blocks expected, 2.04 Changed on done. */
		if (resp.code != COAP_RESPONSE_CODE_CHANGED &&
		    resp.code != 0x5F /* 2.31 Continue */) {
			LOG_ERR("block1 %s blk %u: code 0x%02x", path, block_num, resp.code);
			return -EIO;
		}

		offset += (size_t)got;
		block_num++;
	}

	return 0;
}

void cloud_telemetry_init(struct cloud_telemetry *t)
{
	memset(t, 0, sizeof(*t));
}

void cloud_telemetry_set_transport(struct cloud_telemetry *t, enum cloud_transport tr)
{
	t->has_transport = true;
	t->transport = tr;
}

void cloud_telemetry_set_fw_version(struct cloud_telemetry *t, const char *version)
{
	t->fw_version = version;
}

void cloud_telemetry_set_timestamp(struct cloud_telemetry *t, uint64_t ts)
{
	t->has_timestamp = true;
	t->timestamp = ts;
}

void cloud_telemetry_set_gnss(struct cloud_telemetry *t,
			      const struct cloud_telemetry_gnss *g)
{
	t->gnss = *g;
	t->gnss.valid = true;
}

void cloud_telemetry_set_cell(struct cloud_telemetry *t,
			      const struct cloud_telemetry_cell *c)
{
	t->cell = *c;
	t->cell.valid = true;
	if (t->cell.ncells > CLOUD_TELEMETRY_MAX_NCELLS) {
		t->cell.ncells = CLOUD_TELEMETRY_MAX_NCELLS;
	}
}

void cloud_telemetry_set_wifi(struct cloud_telemetry *t,
			      const struct cloud_telemetry_wifi *w)
{
	t->wifi = *w;
	t->wifi.valid = true;
	if (t->wifi.count > CLOUD_TELEMETRY_MAX_WIFI) {
		t->wifi.count = CLOUD_TELEMETRY_MAX_WIFI;
	}
}

static int telemetry_add_metric(struct cloud_telemetry *t, struct cloud_metric m)
{
	if (t->metric_count >= CLOUD_TELEMETRY_MAX_METRICS) {
		return -ENOMEM;
	}
	t->metrics[t->metric_count++] = m;
	return 0;
}

int cloud_telemetry_add_uint(struct cloud_telemetry *t, uint16_t key, uint64_t v)
{
	struct cloud_metric m = { .key = key, .type = CLOUD_METRIC_UINT, .value.u = v };

	return telemetry_add_metric(t, m);
}

int cloud_telemetry_add_double(struct cloud_telemetry *t, uint16_t key, double v)
{
	struct cloud_metric m = { .key = key, .type = CLOUD_METRIC_DOUBLE, .value.d = v };

	return telemetry_add_metric(t, m);
}

void cloud_telemetry_set_reset(struct cloud_telemetry *t,
			       const struct cloud_telemetry_reset *r)
{
	t->reset = *r;
	t->reset.valid = true;
}

void cloud_telemetry_set_vitals(struct cloud_telemetry *t,
				const struct cloud_telemetry_vitals *v)
{
	t->vitals = *v;
	t->vitals.valid = true;
}

int cloud_telemetry_vitals_add_uint(struct cloud_telemetry_vitals *v,
				    const char *key, uint32_t value)
{
	if (v->count >= CLOUD_TELEMETRY_MAX_VITALS) {
		return -ENOMEM;
	}
	v->items[v->count].key = key;
	v->items[v->count].type = CLOUD_VITAL_UINT;
	v->items[v->count].value.u = value;
	v->count++;
	return 0;
}

int cloud_telemetry_vitals_add_int(struct cloud_telemetry_vitals *v,
				   const char *key, int32_t value)
{
	if (v->count >= CLOUD_TELEMETRY_MAX_VITALS) {
		return -ENOMEM;
	}
	v->items[v->count].key = key;
	v->items[v->count].type = CLOUD_VITAL_INT;
	v->items[v->count].value.s = value;
	v->count++;
	return 0;
}

void cloud_telemetry_set_crash(struct cloud_telemetry *t,
			       const struct cloud_telemetry_crash *c)
{
	t->crash = *c;
	t->crash.valid = true;
	if (t->crash.reg_count > CLOUD_TELEMETRY_MAX_CRASH_REGS) {
		t->crash.reg_count = CLOUD_TELEMETRY_MAX_CRASH_REGS;
	}
	if (t->crash.stack_count > CLOUD_TELEMETRY_MAX_CRASH_STACK) {
		t->crash.stack_count = CLOUD_TELEMETRY_MAX_CRASH_STACK;
	}
}

void cloud_telemetry_set_device_info(struct cloud_telemetry *t,
				     const struct cloud_telemetry_device_info *d)
{
	t->device_info = *d;
	t->device_info.valid = true;
}

/* Room for the largest telemetry: a crash report (key 22) with full register
 * and stack capture PLUS a full cell/Wi-Fi location scan (keys 5/6) can ride in
 * one crash-boot post, so the buffer must fit both at once. 1472 leaves ~57 B
 * under the OSCORE-usable ceiling: OSCORE_MAX_PLAINTEXT_LEN (1536) holds the
 * whole inner CoAP frame (code + class-E options + marker + this CBOR), and the
 * POST "t" inner options are ~6 B. A genuinely all-maxed payload (~1630 B) would
 * exceed even that and is correctly rejected by the encode_telemetry guard. */
#define CLOUD_TELEMETRY_CBOR_MAX 1472

/* The telemetry encode scratch lives in BSS, not on the caller's stack: at 1280
 * bytes it would otherwise dominate the cloud thread's deepest frame (telemetry
 * struct + this buffer + the OSCORE protect buffers), which overflowed the stack
 * once the crash-report path was added. The cloud client is driven by the single
 * cloud module thread and every post is synchronous, so a shared static is safe;
 * it must not be used from any other context. */
static uint8_t telemetry_cbor_buf[CLOUD_TELEMETRY_CBOR_MAX];

/* Worst-case size of the nested GNSS map (key 4): map header + up to 6 entries,
 * each a <=2 byte text key plus a <=9 byte value. */
#define CLOUD_TELEMETRY_GNSS_CBOR_MAX 80

/* Worst-case cell map (key 5): 8 scalar entries + a neighbor array of up to
 * CLOUD_TELEMETRY_MAX_NCELLS maps (5 entries each, <=12 bytes per entry). */
#define CLOUD_TELEMETRY_CELL_CBOR_MAX (64 + CLOUD_TELEMETRY_MAX_NCELLS * 36)

/* Worst-case Wi-Fi array (key 6): up to CLOUD_TELEMETRY_MAX_WIFI maps, each a
 * 6-byte MAC byte-string plus an RSSI. */
#define CLOUD_TELEMETRY_WIFI_CBOR_MAX (4 + CLOUD_TELEMETRY_MAX_WIFI * 16)

/* Emit the GNSS fix as a nested CBOR map under integer key 4. Text sub-keys
 * (t/la/lo/ac/tf/al) match the server's location ingest (agnss-schema.md). */
static size_t encode_gnss(const struct cloud_telemetry_gnss *g, uint8_t *buf)
{
	size_t entries = 2; /* la, lo always present */
	size_t n = 0;

	entries += (g->fix_time_sec > 0 ? 1 : 0) + 1 /* ac */ +
		   (g->ttff_ms > 0 ? 1 : 0) + (g->have_alt ? 1 : 0);

	n += cbor_write_uint(buf + n, 4);
	n += cbor_write_map_header(buf + n, entries);
	if (g->fix_time_sec > 0) {
		n += cbor_write_tstr(buf + n, "t", 1);
		n += cbor_write_uint(buf + n, g->fix_time_sec);
	}
	n += cbor_write_tstr(buf + n, "la", 2);
	n += cbor_write_double(buf + n, g->lat);
	n += cbor_write_tstr(buf + n, "lo", 2);
	n += cbor_write_double(buf + n, g->lon);
	n += cbor_write_tstr(buf + n, "ac", 2);
	n += cbor_write_double(buf + n, g->accuracy);
	if (g->ttff_ms > 0) {
		n += cbor_write_tstr(buf + n, "tf", 2);
		n += cbor_write_uint(buf + n, g->ttff_ms);
	}
	if (g->have_alt) {
		n += cbor_write_tstr(buf + n, "al", 2);
		n += cbor_write_double(buf + n, g->altitude);
	}
	return n;
}

/* Cell scan as a nested CBOR map under integer key 5 (agnss-schema.md). */
static size_t encode_cell(const struct cloud_telemetry_cell *c, uint8_t *buf)
{
	size_t entries = 8; /* ci, mcc, mnc, tac, ea, rp, rq, ta */
	size_t n = 0;
	bool have_nc = c->ncells > 0;

	entries += have_nc ? 1 : 0;

	n += cbor_write_uint(buf + n, 5);
	n += cbor_write_map_header(buf + n, entries);
	n += cbor_write_tstr(buf + n, "ci", 2);
	n += cbor_write_uint(buf + n, c->id);
	n += cbor_write_tstr(buf + n, "mcc", 3);
	n += cbor_write_uint(buf + n, c->mcc);
	n += cbor_write_tstr(buf + n, "mnc", 3);
	n += cbor_write_uint(buf + n, c->mnc);
	n += cbor_write_tstr(buf + n, "tac", 3);
	n += cbor_write_uint(buf + n, c->tac);
	n += cbor_write_tstr(buf + n, "ea", 2);
	n += cbor_write_uint(buf + n, c->earfcn);
	n += cbor_write_tstr(buf + n, "rp", 2);
	n += cbor_write_int(buf + n, c->rsrp);
	n += cbor_write_tstr(buf + n, "rq", 2);
	n += cbor_write_int(buf + n, c->rsrq);
	n += cbor_write_tstr(buf + n, "ta", 2);
	n += cbor_write_uint(buf + n, c->timing_advance);
	if (have_nc) {
		n += cbor_write_tstr(buf + n, "nc", 2);
		n += cbor_write_array_header(buf + n, c->ncells);
		for (uint8_t i = 0; i < c->ncells; i++) {
			const struct cloud_neighbor_cell *nb = &c->neighbors[i];

			n += cbor_write_map_header(buf + n, 5);
			n += cbor_write_tstr(buf + n, "ea", 2);
			n += cbor_write_uint(buf + n, nb->earfcn);
			n += cbor_write_tstr(buf + n, "pci", 3);
			n += cbor_write_uint(buf + n, nb->phys_cell_id);
			n += cbor_write_tstr(buf + n, "rp", 2);
			n += cbor_write_int(buf + n, nb->rsrp);
			n += cbor_write_tstr(buf + n, "rq", 2);
			n += cbor_write_int(buf + n, nb->rsrq);
			n += cbor_write_tstr(buf + n, "td", 2);
			n += cbor_write_int(buf + n, nb->time_diff);
		}
	}
	return n;
}

/* Wi-Fi scan as a CBOR array of {m: mac, r: rssi} maps under integer key 6. */
static size_t encode_wifi(const struct cloud_telemetry_wifi *w, uint8_t *buf)
{
	size_t n = 0;

	n += cbor_write_uint(buf + n, 6);
	n += cbor_write_array_header(buf + n, w->count);
	for (uint8_t i = 0; i < w->count; i++) {
		const struct cloud_wifi_ap *ap = &w->aps[i];

		n += cbor_write_map_header(buf + n, 2);
		n += cbor_write_tstr(buf + n, "m", 1);
		n += cbor_write_bstr(buf + n, ap->mac, ap->mac_len);
		n += cbor_write_tstr(buf + n, "r", 1);
		n += cbor_write_int(buf + n, ap->rssi);
	}
	return n;
}

/* Boot report as a nested CBOR map under integer key 20 (deviceapi diag.go). */
static size_t encode_reset(const struct cloud_telemetry_reset *r, uint8_t *buf)
{
	size_t entries = 2; /* hc, rs always */
	size_t n = 0;

	entries += (r->prev_uptime_s > 0 ? 1 : 0) + (r->boot_count > 0 ? 1 : 0) +
		   (r->crash_pending ? 1 : 0);

	n += cbor_write_uint(buf + n, 20);
	n += cbor_write_map_header(buf + n, entries);
	n += cbor_write_tstr(buf + n, "hc", 2);
	n += cbor_write_uint(buf + n, r->hw_cause);
	n += cbor_write_tstr(buf + n, "rs", 2);
	n += cbor_write_uint(buf + n, r->reason);
	if (r->prev_uptime_s > 0) {
		n += cbor_write_tstr(buf + n, "up", 2);
		n += cbor_write_uint(buf + n, r->prev_uptime_s);
	}
	if (r->boot_count > 0) {
		n += cbor_write_tstr(buf + n, "bc", 2);
		n += cbor_write_uint(buf + n, r->boot_count);
	}
	if (r->crash_pending) {
		n += cbor_write_tstr(buf + n, "cp", 2);
		n += cbor_write_bool(buf + n, true);
	}
	return n;
}

/* Vitals heartbeat as a nested CBOR map under integer key 21 (deviceapi). The
 * map is built by walking the generic sample list, so the encoder never needs to
 * change when the device starts reporting a new metric. */
static size_t encode_vitals(const struct cloud_telemetry_vitals *v, uint8_t *buf)
{
	size_t n = 0;

	n += cbor_write_uint(buf + n, 21);
	n += cbor_write_map_header(buf + n, v->count);
	for (uint8_t i = 0; i < v->count; i++) {
		const struct cloud_vital *it = &v->items[i];

		n += cbor_write_tstr(buf + n, it->key, 2);
		if (it->type == CLOUD_VITAL_INT) {
			n += cbor_write_int(buf + n, it->value.s);
		} else {
			n += cbor_write_uint(buf + n, it->value.u);
		}
	}
	return n;
}

/* Minimal crash report as a nested CBOR map under integer key 22. The server
 * symbolicates pc/lr and the stack return-address candidates against the ELF. */
static size_t encode_crash(const struct cloud_telemetry_crash *c, uint8_t *buf)
{
	size_t entries = 3; /* ft, pc, lr always */
	size_t n = 0;

	entries += (c->build_id[0] != '\0' ? 1 : 0) + (c->reg_count > 0 ? 1 : 0) +
		   (c->stack_count > 0 ? 1 : 0) + (c->breadcrumb_len > 0 ? 1 : 0);

	n += cbor_write_uint(buf + n, 22);
	n += cbor_write_map_header(buf + n, entries);
	n += cbor_write_tstr(buf + n, "ft", 2);
	n += cbor_write_uint(buf + n, c->fault_type);
	n += cbor_write_tstr(buf + n, "pc", 2);
	n += cbor_write_uint(buf + n, c->pc);
	n += cbor_write_tstr(buf + n, "lr", 2);
	n += cbor_write_uint(buf + n, c->lr);
	if (c->build_id[0] != '\0') {
		n += cbor_write_tstr(buf + n, "bi", 2);
		n += cbor_write_tstr(buf + n, c->build_id, strlen(c->build_id));
	}
	if (c->reg_count > 0) {
		n += cbor_write_tstr(buf + n, "rg", 2);
		n += cbor_write_array_header(buf + n, c->reg_count);
		for (uint8_t i = 0; i < c->reg_count; i++) {
			n += cbor_write_uint(buf + n, c->regs[i]);
		}
	}
	if (c->stack_count > 0) {
		n += cbor_write_tstr(buf + n, "st", 2);
		n += cbor_write_array_header(buf + n, c->stack_count);
		for (uint8_t i = 0; i < c->stack_count; i++) {
			n += cbor_write_uint(buf + n, c->stack[i]);
		}
	}
	if (c->breadcrumb_len > 0) {
		n += cbor_write_tstr(buf + n, "bc", 2);
		n += cbor_write_tstr(buf + n, c->breadcrumbs, c->breadcrumb_len);
	}
	return n;
}

/* Device info as a nested CBOR map under integer key 23 (deviceapi deviceinfo.go).
 * Short text sub-keys (bd/mf/im/ic); an empty field is omitted so a device that
 * cannot read (say) the ICCID still reports the rest. */
static size_t encode_device_info(const struct cloud_telemetry_device_info *d, uint8_t *buf)
{
	const struct {
		const char *key;
		const char *val;
	} fields[] = {
		{ "bd", d->board },
		{ "mf", d->modem_fw },
		{ "im", d->imei },
		{ "ic", d->iccid },
	};
	size_t entries = 0;
	size_t n = 0;

	for (size_t i = 0; i < ARRAY_SIZE(fields); i++) {
		if (fields[i].val[0] != '\0') {
			entries++;
		}
	}

	n += cbor_write_uint(buf + n, 23);
	n += cbor_write_map_header(buf + n, entries);
	for (size_t i = 0; i < ARRAY_SIZE(fields); i++) {
		if (fields[i].val[0] == '\0') {
			continue;
		}
		n += cbor_write_tstr(buf + n, fields[i].key, strlen(fields[i].key));
		n += cbor_write_tstr(buf + n, fields[i].val, strlen(fields[i].val));
	}
	return n;
}

/* Worst-case nested map sizes (key + map header + entries). Vitals: key 21 (1) +
 * map header (1) + up to MAX_VITALS entries of a 2-char key (3) plus a 5-byte
 * value (0x1a + uint32) = 8 bytes each. */
#define CLOUD_TELEMETRY_RESET_CBOR_MAX  48
/* Device info: key 23 (1) + map header (1) + 4 entries, each a <=3-byte text key
 * plus a text value that fits its struct field (<=40 chars + 2-byte header). */
#define CLOUD_TELEMETRY_DEVINFO_CBOR_MAX (2 + 4 * (3 + 2 + 40))
#define CLOUD_TELEMETRY_VITALS_CBOR_MAX (2 + CLOUD_TELEMETRY_MAX_VITALS * 8)
#define CLOUD_TELEMETRY_CRASH_CBOR_MAX \
	(32 + 46 /* "bi" + 40-hex build-id */ + \
	 (CLOUD_TELEMETRY_MAX_CRASH_REGS + CLOUD_TELEMETRY_MAX_CRASH_STACK) * 5 + \
	 CLOUD_TELEMETRY_MAX_BREADCRUMB + 4)

static size_t encode_telemetry(const struct cloud_telemetry *t, uint8_t *buf, size_t buf_size)
{
	size_t entries = (t->has_transport ? 1 : 0) + (t->fw_version ? 1 : 0) +
			 (t->has_timestamp ? 1 : 0) + t->metric_count +
			 (t->gnss.valid ? 1 : 0) + (t->cell.valid ? 1 : 0) +
			 (t->wifi.valid ? 1 : 0) + (t->reset.valid ? 1 : 0) +
			 (t->vitals.valid ? 1 : 0) + (t->crash.valid ? 1 : 0) +
			 (t->device_info.valid ? 1 : 0);
	size_t reserve = 24;
	size_t n = 0;

	/* Reserve from the ACTUAL element counts, not the per-section maxima. The
	 * worst-case maxima (10 neighbor cells, 24 vitals, 256-byte breadcrumb, ...)
	 * sum well past this buffer, so a crash-boot post that also carries a cell
	 * scan would be rejected here with 0 -> -ENOMEM even though the real payload
	 * is a few hundred bytes. Each per-element multiplier still upper-bounds that
	 * element's encoded size, so the "reserve >= actual" overflow guarantee holds. */
	if (t->gnss.valid) {
		reserve += CLOUD_TELEMETRY_GNSS_CBOR_MAX;
	}
	if (t->cell.valid) {
		reserve += 64 + t->cell.ncells * 36;
	}
	if (t->wifi.valid) {
		reserve += 4 + t->wifi.count * 16;
	}
	if (t->reset.valid) {
		reserve += CLOUD_TELEMETRY_RESET_CBOR_MAX;
	}
	if (t->vitals.valid) {
		reserve += 2 + t->vitals.count * 8;
	}
	if (t->crash.valid) {
		reserve += 32 + (t->crash.build_id[0] != '\0' ? 46 : 0) +
			   (t->crash.reg_count + t->crash.stack_count) * 5 +
			   t->crash.breadcrumb_len + 4;
	}
	if (t->device_info.valid) {
		reserve += CLOUD_TELEMETRY_DEVINFO_CBOR_MAX;
	}

	/* Size estimate = map header + scalar entries (each key+value) + fw string +
	 * the nested-section reserves above. NOT `entries * 12`: that multiplier
	 * double-counted the nested sections (cell/wifi/reset/vitals/crash), which
	 * are already fully reserved and each write their own key, so a crash-boot
	 * post carrying a location scan estimated ~150 B over its true size and was
	 * wrongly rejected with 0 -> -ENOMEM. Scalars: transport/timestamp key+uint
	 * <= 10 B; each metric key(uint16 <= 3) + double/uint(<= 9) = 12 B; fw is a
	 * tstr < 24 B (key + header + chars <= 26). */
	size_t est = 1 /* map header, entries < 24 */ + reserve +
		     (t->has_transport ? 10 : 0) + (t->has_timestamp ? 10 : 0) +
		     (t->fw_version ? 26 : 0) + t->metric_count * 12;

	if (entries >= 24 || buf_size < est) {
		LOG_WRN("telemetry won't fit: est=%u buf=%u entries=%u "
			"(g=%d c=%d/%u w=%d/%u r=%d v=%d/%u x=%d d=%d)",
			(unsigned)est, (unsigned)buf_size, (unsigned)entries,
			t->gnss.valid, t->cell.valid, (unsigned)t->cell.ncells,
			t->wifi.valid, (unsigned)t->wifi.count, t->reset.valid,
			t->vitals.valid, (unsigned)t->vitals.count, t->crash.valid,
			t->device_info.valid);
		return 0;
	}

	n += cbor_write_map_header(buf + n, entries);
	if (t->has_transport) {
		n += cbor_write_uint(buf + n, 1);
		n += cbor_write_uint(buf + n, (uint64_t)t->transport);
	}
	if (t->fw_version) {
		size_t vlen = strlen(t->fw_version);

		if (vlen >= 24) {
			return 0;
		}
		n += cbor_write_uint(buf + n, 2);
		n += cbor_write_tstr(buf + n, t->fw_version, vlen);
	}
	if (t->has_timestamp) {
		n += cbor_write_uint(buf + n, 3);
		n += cbor_write_uint(buf + n, t->timestamp);
	}
	for (size_t i = 0; i < t->metric_count; i++) {
		n += cbor_write_uint(buf + n, t->metrics[i].key);
		if (t->metrics[i].type == CLOUD_METRIC_DOUBLE) {
			n += cbor_write_double(buf + n, t->metrics[i].value.d);
		} else {
			n += cbor_write_uint(buf + n, t->metrics[i].value.u);
		}
	}
	if (t->gnss.valid) {
		n += encode_gnss(&t->gnss, buf + n);
	}
	if (t->cell.valid) {
		n += encode_cell(&t->cell, buf + n);
	}
	if (t->wifi.valid) {
		n += encode_wifi(&t->wifi, buf + n);
	}
	if (t->reset.valid) {
		n += encode_reset(&t->reset, buf + n);
	}
	if (t->vitals.valid) {
		n += encode_vitals(&t->vitals, buf + n);
	}
	if (t->crash.valid) {
		n += encode_crash(&t->crash, buf + n);
	}
	if (t->device_info.valid) {
		n += encode_device_info(&t->device_info, buf + n);
	}
	return n;
}

static int decode_shadow_delta(const uint8_t *body, size_t body_len,
			       struct cloud_shadow_delta *out)
{
	struct cbor_reader r;
	uint8_t major;
	uint64_t nentries;
	bool have_version = false;

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
		if (key == SHADOW_KEY_VERSION) {
			uint8_t vmaj;
			uint64_t v;

			if (cbor_read_head(&r, &vmaj, &v) != 0 || vmaj != CBOR_MAJOR_UINT) {
				return -EINVAL;
			}
			out->desired_version = v;
			have_version = true;
		} else if (key == SHADOW_KEY_DIFF) {
			uint8_t dmaj;
			uint64_t dn;

			if (cbor_read_head(&r, &dmaj, &dn) != 0 || dmaj != CBOR_MAJOR_MAP) {
				return -EINVAL;
			}
			for (uint64_t j = 0; j < dn; j++) {
				struct cloud_shadow_entry *e =
					out->entry_count < CLOUD_SHADOW_MAX_ENTRIES
						? &out->entries[out->entry_count]
						: NULL;
				uint8_t tmaj;
				uint64_t klen;
				size_t kstart = r.pos;

				if (cbor_read_head(&r, &tmaj, &klen) != 0 ||
				    tmaj != CBOR_MAJOR_TSTR || r.pos + klen > r.len) {
					r.pos = kstart;
					if (cbor_skip(&r) != 0 || cbor_skip(&r) != 0) {
						return -EINVAL;
					}
					continue;
				}
				if (e) {
					int kn = (int)MIN(klen, sizeof(e->key) - 1);

					memcpy(e->key, &r.buf[r.pos], kn);
					e->key[kn] = '\0';
				}
				r.pos += klen;
				if (e) {
					cbor_render_value(&r, e->value, sizeof(e->value));
					out->entry_count++;
				} else {
					(void)cbor_skip(&r);
				}
			}
		} else {
			if (cbor_skip(&r) != 0) {
				return -EINVAL;
			}
		}
	}
	return have_version ? 0 : -EINVAL;
}

int cloud_client_post_telemetry(const struct cloud_telemetry *t, struct cloud_downlink *dl)
{
	uint8_t *cbor = telemetry_cbor_buf;
	size_t n = encode_telemetry(t, cbor, CLOUD_TELEMETRY_CBOR_MAX);
	struct coap_oscore_response resp;
	int err;

	if (n == 0) {
		return -ENOMEM;
	}

	err = coap_oscore_request(COAP_METHOD_POST, COAP_TYPE_CON, "t", cbor, n, &resp);
	if (err) {
		return err;
	}

	if (!dl) {
		return 0;
	}
	memset(dl, 0, sizeof(*dl));
	dl->response_code = resp.code;

	if (!resp.payload || resp.payload_len == 0) {
		return 0;
	}

	struct cbor_reader r;
	uint8_t major;
	uint64_t nentries;

	cbor_reader_init(&r, resp.payload, resp.payload_len);
	if (cbor_read_head(&r, &major, &nentries) != 0 || major != CBOR_MAJOR_MAP) {
		return 0;
	}
	for (uint64_t i = 0; i < nentries; i++) {
		uint8_t kmaj;
		uint64_t key;

		if (cbor_read_head(&r, &kmaj, &key) != 0 || kmaj != CBOR_MAJOR_UINT) {
			break;
		}
		if (key == ENVELOPE_KEY_FLAGS) {
			uint8_t vmaj;
			uint64_t v;

			if (cbor_read_head(&r, &vmaj, &v) != 0 || vmaj != CBOR_MAJOR_UINT) {
				break;
			}
			dl->shadow_delta_pending = v & ENVELOPE_FLAG_SHADOW_DELTA;
			dl->fota_job_pending = v & ENVELOPE_FLAG_FOTA_JOB;
		} else if (key == ENVELOPE_KEY_DELTA) {
			size_t start = r.pos;

			if (cbor_skip(&r) != 0) {
				break;
			}
			if (decode_shadow_delta(&resp.payload[start], r.pos - start,
						&g_inline_delta) == 0) {
				dl->has_inline_delta = true;
			}
		} else {
			if (cbor_skip(&r) != 0) {
				break;
			}
		}
	}

	return 0;
}

int cloud_client_post_telemetry_non(const struct cloud_telemetry *t)
{
	uint8_t *cbor = telemetry_cbor_buf;
	size_t n = encode_telemetry(t, cbor, CLOUD_TELEMETRY_CBOR_MAX);

	if (n == 0) {
		return -ENOMEM;
	}
	return coap_oscore_request(COAP_METHOD_POST, COAP_TYPE_NON, "t", cbor, n, NULL);
}

int cloud_client_fetch_shadow_delta(struct cloud_shadow_delta *delta)
{
	struct coap_oscore_response resp;
	int err;

	if (!delta) {
		return -EINVAL;
	}

	memset(delta, 0, sizeof(*delta));

	err = coap_oscore_request(COAP_METHOD_GET, COAP_TYPE_CON, "s", NULL, 0, &resp);
	if (err) {
		return err;
	}

	if (!resp.payload || resp.payload_len == 0) {
		return 0;
	}

	return decode_shadow_delta(resp.payload, resp.payload_len, delta);
}

int cloud_client_report_shadow(uint64_t version, const struct cloud_shadow_entry *entries,
			       size_t entry_count)
{
	uint8_t cbor[128];
	size_t n = 0;
	struct coap_oscore_response resp;
	int err;

	if (entry_count > CLOUD_SHADOW_MAX_ENTRIES) {
		return -EINVAL;
	}

	n += cbor_write_map_header(cbor + n, entry_count > 0 ? 2 : 1);
	n += cbor_write_uint(cbor + n, SHADOW_KEY_VERSION);
	n += cbor_write_uint(cbor + n, version);

	if (entry_count > 0) {
		n += cbor_write_uint(cbor + n, SHADOW_KEY_DIFF);
		n += cbor_write_map_header(cbor + n, entry_count);
		for (size_t i = 0; i < entry_count; i++) {
			size_t klen = strlen(entries[i].key);
			uint64_t val = strtoull(entries[i].value, NULL, 10);

			if (klen >= 24 || n + 1 + klen + 9 > sizeof(cbor)) {
				return -ENOMEM;
			}
			n += cbor_write_tstr(cbor + n, entries[i].key, klen);
			n += cbor_write_uint(cbor + n, val);
		}
	}

	err = coap_oscore_request(COAP_METHOD_POST, COAP_TYPE_CON, "s", cbor, n, &resp);
	if (err) {
		return err;
	}

	LOG_DBG("POST /s report code=%u", resp.code);
	return 0;
}

int cloud_client_ack_shadow(uint64_t version)
{
	return cloud_client_report_shadow(version, NULL, 0);
}

int cloud_client_sync_shadow(cloud_shadow_cb cb, void *user)
{
	struct cloud_shadow_delta delta;
	int err;

	err = cloud_client_fetch_shadow_delta(&delta);
	if (err) {
		return err;
	}

	if (delta.entry_count == 0 && delta.desired_version == 0) {
		return 0;
	}

	if (cb) {
		cb(&delta, user);
	}
	return cloud_client_ack_shadow(delta.desired_version);
}

const struct cloud_shadow_delta *cloud_client_inline_delta(void)
{
	return &g_inline_delta;
}

int cloud_client_process_downlink(const struct cloud_downlink *dl, cloud_shadow_cb cb, void *user)
{
	/* FOTA is no longer driven here. A pending FOTA job is handled by the
	 * cloud module's message loop via fota_client_step(), so the long Block2
	 * download is split into chunks and telemetry/shadow traffic interleaves
	 * between them instead of being starved for the whole download.
	 */
	if (dl->has_inline_delta) {
		if (cb) {
			cb(&g_inline_delta, user);
		}
		return cloud_client_ack_shadow(g_inline_delta.desired_version);
	}
	if (dl->shadow_delta_pending) {
		return cloud_client_sync_shadow(cb, user);
	}
	return 0;
}

/* ------------------------------------------------------------------------
 * Shell: coap [bearer auto|tn|ntn] [impair <tx%> <rx%> <delay_ms>] [reset]
 * ------------------------------------------------------------------------ */
#if defined(CONFIG_SHELL)
static int cmd_coap_show(const struct shell *sh, size_t argc, char **argv)
{
	const struct xmit_profile *p = xmit_profile();

	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	shell_print(sh, "bearer %s (detected %s, override %s)",
		    cloud_client_transport() == CLOUD_TRANSPORT_NTN ? "NTN" : "TN",
		    g_bearer_detected == CLOUD_TRANSPORT_NTN ? "NTN" : "TN",
		    g_bearer_override == BEARER_AUTO ? "auto" :
		    g_bearer_override == BEARER_FORCE_TN ? "tn" : "ntn");
	shell_print(sh, "ACK timeout %u ms, max retransmit %u, token %u B", p->ack_timeout_ms,
		    p->max_retransmit, COAP_TOKEN_LEN);
	shell_print(sh, "requests %u retransmits %u timeouts %u stale %u empty_acks %u "
		    "con_acked %u rtt last %u max %u ms",
		    g_xstats.requests, g_xstats.retransmits, g_xstats.timeouts, g_xstats.stale,
		    g_xstats.empty_acks, g_xstats.con_acked, g_xstats.last_rtt_ms,
		    g_xstats.max_rtt_ms);
#if defined(CONFIG_OSCORE_CLOUD_TEST_IMPAIR)
	shell_print(sh, "impair tx %u%% rx %u%% delay %u ms (dropped tx %u rx %u)",
		    g_impair.tx_drop_pct, g_impair.rx_drop_pct, g_impair.delay_ms,
		    g_impair.tx_dropped, g_impair.rx_dropped);
#endif
	return 0;
}

static int cmd_coap_bearer(const struct shell *sh, size_t argc, char **argv)
{
	if (argc != 2) {
		shell_error(sh, "usage: coap bearer auto|tn|ntn");
		return -EINVAL;
	}
	if (strcmp(argv[1], "auto") == 0) {
		g_bearer_override = BEARER_AUTO;
	} else if (strcmp(argv[1], "tn") == 0) {
		g_bearer_override = BEARER_FORCE_TN;
	} else if (strcmp(argv[1], "ntn") == 0) {
		g_bearer_override = BEARER_FORCE_NTN;
	} else {
		shell_error(sh, "usage: coap bearer auto|tn|ntn");
		return -EINVAL;
	}
	log_bearer();
	return cmd_coap_show(sh, 1, argv);
}

static int cmd_coap_reset(const struct shell *sh, size_t argc, char **argv)
{
	memset(&g_xstats, 0, sizeof(g_xstats));
#if defined(CONFIG_OSCORE_CLOUD_TEST_IMPAIR)
	g_impair.tx_dropped = 0;
	g_impair.rx_dropped = 0;
#endif
	return cmd_coap_show(sh, argc, argv);
}

#if defined(CONFIG_OSCORE_CLOUD_TEST_IMPAIR)
static int cmd_coap_impair(const struct shell *sh, size_t argc, char **argv)
{
	if (argc != 4) {
		shell_error(sh, "usage: coap impair <tx_drop_%%> <rx_drop_%%> <delay_ms>");
		return -EINVAL;
	}
	g_impair.tx_drop_pct = (uint8_t)MIN(strtoul(argv[1], NULL, 10), 100UL);
	g_impair.rx_drop_pct = (uint8_t)MIN(strtoul(argv[2], NULL, 10), 100UL);
	g_impair.delay_ms = (uint32_t)strtoul(argv[3], NULL, 10);
	return cmd_coap_show(sh, 1, argv);
}

static int cmd_coap_burst(const struct shell *sh, size_t argc, char **argv)
{
	g_impair.burst_skip = (uint32_t)strtoul(argv[1], NULL, 10);
	g_impair.burst_drop = (uint32_t)strtoul(argv[2], NULL, 10);
	shell_print(sh, "next %u datagram(s) pass, then %u are dropped", g_impair.burst_skip,
		    g_impair.burst_drop);
	return 0;
}
#endif

SHELL_STATIC_SUBCMD_SET_CREATE(
	coap_cmds,
	SHELL_CMD(bearer, NULL, "Force the bearer profile: auto|tn|ntn", cmd_coap_bearer),
#if defined(CONFIG_OSCORE_CLOUD_TEST_IMPAIR)
	SHELL_CMD(impair, NULL, "Test impairment: <tx_drop_%> <rx_drop_%> <delay_ms>",
		  cmd_coap_impair),
	SHELL_CMD_ARG(burst, NULL, "Test: let <skip> datagrams pass, then drop <n>",
		      cmd_coap_burst, 3, 0),
#endif
	SHELL_CMD(reset, NULL, "Reset the counters", cmd_coap_reset),
	SHELL_SUBCMD_SET_END);

SHELL_CMD_REGISTER(coap, &coap_cmds, "CoAP transport: bearer, timeouts, counters",
		   cmd_coap_show);
#endif /* CONFIG_SHELL */
