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

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/socket.h>

#include <errno.h>
#include <stdio.h>
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

/* Bound on how long a single (non-Block2) request waits for its response.
 * poll() is used instead of SO_RCVTIMEO, which the nRF91 offloaded socket
 * mishandles (see BLOCK2_RECV_TIMEOUT_MS note). Without this cap, a CON response
 * lost in marginal coverage blocks the cloud thread in recvfrom() indefinitely,
 * starving the task-watchdog feed and forcing a reboot loop. The timeout
 * comfortably exceeds the eDRX cycle (5.12 s). */
#define REQUEST_RECV_TIMEOUT_MS 10000

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

	return 0;
}

void cloud_client_deinit(void)
{
	if (g_sock >= 0) {
		(void)zsock_close(g_sock);
		g_sock = -1;
	}
}

static void server_addr(struct sockaddr_in *server)
{
	memset(server, 0, sizeof(*server));
	server->sin_family = AF_INET;
	server->sin_port = htons(g_cfg.server_port);
	zsock_inet_pton(AF_INET, g_cfg.server_ip, &server->sin_addr);
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
	 * SO_RCVTIMEO (see BLOCK2_RECV_TIMEOUT_MS note). When poll reports data the
	 * recvfrom returns immediately. */
	while (count < 16) {
		struct zsock_pollfd pfd = { .fd = g_sock, .events = ZSOCK_POLLIN };
		int pr = zsock_poll(&pfd, 1, 0);

		if (pr <= 0 || !(pfd.revents & ZSOCK_POLLIN)) {
			break;
		}
		if (zsock_recvfrom(g_sock, recv_buf, sizeof(recv_buf), 0, NULL, NULL) < 0) {
			break;
		}
		count++;
	}
	if (count > 0) {
		LOG_WRN("flushed %d stale datagram(s) before request", count);
	}
}

static int oscore_recv_response(const char *path, struct coap_oscore_response *resp,
				struct coap_packet *parsed)
{
	struct sockaddr_in from;
	socklen_t fromlen = sizeof(from);
	ssize_t received;
	size_t recv_len;
	struct coap_packet local;
	int err;

	received = zsock_recvfrom(g_sock, recv_buf, sizeof(recv_buf), 0,
				  (struct sockaddr *)&from, &fromlen);
	if (received < 0) {
		LOG_ERR("recvfrom %s: %d", path, -errno);
		return -errno;
	}

	recv_len = (size_t)received;
	err = oscore_wrapper_unprotect(recv_buf, &recv_len, sizeof(recv_buf));
	if (err) {
		LOG_ERR("oscore unprotect %s (%u B wire): %d", path, (unsigned)received, err);
		return err;
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

static int coap_oscore_request(uint8_t method, uint8_t coap_type, const char *path,
			       const uint8_t *payload, size_t payload_len,
			       struct coap_oscore_response *resp)
{
	struct sockaddr_in server;
	struct coap_packet request;
	ssize_t len;
	int err;

	server_addr(&server);

	err = coap_packet_init(&request, coap_buf, sizeof(coap_buf), COAP_VERSION_1,
			       coap_type, 8, coap_next_token(), method, coap_next_id());
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

	flush_rx();

	ssize_t sent = zsock_sendto(g_sock, coap_buf, len, 0,
				    (struct sockaddr *)&server, sizeof(server));
	if (sent != len) {
		LOG_ERR("sendto %s: %zd", path, sent);
		return -EIO;
	}

	/* NON requests have no response; do not block on recv. */
	if (coap_type == COAP_TYPE_NON && !resp) {
		return 0;
	}

	/* Cap the response wait so a lost datagram cannot hang the cloud thread
	 * (and trip the watchdog). On timeout the caller treats it as a network
	 * error and rebuilds the connection. */
	struct zsock_pollfd pfd = { .fd = g_sock, .events = ZSOCK_POLLIN };
	int pr = zsock_poll(&pfd, 1, REQUEST_RECV_TIMEOUT_MS);

	if (pr == 0) {
		LOG_WRN("recv timeout %s", path);
		return -EAGAIN;
	}
	if (pr < 0) {
		LOG_ERR("poll %s: %d", path, -errno);
		return -errno;
	}
	if (!(pfd.revents & ZSOCK_POLLIN)) {
		LOG_ERR("poll %s: revents 0x%x", path, pfd.revents);
		return -EIO;
	}

	return oscore_recv_response(path, resp, NULL);
}

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

/* Per-block receive budget and retransmit count. A long FOTA download (~800
 * CON request/response exchanges over LTE-M) will eventually hit a lost
 * datagram; without a bounded wait + retransmit the cloud thread blocks in
 * recvfrom forever, which also starves telemetry (same thread). zsock_poll()
 * is used instead of SO_RCVTIMEO because the latter is mishandled by the nRF91
 * offloaded socket. The timeout comfortably exceeds the eDRX cycle (5.12 s).
 */
#define BLOCK2_RECV_TIMEOUT_MS 10000
#define BLOCK2_MAX_RETRIES     5

/* Build, OSCORE-protect, and send one Block2 GET request. Each call advances
 * the OSCORE sequence number, so a retransmit is a fresh request (a late
 * response to a prior attempt simply fails verification and is retried). */
static int block2_send_request(const char *path, uint32_t block_num, uint8_t szx)
{
	struct sockaddr_in server;
	struct coap_packet request;
	ssize_t len;
	int err;

	server_addr(&server);
	err = coap_packet_init(&request, coap_buf, sizeof(coap_buf), COAP_VERSION_1,
			       COAP_TYPE_CON, 8, coap_next_token(), COAP_METHOD_GET,
			       coap_next_id());
	if (err) {
		return err;
	}
	err = append_uri_path(&request, path);
	if (err) {
		return err;
	}
	err = append_block2_option(&request, block_num, szx);
	if (err) {
		return err;
	}

	len = request.offset;
	err = oscore_wrapper_protect(coap_buf, (size_t *)&len, sizeof(coap_buf));
	if (err) {
		LOG_ERR("oscore protect block2 %s blk %u: %d", path, block_num, err);
		return err;
	}

	flush_rx();

	ssize_t sent = zsock_sendto(g_sock, coap_buf, len, 0,
				    (struct sockaddr *)&server, sizeof(server));
	if (sent != len) {
		LOG_ERR("block2 sendto %s blk %u: %zd", path, block_num, sent);
		return -EIO;
	}
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
		int attempts = 0;
		bool got = false;

		err = block2_send_request(path, block_num, szx);
		if (err) {
			return err;
		}

		while (!got) {
			oscore_cloud_feed_wdt();

			struct zsock_pollfd pfd = { .fd = g_sock, .events = ZSOCK_POLLIN };
			int pr = zsock_poll(&pfd, 1, BLOCK2_RECV_TIMEOUT_MS);

			if (pr < 0) {
				LOG_ERR("block2 poll %s blk %u: %d", path, block_num, -errno);
				return -errno;
			}
			if (pr == 0 || !(pfd.revents & ZSOCK_POLLIN)) {
				if (++attempts > BLOCK2_MAX_RETRIES) {
					LOG_ERR("block2 %s blk %u: no response after %d attempts",
						path, block_num, attempts);
					return -ETIMEDOUT;
				}
				LOG_WRN("block2 %s blk %u: recv timeout, retransmit %d/%d",
					path, block_num, attempts, BLOCK2_MAX_RETRIES);
				err = block2_send_request(path, block_num, szx);
				if (err) {
					return err;
				}
				continue;
			}

			err = oscore_recv_response(path, &resp, &response);
			if (err) {
				/* Stale/duplicate/garbled datagram (e.g. a late response
				 * to a previous attempt that fails OSCORE verification).
				 * Recoverable: retransmit and keep waiting.
				 */
				if (++attempts > BLOCK2_MAX_RETRIES) {
					LOG_ERR("block2 %s blk %u: recv error %d after retries",
						path, block_num, err);
					return err;
				}
				LOG_WRN("block2 %s blk %u: recv error %d, retransmit %d/%d",
					path, block_num, err, attempts, BLOCK2_MAX_RETRIES);
				err = block2_send_request(path, block_num, szx);
				if (err) {
					return err;
				}
				continue;
			}

			if (resp.code != COAP_RESPONSE_CODE_CONTENT) {
				LOG_ERR("block2 GET %s blk %u: code 0x%02x", path, block_num,
					resp.code);
				return -EIO;
			}
			got = true;
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

/* Build, OSCORE-protect, and send one Block2 POST request. The CBOR request body
 * is included only on block 0 (matching the server, which decodes the request on
 * the first POST and serves continuation blocks from its per-device cache);
 * later blocks are empty POSTs carrying just the incremented Block2 option. */
static int block2_post_send_request(const char *path, uint32_t block_num, uint8_t szx,
				    const uint8_t *body, size_t body_len)
{
	struct sockaddr_in server;
	struct coap_packet request;
	ssize_t len;
	int err;

	server_addr(&server);
	err = coap_packet_init(&request, coap_buf, sizeof(coap_buf), COAP_VERSION_1,
			       COAP_TYPE_CON, 8, coap_next_token(), COAP_METHOD_POST,
			       coap_next_id());
	if (err) {
		return err;
	}
	err = append_uri_path(&request, path);
	if (err) {
		return err;
	}
	err = append_block2_option(&request, block_num, szx);
	if (err) {
		return err;
	}

	if (block_num == 0 && body && body_len > 0) {
		err = coap_append_option_int(&request, COAP_OPTION_CONTENT_FORMAT,
					     COAP_CONTENT_FORMAT_APPLICATION_CBOR);
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
	}

	len = request.offset;
	err = oscore_wrapper_protect(coap_buf, (size_t *)&len, sizeof(coap_buf));
	if (err) {
		LOG_ERR("oscore protect block2 post %s blk %u: %d", path, block_num, err);
		return err;
	}

	flush_rx();

	ssize_t sent = zsock_sendto(g_sock, coap_buf, len, 0,
				    (struct sockaddr *)&server, sizeof(server));
	if (sent != len) {
		LOG_ERR("block2 post sendto %s blk %u: %zd", path, block_num, sent);
		return -EIO;
	}
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
		int attempts = 0;
		bool got = false;

		err = block2_post_send_request(path, block_num, szx, body, body_len);
		if (err) {
			return err;
		}

		while (!got) {
			oscore_cloud_feed_wdt();

			struct zsock_pollfd pfd = { .fd = g_sock, .events = ZSOCK_POLLIN };
			int pr = zsock_poll(&pfd, 1, BLOCK2_RECV_TIMEOUT_MS);

			if (pr < 0) {
				LOG_ERR("block2 post poll %s blk %u: %d", path, block_num, -errno);
				return -errno;
			}
			if (pr == 0 || !(pfd.revents & ZSOCK_POLLIN)) {
				if (++attempts > BLOCK2_MAX_RETRIES) {
					LOG_ERR("block2 post %s blk %u: no response after %d",
						path, block_num, attempts);
					return -ETIMEDOUT;
				}
				LOG_WRN("block2 post %s blk %u: timeout, retransmit %d/%d",
					path, block_num, attempts, BLOCK2_MAX_RETRIES);
				err = block2_post_send_request(path, block_num, szx, body,
							       body_len);
				if (err) {
					return err;
				}
				continue;
			}

			err = oscore_recv_response(path, &resp, &response);
			if (err) {
				if (++attempts > BLOCK2_MAX_RETRIES) {
					LOG_ERR("block2 post %s blk %u: recv error %d",
						path, block_num, err);
					return err;
				}
				LOG_WRN("block2 post %s blk %u: recv error %d, retransmit %d/%d",
					path, block_num, err, attempts, BLOCK2_MAX_RETRIES);
				err = block2_post_send_request(path, block_num, szx, body,
							       body_len);
				if (err) {
					return err;
				}
				continue;
			}

			if (resp.code != COAP_RESPONSE_CODE_CONTENT &&
			    resp.code != COAP_RESPONSE_CODE_CHANGED) {
				LOG_ERR("block2 POST %s blk %u: code 0x%02x", path, block_num,
					resp.code);
				return -EIO;
			}
			got = true;
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

/* Build, OSCORE-protect and send one Block1 POST carrying [chunk, chunk_len). */
static int block1_send_request(const char *path, uint32_t block_num, uint8_t szx, bool more,
			       const uint8_t *chunk, size_t chunk_len)
{
	struct sockaddr_in server;
	struct coap_packet request;
	ssize_t len;
	int err;

	server_addr(&server);
	err = coap_packet_init(&request, coap_buf, sizeof(coap_buf), COAP_VERSION_1,
			       COAP_TYPE_CON, 8, coap_next_token(), COAP_METHOD_POST,
			       coap_next_id());
	if (err) {
		return err;
	}
	err = append_uri_path(&request, path);
	if (err) {
		return err;
	}
	err = append_block1_option(&request, block_num, szx, more);
	if (err) {
		return err;
	}
	if (chunk && chunk_len > 0) {
		err = coap_append_option_int(&request, COAP_OPTION_CONTENT_FORMAT,
					     COAP_CONTENT_FORMAT_APPLICATION_CBOR);
		if (err) {
			return err;
		}
		err = coap_packet_append_payload_marker(&request);
		if (err) {
			return err;
		}
		err = coap_packet_append_payload(&request, chunk, chunk_len);
		if (err) {
			return err;
		}
	}

	len = request.offset;
	err = oscore_wrapper_protect(coap_buf, (size_t *)&len, sizeof(coap_buf));
	if (err) {
		LOG_ERR("oscore protect block1 %s blk %u: %d", path, block_num, err);
		return err;
	}

	flush_rx();
	ssize_t sent = zsock_sendto(g_sock, coap_buf, len, 0,
				    (struct sockaddr *)&server, sizeof(server));
	if (sent != len) {
		LOG_ERR("block1 sendto %s blk %u: %zd", path, block_num, sent);
		return -EIO;
	}
	return 0;
}

int cloud_client_oscore_block1_post(const char *path, size_t total_len, uint8_t szx,
				    cloud_block1_source source, void *ctx)
{
	const size_t block_size = (size_t)16U << (szx & 0x07U);
	static uint8_t chunk[1024];
	uint32_t block_num = 0;
	size_t offset = 0;
	int err;

	if (!path || !source || total_len == 0 || block_size > sizeof(chunk)) {
		return -EINVAL;
	}

	while (offset < total_len) {
		size_t want = MIN(block_size, total_len - offset);
		int got = source(chunk, want, offset, ctx);

		if (got <= 0) {
			LOG_ERR("block1 source %s @%zu: %d", path, offset, got);
			return got < 0 ? got : -EIO;
		}
		bool more = (offset + (size_t)got) < total_len;
		int attempts = 0;
		bool acked = false;

		err = block1_send_request(path, block_num, szx, more, chunk, (size_t)got);
		if (err) {
			return err;
		}

		while (!acked) {
			oscore_cloud_feed_wdt();

			struct zsock_pollfd pfd = { .fd = g_sock, .events = ZSOCK_POLLIN };
			int pr = zsock_poll(&pfd, 1, BLOCK2_RECV_TIMEOUT_MS);

			if (pr < 0) {
				return -errno;
			}
			if (pr == 0 || !(pfd.revents & ZSOCK_POLLIN)) {
				if (++attempts > BLOCK2_MAX_RETRIES) {
					LOG_ERR("block1 %s blk %u: no ack", path, block_num);
					return -ETIMEDOUT;
				}
				err = block1_send_request(path, block_num, szx, more, chunk,
							  (size_t)got);
				if (err) {
					return err;
				}
				continue;
			}

			struct coap_oscore_response resp;

			err = oscore_recv_response(path, &resp, NULL);
			if (err) {
				if (++attempts > BLOCK2_MAX_RETRIES) {
					return err;
				}
				err = block1_send_request(path, block_num, szx, more, chunk,
							  (size_t)got);
				if (err) {
					return err;
				}
				continue;
			}
			/* 2.31 Continue while more blocks expected, 2.04 Changed on done. */
			if (resp.code != COAP_RESPONSE_CODE_CHANGED &&
			    resp.code != 0x5F /* 2.31 Continue */) {
				LOG_ERR("block1 %s blk %u: code 0x%02x", path, block_num,
					resp.code);
				return -EIO;
			}
			acked = true;
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
