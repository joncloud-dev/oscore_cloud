/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Resumable, compressed coredump upload (terrestrial bearer only).
 *
 * Protocol (both requests OSCORE-protected, CBOR, int keys):
 *
 *   POST /c/o   open    {1: id (crc32 of raw dump), 2: encoded len, 3: raw len,
 *                        4: encoding (0 raw, 1 ZRL1), 5: crashing boot count,
 *                        6: fatal reason, 7: build-id bstr, 8: truncated,
 *                        9: Block1 SZX}
 *               -> 2.04 {1: next Block1 number the server expects,
 *                        2: true if it already holds the complete dump}
 *   POST /c/d   data    Block1 (RFC 7959) of the encoded stream, from block 1:n
 *
 * The server keeps the partial upload keyed by (device, id) across sessions and
 * reboots, so a link drop resumes at the next missing block instead of block 0.
 * A server without /c/o answers the open with 4.04; we then fall back to the
 * legacy raw Block1 upload to /c.
 *
 * ZRL1 encoding (wire contract with the server's decoder):
 *   header  'Z' 'R' 'L' '1', raw_len u32le, raw_crc32 u32le
 *   token   0x00..0x7F  literal: (t + 1) bytes follow
 *           0x80..0xFF  run: lo, value; count = ((t & 0x7F) << 8 | lo) + 4
 * RAM dumps are mostly 0x00 and 0xAA (stack fill), so runs dominate.
 *
 * The encoder is a deterministic stream over the stored dump: a Block1 source
 * asking for an offset behind the cursor restarts it from 0 and skips forward,
 * which is how a resumed upload re-derives bytes it never kept.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/coap.h>
#include <zephyr/sys/byteorder.h>

#include <oscore_cloud/cbor.h>
#include <oscore_cloud/cloud_client.h>
#include <oscore_cloud/cloud_config.h>
#include <oscore_cloud/diag.h>


LOG_MODULE_DECLARE(oscore_cloud_diag, CONFIG_OSCORE_CLOUD_DIAG_LOG_LEVEL);

#define SZX_1024   6U
#define BLOCK_SIZE 1024U

#define ZRL_HDR_LEN   12U
#define ZRL_MIN_RUN   4U
#define ZRL_MAX_RUN   (0x7FFFU + ZRL_MIN_RUN)
#define ZRL_MAX_LIT   128U

/* ---- Raw reader with a small window cache ---------------------------------- */

struct raw_reader {
	uint32_t size;
	uint32_t win_off;
	uint32_t win_len;
	uint8_t win[256];
	int err;
};

static int raw_byte(struct raw_reader *r, uint32_t pos)
{
	if (pos >= r->size) {
		return -1;
	}
	if (pos < r->win_off || pos >= r->win_off + r->win_len) {
		/* Start the window a little behind pos: the encoder's run lookahead
		 * crosses the window edge and then steps back to the literal cursor,
		 * which would otherwise refill the window twice per edge. */
		uint32_t start = pos - MIN(pos, 8U);
		uint32_t n = MIN(sizeof(r->win), r->size - start);
		int rc = diag_coredump_read(r->win, n, start);

		if (rc < 0) {
			r->err = rc;
			return -1;
		}
		r->win_off = start;
		r->win_len = n;
	}
	return r->win[pos - r->win_off];
}

/* ---- Streaming ZRL1 encoder ------------------------------------------------ */

struct zrl_enc {
	struct raw_reader in;
	uint32_t crc;
	uint32_t in_pos;
	uint32_t out_pos;
	uint8_t pend[1 + ZRL_MAX_LIT];
	uint16_t pend_len;
	uint16_t pend_idx;
	bool hdr_done;
};

static uint32_t run_len(struct zrl_enc *e, uint32_t pos)
{
	int b = raw_byte(&e->in, pos);
	uint32_t n = 0;

	if (b < 0) {
		return 0;
	}
	while (n < ZRL_MAX_RUN && raw_byte(&e->in, pos + n) == b) {
		n++;
	}
	return n;
}

static void zrl_reset(struct zrl_enc *e, uint32_t raw_size, uint32_t crc)
{
	memset(e, 0, sizeof(*e));
	e->in.size = raw_size;
	e->crc = crc;
}

/* Produce the next token into pend[]. Returns false at end of stream. */
static bool zrl_fill(struct zrl_enc *e)
{
	e->pend_idx = 0;
	e->pend_len = 0;

	if (!e->hdr_done) {
		uint8_t *p = e->pend;

		memcpy(p, "ZRL1", 4);
		sys_put_le32(e->in.size, p + 4);
		sys_put_le32(e->crc, p + 8);
		e->pend_len = ZRL_HDR_LEN;
		e->hdr_done = true;
		return true;
	}
	if (e->in_pos >= e->in.size || e->in.err) {
		return false;
	}

	uint32_t r = run_len(e, e->in_pos);

	if (r >= ZRL_MIN_RUN) {
		uint32_t c = r - ZRL_MIN_RUN;

		e->pend[0] = 0x80U | (uint8_t)(c >> 8);
		e->pend[1] = (uint8_t)c;
		e->pend[2] = (uint8_t)raw_byte(&e->in, e->in_pos);
		e->pend_len = 3;
		e->in_pos += r;
		return true;
	}

	/* Literal: take bytes until a run of >= ZRL_MIN_RUN starts or 128 bytes. */
	uint16_t n = 0;

	while (n < ZRL_MAX_LIT && e->in_pos < e->in.size) {
		if (n > 0 && run_len(e, e->in_pos) >= ZRL_MIN_RUN) {
			break;
		}
		int b = raw_byte(&e->in, e->in_pos);

		if (b < 0) {
			break;
		}
		e->pend[1 + n] = (uint8_t)b;
		n++;
		e->in_pos++;
	}
	if (n == 0) {
		return false;
	}
	e->pend[0] = (uint8_t)(n - 1U);
	e->pend_len = 1U + n;
	return true;
}

/* Copy up to `want` encoded bytes into buf (buf may be NULL to skip). */
static size_t zrl_read(struct zrl_enc *e, uint8_t *buf, size_t want)
{
	size_t got = 0;

	while (got < want) {
		if (e->pend_idx >= e->pend_len && !zrl_fill(e)) {
			break;
		}
		size_t n = MIN(want - got, (size_t)(e->pend_len - e->pend_idx));

		if (buf != NULL) {
			memcpy(buf + got, &e->pend[e->pend_idx], n);
		}
		e->pend_idx += n;
		got += n;
	}
	e->out_pos += got;
	return got;
}

/* ---- Block1 sources ------------------------------------------------------ */

static struct zrl_enc g_enc;
static struct diag_coredump_info g_ci;

static int zrl_source(uint8_t *buf, size_t want, size_t offset, void *ctx)
{
	ARG_UNUSED(ctx);

	if (offset < g_enc.out_pos) {
		zrl_reset(&g_enc, g_ci.size, g_ci.crc);
	}
	while (g_enc.out_pos < offset) {
		size_t skip = MIN(offset - g_enc.out_pos, (size_t)4096);

		if (zrl_read(&g_enc, NULL, skip) == 0) {
			return -EIO;
		}
		oscore_cloud_feed_wdt();
	}
	size_t n = zrl_read(&g_enc, buf, want);

	if (g_enc.in.err) {
		return g_enc.in.err;
	}
	return n > 0 ? (int)n : -EIO;
}

static int raw_source(uint8_t *buf, size_t want, size_t offset, void *ctx)
{
	ARG_UNUSED(ctx);
	return diag_coredump_read(buf, want, offset);
}

static uint32_t zrl_encoded_len(void)
{
	zrl_reset(&g_enc, g_ci.size, g_ci.crc);
	while (zrl_read(&g_enc, NULL, 4096) > 0) {
		oscore_cloud_feed_wdt();
	}
	uint32_t len = g_enc.in.err ? 0 : g_enc.out_pos;

	zrl_reset(&g_enc, g_ci.size, g_ci.crc);
	return len;
}

/* ---- Open handshake -------------------------------------------------------- */

static int open_session(uint32_t enc_len, uint8_t encoding, uint32_t *next_block,
			bool *complete)
{
	uint8_t req[96];
	uint8_t *p = req;
	size_t n = 8 + (g_ci.build_id_valid ? 1 : 0);

	p += cbor_write_map_header(p, n);
	p += cbor_write_uint(p, 1);
	p += cbor_write_uint(p, g_ci.crc);
	p += cbor_write_uint(p, 2);
	p += cbor_write_uint(p, enc_len);
	p += cbor_write_uint(p, 3);
	p += cbor_write_uint(p, g_ci.size);
	p += cbor_write_uint(p, 4);
	p += cbor_write_uint(p, encoding);
	p += cbor_write_uint(p, 5);
	p += cbor_write_uint(p, g_ci.boot_count);
	p += cbor_write_uint(p, 6);
	p += cbor_write_uint(p, g_ci.reason);
	if (g_ci.build_id_valid) {
		p += cbor_write_uint(p, 7);
		p += cbor_write_bstr(p, g_ci.build_id, sizeof(g_ci.build_id));
	}
	p += cbor_write_uint(p, 8);
	p += cbor_write_bool(p, g_ci.truncated);
	p += cbor_write_uint(p, 9);
	p += cbor_write_uint(p, SZX_1024);

	struct coap_oscore_response resp;
	int err = cloud_client_oscore_post("c/o", req, (size_t)(p - req), &resp);

	if (err) {
		return err;
	}
	if (resp.code == COAP_RESPONSE_CODE_NOT_FOUND) {
		return -ENOENT;
	}
	if (resp.code != COAP_RESPONSE_CODE_CHANGED) {
		LOG_WRN("coredump open: code 0x%02x", resp.code);
		return -EIO;
	}

	struct cbor_reader r;
	uint8_t major;
	uint64_t arg, pairs;

	*next_block = 0;
	*complete = false;
	cbor_reader_init(&r, resp.payload, resp.payload_len);
	if (cbor_read_head(&r, &major, &pairs) != 0 || major != CBOR_MAJOR_MAP) {
		return -EBADMSG;
	}
	for (uint64_t i = 0; i < pairs; i++) {
		uint64_t key;

		if (cbor_read_head(&r, &major, &key) != 0 || major != CBOR_MAJOR_UINT) {
			return -EBADMSG;
		}
		if (cbor_read_head(&r, &major, &arg) != 0) {
			return -EBADMSG;
		}
		if (key == 1 && major == CBOR_MAJOR_UINT) {
			*next_block = (uint32_t)arg;
		} else if (key == 2 && major == CBOR_MAJOR_SIMPLE) {
			*complete = (arg == 21); /* CBOR true */
		}
	}
	return 0;
}

int diag_coredump_upload(void)
{
	int size = diag_coredump_size();

	if (size <= 0) {
		return 0;
	}

	bool legacy = (diag_coredump_info(&g_ci) != 0 || g_ci.state != DIAG_COREDUMP_PENDING);
	uint8_t encoding = IS_ENABLED(CONFIG_OSCORE_CLOUD_DIAG_COREDUMP_COMPRESS) ? 1 : 0;
	uint32_t enc_len = (uint32_t)size;
	uint32_t next_block = 0;
	bool complete = false;
	int err;

	if (!legacy) {
		int64_t t0 = k_uptime_get();

		if (encoding == 1) {
			enc_len = zrl_encoded_len();
			if (enc_len == 0) {
				return -EIO;
			}
		}
		err = open_session(enc_len, encoding, &next_block, &complete);
		if (err == -ENOENT) {
			LOG_INF("server has no /c/o, using legacy coredump upload");
			legacy = true;
		} else if (err) {
			LOG_WRN("coredump open failed: %d", err);
			return err;
		} else {
			LOG_INF("Uploading coredump id %08x: %u B raw, %u B %s, boot %u, "
				"resume at block %u%s (prep %lld ms)",
				g_ci.crc, g_ci.size, enc_len, encoding ? "zrl1" : "raw",
				g_ci.boot_count, next_block, complete ? ", already complete" : "",
				k_uptime_get() - t0);
		}
	}

	if (legacy) {
		LOG_INF("Uploading stored coredump (%d bytes) over Block1 /c", size);
		err = cloud_client_oscore_block1_post("c", (size_t)size, SZX_1024, raw_source,
						      NULL);
	} else if (complete || (size_t)next_block * BLOCK_SIZE >= enc_len) {
		err = 0;
	} else {
		int64_t t0 = k_uptime_get();

		err = cloud_client_oscore_block1_post_from(
			"c/d", enc_len, SZX_1024, next_block,
			encoding ? zrl_source : raw_source, NULL);
		if (err == 0) {
			LOG_INF("coredump upload: %u blocks in %lld ms",
				DIV_ROUND_UP(enc_len, BLOCK_SIZE) - next_block,
				k_uptime_get() - t0);
		}
	}
	if (err) {
		LOG_WRN("coredump upload failed: %d (will resume next session)", err);
		return err;
	}

	diag_coredump_erase();
	LOG_INF("Coredump uploaded and erased from flash");
	return 0;
}
