/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Minimal CBOR codec. See cbor.h for the contract.
 */

#include <oscore_cloud/cbor.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

size_t cbor_write_uint(uint8_t *p, uint64_t v)
{
	if (v < 24U) {
		p[0] = (uint8_t)v;
		return 1;
	}
	if (v <= 0xffU) {
		p[0] = 0x18;
		p[1] = (uint8_t)v;
		return 2;
	}
	if (v <= 0xffffU) {
		p[0] = 0x19;
		p[1] = (uint8_t)(v >> 8);
		p[2] = (uint8_t)v;
		return 3;
	}
	if (v <= 0xffffffffU) {
		p[0] = 0x1a;
		p[1] = (uint8_t)(v >> 24);
		p[2] = (uint8_t)(v >> 16);
		p[3] = (uint8_t)(v >> 8);
		p[4] = (uint8_t)v;
		return 5;
	}
	p[0] = 0x1b;
	for (int i = 0; i < 8; i++) {
		p[1 + i] = (uint8_t)(v >> (56 - 8 * i));
	}
	return 9;
}

size_t cbor_write_int(uint8_t *p, int64_t v)
{
	if (v >= 0) {
		return cbor_write_uint(p, (uint64_t)v);
	}
	/* CBOR negative integer: major type 1, argument = -1 - v. Reuse the uint
	 * length encoding (which writes major type 0) and flip in the type bits. */
	size_t n = cbor_write_uint(p, (uint64_t)(-(v + 1)));

	p[0] |= 0x20U;
	return n;
}

size_t cbor_write_map_header(uint8_t *p, size_t n)
{
	/* Definite-length map header. Reuses the uint length encoding (which writes
	 * major type 0) and rewrites the type bits to major 5 (map). */
	size_t len = cbor_write_uint(p, (uint64_t)n);

	p[0] = (uint8_t)((p[0] & 0x1fU) | 0xa0U);
	return len;
}

size_t cbor_write_array_header(uint8_t *p, size_t n)
{
	/* Definite-length array header. Like the map header, but major 4 (array).
	 * Supporting counts >= 24 lets the crash report carry a full stack capture. */
	size_t len = cbor_write_uint(p, (uint64_t)n);

	p[0] = (uint8_t)((p[0] & 0x1fU) | 0x80U);
	return len;
}

size_t cbor_write_bool(uint8_t *p, bool b)
{
	/* Major type 7 simple value: 0xf5 true, 0xf4 false. */
	p[0] = b ? 0xf5U : 0xf4U;
	return 1;
}

size_t cbor_write_bstr(uint8_t *p, const uint8_t *b, size_t len)
{
	/* Byte string with a small (< 24) length: 0x40 | len. */
	p[0] = (uint8_t)(0x40U | (len & 0x1fU));
	memcpy(p + 1, b, len);
	return 1 + len;
}

size_t cbor_write_tstr(uint8_t *p, const char *s, size_t len)
{
	/* Definite-length text string. Encode the length like a uint then stamp the
	 * major type (3) over the high bits, so strings >= 24 bytes (e.g. inline log
	 * breadcrumbs) get a correct multi-byte header instead of a truncated one. */
	size_t hlen = cbor_write_uint(p, (uint64_t)len);

	p[0] = (uint8_t)((p[0] & 0x1fU) | 0x60U);
	memcpy(p + hlen, s, len);
	return hlen + len;
}

size_t cbor_write_double(uint8_t *p, double d)
{
	uint64_t bits;

	memcpy(&bits, &d, sizeof(bits));
	p[0] = 0xfb;
	for (int i = 0; i < 8; i++) {
		p[1 + i] = (uint8_t)(bits >> (56 - 8 * i));
	}
	return 9;
}

void cbor_reader_init(struct cbor_reader *r, const uint8_t *buf, size_t len)
{
	r->buf = buf;
	r->len = len;
	r->pos = 0;
}

int cbor_read_head(struct cbor_reader *r, uint8_t *major, uint64_t *arg)
{
	if (r->pos >= r->len) {
		return -EINVAL;
	}

	uint8_t ib = r->buf[r->pos++];
	uint8_t ai = ib & 0x1fU;
	size_t nbytes;

	*major = ib >> 5;
	if (ai < 24U) {
		*arg = ai;
		return 0;
	}
	switch (ai) {
	case 24: nbytes = 1; break;
	case 25: nbytes = 2; break;
	case 26: nbytes = 4; break;
	case 27: nbytes = 8; break;
	default: return -ENOTSUP;
	}
	if (r->pos + nbytes > r->len) {
		return -EINVAL;
	}

	uint64_t v = 0;
	for (size_t i = 0; i < nbytes; i++) {
		v = (v << 8) | r->buf[r->pos++];
	}
	*arg = v;
	return 0;
}

int cbor_skip(struct cbor_reader *r)
{
	uint8_t major;
	uint64_t arg;
	int err = cbor_read_head(r, &major, &arg);

	if (err) {
		return err;
	}
	switch (major) {
	case CBOR_MAJOR_UINT:
	case CBOR_MAJOR_NINT:
	case CBOR_MAJOR_SIMPLE: /* simple/float bytes already consumed by head */
		return 0;
	case CBOR_MAJOR_BSTR:
	case CBOR_MAJOR_TSTR:
		if (r->pos + arg > r->len) {
			return -EINVAL;
		}
		r->pos += arg;
		return 0;
	case CBOR_MAJOR_ARRAY:
		for (uint64_t i = 0; i < arg; i++) {
			if ((err = cbor_skip(r)) != 0) {
				return err;
			}
		}
		return 0;
	case CBOR_MAJOR_MAP:
		for (uint64_t i = 0; i < arg; i++) {
			if ((err = cbor_skip(r)) != 0 || (err = cbor_skip(r)) != 0) {
				return err;
			}
		}
		return 0;
	default:
		return -ENOTSUP;
	}
}

void cbor_render_value(struct cbor_reader *r, char *dst, size_t dstsz)
{
	size_t start = r->pos;
	uint8_t major;
	uint64_t arg;

	if (cbor_read_head(r, &major, &arg) != 0) {
		snprintf(dst, dstsz, "<trunc>");
		return;
	}
	switch (major) {
	case CBOR_MAJOR_UINT:
		snprintf(dst, dstsz, "%llu", (unsigned long long)arg);
		return;
	case CBOR_MAJOR_NINT:
		snprintf(dst, dstsz, "-%llu", (unsigned long long)arg + 1ULL);
		return;
	case CBOR_MAJOR_TSTR:
		if (r->pos + arg > r->len) {
			snprintf(dst, dstsz, "<trunc>");
			return;
		}
		snprintf(dst, dstsz, "\"%.*s\"", (int)arg, &r->buf[r->pos]);
		r->pos += arg;
		return;
	case CBOR_MAJOR_SIMPLE:
		if (arg == 20) { snprintf(dst, dstsz, "false"); return; }
		if (arg == 21) { snprintf(dst, dstsz, "true"); return; }
		if (arg == 22) { snprintf(dst, dstsz, "null"); return; }
		snprintf(dst, dstsz, "<float>"); /* FP printf may be disabled */
		return;
	default:
		/* array/map/bstr: rewind and skip the whole item */
		r->pos = start;
		(void)cbor_skip(r);
		snprintf(dst, dstsz, "<complex>");
		return;
	}
}
