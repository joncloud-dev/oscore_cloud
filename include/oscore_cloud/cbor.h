/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Minimal CBOR codec (RFC 8949 subset) used by the cloud client.
 *
 * This is a generic, application-agnostic helper layer: it knows how to write
 * and walk CBOR items but nothing about telemetry, shadows, or the server
 * protocol. Higher layers (cloud_client.c) compose these primitives; the
 * application layer (main.c) should not need to touch CBOR at all.
 */

#ifndef CBOR_H
#define CBOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* CBOR major types (high 3 bits of the initial byte). */
#define CBOR_MAJOR_UINT   0
#define CBOR_MAJOR_NINT   1
#define CBOR_MAJOR_BSTR   2
#define CBOR_MAJOR_TSTR   3
#define CBOR_MAJOR_ARRAY  4
#define CBOR_MAJOR_MAP    5
#define CBOR_MAJOR_SIMPLE 7

/* --- Writer ---------------------------------------------------------------
 * Each writer appends one item at *p and returns the number of bytes written.
 * The caller is responsible for providing enough space (worst case 9 bytes for
 * a uint/double, 1 + len for a tstr, 1 byte for a small map/array header).
 */

/** Encode an unsigned integer (major type 0). Returns 1, 2, 3, 5, or 9 bytes. */
size_t cbor_write_uint(uint8_t *p, uint64_t v);

/** Encode a signed integer (major type 0 or 1). Returns 1, 2, 3, 5, or 9 bytes. */
size_t cbor_write_int(uint8_t *p, int64_t v);

/** Encode a definite-length map header for n entries. n must be < 24. */
size_t cbor_write_map_header(uint8_t *p, size_t n);

/** Encode a definite-length array header for n elements. n must be < 24. */
size_t cbor_write_array_header(uint8_t *p, size_t n);

/** Encode a text string (major type 3). len must be < 24 (single-byte head). */
size_t cbor_write_tstr(uint8_t *p, const char *s, size_t len);

/** Encode a byte string (major type 2). len must be < 24 (single-byte head). */
size_t cbor_write_bstr(uint8_t *p, const uint8_t *b, size_t len);

/** Encode an IEEE-754 double (major type 7, value 27). Returns 9 bytes. */
size_t cbor_write_double(uint8_t *p, double d);

/** Encode a boolean (major type 7, simple value 20/21). Returns 1 byte. */
size_t cbor_write_bool(uint8_t *p, bool b);

/* --- Reader ---------------------------------------------------------------
 * A cursor over an immutable CBOR buffer. Just enough to walk maps and skip
 * values; indefinite-length and tagged items are not supported.
 */
struct cbor_reader {
	const uint8_t *buf;
	size_t len;
	size_t pos;
};

/** Initialise a reader over [buf, buf+len). */
void cbor_reader_init(struct cbor_reader *r, const uint8_t *buf, size_t len);

/**
 * Read one CBOR head at the cursor: major type into *major and its argument
 * (small value, length, or float bits) into *arg, advancing past the head and
 * any extension bytes. Returns -EINVAL on truncation, -ENOTSUP for
 * indefinite-length / reserved forms.
 */
int cbor_read_head(struct cbor_reader *r, uint8_t *major, uint64_t *arg);

/** Recursively skip the next CBOR data item at the cursor. */
int cbor_skip(struct cbor_reader *r);

/**
 * Render the next CBOR value at the cursor to a short human string in dst,
 * handling scalar types (uint, nint, tstr, bool/null). Complex values are
 * skipped and shown as "<complex>". Always leaves the cursor past the value.
 */
void cbor_render_value(struct cbor_reader *r, char *dst, size_t dstsz);

#endif /* CBOR_H */
