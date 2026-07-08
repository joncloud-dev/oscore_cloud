/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Wrapper for uoscore-uedhoc: init context (hardcoded PoC), protect request,
 * unprotect response. Implementation in oscore_wrapper.c ties to the actual
 * uoscore-uedhoc API provided by the Zephyr module in NCS.
 */

#ifndef OSCORE_WRAPPER_H
#define OSCORE_WRAPPER_H

#include <stddef.h>
#include <stdint.h>

/** One-time init of OSCORE context from PSA-provisioned material (opaque master
 *  secret key + Protected Storage salt/IDs). This is the default path. */
int oscore_wrapper_init(void);

/**
 * One-time init of OSCORE context from raw, caller-supplied key material,
 * bypassing PSA provisioning. Intended for a self-contained application that
 * hardcodes its OSCORE context. The buffers are copied internally. Uses a fresh
 * (per-boot) sequence number. Returns 0 on success or a negative errno.
 */
int oscore_wrapper_init_with_keys(const uint8_t *master_secret, size_t master_secret_len,
				  const uint8_t *master_salt, size_t master_salt_len,
				  const uint8_t *sender_id, size_t sender_id_len,
				  const uint8_t *recipient_id, size_t recipient_id_len);

#if defined(CONFIG_OSCORE_USE_EDHOC)
/** Run EDHOC with server, derive OSCORE context, then use protect/unprotect. */
int edhoc_oscore_init(void);

/** Return the UDP socket file descriptor from the EDHOC exchange.
 *  The OSCORE request must be sent from the same transport endpoint so the
 *  server can match the security context.  Returns -1 when unavailable. */
int oscore_wrapper_get_socket(void);
#endif

/**
 * Protect (encrypt/sign) CoAP request in place. On entry, buf contains plain
 * CoAP; on success, buf contains OSCORE-protected CoAP and *len is updated.
 */
int oscore_wrapper_protect(uint8_t *buf, size_t *len, size_t max_len);

/**
 * Unprotect (decrypt/verify) CoAP response in place. On entry, buf contains
 * OSCORE-protected CoAP; on success, buf contains plain CoAP and *len updated.
 */
int oscore_wrapper_unprotect(uint8_t *buf, size_t *len, size_t max_len);

#endif /* OSCORE_WRAPPER_H */
