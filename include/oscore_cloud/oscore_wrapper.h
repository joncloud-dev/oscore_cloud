/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Wrapper for uoscore-uedhoc: init context (hardcoded PoC), protect request,
 * unprotect response. Implementation in oscore_wrapper.c ties to the actual
 * uoscore-uedhoc API provided by the Zephyr module in NCS.
 */

#ifndef OSCORE_WRAPPER_H
#define OSCORE_WRAPPER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** Init the OSCORE context from PSA-provisioned material (opaque master secret
 *  key + Protected Storage salt/IDs). This is the default path. It loads the
 *  durable epoch record and derives the context of the current PSK epoch.
 *  Idempotent while a context is live; after oscore_wrapper_deinit() it
 *  derives the context again. */
int oscore_wrapper_init(void);

/** Tear down the live context and destroy its derived (volatile) PSA keys.
 *  The durable epoch record and the provisioned key are left as they are. */
void oscore_wrapper_deinit(void);

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

/**
 * Tell the wrapper that the request it last protected never reached the
 * transmit path (send failed), so its missing response is not counted toward
 * the epoch self-bump.
 */
void oscore_wrapper_request_not_sent(void);

/** PSK epoch state (docs/NTN-SECURITY-A3.md). */
struct oscore_epoch_status {
	uint32_t epoch;        /**< current epoch (ID Context = base || epoch) */
	uint32_t confirmed;    /**< newest epoch a verified response proved */
	uint64_t ssn;          /**< next sender sequence number */
	uint8_t misses;        /**< CON requests in a row without a verified response */
	bool ready;            /**< a context is derived */
	bool kid_context_sent; /**< requests carry the kid context */
	bool rekey_requested;  /**< server asked for the next epoch */
};

/** Read the epoch state. -ENOTSUP when the context has no epochs (raw keys,
 *  EDHOC, or no NVM support). */
int oscore_wrapper_epoch_status(struct oscore_epoch_status *out);

/** Ask for the next epoch before the next request (testing). -EALREADY when
 *  the epoch is already confirmed + CONFIG_OSCORE_CLOUD_EPOCH_WINDOW. */
int oscore_wrapper_epoch_request_bump(void);

#endif /* OSCORE_WRAPPER_H */
