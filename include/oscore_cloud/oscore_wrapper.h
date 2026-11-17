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

/** State of the active context and of a pending EDHOC context
 *  (docs/NTN-SECURITY-A3.md epochs, docs/NTN-SECURITY-A6.md §4 transition). */
struct oscore_epoch_status {
	uint32_t epoch;        /**< current epoch of the active context */
	uint32_t confirmed;    /**< newest epoch a verified response proved */
	uint64_t ssn;          /**< next sender sequence number */
	uint8_t misses;        /**< CON requests in a row without a verified response */
	bool ready;            /**< a context is derived */
	bool kid_context_sent; /**< requests carry the kid context */
	bool rekey_requested;  /**< server asked for a rekey */
	const char *lane;      /**< active context: "psk", "edhoc-a" or "edhoc-b" */
	bool edhoc;            /**< the active context comes from EDHOC */
	uint32_t run;          /**< EDHOC run number of the active context */
	uint8_t kid[8];        /**< Sender ID (kid) of the active context */
	uint8_t kid_len;
	bool psk_parked;       /**< an EDHOC context was confirmed; PSK is not used */
	uint32_t psk_epoch;    /**< recorded PSK epoch (the rejoin point) */
	bool fallback;         /**< next CON goes under the active context (rule 3) */
	bool edhoc_rekey_inflight; /**< a rekey is waiting for an EDHOC run */
	const char *pending;   /**< pending EDHOC slot, or NULL */
	uint32_t pending_run;
	uint64_t pending_ssn;
	uint8_t pending_kid[8];
	uint8_t pending_kid_len;
};

/** Read the context state. -ENOTSUP when the context has no epochs (raw keys,
 *  or no NVM support). */
int oscore_wrapper_epoch_status(struct oscore_epoch_status *out);

/** Ask for the next epoch of the active context before the next request
 *  (testing). -EALREADY when the epoch is already confirmed +
 *  CONFIG_OSCORE_CLOUD_EPOCH_WINDOW. */
int oscore_wrapper_epoch_request_bump(void);

/**
 * Store the result of a completed EDHOC run (message_4 verified) as the
 * pending context (docs/NTN-SECURITY-A6.md §4 rule 1). The master secret is
 * imported as a persistent PSA key in a free A/B slot (or the slot of the
 * pending context it replaces, rule 6); the salt, the IDs and the epoch state
 * go to settings before the first request under it. sender_id is C_R,
 * recipient_id C_I. fp is a short fingerprint for logs. The caller wipes its
 * copy of the secret.
 */
int oscore_wrapper_edhoc_install(const uint8_t *secret, size_t secret_len, const uint8_t *salt,
				 size_t salt_len, const uint8_t *sender_id, size_t sender_id_len,
				 const uint8_t *recipient_id, size_t recipient_id_len,
				 const uint8_t fp[4]);

/** A requested EDHOC run ended (0 = a context was installed, else why not).
 *  A rekey that asked for the run moves to a new epoch instead on failure. */
void oscore_wrapper_edhoc_run_done(int err);

#if defined(CONFIG_OSCORE_CLOUD_TEST_IMPAIR)
/** Test faults for the transition: "confirm" drops the next response under
 *  the pending context, "reboot" reboots on it, "none" clears both. */
int oscore_wrapper_test_fault(const char *name);

/** Test: erase both EDHOC slots, as a lost EDHOC context (rule 4). */
int oscore_wrapper_test_forget_edhoc(void);
#endif

#endif /* OSCORE_WRAPPER_H */
