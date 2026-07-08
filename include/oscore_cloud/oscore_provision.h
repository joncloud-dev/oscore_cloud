/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * OSCORE bench provisioning (Phase 3).
 *
 * The OSCORE master secret is held as an opaque, persistent PSA key in the
 * TF-M secure domain (key id OSCORE_MASTER_SECRET_KEY_ID); its raw bytes never
 * persist in non-secure RAM. The non-secret salt and sender/recipient IDs are
 * stored in PSA Protected Storage. Both are loaded at boot by
 * oscore_wrapper_init().
 *
 * A device is provisioned once, on the bench, via the shell command:
 *   oscore provision <secret_hex(16B)> <salt_hex(8B)> <sender_id_hex> <recipient_id_hex>
 * after which it must be rebooted to take effect.
 */

#ifndef OSCORE_PROVISION_H
#define OSCORE_PROVISION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/psa/key_ids.h>

/* Fixed PSA key id for the OSCORE master secret (persistent, TF-M ITS).
 * Uses the start of Zephyr's dedicated application key-id range (0x30000000). */
#define OSCORE_MASTER_SECRET_KEY_ID ZEPHYR_PSA_APPLICATION_KEY_ID_RANGE_BEGIN

#define OSCORE_MASTER_SECRET_LEN 16
#define OSCORE_MASTER_SALT_MAX   8
#define OSCORE_ID_MAX            7 /* uoscore sender_id_buf is 7 bytes */

/* Non-secret material kept in Protected Storage as one fixed-size record.
 * Device-side perspective: sender_id is what this device puts on the wire
 * (= the server's Recipient ID), recipient_id identifies the server
 * (= the server's Sender ID). */
struct oscore_ps_material {
	uint8_t salt[OSCORE_MASTER_SALT_MAX];
	uint8_t sender_id[OSCORE_ID_MAX];
	uint8_t recipient_id[OSCORE_ID_MAX];
	uint8_t salt_len;
	uint8_t sender_id_len;
	uint8_t recipient_id_len;
};

/**
 * @brief Check whether the OSCORE master-secret key has been provisioned.
 * @return true if a key exists at OSCORE_MASTER_SECRET_KEY_ID.
 */
bool oscore_provision_has_key(void);

/**
 * @brief Load the non-secret salt + IDs from Protected Storage.
 * @param out  Receives the stored material.
 * @return 0 on success, -ENOENT if not provisioned, negative errno otherwise.
 */
int oscore_provision_load(struct oscore_ps_material *out);

#endif /* OSCORE_PROVISION_H */
