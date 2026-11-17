/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * EDHOC on the device (NTN security B3): method 3 (static DH both sides),
 * cipher suite 2, against the Go responder at /.well-known/edhoc
 * (docs/NTN-SECURITY-A5.md).
 *
 * The device's static P-256 key is a persistent, non-exportable PSA key; the
 * ephemeral key is a volatile PSA key destroyed after each run. Neither private
 * key is ever held in application RAM: uedhoc's ECDH hook (shared_secret_derive)
 * is overridden to call psa_raw_key_agreement() on the key handles.
 *
 * Credentials (CRED_I as built by the server, and the pinned CRED_R) are
 * public and stored in settings ("edhoc/i", "edhoc/r"). Provision from the
 * shell:
 *
 *   edhoc keygen                        create the static key, print its public key
 *   (server) POST /api/provision/edhoc {"hw_id", "edhoc_pub"}
 *   edhoc cred <edhoc_kid> <edhoc_cred> store CRED_I exactly as returned
 *   edhoc server <kid> <cred>           pin CRED_R (edhoc_server_kid/_cred)
 *   edhoc run [force]                   run EDHOC on the cloud thread (TN only
 *                                       unless forced)
 *
 * B3 stops at a verified message_4: the server then holds a pending EDHOC
 * context, and the derived OSCORE keys are reported by fingerprint and wiped.
 * Switching traffic to the new context is B4 (docs/NTN-SECURITY-A6.md §4).
 */

#ifndef OSCORE_EDHOC_H
#define OSCORE_EDHOC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Run a requested EDHOC exchange. Called by the cloud client on its own
 * thread before each OSCORE request; returns at once when nothing is
 * requested. */
void oscore_edhoc_service(void);

/* Ask for a run on the next cloud request. force skips the TN-only check. */
int oscore_edhoc_request_run(bool force);

/* Unprotected CON POST /.well-known/edhoc on the cloud socket, with the CoAP
 * retransmission of the cloud client. Implemented in cloud_client.c. */
int cloud_client_edhoc_post(const uint8_t *body, size_t body_len, uint8_t *code, uint8_t *out,
			    size_t *out_len);

#endif /* OSCORE_EDHOC_H */
