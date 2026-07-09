/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Access to the GNU build-id the linker embeds in the image (see
 * gnu-build-id.ld). The build-id is a hash of the binary itself, so it uniquely
 * identifies the exact build: the cloud uses it to select the matching symbol
 * ELF for crash symbolication and to distinguish firmware versions that share
 * the same semantic version string.
 *
 * Compiled into the library when CONFIG_OSCORE_CLOUD_DIAG_BUILD_ID is enabled;
 * the macros below are always available so the diagnostics structs can reserve
 * space for a build-id regardless.
 */

#ifndef OSCORE_CLOUD_BUILD_ID_H_
#define OSCORE_CLOUD_BUILD_ID_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Raw build-id length: ld's default --build-id style is a 160-bit SHA1. */
#define APP_BUILD_ID_LEN 20

/* Hex digits of the build-id appended to the reported firmware version. Long
 * enough to be unique per build in practice, short enough to keep the version
 * string inside the telemetry encoder's < 24 byte budget. */
#define APP_BUILD_ID_SHORT_HEX 8

/* Copy the raw build-id into out. Returns 0 on success or -ENOENT when the
 * image carries no valid build-id note. Reads only ROM, so it is safe to call
 * from a fault handler. */
int app_build_id_get(uint8_t out[APP_BUILD_ID_LEN]);

/* The full build-id as a lowercase hex string, or "" when absent. */
const char *app_build_id_hex(void);

/* The firmware version reported to the cloud:
 * APP_VERSION_STRING "+" first APP_BUILD_ID_SHORT_HEX hex digits of the
 * build-id (e.g. "1.4.0-dev+3f9c2a1b"), or plain APP_VERSION_STRING when the
 * image carries no build-id. Auto-generated: every build gets a distinct
 * version string with no manual bookkeeping. */
const char *app_fw_version(void);

#ifdef __cplusplus
}
#endif

#endif /* OSCORE_CLOUD_BUILD_ID_H_ */
