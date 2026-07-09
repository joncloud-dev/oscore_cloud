/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <app_version.h>

#include <oscore_cloud/build_id.h>

/* Layout of the .note.gnu.build-id ELF note the linker emits: three LE
 * uint32 words, the 4-byte "GNU\0" name, then the id bytes. */
struct gnu_build_id_note {
	uint32_t namesz;
	uint32_t descsz;
	uint32_t type; /* NT_GNU_BUILD_ID == 3 */
	uint8_t data[];
};

#define NT_GNU_BUILD_ID 3

/* Placed by gnu-build-id.ld. Weak so images linked without the fragment
 * (e.g. host/posix builds) degrade to "no build-id" instead of failing. */
extern const struct gnu_build_id_note __gnu_build_id_start __attribute__((weak));

static const uint8_t *note_id(size_t *len)
{
	const struct gnu_build_id_note *n = &__gnu_build_id_start;

	if (n == NULL || n->type != NT_GNU_BUILD_ID || n->namesz != 4 ||
	    memcmp(n->data, "GNU", 4) != 0 || n->descsz < 8 ||
	    n->descsz > APP_BUILD_ID_LEN) {
		return NULL;
	}
	*len = n->descsz;
	return &n->data[4]; /* namesz (4) is already 4-byte aligned */
}

int app_build_id_get(uint8_t out[APP_BUILD_ID_LEN])
{
	size_t len = 0;
	const uint8_t *id = note_id(&len);

	if (id == NULL) {
		return -ENOENT;
	}
	memset(out, 0, APP_BUILD_ID_LEN);
	memcpy(out, id, len);
	return 0;
}

const char *app_build_id_hex(void)
{
	static char hex[2 * APP_BUILD_ID_LEN + 1];
	static bool init;

	if (!init) {
		static const char digits[] = "0123456789abcdef";
		size_t len = 0;
		const uint8_t *id = note_id(&len);

		for (size_t i = 0; id != NULL && i < len; i++) {
			hex[2 * i] = digits[id[i] >> 4];
			hex[2 * i + 1] = digits[id[i] & 0xFU];
		}
		init = true;
	}
	return hex;
}

const char *app_fw_version(void)
{
	static char ver[sizeof(APP_VERSION_STRING) + 1 + APP_BUILD_ID_SHORT_HEX];
	static bool init;

	if (!init) {
		const char *hex = app_build_id_hex();

		if (hex[0] != '\0') {
			(void)snprintf(ver, sizeof(ver), "%s+%.*s", APP_VERSION_STRING,
				       APP_BUILD_ID_SHORT_HEX, hex);
		} else {
			(void)snprintf(ver, sizeof(ver), "%s", APP_VERSION_STRING);
		}
		init = true;
	}
	return ver;
}
