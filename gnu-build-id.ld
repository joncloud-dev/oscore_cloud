/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Explicitly place the GNU build-id note in ROM. Zephyr's linker scripts do not
 * reserve a slot for .note.gnu.build-id, so enabling -Wl,--build-id without this
 * fragment produces an orphan section and a "cannot move location counter
 * backwards" link failure. Same approach as the Memfault Zephyr port.
 *
 * __gnu_build_id_start is read at runtime by src/build_id.c.
 */
SECTION_PROLOGUE(.note.gnu.build-id,,)
{
	__gnu_build_id_start = .;
	KEEP(*(.note.gnu.build-id))
} GROUP_LINK_IN(ROMABLE_REGION)
