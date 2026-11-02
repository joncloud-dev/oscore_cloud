# SPDX-License-Identifier: Apache-2.0
#
# oscore_cloud: a framework-agnostic OSCORE cloud client library. It has no
# dependency on zbus or the Zephyr State Machine Framework, so it can be used
# from a plain main()-loop application as well as from the Asset-Tracker-Template
# cloud module.

if(CONFIG_OSCORE_CLOUD)

# Persist the OSCORE Sender Sequence Number (replay counter) across reboots.
# This compiles the uoscore-uedhoc NVM hooks (nvm_read_ssn/nvm_write_ssn, which
# oscore_wrapper.c overrides) and is propagated to the uoscore library via
# zephyr_interface. Requires the settings subsystem for the NVS-backed storage.
if(CONFIG_UOSCORE AND CONFIG_SETTINGS)
  zephyr_compile_definitions(OSCORE_NVM_SUPPORT)
endif()

# Raise uoscore's fixed message-staging buffers. OSCORE_MAX_PLAINTEXT_LEN sizes
# the plaintext[] / ciphertext[] arrays that coap2oscore (encrypt) and
# oscore2coap (decrypt) use for the entire inner CoAP frame (code + class-E
# options + payload). The uoscore default (1064) is overrun by a 1024-byte
# Block2/Block1 body once inner options are added; 1536 gives clear headroom.
# NOTE: with VLA off these buffers are stack-allocated in the OSCORE caller, so
# a consumer that drives OSCORE from a dedicated thread must size that thread's
# stack accordingly (the ATT cloud thread does).
if(CONFIG_UOSCORE)
  zephyr_compile_definitions(OSCORE_MAX_PLAINTEXT_LEN=1536)
endif()

zephyr_include_directories(include)

zephyr_library()
zephyr_library_sources(
  src/cloud_client.c
  src/cbor.c
  src/oscore_wrapper.c
  src/oscore_provision.c
)
zephyr_library_sources_ifdef(CONFIG_OSCORE_CLOUD_FOTA    src/fota_client.c)
zephyr_library_sources_ifdef(CONFIG_OSCORE_CLOUD_AGNSS   src/agnss_client.c)
zephyr_library_sources_ifdef(CONFIG_OSCORE_CLOUD_PGPS    src/pgps_client.c)
zephyr_library_sources_ifdef(CONFIG_OSCORE_CLOUD_PGPS_STORE src/pgps_store.c)
zephyr_library_sources_ifdef(CONFIG_OSCORE_CLOUD_SESSION src/cloud_session.c)

# Device observability collector + bridge (reboot reasons, vitals, crash
# reports). The bridge folds the collected signals into cloud_telemetry, so it
# depends on the wire layer above; enabling OSCORE_CLOUD_DIAG is enough.
zephyr_library_sources_ifdef(CONFIG_OSCORE_CLOUD_DIAG src/diag.c src/diag_bridge.c)
zephyr_library_sources_ifdef(CONFIG_OSCORE_CLOUD_DIAG_BUILD_ID src/build_id.c)
zephyr_library_sources_ifdef(CONFIG_OSCORE_CLOUD_DIAG_COREDUMP_BACKEND_NVMC
  src/coredump_backend_nvmc.c)

# GNU build-id: a hash of the binary embedded by the linker, giving every build
# an automatically distinct identity. Plain -Wl,--build-id conflicts with
# Zephyr's linker scripts (orphan .note.gnu.build-id, "cannot move location
# counter backwards"), so the fragment below reserves an explicit ROM slot for
# the note. The device reads it at runtime (src/build_id.c) to suffix the
# reported firmware version and to tag crash reports for exact symbol-ELF
# matching.
if(CONFIG_OSCORE_CLOUD_DIAG_BUILD_ID AND NOT CONFIG_ARCH_POSIX)
  zephyr_ld_options("-Wl,--build-id")
  zephyr_linker_sources(SECTIONS gnu-build-id.ld)
endif()

endif() # CONFIG_OSCORE_CLOUD
