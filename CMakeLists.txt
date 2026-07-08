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
zephyr_library_sources_ifdef(CONFIG_OSCORE_CLOUD_SESSION src/cloud_session.c)

endif() # CONFIG_OSCORE_CLOUD
