# oscore_cloud

A framework-agnostic OSCORE cloud client for the Go/PocketBase server
(`oscore_pocketbase`). It provides the CoAP/OSCORE transport, a minimal CBOR
codec, and structured telemetry / device-shadow / downlink operations behind a
small C API. It has **no dependency on zbus or the Zephyr State Machine
Framework**, so it can be used from a plain `main()`-loop application as well as
from the Asset-Tracker-Template cloud module.

## Layers

| Header | Purpose |
| --- | --- |
| `oscore_cloud/cloud_config.h` | Runtime config (`oscore_cloud_init`) and the watchdog-feed hook |
| `oscore_cloud/cloud_client.h` | Telemetry / shadow / downlink protocol + low-level OSCORE GET/POST/Block transfers |
| `oscore_cloud/cloud_session.h` | Optional connect / reconnect-backoff / send helper for simple apps |
| `oscore_cloud/fota_client.h` | OSCORE FOTA (opt-in, `CONFIG_OSCORE_CLOUD_FOTA`) |
| `oscore_cloud/agnss_client.h` | OSCORE A-GNSS assistance (opt-in, `CONFIG_OSCORE_CLOUD_AGNSS`) |
| `oscore_cloud/cbor.h` | CBOR codec used by the client |
| `oscore_cloud/oscore_wrapper.h`, `oscore_cloud/oscore_provision.h` | OSCORE context + bench provisioning |

## Enabling

```
CONFIG_OSCORE_CLOUD=y
CONFIG_OSCORE_CLOUD_SESSION=y   # connect/session helper (default y)
CONFIG_OSCORE_CLOUD_FOTA=y      # optional, needs CONFIG_DFU_TARGET
CONFIG_OSCORE_CLOUD_AGNSS=y     # optional
```

The library requires a CoAP + UDP transport (`CONFIG_COAP`,
`CONFIG_NET_SOCKETS`), the uoscore-uedhoc module (`CONFIG_UOSCORE`), and — for
replay-counter persistence — the settings subsystem (`CONFIG_SETTINGS`).

## Minimal application

```c
#include <oscore_cloud/cloud_config.h>
#include <oscore_cloud/cloud_session.h>

static void on_shadow_delta(const struct cloud_shadow_delta *d, void *user) {
    /* apply desired config; the library acks the version for you */
}

void run(void) {
    const struct oscore_cloud_config cfg = { .server_ip = "203.0.113.10" };
    oscore_cloud_init(&cfg);

    uint32_t attempts = 0;
    while (1) {
        if (oscore_cloud_connect() != 0) {
            k_sleep(K_SECONDS(oscore_cloud_backoff_seconds(++attempts)));
            continue;
        }
        attempts = 0;

        struct cloud_telemetry t;
        cloud_telemetry_init(&t);
        cloud_telemetry_add_double(&t, 10 /* metric key */, battery_percent());
        oscore_cloud_send_telemetry(&t, on_shadow_delta, NULL);

        k_sleep(K_SECONDS(600));
    }
}
```

No OSCORE keys are supplied above, so the context is loaded from the
PSA-provisioned material written once with the `oscore provision ...` shell
command. A self-contained app may instead hardcode raw keys via the
`master_secret` / `master_salt` / `sender_id` / `recipient_id` fields of
`struct oscore_cloud_config`.

## Consuming from another workspace

`zephyr/module.yml` makes this a standalone Zephyr module, so it needs no
`west.yml` of its own. Consume it either way:

- **west manifest `projects` entry** (recommended). Add it to your application
  manifest so `west update` fetches it into the workspace:

  ```yaml
  projects:
    - name: oscore_cloud
      remote: <your-remote>
      repo-path: oscore_cloud
      revision: main
      path: modules/lib/oscore_cloud
  ```

- **out-of-tree module** for local iteration, without touching the manifest:

  ```
  west build -b <board> <app> -- -DZEPHYR_EXTRA_MODULES=<abs-path>/oscore_cloud
  ```

Either way, enable it with `CONFIG_OSCORE_CLOUD=y` (see *Enabling* above). It
requires the modified `uoscore-uedhoc` (opaque PSA keys) pinned by the
consuming application's manifest.

A minimal reference application for the nRF9151 DK lives in the
`oscore_nrf9151_app` repository: it wires this library's `cloud_session` helper
into a plain `main()` loop and shows the west manifest that overrides
`uoscore-uedhoc` with the required fork.
