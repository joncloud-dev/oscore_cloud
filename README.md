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
| `oscore_cloud/diag.h`, `oscore_cloud/diag_bridge.h` | Device observability collector + telemetry bridge (opt-in, `CONFIG_OSCORE_CLOUD_DIAG`) |
| `oscore_cloud/build_id.h` | GNU build-id / auto-generated firmware version (`CONFIG_OSCORE_CLOUD_DIAG_BUILD_ID`) |
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

## Device observability (`CONFIG_OSCORE_CLOUD_DIAG`)

An optional, Memfault-style fleet-observability layer that reports device-health
signals natively over the existing telemetry uplink — no extra agent, no extra
CoAP route. Four signals are folded into an ordinary `POST /t` as nested CBOR
maps, so an NTN device spends a single round-trip:

| Key | Signal | Kconfig |
| --- | --- | --- |
| 20 | Reboot report (hwinfo cause + app intent, boot counter) | `OSCORE_CLOUD_DIAG` |
| 21 | Health-vitals heartbeat (heap/stack/CPU, modem RSRP/SNR/temp/band, airtime, PSM) | `OSCORE_CLOUD_DIAG_VITALS` |
| 22 | Minimal crash report (fault regs + stack slice + build-id + breadcrumbs) | `OSCORE_CLOUD_DIAG_CRASH` |
| 23 | Static device info (board, modem fw, IMEI, ICCID), one-shot on connect | `OSCORE_CLOUD_DIAG_DEVICE_INFO` |

The full Zephyr coredump is pulled on demand over CoAP Block1 (`POST /c`), only
on a terrestrial bearer. See the top-level `OBSERVABILITY.md` for the wire
protocol and the backend side.

### Usage — automatic (default)

Enable the option and call `oscore_cloud_diag_init()` once at boot; the session
helper (`oscore_cloud_send_telemetry`) folds the pending diagnostics into every
post, clears the one-shots on success, and uploads a stored coredump on
terrestrial LTE:

```c
#include <oscore_cloud/cloud_session.h>
#include <oscore_cloud/diag_bridge.h>

void main(void) {
    oscore_cloud_diag_init();   /* boot report + crash recovery, once, early */
    settings_subsys_init();
    /* ... bring up network, oscore_cloud_init() ... */
    while (1) {
        struct cloud_telemetry t;
        cloud_telemetry_init(&t);
        cloud_telemetry_set_transport(&t, CLOUD_TRANSPORT_TN);
        oscore_cloud_send_telemetry(&t, NULL, NULL);  /* diagnostics ride along */
        k_sleep(K_SECONDS(600));
    }
}
```

### Usage — manual control / slower cadence

Urgent one-shots (boot report, crash) always ride the next post, while the
vitals heartbeat rides only every `CONFIG_OSCORE_CLOUD_DIAG_VITALS_INTERVAL`
sends — so fleet vitals can be reported at a lower cadence than telemetry while
still sharing the same packet (saving uplink bytes). For full control, set
`CONFIG_OSCORE_CLOUD_DIAG_AUTO_ATTACH=n` and drive the bridge yourself around
your own `cloud_client_post_telemetry()`:

```c
struct cloud_telemetry t; cloud_telemetry_init(&t); /* ... */
bool oneshot = oscore_cloud_diag_attach(&t);
if (cloud_client_post_telemetry(&t, &dl) == 0 && oneshot) {
    oscore_cloud_diag_attach_clear();
    oscore_cloud_diag_after_send(t.transport);
}
```

### Requirements / coupling

- **Single fatal handler**: `OSCORE_CLOUD_DIAG_CRASH` defines
  `k_sys_fatal_error_handler`, so the application must set
  `CONFIG_RESET_ON_FATAL_ERROR=n` (otherwise the link fails with a duplicate
  symbol).
- **Firmware version**: `OSCORE_CLOUD_DIAG_BUILD_ID` reports
  `<APP_VERSION_STRING>+<build-id>` as the firmware version, which needs an
  `app_version.h` — add a Zephyr `VERSION` file to the application (a build with
  no `VERSION` file reports `0.0.0`).
- **Coredump backend**: enable one — Zephyr's in-memory backend
  (`CONFIG_DEBUG_COREDUMP_BACKEND_IN_MEMORY`, no devicetree overlay, survives a
  warm reset only) or the bundled fault-safe flash backend
  (`CONFIG_DEBUG_COREDUMP_BACKEND_OTHER=y` +
  `CONFIG_OSCORE_CLOUD_DIAG_COREDUMP_BACKEND_NVMC=y`, which needs a
  `coredump_partition` DT nodelabel attributed non-secure on nRF91).
- **Vitals / device-info sources**: enable the sources you want reported —
  `CONFIG_SYS_HEAP_RUNTIME_STATS`, `CONFIG_THREAD_MONITOR` +
  `CONFIG_THREAD_STACK_INFO`, `CONFIG_THREAD_RUNTIME_STATS`, `CONFIG_MODEM_INFO`,
  `CONFIG_LTE_LINK_CONTROL`. Each source is best-effort; an unavailable one is
  simply omitted from the wire map.

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
