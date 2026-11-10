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

## Release Assistance Indication (`CONFIG_OSCORE_CLOUD_RAI`)

RAI lets the device tell the network that it has nothing more to send, so the
RRC connection is released right after an uplink instead of when the network
inactivity timer runs out. It is on by default and needs
`CONFIG_LTE_RAI_REQ=y` so the modem asks the network for RAI support
(`AT%RAI`). Without that, or on a cell that offers no RAI, the hints do
nothing.

The library connects its UDP socket to the server, so `RAI_NO_DATA` works, and
exposes two calls. It never decides on its own that the link is idle, because
only the application knows whether a FOTA download, coredump upload or batch
comes next:

```c
cloud_client_rai_next(CLOUD_RAI_LAST);     /* one-shot: applied to the next send, then reset */
cloud_client_rai_next(CLOUD_RAI_ONE_RESP); /* release after the next send + one response */
cloud_client_rai_release();                /* RAI_NO_DATA: release now */
```

Every Block1 and Block2 request is sent with `RAI_ONGOING`, so a multi-block
transfer is never released halfway. A `setsockopt()` failure is logged once and
never fails a send.

Networks honour different signals, so send both:

| RAT | Mechanism | Honoured | Ignored |
| --- | --- | --- | --- |
| LTE-M | AS-RAI | explicit `RAI_NO_DATA` after the exchange | `RAI_ONE_RESP` |
| NB-IoT | CP-RAI | `RAI_LAST` / `RAI_ONE_RESP` on the uplink | `RAI_NO_DATA` (it has no uplink to ride on) |

So a NON post uses `RAI_LAST`, and a CON post uses `RAI_ONE_RESP` followed by
`cloud_client_rai_release()` once the response is handled. Measured on an
nRF9151 DK (Telenor NO, 2026-11-10), the connected time per post drops from
5.8 s to 2.7–3.0 s on LTE-M and from 10.4–10.9 s to 0.2–0.6 s on NB-IoT. The
charge for a NON post above the sleep floor drops by about 19 % on LTE-M and
71 % on NB-IoT. The Asset Tracker Template `cloud` module shows the full
policy (`cloud_rai_*` in `att/app/src/modules/cloud/cloud.c`).

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

The full Zephyr coredump goes up as a second exchange, only on a terrestrial
bearer: resumable and ZRL1-compressed over `POST /c/o` + `POST /c/d`, with a
fallback to the legacy raw Block1 `POST /c` on an older server. Watchdog
expiries (`CONFIG_OSCORE_CLOUD_DIAG_WATCHDOG`) also end in a coredump. See
`docs/OBSERVABILITY.md` in `oscore_pocketbase` for the whole pipeline and
`go/sdk/protocol/README.md` there for the byte-level contract.

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
- **Coredump backend**: enable one of
  - the bundled **external SPI NOR** backend (recommended):
    `CONFIG_DEBUG_COREDUMP_BACKEND_OTHER=y` +
    `CONFIG_OSCORE_CLOUD_DIAG_COREDUMP_BACKEND_SPI_NOR=y`. Needs a
    `coredump_partition` nodelabel in the fixed-partitions of a
    `jedec,spi-nor` device on an `nordic,nrf-spim` bus, 64 KiB aligned and
    sized (1 MiB holds a full-RAM dump: 127 KB on the nRF9151 DK, 178 KB on
    the Thingy:91 X, written in ~0.4–0.5 s). The fault handler
    programs it through polled SPIM register access (no RTOS), the slot is
    pre-erased in the background after upload, a full slot truncates instead
    of discarding, and in a crash loop the first un-uploaded dump is kept
    (`CONFIG_OSCORE_CLOUD_DIAG_COREDUMP_KEEP_FIRST`). Shell: `diag coredump
    [verify|erase]`.

    Uploads are resumable and ZRL1-compressed (`POST /c/o` + `/c/d`, see
    `go/sdk/protocol/README.md`; RAM dumps shrink to about a third), and fall
    back to the legacy raw `POST /c` on an older server. Use
    `CONFIG_DEBUG_COREDUMP_MEMORY_DUMP_LINKER_RAM=y` +
    `CONFIG_DEBUG_COREDUMP_THREADS_METADATA=y` for a full-RAM dump: it then
    carries the RAM log ring `oscore_diag_log_ring`
    (`CONFIG_OSCORE_CLOUD_DIAG_LOG_RING_SIZE`, default 8 KiB, timestamped
    lines, never written to flash on its own) and the `oscore_diag_crash_meta`
    block (boot counter, build-id, firmware version). Deferred logs are flushed
    into the ring before the dump is written; the console gets them afterwards.
  - the **internal flash** backend, for boards without external flash:
    `..._BACKEND_NVMC=y`, `coredump_partition` in internal flash attributed
    non-secure on nRF91. It is capacity-limited (typically 32 KiB, so only a
    THREADS-scope dump with short stack tops fits), and the whole partition
    is erased in the fault handler.
  - Zephyr's in-memory backend (`CONFIG_DEBUG_COREDUMP_BACKEND_IN_MEMORY`, no
    devicetree overlay, survives a warm reset only).
- **Watchdogs** (`CONFIG_OSCORE_CLOUD_DIAG_WATCHDOG`, needs `TASK_WDT` +
  `TASK_WDT_HW_FALLBACK`): the library calls `task_wdt_init()` itself. Call
  `diag_watchdog_trigger(channel, thread)` from your task_wdt callbacks; the
  starved thread then appears as the culprit in the dump. The RTC0
  zero-latency pre-watchdog (`_PRE_WATCHDOG`, default y) catches IRQ-locked
  spins and runaway ISRs 2 s before the hardware WDT resets.
  `TASK_WDT_HW_FALLBACK_DELAY` must exceed the margin plus 500 ms (a
  BUILD_ASSERT checks this). Shell: `diag hang thread|irqlock|isr`.
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
