/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Cloud client API for the OSCORE platform (Go server in oscore_pocketbase).
 *
 * This is the "easy to use" cloud interface. It hides CoAP, OSCORE/EDHOC,
 * sockets, and CBOR behind a small set of structured calls. The application
 * (main.c) builds telemetry, reacts to downlinks, and never touches the wire
 * format.
 *
 * Layering:
 *   main.c            application logic (this file's only consumer)
 *   cloud_client.[ch] telemetry/shadow/downlink protocol  <-- you are here
 *   cbor.[ch]         CBOR codec
 *   oscore_wrapper.*  OSCORE/EDHOC + UDP transport
 *
 * Everything here is single-threaded and uses static internal buffers; call
 * from one context only (the PoC calls everything from main()).
 */

#ifndef CLOUD_CLIENT_H
#define CLOUD_CLIENT_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* Transport indicator reported in telemetry well-known key 1. */
enum cloud_transport {
	CLOUD_TRANSPORT_TN  = 1, /* terrestrial (LTE-M / NB-IoT) */
	CLOUD_TRANSPORT_NTN = 2, /* non-terrestrial (satellite) */
};

/* ------------------------------------------------------------------------
 * Telemetry
 *
 * Fill a cloud_telemetry with the named setters (well-known keys) and/or
 * free-form metrics, then hand it to a post call. The server (deviceapi)
 * reads integer keys: 1 = transport, 2 = fw version, 3 = timestamp; any
 * other integer key is stored as a free-form metric.
 * ------------------------------------------------------------------------ */

#define CLOUD_TELEMETRY_MAX_METRICS 8

struct cloud_metric {
	uint16_t key;
	enum { CLOUD_METRIC_UINT, CLOUD_METRIC_DOUBLE } type;
	union {
		uint64_t u;
		double d;
	} value;
};

/* Optional GNSS fix carried in a telemetry payload under map key 4 (a nested
 * CBOR map; see agnss-schema.md). Folding the fix into telemetry lets one round
 * upload sensors + position in a single message. Keys 5 (cell) and 6 (Wi-Fi)
 * measurements are reserved for a later phase and not yet emitted. */
struct cloud_telemetry_gnss {
	bool valid;
	double lat;
	double lon;
	double accuracy;        /* horizontal accuracy, metres */
	bool have_alt;
	double altitude;        /* metres, valid only when have_alt */
	uint32_t ttff_ms;       /* time to fix, ms; 0 = omit */
	uint64_t fix_time_sec;  /* fix epoch seconds; 0 = omit (server stamps) */
};

/* Cell/Wi-Fi scan measurements, emitted under telemetry keys 5 (cell) and 6
 * (Wi-Fi). Transport-neutral mirrors of the location library's structs so this
 * layer stays independent of the Location API; cloud.c maps the scan in. The
 * counts are capped to bound the telemetry payload. */
#define CLOUD_TELEMETRY_MAX_NCELLS 10
#define CLOUD_TELEMETRY_MAX_WIFI   10

struct cloud_neighbor_cell {
	uint32_t earfcn;
	uint16_t phys_cell_id;
	int16_t rsrp;
	int16_t rsrq;
	int32_t time_diff;
};

struct cloud_telemetry_cell {
	bool valid;
	uint32_t id;             /* E-UTRAN cell id */
	uint16_t mcc;
	uint16_t mnc;
	uint32_t tac;
	uint32_t earfcn;
	int16_t rsrp;
	int16_t rsrq;
	uint16_t timing_advance;
	uint8_t ncells;          /* number of neighbors below */
	struct cloud_neighbor_cell neighbors[CLOUD_TELEMETRY_MAX_NCELLS];
};

struct cloud_wifi_ap {
	uint8_t mac[6];
	uint8_t mac_len;
	int8_t rssi;
};

struct cloud_telemetry_wifi {
	bool valid;
	uint8_t count;
	struct cloud_wifi_ap aps[CLOUD_TELEMETRY_MAX_WIFI];
};

/* Observability diagnostics carried as nested CBOR maps under integer keys
 * 20 (boot report), 21 (vitals heartbeat) and 22 (minimal crash report). These
 * are populated from the diag module and folded into an ordinary telemetry post
 * so a device reports fleet health without an extra CoAP route. */
#define CLOUD_TELEMETRY_MAX_CRASH_REGS  16
#define CLOUD_TELEMETRY_MAX_CRASH_STACK 32
/* Inline log breadcrumbs carried with the minimal crash report. Kept small to
 * respect the NTN byte budget; the full ring is also in the coredump. */
#define CLOUD_TELEMETRY_MAX_BREADCRUMB  256

struct cloud_telemetry_reset {
	bool valid;
	uint32_t hw_cause;      /* hwinfo reset-cause bitmap */
	uint8_t reason;         /* enum diag_reset_reason (wire value) */
	uint32_t prev_uptime_s; /* uptime of the previous boot, 0 = omit */
	uint32_t boot_count;
	bool crash_pending;
};

/* Vitals heartbeat (key 21) as an extensible list of typed {key,value} samples.
 * The wire layer stays metric-agnostic: it just encodes whatever the diag module
 * collected, so adding a device metric never touches this file. */
#define CLOUD_TELEMETRY_MAX_VITALS 24

enum cloud_vital_type {
	CLOUD_VITAL_UINT,
	CLOUD_VITAL_INT,
};

struct cloud_vital {
	const char *key; /* 2-char wire key */
	enum cloud_vital_type type;
	union {
		uint32_t u;
		int32_t s;
	} value;
};

struct cloud_telemetry_vitals {
	bool valid;
	uint8_t count;
	struct cloud_vital items[CLOUD_TELEMETRY_MAX_VITALS];
};

struct cloud_telemetry_crash {
	bool valid;
	uint32_t fault_type;
	uint32_t pc;
	uint32_t lr;
	char build_id[41]; /* GNU build-id hex of the crashing image, "" = omit */
	uint8_t reg_count;
	uint32_t regs[CLOUD_TELEMETRY_MAX_CRASH_REGS];
	uint8_t stack_count;
	uint32_t stack[CLOUD_TELEMETRY_MAX_CRASH_STACK];
	uint16_t breadcrumb_len; /* bytes in breadcrumbs[], 0 = omit */
	char breadcrumbs[CLOUD_TELEMETRY_MAX_BREADCRUMB];
};

/* Static device identity/metadata (key 23): board, modem firmware, IMEI and SIM
 * ICCID. Unlike the telemetry time-series this rarely changes, so the device
 * reports it one-shot after boot (armed by the on-connect device-info trigger);
 * the server folds it onto the device record. Each field is a NUL-terminated
 * string; an empty string is omitted from the wire map. */
struct cloud_telemetry_device_info {
	bool valid;
	char board[32];    /* CONFIG_BOARD (kit / SoC name) */
	char modem_fw[40]; /* modem firmware version (e.g. "mfw_nrf91x1_2.0.2") */
	char imei[24];     /* modem IMEI / serial number */
	char iccid[24];    /* SIM ICCID */
};

struct cloud_telemetry {
	bool has_transport;
	enum cloud_transport transport;
	const char *fw_version; /* NULL to omit; must be < 24 bytes */
	bool has_timestamp;
	uint64_t timestamp;
	size_t metric_count;
	struct cloud_metric metrics[CLOUD_TELEMETRY_MAX_METRICS];
	struct cloud_telemetry_gnss gnss; /* gnss.valid = false to omit */
	struct cloud_telemetry_cell cell; /* cell.valid = false to omit */
	struct cloud_telemetry_wifi wifi; /* wifi.valid = false to omit */
	struct cloud_telemetry_reset reset;   /* key 20; .valid = false to omit */
	struct cloud_telemetry_vitals vitals; /* key 21; .valid = false to omit */
	struct cloud_telemetry_crash crash;   /* key 22; .valid = false to omit */
	struct cloud_telemetry_device_info device_info; /* key 23; .valid=false to omit */
};

/** Reset a telemetry record to empty. */
void cloud_telemetry_init(struct cloud_telemetry *t);
void cloud_telemetry_set_transport(struct cloud_telemetry *t, enum cloud_transport tr);
void cloud_telemetry_set_fw_version(struct cloud_telemetry *t, const char *version);
void cloud_telemetry_set_timestamp(struct cloud_telemetry *t, uint64_t ts);

/** Attach a GNSS fix, emitted as a nested CBOR map under telemetry key 4. */
void cloud_telemetry_set_gnss(struct cloud_telemetry *t,
			      const struct cloud_telemetry_gnss *g);

/** Attach a cell scan (key 5) / Wi-Fi scan (key 6). Sets the .valid flag. */
void cloud_telemetry_set_cell(struct cloud_telemetry *t,
			      const struct cloud_telemetry_cell *c);
void cloud_telemetry_set_wifi(struct cloud_telemetry *t,
			      const struct cloud_telemetry_wifi *w);

/** Add a free-form metric. Returns -ENOMEM if the metric array is full. */
int cloud_telemetry_add_uint(struct cloud_telemetry *t, uint16_t key, uint64_t v);
int cloud_telemetry_add_double(struct cloud_telemetry *t, uint16_t key, double v);

/** Attach a boot report (key 20), vitals heartbeat (key 21) or crash report
 *  (key 22). Each sets the corresponding .valid flag. */
void cloud_telemetry_set_reset(struct cloud_telemetry *t,
			       const struct cloud_telemetry_reset *r);
void cloud_telemetry_set_vitals(struct cloud_telemetry *t,
				const struct cloud_telemetry_vitals *v);

/** Append a typed sample to a vitals heartbeat. Returns -ENOMEM if the list is
 *  full. `key` must be a 2-char static string. */
int cloud_telemetry_vitals_add_uint(struct cloud_telemetry_vitals *v,
				    const char *key, uint32_t value);
int cloud_telemetry_vitals_add_int(struct cloud_telemetry_vitals *v,
				   const char *key, int32_t value);
void cloud_telemetry_set_crash(struct cloud_telemetry *t,
			       const struct cloud_telemetry_crash *c);

/** Attach a static device info record (key 23): board, modem firmware, IMEI and
 *  SIM ICCID. Sets the .valid flag; empty string fields are omitted on the wire. */
void cloud_telemetry_set_device_info(struct cloud_telemetry *t,
				     const struct cloud_telemetry_device_info *d);

/* ------------------------------------------------------------------------
 * Downlink / shadow
 * ------------------------------------------------------------------------ */

/* A decoded shadow delta: the desired configuration version and the set of
 * keys whose desired value differs from what the device last reported. Values
 * are pre-rendered to short strings so the application needs no CBOR. */
#define CLOUD_SHADOW_MAX_ENTRIES 8
#define CLOUD_SHADOW_KEY_MAX     32
#define CLOUD_SHADOW_VAL_MAX     48

struct cloud_shadow_entry {
	char key[CLOUD_SHADOW_KEY_MAX];
	char value[CLOUD_SHADOW_VAL_MAX];
};

struct cloud_shadow_delta {
	uint64_t desired_version;
	size_t entry_count;
	struct cloud_shadow_entry entries[CLOUD_SHADOW_MAX_ENTRIES];
};

/* Application callback invoked when a shadow delta is received. The library
 * acknowledges the version automatically after the callback returns, so the
 * callback only has to apply the desired changes. */
typedef void (*cloud_shadow_cb)(const struct cloud_shadow_delta *delta, void *user);

/* The queue-mode envelope returned by a confirmable telemetry post. Inspect
 * the flags or just pass it to cloud_client_process_downlink(). */
struct cloud_downlink {
	uint8_t response_code;     /* CoAP response code (e.g. 2.04 Changed) */
	bool shadow_delta_pending; /* a shadow delta is waiting for the device */
	bool fota_job_pending;     /* a FOTA job is queued */
	bool has_inline_delta;     /* the delta was inlined in this response... */
	/* ...and decoded into an internal buffer, so cloud_client_process_downlink
	 * can apply it without a separate GET /s round-trip. */
};

/** Raw OSCORE response from a single CoAP exchange. */
struct coap_oscore_response {
	uint8_t code;
	const uint8_t *payload;
	uint16_t payload_len;
};

/** Low-level OSCORE GET (used by FOTA client). */
int cloud_client_oscore_get(const char *path, struct coap_oscore_response *resp);

/** Low-level OSCORE POST (used by FOTA client). */
int cloud_client_oscore_post(const char *path, const uint8_t *payload, size_t payload_len,
			     struct coap_oscore_response *resp);

/**
 * Block2 GET over OSCORE: requests path with SZX block size from start_block.
 * sink is called per block. max_blocks bounds how many blocks this call fetches
 * (0 = run to completion); a bounded call returns early so the caller can yield
 * the cloud thread between chunks (e.g. to service telemetry) and resume.
 *
 * On return: *next_block_out = block to resume from, *total_out = payload bytes
 * fetched this call, *more_out = whether more blocks remain. Any out pointer may
 * be NULL.
 */
int cloud_client_oscore_block2_get(const char *path, uint8_t szx,
				   int (*sink)(const uint8_t *data, size_t len, void *ctx),
				   void *ctx, uint32_t start_block, uint32_t max_blocks,
				   size_t expected_size, uint32_t *next_block_out,
				   size_t *total_out, bool *more_out);

/**
 * Block2 POST over OSCORE: POSTs path with a CBOR request body and reads the
 * (potentially multi-block) response. The first request carries body + Block2
 * num 0; subsequent requests are empty POSTs with an incremented Block2 number,
 * matching the server's response-side Block2 on POST (used by A-GNSS /a). sink
 * is called per response block. Runs to completion in one call. 0 on success.
 */
int cloud_client_oscore_block2_post(const char *path, const uint8_t *body, size_t body_len,
				    uint8_t szx,
				    int (*sink)(const uint8_t *data, size_t len, void *ctx),
				    void *ctx);

/**
 * Block1 POST over OSCORE: uploads total_len bytes to path in szx-sized chunks
 * (RFC 7959 request payload), the mirror of the Block2 download path used by
 * FOTA. The source callback fills up to `want` bytes at `offset` and returns the
 * number written (or <0 on error). Used to push a stored coredump to POST /c.
 * Runs to completion in one call. 0 on success.
 */
typedef int (*cloud_block1_source)(uint8_t *buf, size_t want, size_t offset, void *ctx);
int cloud_client_oscore_block1_post(const char *path, size_t total_len, uint8_t szx,
				    cloud_block1_source source, void *ctx);

/** As cloud_client_oscore_block1_post(), but start at Block1 number
 * start_block (byte offset start_block * block size) to resume an interrupted
 * upload the server has partially stored. */
int cloud_client_oscore_block1_post_from(const char *path, size_t total_len, uint8_t szx,
					 uint32_t start_block, cloud_block1_source source,
					 void *ctx);

/* ------------------------------------------------------------------------
 * Lifecycle and operations
 * ------------------------------------------------------------------------ */

/**
 * Initialize OSCORE context and open the UDP socket. Must be called once the
 * network is up, before any operation below. Safe to call again to re-establish
 * the transport: any previously opened socket is closed first.
 */
int cloud_client_init(void);

/**
 * Close the UDP socket opened by cloud_client_init(). Call when tearing down the
 * cloud connection (e.g. on disconnect) so the modem socket descriptor is freed
 * rather than leaked across reconnects.
 */
void cloud_client_deinit(void);

/* ------------------------------------------------------------------------
 * Release Assistance Indication (RAI)
 *
 * Lets the caller tell the LTE modem when the device is done, so the network
 * can release the RRC connection instead of waiting for its inactivity timer.
 * Only the caller knows whether more traffic follows (FOTA, coredump, A-GNSS,
 * a storage batch...), so the library never releases on its own. Block1/Block2
 * transfers mark every block request RAI_ONGOING so they never release
 * mid-transfer. Requires CONFIG_OSCORE_CLOUD_RAI (and CONFIG_LTE_RAI_REQ for
 * the modem to act on it); otherwise these calls are no-ops.
 * ------------------------------------------------------------------------ */

enum cloud_rai_hint {
	CLOUD_RAI_NONE,     /* no indication (default) */
	CLOUD_RAI_LAST,     /* release after the next send (NON uplink) */
	CLOUD_RAI_ONE_RESP, /* release after the next send + one response (CON) */
	CLOUD_RAI_ONGOING,  /* keep the link up after the next send */
};

/**
 * Queue a one-shot RAI hint for the next request send. The send consumes it
 * and the hint resets to CLOUD_RAI_NONE. A Block1/Block2 transfer drops any
 * pending hint (it always continues past its sends). Never fails a send.
 */
void cloud_client_rai_next(enum cloud_rai_hint hint);

/**
 * Ask the modem to release the link now, without sending (SO_RAI =
 * RAI_NO_DATA on the connected socket). Call after the last exchange of a
 * batch or bulk transfer. 0 on success or when RAI is disabled, negative errno
 * if the socket option fails (harmless: the inactivity timer releases).
 */
int cloud_client_rai_release(void);

/**
 * Send a confirmable telemetry check-in (POST /t) and read the queue-mode
 * response envelope into *dl (may be NULL to ignore it). 0 on success.
 */
int cloud_client_post_telemetry(const struct cloud_telemetry *t,
				struct cloud_downlink *dl);

/**
 * Send a non-confirmable telemetry check-in (POST /t, fire-and-forget). No
 * response is read, so no downlink is observed; pair with a shadow sync when
 * downlink is needed. Suits sleepy NTN / NB-IoT uplinks. 0 on success.
 */
int cloud_client_post_telemetry_non(const struct cloud_telemetry *t);

/**
 * Return the shadow delta that was inlined in the most recent telemetry response
 * (valid only when the matching cloud_downlink.has_inline_delta was set). The
 * delta is owned by the library and is overwritten by the next telemetry post,
 * so read it before posting again.
 */
const struct cloud_shadow_delta *cloud_client_inline_delta(void);

/**
 * Act on a downlink envelope from cloud_client_post_telemetry(): if a shadow
 * delta is pending, fetch/decode it, invoke cb, and acknowledge the version.
 * FOTA (flag bit1) is handled separately by the caller via fota_client_step(),
 * not here, so the download can be interleaved with other traffic. 0 on success.
 */
int cloud_client_process_downlink(const struct cloud_downlink *dl,
				  cloud_shadow_cb cb, void *user);

/**
 * Explicitly fetch the shadow delta (GET /s). If one is pending it is decoded,
 * passed to cb, and acknowledged so the server marks the device converged.
 * Does nothing (returns 0) when the device is already converged.
 */
int cloud_client_sync_shadow(cloud_shadow_cb cb, void *user);

/**
 * Fetch a pending shadow delta (GET /s) without acknowledging it.
 * Returns 0 with delta->entry_count == 0 when converged.
 */
int cloud_client_fetch_shadow_delta(struct cloud_shadow_delta *delta);

/**
 * Report applied shadow state to the server (POST /s with {1: version, 2: map}).
 */
int cloud_client_report_shadow(uint64_t version, const struct cloud_shadow_entry *entries,
			       size_t entry_count);

/**
 * Acknowledge that the device has applied a shadow version (POST /s with
 * {1: version}). Normally done automatically by the calls above. 0 on success.
 */
int cloud_client_ack_shadow(uint64_t version);

#endif /* CLOUD_CLIENT_H */
