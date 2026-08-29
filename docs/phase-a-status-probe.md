# TEMPORARY RESEARCH HARNESS — DO NOT MERGE

`tuya_ble.phase_a_status_probe` exists only on the temporary
`research/s1-status-phase-a-harness` branch to collect the Issue #37 Phase-A
S1 Device Status inventory. It is not the production Refresh Status feature.
Close the research branch without merge after the authorized inventory, then
restore Home Assistant to a reviewed non-harness commit.

## Scope and safeguards

The real action accepts exactly one private `config_entry_id`, one `mode`, and
an opaque, caller-generated `invocation_nonce` of 16–32 lowercase hexadecimal
characters. The nonce must contain no device or account information:

- `cold` performs one cold Device Status request.
- `cold_then_retained` performs one cold request and, only after the first
  request has an exact successful ACK and the same authenticated session is
  still active, one retained-session request.

The target must be the exact S1 product `jtmspro` / `xqeob8h6`, with BLE
Control enabled and Connection Mode set to On Demand. Before any request, it
atomically requires an idle runtime: no GATT client, authenticated session,
connection lease, pending release, reconnect, or disconnect transition. A
failed precondition returns a sanitized result and sends no request. The
service has a dedicated owner keyed to the in-memory device object, so a
simultaneous probe is rejected before BLE I/O without retaining the supplied
Config Entry ID in its lock state.

The implementation calls the existing reviewed `TuyaBLEDevice.update()` path
exactly once for `cold` and at most twice for `cold_then_retained`. It makes no
DP write, Lock/Unlock/Open command, policy update, hold-time change, retry,
keepalive, reconnect, or persistent record. Returning from `update()` is not a
success signal: the existing private observer must report the matching exact
`ACK_SUCCESS`. The retained leg additionally requires the same live private
session object; a disconnect, replacement, failure, timeout, or missing ACK
prevents that second request.

After the final attempted request, the handler keeps its observer active only
through the configured normal On-Demand Hold Time plus a cleanup margin. A
narrow private lifecycle callback confirms a completed `ON_DEMAND_IDLE`
release; generic session invalidation is not considered normal release. All
callbacks and in-memory collector state are removed before the call returns.
The harness creates no background task.

## Response and privacy boundary

Call the service with Home Assistant's response-capable service API. Its
response is JSON-serializable and contains only the mode, classification,
attempt/count flags, same-session and normal-release booleans, relative
monotonic durations, separately classified logical requests, and at most 64
observer events. An event has only its trial and observer ordinals, origin,
kind, batch ordinal, DP IDs and type names, encoded value lengths,
exact-session flag, ACK metadata, and a relative monotonic duration.

The response never contains the supplied Config Entry ID, Device/Entity
Registry IDs, address, UUID, session token or epoch, sequence number, DP value,
packet bytes, keys, credentials, or wall-clock timestamp. On collector
overflow it sets `observation_overflow: true` and classifies the probe invalid;
it does not silently truncate a valid result.

## BLE-free response-path preflight and receipt lookup

`tuya_ble.phase_a_status_probe_preflight` is a separate, response-only
temporary service. It accepts an optional opaque `nonce` and returns exactly
`result: preflight_ok`, `protocol_version: 1`, and the supplied nonce. With no
nonce it omits that field. The repository helper always generates and submits
a nonce, then requires an exact echoed match before accepting the response. It
performs no device lookup, connection, lease, Device Status, Device Info, pair, lock,
unlock, open, DP write, policy update, reconnect, or keepalive.

`tuya_ble.phase_a_status_probe_receipt` accepts only the opaque nonce. It
returns a bounded in-memory receipt projection: whether the service was
entered, whether a Device Status request was handed to transport, a sanitized
terminal class, and whether a response became available. The ledger is bounded
to 32 details that expire after 15 minutes, is never persisted, and clears when
the last integration entry unloads. A separate non-evicting 32-nonce
process-local fence rejects reuse until that unload; once full it fails closed
before device lookup or BLE. A duplicate real-probe nonce returns a local
`duplicate_nonce` response and can never invoke BLE a second time.

The repository-owned `scripts/phase_a_status_probe_helper.py` uses the same
HTTP request, REST-wrapper extraction, response allowlist, outcome mapping,
and sanitized evidence writer for preflight, real probe, and receipt lookup.
It drops `changed_states` before validation or persistence. Its exit classes
are non-overlapping: 0 valid response, 65 definitely not submitted, 66 known
service rejection, 67 local schema/privacy failure after a response, and 78 a
potentially submitted HTTP transport ambiguity. A received valid service
response never maps to 78. The CLI reads a real-probe Config Entry ID only from
a private process environment variable, never command-line arguments, and
reports the non-sensitive generated nonce even for ambiguity. A nonce proves
only response identity; receipt lookup, not retry, is the permitted follow-up
to a lost real probe response.

## Intended later invocation

From an authorized Home Assistant OS administration environment with Home
Assistant API access enabled, the intended route is:

```text
POST http://supervisor/core/api/services/tuya_ble/phase_a_status_probe?return_response
```

Use the Supervisor proxy only when that environment supplies its normal
Supervisor authentication material. Never print, persist, paste, or include a
Supervisor token in a transcript, issue, pull request, or response. This
repository branch neither authorizes nor performs a deployment, reload, service
call, Bluetooth connection, Device Status request, or physical action.

The future hardware worker must make the separately authorized calls for five
`cold_then_retained` trials followed by five `cold` trials. That permits at
most 15 Device Status requests: 10 cold and 5 retained. Do not improvise extra
calls to recover a failed or incomplete trial.
