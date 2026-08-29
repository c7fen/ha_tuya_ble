# TEMPORARY RESEARCH HARNESS — DO NOT MERGE

`tuya_ble.phase_a_status_probe` exists only on the temporary
`research/s1-status-phase-a-harness` branch to collect the Issue #37 Phase-A
S1 Device Status inventory. It is not the production Refresh Status feature.
Close the research branch without merge after the authorized inventory, then
restore Home Assistant to a reviewed non-harness commit.

## Scope and safeguards

The action accepts exactly one private `config_entry_id` and one `mode`:

- `cold` performs one cold Device Status request.
- `cold_then_retained` performs one cold request and, only after the first
  request has an exact successful ACK and the same authenticated session is
  still active, one retained-session request.

The target must be the exact S1 product `jtmspro` / `xqeob8h6`, with BLE
Control enabled and Connection Mode set to On Demand. Before any request, it
atomically requires an idle runtime: no GATT client, authenticated session,
connection lease, pending release, reconnect, or disconnect transition. A
failed precondition returns a sanitized result and sends no request. The
service has a dedicated per-device owner, so a simultaneous probe is rejected
before BLE I/O.

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
