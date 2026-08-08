# Tuya BLE Connection Policy Design

## 1. Current behavior

Config-entry setup currently requires a current `BLEDevice` for the stored
address. It creates the cloud-backed device manager, loads device credentials,
decodes advertisement metadata, creates the coordinator, and schedules an
immediate `device.update()` call. The update lazily opens GATT, starts
notifications, completes the Tuya device-information and pairing exchange, and
retains the client. Entity writes use the same lazy connection path.

The transport has one connection lock and one operation lock, but the
`_expected_disconnect` flag currently combines terminal stop, intentional
disconnect, and reconnect suppression. An unexpected paired disconnect starts
another reconnect task. Transport failures can also schedule a resend or
reconnect. The coordinator delays ordinary disconnected availability for the
existing ten-minute grace period, which is unsuitable for an actual
connectivity diagnostic.

Disabling a config entry now starts a reversible unload quiesce before platform
teardown. The runtime blocks new leases, drains active work, and verifies GATT
release while it is still nonterminal. Only a complete platform unload is
followed by terminal stop and runtime removal. A failed platform unload restores
the complete platform set and the latest desired runtime policy before the
unload reports failure. Disabling only an ordinary entity does not own the
transport, so it cannot release GATT or prevent a background status update or
reconnect.

## 2. User-visible entities

Only the S1 product `jtmspro/xqeob8h6` and the V1 product `ms/7a4xvbtt` receive
the three new entities in this implementation.

* `Connection Mode` is a config select with `always_connected` and `on_demand`
  values. Its visible states are `Always connected` and `On demand`.
* `Home Assistant BLE Control` is a config switch. On permits HA connections
  according to the selected mode; off persistently suspends HA BLE control.
* `Bluetooth Connection` is an always-available diagnostic binary sensor with
  connectivity device class. It is on only for an authenticated and paired
  GATT session.

The control entities are local policy entities. They remain available while
the entry is disconnected or suspended. No address, UUID, device identifier,
credential, payload, or policy internals are exposed as entity attributes.

## 3. Persisted options

The following keys are merged into the existing config-entry options:

* `connection_mode`: `always_connected` or `on_demand`;
* `ble_control_enabled`: a boolean.

Missing values default to `always_connected` and `true`, preserving current
behavior for existing entries. Invalid values are normalized to those safe
defaults without changing credentials or other options. Every entity and
options-flow update starts with a copy of the complete existing options and
updates only the policy keys. No storage file is edited, and no entry is
removed or recreated.

Suspension persists `ble_control_enabled = false` before the runtime begins
disconnecting. A persistence failure leaves the active policy unchanged and
returns a translated transition error; it does not disconnect first.

## 4. Effective policy calculation

The runtime calculates the effective policy from the desired mode and the
persistent permission:

```text
if not ble_control_enabled:
    SUSPENDED
elif connection_mode == always_connected:
    ALWAYS_CONNECTED
else:
    ON_DEMAND
```

Desired mode, BLE-control permission, terminal stop, expected transient
disconnect, physical client state, authenticated state, leases, reconnect
work, idle-disconnect work, and a suspension request are separate values.

## 5. Connection state machine

The policy controller uses these conceptual states:

* `STOPPED`: terminal state after unload or Home Assistant shutdown;
* `SUSPENDED`: persistent HA-control suspension with no policy-created GATT;
* `ALWAYS_CONNECTED_CONNECTING`: an enabled always-connected session is being
  established;
* `ALWAYS_CONNECTED_ACTIVE`: an authenticated and paired session is retained;
* `ON_DEMAND_IDLE`: enabled but intentionally disconnected with no lease;
* `ON_DEMAND_CONNECTING`: an explicit lease is establishing a session;
* `ON_DEMAND_ACTIVE`: one or more leases protect an active session;
* `DISCONNECTING`: notifications and GATT are being released.

`STOPPED` is irreversible for the device object. `SUSPENDED` is reversible
only through an explicit Home Assistant policy action. Mode changes while
suspended update desired policy but cannot cause a connection.

## 6. Connection lease semantics

`TuyaBLEDevice.connection_lease(reason)` is an asynchronous context manager.
Acquisition rejects `STOPPED`, `SUSPENDED`, and any lease after a suspension
request. It cancels the per-device idle task, increments the count under the
policy lock, and waits for a usable paired session. Release decrements the
count under the same lock and never permits a negative count.

Nested and concurrent leases are reference-counted. Always-connected release
leaves GATT active. On-demand release schedules one cancellable idle task only
when the count reaches zero. The task uses the internal
`DEFAULT_ON_DEMAND_IDLE_DISCONNECT_SECONDS = 15.0` constant and checks policy
again before disconnecting. A new lease, mode change, suspension, unload, or
shutdown cancels it.

Generic datapoint writes and status updates own a lease. S1 lock and unlock
operations own one outer lease around their complete operation; nested
datapoint leases cannot release the physical session early. V1 commands own
one lease through the correctly correlated confirmation. Lease cleanup runs in
`finally` blocks so cancellation and exceptions cannot leak the count.

## 7. Startup without active BLE discovery

The stored config-entry address and credentials are sufficient to construct the
local device model, determine its product mapping, and create local policy
entities. Setup therefore remains loaded when no current advertisement exists.
The device keeps an optional live `BLEDevice` target. Bluetooth callbacks
replace or refresh that target later.

An actual connection waits for a later callback or uses the current target with
a bounded timeout. It never fabricates a GATT target. Suspended and on-demand
idle entries do not connect during setup. Always-connected entries start one
bounded status/connection path when possible and remain loaded if discovery or
the app currently prevents connection.

## 8. Reconnect behavior

Always-connected mode schedules at most one reconnect task after an unexpected
paired disconnect. Each failed attempt uses bounded backoff and rechecks
policy, terminal stop, and the live target. Suspension, mode changes, unload,
and shutdown cancel the task. Re-enabling always-connected mode makes at most
one immediate attempt and then uses the same bounded single-task backoff; it
does not run the old tight 100-attempt loop.

On-demand mode never reconnects because an advertisement arrived. It waits for
an explicit lease-backed operation. A transport failure does not cause an
ambiguous V1 command to be replayed or start a delayed background resend.

## 9. On-demand idle behavior

On-demand setup and restart leave GATT disconnected and perform no background
status update. A command or configuration write acquires a lease, connects and
authenticates, performs the complete operation, and waits for its required
response. The last lease schedules a 15-second idle disconnect. Events that
occur while disconnected cannot be observed; this limitation is documented in
the user guide.

## 10. Suspension and re-enable behavior

Turning HA BLE Control off persists the option first, marks suspension pending,
blocks new leases, cancels reconnect and idle work, waits for existing leases,
stops notifications, disconnects, clears session transport state, publishes
actual connectivity off, and enters `SUSPENDED`. The bounded transition wait
never force-disconnects an active S1 DP70/DP71 sequence or an unconfirmed V1
command. A timeout returns a translated error and leaves new work blocked.

Turning control on persists first. In always-connected mode it leaves
suspension, makes one connection attempt, refreshes status after successful
pairing, and retains the session. In on-demand mode it leaves suspension and
enters `ON_DEMAND_IDLE` without connecting. If the app still owns GATT, the
runtime keeps the actual diagnostic off and uses only bounded retry behavior.

## 11. Config-entry unload transaction

Unload preparation is a reversible quiesce rather than terminal stop. It blocks
new leases, waits for operation and response-drain ownership, lets any physical
disconnect already in progress finish, and then verifies that GATT is released.
An in-progress release is never cancelled merely to change its pending reason.

If release fails while the client remains connected, rollback restarts
notifications before the runtime is declared usable. FD50 devices retain the
required BlueZ `use_start_notify` option. A notification restart failure is a
mandatory setup-repair obligation: ordinary commands and reconnects remain
blocked, and one release retry retains ownership until physical cleanup is
verified. On-demand rollback likewise retains a physical-release owner when an
idle disconnect was already in progress.

Platforms unload as one recoverable set. If any platform does not unload, every
platform is checked and missing platforms are restored directly through the
Home Assistant entity component while the config entry is still in its unload
transition. Restoration is retried and the failed unload does not return until
the complete loaded set has finished entity-platform setup, preventing a loaded
entry with missing, partial, or duplicate policy entities. Cancellation is
deferred until that transaction reaches a consistent terminal or rolled-back
result. A rolled-back Home Assistant entry is restored to `LOADED`, so a later
clean unload can retry normally. Only a fully successful platform teardown makes
the device terminally `STOPPED`; a failed transaction returns to the latest
desired connection policy.

## 12. Entity availability and state freshness

The connectivity binary sensor and both policy entities are available whenever
the config entry is loaded. The connectivity sensor reads the actual paired
GATT state immediately and does not use the coordinator's delayed grace
period.

`state_data_fresh` is an internal device property. It becomes true only after
current-session inbound device data is received and becomes false immediately
on disconnect. Read-only sensors are unavailable or stale when it is false.
On-demand command entities remain callable while control is enabled. Lock
state returns unknown without fresh confirmation, rather than presenting a
cached value as current. Suspended ordinary entities are unavailable and their
write paths reject before connecting or writing. Historical HA state is not
treated as a current physical state.

## 13. Config-entry Options Flow

The Options Flow presents a menu with `Connection settings` and `Tuya
credentials`. Connection settings contain only Connection Mode and Home
Assistant BLE Control. They can be opened and saved while suspended, while no
advertisement is present, or while the Tuya app owns GATT. They never display
secrets and never require device access.

Credential reconfiguration remains available. Its result merges new login data
with all existing options, including policy keys and unrelated credential
fields. Saving connection settings applies the loaded device in place through
the same policy transition used by entities. It does not reload the complete
entry merely to show or save the form. A listener applies options again
idempotently after Home Assistant persists them.

## 14. S1 safety

S1 Lock holds one lease around exactly one DP46 true action. S1 Unlock validates
the complete device-scoped DP70/DP71 template before acquiring or writing,
then holds one lease around DP70, the required 0.8-second delay, rebuilt DP71,
and required response handling. No idle task or suspension transition can
disconnect between DP70 and DP71. Missing or invalid templates perform zero
BLE writes.

## 15. V1 safety

V1 Lock holds one lease around exactly one product-specific DP46 true command
and its correlated confirmation. V1 Unlock holds one lease around exactly one
product-specific DP6 action and its correlated confirmation. Only the expected
sender-DPS response is accepted. An ambiguous transport error never schedules
a replay, second lease-based retry, or delayed resend. DP33 remains Auto-Lock
configuration and DP47 remains read-only; Open is not added.

## 16. Unrelated-device compatibility

Only the exact S1 and V1 category/product pairs receive the new entities.
Existing product and platform mappings remain additive. Default policy values
preserve the effective always-connected behavior for existing entries, while
the common transport gates policy work without changing product-specific DP
selection, S1 template provenance, or V1 at-most-once handling.

## 17. Privacy

Logs and translated errors use only the process-local opaque device log label
and payload-free status text. They do not include complete addresses, device
IDs, UUIDs, keys, access material, passwords, raw DP values, S1 templates, V1
values, packet bytes, decrypted frames, or foreign exception text. Diagnostic
entities expose no transport identifiers or sensitive attributes.

## 18. Deployment and hardware test plan

Before deployment, the exact reviewed feature head must be bound to a complete
Home Assistant backup and a draft PR. The agent stops before any host access,
Core restart, service call, or physical action and requests the exact
SHA-bound authorization.

After authorization, deployment is integration-only over the approved SSH
route, with a rollback copy, transferred-hash verification, one Core restart,
and non-actuating checks. The owner, not the agent, performs S1 and V1 Lock and
Unlock tests with doors open, alternate access available, and the Tuya app
initially closed. The hardware matrix covers both modes, idle release,
persistent suspension, app handoff, re-enable behavior, restart persistence,
duplicate entities, and reauthentication.

## 19. Rollback

Rollback restores only the prior integration directory from the verified
integration-only copy, then performs the owner-approved supported Core restart
path. It does not edit Home Assistant storage or credentials. Persistent policy
options remain backward-compatible and are ignored by older integration code;
the prior runtime therefore resumes its default always-connected behavior after
rollback.

## 20. Known limitations

On-demand mode cannot observe local device events while GATT is intentionally
disconnected, so it is unsuitable for complete access-event monitoring or a
future Passage Mode Guard. Repeated short operations trade persistent GATT
ownership for connection and pairing work; no battery percentage claim is made.
The Tuya app and Home Assistant generally compete for exclusive GATT ownership,
and simultaneous reliable use is not guaranteed. Discovery and app ownership
can delay a bounded connection attempt, but the entry remains loaded and local
connection controls remain usable.
