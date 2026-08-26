# Tuya BLE Connection Policy Design

## 1. Current behavior

Config-entry setup currently requires a current `BLEDevice` for the stored
address. It creates the cloud-backed device manager, loads device credentials,
decodes advertisement metadata, creates the coordinator, and schedules an
immediate `device.startup_update()` call. For the reviewed S1 and V1 products,
that path establishes the retained session and requests current status once.
For every unrelated product it delegates to the pre-existing `device.update()`
behavior. Both paths lazily open GATT, start notifications, complete the Tuya
device-information and pairing exchange, and retain the client. Entity writes
use the same lazy connection path.

The transport has one connection lock and one operation lock per exact session,
but the
`_expected_disconnect` flag currently combines terminal stop, intentional
disconnect, and reconnect suppression. An unexpected paired disconnect starts
another reconnect task. A transport failure may reconnect only to restore a
future session; it never retains or replays the failed packet. The coordinator
delays ordinary disconnected availability for the existing ten-minute grace
period, which is unsuitable for an actual connectivity diagnostic.

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
the three shared policy entities in this implementation. S1 additionally
receives one local hold-time number.

* `Connection Mode` is a config select with `always_connected` and `on_demand`
  values. Its visible states are `Always connected` and `On demand`.
* `Home Assistant BLE Control` is a config switch. On permits HA connections
  according to the selected mode; off persistently suspends HA BLE control.
* `Bluetooth Connection` is an always-available diagnostic binary sensor with
  connectivity device class. It is on only for an authenticated and paired
  physical GATT session. This physical diagnostic remains on if notification
  teardown succeeded but GATT release has not yet completed; such a session is
  not usable for integration traffic.
* `On-Demand Connection Hold Time` is an S1-only config number in seconds. It
  accepts integral values from 15 through 105 and defaults to 15. It affects
  only `On demand`; it is not a third connection mode.

The control entities are local policy entities. They remain available while
the entry is disconnected or suspended. No address, UUID, device identifier,
credential, payload, or policy internals are exposed as entity attributes.

## 3. Persisted options

The following keys are merged into the existing config-entry options:

* `connection_mode`: `always_connected` or `on_demand`;
* `ble_control_enabled`: a boolean;
* `on_demand_connection_hold_time`: an S1-only integer from 15 through 105.

Missing values default to `always_connected` and `true`, preserving current
behavior for existing entries. Invalid values are normalized to those safe
defaults without changing credentials or other options. Every entity and
options-flow update starts with a copy of the complete existing options and
updates only the policy keys. No storage file is edited, and no entry is
removed or recreated.

A missing S1 hold-time value behaves as 15 seconds and is not silently written
while loading the entry. An invalid persisted hold time also reads as 15
seconds without preventing setup or rewriting unrelated options. V1 and all
unrelated products receive neither this option nor the number entity.

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

### 4.1 Exact session ownership

Every integration-owned physical connection has an immutable session token
containing the exact Bleak client object and a monotonically increasing epoch.
The epoch is allocated after `establish_connection()` returns a connected
client and before notifications are registered. It is never reused. A token is
current only while both the stored client is that exact object and the stored
connection epoch equals the token epoch.

The notification callback registered with Bleak is a per-session closure. It
captures the token and verifies it before decryption, response correlation,
protocol-response scheduling, freshness changes, or datapoint parsing. A
delayed callback from a retired client therefore cannot be decrypted with a
replacement key, satisfy a replacement response future, or update replacement
state. Response futures and response tasks are likewise keyed or parameterized
by the exact token, not by a sequence number alone. Session invalidation cancels
that token's pending protocol-response tasks. Each token also owns its operation
lock, so delayed cancellation cleanup from a retired response cannot block
replacement-session setup or transport.

The Bleak disconnect callback is also a per-establishment closure bound to that
token. Client identity alone is insufficient because a connector may reuse the
same client object for a later epoch. A delayed old-epoch disconnect is ignored.
If callback delivery was missed and connection establishment observes a dead
owned client, it retires that token, fails its response futures, and publishes
provenance loss before claiming a replacement. Claiming never forgets a client
that still reports physically connected.

Connection establishment retains the connection lock through Device-Info,
pairing, the optional one-shot status request, and connected-state publication.
Every await boundary rechecks exact ownership. Connected callbacks are
published once for each successfully finalized token, so completion from a
retired session cannot activate or republish a replacement session.
The claim-to-finalization task and every in-flight status owner are registered
against that exact token. Retirement cancels those owners so Device-Info,
pairing, or status I/O cannot retain the connection lock ahead of a replacement.
Status-specific transport boundaries additionally recheck the effective
Always-connected policy. Tracked startup status work is cancelled when
suspension, On-demand mode, unload, terminal stop, or token retirement
supersedes it. An unexpected loss before pairing uses the same bounded future
reconnect policy as a later session loss; On-demand retirement instead settles
idle and creates no reconnect or idle-disconnect timer.

## 5. Connection state machine

The policy controller uses these conceptual states:

* `STOPPED`: terminal state after unload or Home Assistant shutdown;
* `SUSPENDED`: persistent HA-control suspension with no policy-created GATT;
* `ALWAYS_CONNECTED_CONNECTING`: an enabled always-connected session is being
  established;
* `ALWAYS_CONNECTED_ACTIVE`: an authenticated, paired, notification-ready
  session is retained;
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
policy lock, grants only that acquiring task a temporary setup context, and
waits for a usable paired session. The setup context is installed only after
the policy checks succeed and is removed before acquisition returns. Release
decrements the count under the same lock and never permits a negative count.

Nested and concurrent leases are reference-counted. Always-connected release
leaves GATT active. For S1, On-demand release retains one cancellable owner only
when the count reaches zero and confirmed current-session activity exists. Its
monotonic deadline is the latest confirmed activity plus the configured hold
time. Later confirmed activity replaces the deadline; no periodic status or
other keep-alive is sent. A new lease, mode change, suspension, session
replacement, unload, or shutdown cancels or safely reconciles the owner. A
failed or cancelled setup that has already released GATT settles directly in
`ON_DEMAND_IDLE` and never creates this timer. Unrelated products retain their
existing fixed idle-delay behavior.

Generic datapoint writes and status updates own a lease. S1 lock and unlock
operations own one outer lease around their complete operation; nested
datapoint leases cannot release the physical session early. V1 commands own
one lease through the correctly correlated confirmation. Lease cleanup runs in
`finally` blocks so cancellation and exceptions cannot leak the count. Every
post-increment setup and state-finalization await is covered by the same
cancellation guard; counted-lease release is allowed to finish before repeated
cancellation is propagated.

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
paired disconnect. A verified unexpected loss waits at least one second. Each
short-lived replacement doubles that delay up to 60 seconds; only a session
that remains stable for at least 30 seconds resets it for products other than
S1. S1 `jtmspro/xqeob8h6` uses the same 1, 2, and 4 second initial sequence,
then enters a 15-minute cooldown. S1 setup failures use this sequence rather
than the dependency's 0.1-second generic transport delay, and only an
authenticated session lasting 15 minutes resets the S1 failure pressure. A
continuously failing S1 therefore makes at most seven background connection
attempts in its first hour and four per hour after that.

If an S1 setup or session failure leaves GATT physically connected, the
computed reconnect delay remains attached to that mandatory release and is
scheduled only after physical cleanup is verified. Physical-release retries
have an independent 1, 2, and 4 second sequence followed by the same 15-minute
cooldown. They do not advance reconnect failure pressure. Other products,
including V1, retain the dependency's generic physical-release retry delay.

A reconnect request that arrives while an attempt is active is retained as one
bounded follow-up, never as a parallel task. A larger delay arriving while the
current reconnect owner is still sleeping replaces that sleeper, so the later
backoff cannot be lost. Other products retain the existing bounded transport
backoff for connection-attempt failures. Every attempt rechecks policy,
terminal stop, and the live target. Suspension, mode changes, unload, and
shutdown cancel both the active task and pending follow-up. Re-enabling
always-connected mode makes at most one immediate policy attempt; an unexpected
post-connect loss still uses the non-zero loss backoff.

Automatic Device Status synchronization is limited to the exact reviewed
products `jtmspro/xqeob8h6` and `ms/7a4xvbtt`. Each physical session can attempt
it once, after pairing, with empty data. The request is awaited while exact
connection-establishment ownership is held; it is not detached, replayed, or
silently repeated after an ambiguous failure. An acknowledgement alone does
not make any datapoint current. Synthetic protocol-v3, protocol-v4, and FD50
products retain their pre-existing setup update behavior and receive no new
reconnect-specific status request.

On-demand mode never reconnects because an advertisement arrived. It waits for
an explicit lease-backed operation. An ambiguous transport failure never
replays a command or starts a delayed background resend for any product.
Local command rollback is revision-bound: if a newer inbound or local mutation
wins while an older write is failing, the older failure cannot overwrite it.

## 9. On-demand idle behavior

On-demand setup and restart leave GATT disconnected and perform no background
status update. A command or configuration write acquires a lease, connects and
authenticates, performs the complete operation, and waits for its required
response. For S1, the last lease retains one release owner until the configured
15–105 second monotonic deadline measured from the latest successfully
confirmed current-session activity. Correlated Device Info, Pair, Device
Status, and command responses and accepted device-originated reports qualify;
connection start, advertisements, write return alone, timeouts, rejected data,
and old-session callbacks do not. Active leases and response drains postpone
release and force deadline recalculation. A successful intentional release
does not reconnect or add reconnect-failure pressure; a failed physical release
retains mandatory cleanup ownership. Events that occur while disconnected
cannot be observed; this limitation is documented in the user guide.

## 10. Suspension and re-enable behavior

Turning HA BLE Control off persists the option first, marks suspension pending,
blocks new leases, cancels reconnect and idle work, waits for existing leases,
stops notifications, disconnects, clears session transport state, publishes
actual connectivity off, and enters `SUSPENDED`. The bounded transition wait
never force-disconnects an active S1 DP70/DP71 sequence or an unconfirmed V1
command. A timeout returns a translated error and leaves new work blocked.

Turning control on persists first. In always-connected mode it leaves
suspension, makes one connection attempt, refreshes status after successful
pairing only for the exact reviewed S1/V1 products, and retains the session. In
on-demand mode it leaves suspension and enters `ON_DEMAND_IDLE` without
connecting. If the app still owns GATT, the runtime keeps the actual diagnostic
off and uses only bounded retry behavior.

### 10.1 Release supersession matrix

| Pending release | Session condition | New desired policy | Result |
| --- | --- | --- | --- |
| `SUSPEND` | physical teardown has not begun and the session remains paired and notification-ready | BLE control enabled | Cancel the reversible release and apply the newest mode. |
| `ON_DEMAND_IDLE` | physical teardown has not begun and the session remains paired and notification-ready | Always connected | Cancel the reversible release and retain the usable session. |
| `SUSPEND` or `ON_DEMAND_IDLE` | physical teardown is in progress | any visible policy change | Retain the single release owner; apply the newest policy only after verified GATT release. |
| `SUSPEND` or `ON_DEMAND_IDLE` | notification state became inactive or unknown and GATT release failed | any visible policy change | Convert to mandatory `SETUP_FAILURE`; reject commands and reconnect until verified cleanup. |
| `SETUP_FAILURE` | connected client remains unusable | any visible policy change | Never supersede; retain the exact client and one disconnect retry owner. |
| `SESSION_FAILURE` | `write_gatt_char()` raised while the exact client still reports connected | any visible policy change | Never infer a callback. Retain the paired GATT client, mark notifications unready, reject ordinary traffic, and retain one physical-release retry owner. |
| `UNLOAD` | platform teardown fails but notifications are positively restored on the same paired client | latest enabled policy | Cancel unload release ownership and reconcile the latest policy. |
| `UNLOAD` | notification restoration fails or remains unknown | any policy | Convert to mandatory `SETUP_FAILURE` and retain cleanup ownership. |
| `STOP` | any | any | Terminal and non-cancellable; retain cleanup ownership until physical release. |

Successful physical release always reconciles the newest persisted policy.
The controller never starts a reconnect while an unusable connected client or
an in-progress physical release remains owned.

### 10.2 Transport failure ownership audit

`_disconnected(client, token)` is reserved for the session-bound Bleak
callback. A local transport path may clear the current client only after
checking that the exact current client is no longer physically connected. A
connected client is always either command-ready or owned by a
non-supersedable release obligation.

| Failure point | Client retained? | Physical release attempted? | Retry owner | Replay permitted? |
| --- | --- | --- | --- | --- |
| Establish connection | Yes, after a connected client is created | Yes, if notification, Device-Info, or pairing setup fails | `SETUP_FAILURE` or `STOP` | No |
| Start notifications | Yes, when GATT remains connected | Yes | `SETUP_FAILURE` or `STOP` | No |
| Device-Info | Yes, when GATT remains connected | Yes | `SETUP_FAILURE` or `STOP` | No |
| Pairing | Yes, when GATT remains connected | Yes | `SETUP_FAILURE` or `STOP` | No |
| GATT write | Yes, while `is_connected` remains true; notifications become unready | Yes | `SESSION_FAILURE` | No |
| Protocol response write | Yes, while `is_connected` remains true; notifications become unready | Yes | `SESSION_FAILURE` | No |
| Response timeout | Yes | No; the session remains usable unless another verified failure occurs | None | No |
| Stop notifications | Yes, until disconnect is verified | Yes | Existing pending reason, or `SETUP_FAILURE` / `STOP` when cleanup fails | No |
| Disconnect | Yes, until `is_connected` is false | Yes | Existing pending reason, one bounded retry | No |
| Unexpected callback | No; the exact callback client is already physically gone | Not required | One normal reconnect only for enabled Always connected policy | No |
| Unload | Yes, until release succeeds or rollback establishes mandatory repair | Yes | `UNLOAD`, then `SETUP_FAILURE` if rollback cannot restore readiness | No |
| Shutdown | Yes, until terminal release succeeds | Yes | non-cancellable `STOP` | No |

The transport stores no failed packet fragments, encrypted ciphertext, response
correlation, or semantic command for later replay. After an ambiguous write,
the release owner may restore GATT according to the latest policy, but only a
new explicit operation may send a new current-session command.

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

Platforms unload as one recoverable set. The same platform deadline covers the
initial parallel unload calls as well as restoration, so a platform that hangs
before rollback begins is cancelled with its siblings. If any platform does not
unload, every platform is checked and missing platforms are restored directly
through the Home Assistant entity component while the config entry is still in
its unload transition. Restoration also has an explicit attempt limit and
backoff.

The complete shielded entry transaction has a separate outer deadline covering
GATT quiesce, notification rollback, platform work, and terminal cleanup.
Cancellation is deferred only until that deadline. If it expires, in-flight
children are cancelled, the runtime remains owned, a connected session becomes
notification-unready mandatory repair with one release owner, and the entry is
reported as `FAILED_UNLOAD` instead of leaving unload or shutdown waiting.

Complete restoration is verified from every expected entity platform's
setup-complete marker before the entry is returned to `LOADED`. If restoration
is exhausted, the integration stops all rollback work, returns unload failure,
keeps the runtime and BLE owner, and leaves the entry honestly in
`FAILED_UNLOAD`; it never presents a partial platform set as loaded. Home
Assistant 2025.1 treats `FAILED_UNLOAD` as non-recoverable during the same
process, so a restart reconstructs the retained entry before a later clean
unload. Only a fully successful platform teardown makes the device terminally
`STOPPED`.

Terminal success also shuts down the coordinator's device callback
registrations and cancels any pending ten-minute disconnect-grace handle. A
failed or rolled-back unload retains those registrations because the runtime
remains loaded.

## 12. Entity availability and state freshness

The connectivity binary sensor and both policy entities are available whenever
the config entry is loaded. The connectivity sensor reads the actual paired
physical GATT state immediately and does not use the coordinator's delayed
grace period. Internal `is_connection_active` is stricter: it additionally
requires active notifications, because commands and acknowledgements require a
usable bidirectional session.

`state_data_fresh` is an aggregate internal device property. It becomes true
only after exact-current-session inbound device data is received and becomes
false immediately on disconnect or a write failure that leaves the GATT client
connected but notification-unready. The device publishes that session-data
invalidation to the coordinator immediately. Entity listeners therefore write
unknown or unavailable current state without waiting for the coordinator's
existing ten-minute general connectivity grace; that grace remains unchanged
and independent.

Each accepted inbound datapoint also stores the exact receipt epoch. A
datapoint is current only when that epoch equals the active exact session epoch.
The compatibility `received_from_device` property is derived from this
comparison. Cached values need not be erased on disconnect, and an unrelated
datapoint in a replacement session cannot make an old value current.

For S1, Battery DP8, Motor State DP47, Authentication Mode DP34, Auto-Lock DP33,
Auto-Lock Delay DP36, and Door State DP40 require their own current-session
receipt. After reconnect, a DP8-only report can restore Battery but none of the
other five values. Configuration entities remain callable when policy permits
even while their displayed value is unknown. Alarm DP21 and the Last Unlock
Method datapoints retain their historical/event semantics; they are not proof
of current configuration and are not cleared merely because a session ended.

The exact reviewed V1 lock exposes read-only Motor State DP47 only when DP47
itself was received in the active epoch. V1 Auto-Lock DP33 and Auto-Lock Delay
DP36 likewise display unknown until their own datapoint arrives in the active
session; their commands remain callable whenever policy permits. A replacement
DP8 or another unrelated report cannot refresh any of these cached values. V1
Alarm DP21 and Last Unlock Method retain their documented historical/event
semantics. This does not change V1 command behavior. The physical S1 connection
churn remains indeterminate and hardware has not been verified.

Other read-only entities are unavailable when aggregate current-session data
is absent. On-demand command entities remain callable while control is enabled.
Suspended ordinary entities are unavailable and their write paths reject before
connecting or writing. Historical Home Assistant state is not treated as a
current physical state.

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

S1 Lock and Unlock share one per-device operation lock, so a DP46 action cannot
interleave with an Unlock sequence. On demand Unlock first establishes its
authenticated session, then selects the effective complete validated
device-scoped DP70/DP71 pair. A complete pair received from that exact session
supersedes the persisted pair; when the session supplies no complete pair, the
most recent complete validated same-device pair remains available. Session-local
halves remain private and pending until both belong to the same exact session.
They cannot replace one persisted half, combine across session epochs, or create
an intermediate Store snapshot. Complete-pair promotion updates DP70 and DP71
atomically. Always connected uses the same device-scoped rule.

Unlock holds one outer lease around connection, selection, DP70, the required
0.8-second delay, rebuilt DP71, and required response handling. The timestamp is
rebuilt only after the effective pair is selected. No idle task or suspension
transition can disconnect between DP70 and DP71. Missing or invalid templates
perform zero BLE writes. An ambiguous DP46, DP70, or DP71 write restores local
transient state, releases the failed session safely, and never retries either
the individual datapoint or the protected unlock sequence.

An executable synthetic ordering reproduced the previous preconnection
template-selection race: Pair A was selected before Session 2 connected and
remained outgoing after Session 2 supplied complete Pair B during setup. The
root cause of the original physical On-demand Unlock failure remains
indeterminate, and transient BLE, proxy-routing, GATT-session, or transport
failure remains plausible. The reviewed runtime was installed and
owner-operated on one selected S1 for one cold Lock and one warm same-session
Unlock, with exactly one physical action each. This is not an all-S1 or
all-command-path claim. The final confirmed-activity timestamp of that physical
run was not independently exposed; the 105-second production timer contract
was established by separate non-actuating W105 runs. No broader physical-success
claim is made.

## 15. V1 safety

V1 Lock holds one lease around exactly one product-specific DP46 true command
and its correlated confirmation. V1 Unlock holds one lease around exactly one
product-specific DP6 action and its correlated confirmation. Only the expected
sender-DPS response is accepted. An ambiguous transport error never schedules
a replay, second lease-based retry, or delayed resend. DP33 remains Auto-Lock
configuration and DP47 remains read-only and exact-session gated; Open is not
added.

## 16. Unrelated-device compatibility

Only the exact S1 and V1 category/product pairs receive the new entities and
the new reconnect-time automatic status synchronization. Existing product and
platform mappings remain additive. Default policy values preserve the effective
always-connected behavior for existing entries, while the common transport
gates policy work without changing product-specific DP selection, S1 template
provenance, or V1 at-most-once handling.

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

The cause of the observed short S1 post-status disconnect remains
hardware-indeterminate. The non-zero bounded reconnect policy prevents the
integration from amplifying that churn; it does not claim to correct the lock,
radio, firmware, mobile-app ownership, or physical environment.
