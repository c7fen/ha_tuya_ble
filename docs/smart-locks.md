# Smart-lock behavior and safety

This integration controls access hardware. A successful Home Assistant service
call is not a substitute for checking the physical state.

## Before any physical test

- Keep the door open.
- Retain alternate authorized access.
- Confirm nobody depends on the current lock state.
- Close the Tuya mobile app so it does not hold the exclusive GATT connection.
- Perform one deliberate user action at a time and count physical motor actions.
- Stop after an ambiguous result; inspect the device before deciding to retry.

The integration must not be used to discover commands by trying datapoints,
values, or encodings on hardware.

## V1 / Lock P1

Product `ms/7a4xvbtt` exposes a `LockEntity`.

| Home Assistant behavior | Contract |
| --- | --- |
| Lock | One DP46 secure/uncouple operation |
| Unlock | One product-specific DP6 access/couple operation |
| State | Read-only DP47; `false` is secure/uncoupled and `true` is access-enabled/coupled |
| Open | Unsupported |
| Auto-Lock | DP33 configuration only |
| Auto-Lock Delay | DP36 configuration only |
| Motor State | Read-only diagnostic binary sensor |

V1 commands are serialized. The expected sender-DPS response must correlate to
the current request and report success. A timeout, disconnect, malformed
response, or transport failure is ambiguous: the integration reports an error
and does not replay the command automatically. Inspect the physical state before
issuing another action.

The former `manual_lock` button migrates to the lock domain. Update automations
that call the old button service to use `lock.lock` or `lock.unlock`.

## S1-TY-BLE-PRO

Product `jtmspro/xqeob8h6` exposes a `LockEntity` with fail-closed Unlock.

| Home Assistant behavior | Contract |
| --- | --- |
| Lock | The separately evidenced DP46 secure operation |
| Unlock | Uses a complete DP70/DP71 template pair from the same authenticated device |
| State | Read-only DP47; `false` is secure/uncoupled and `true` is access-enabled/coupled |
| Auto-Lock | Configuration only |
| Auto-Lock Delay | Configuration only |
| Motor State | Read-only diagnostic binary sensor |

The templates are validated, device-scoped, and stored in a private regular
file with mode `0600`. There is no global, product-wide, or cross-device
fallback. Missing, incomplete, foreign, noncanonical, or ambiguous material
fails before a Bluetooth write.

In On demand mode, S1 Unlock first establishes its authenticated session, then
selects the latest complete validated device-scoped pair. A complete DP70/DP71
pair received from that exact session supersedes the persisted pair. If the
session supplies no complete pair, the most recent complete validated
same-device pair remains available. Partial session pairs stay private and
pending: they neither replace one persisted half nor combine with a half from a
different session. Store promotion replaces both halves atomically. Always
connected mode uses the same device-scoped template rule.

S1 Lock has exactly one DP46 attempt. S1 Unlock has exactly one protected
DP70, delay, DP71 sequence. An ambiguous write is reported without replaying a
datapoint, packet, or sequence after reconnect; inspect the physical state
before issuing another deliberate action. Do not copy template material between
devices and do not publish it.

A synthetic ordering test reproduced a preconnection template-selection race
in the prior implementation. The root cause of the originally observed
physical On-demand Unlock failure remains indeterminate; a transient BLE,
proxy-routing, GATT-session, or transport failure remains plausible. The local
candidate has not been installed or tested on hardware, so it makes no hardware
success claim.

For both products, the Motor State binary sensor mirrors the Boolean DP47 report:
off corresponds to secure/uncoupled and on corresponds to access-enabled/coupled.
It is diagnostic state only and never writes the device. Battery, alarm,
last-unlock method, signal strength, and other configuration or diagnostic
entities depend on the product metadata and remain separate from lock control.
Integral battery percentages are exposed as integers with a suggested display
precision of zero. Home Assistant still honors an explicit user-configured
sensor precision. Invalid percentages are unavailable rather than displayed,
and fractional values from products with scaling coefficients remain precise.

## Bluetooth ownership

A Tuya BLE peripheral normally accepts one active GATT client. The Tuya app can
therefore prevent Home Assistant from connecting, and Home Assistant can prevent
the app from connecting. Close the inactive client and wait for its connection
to end; repeatedly reloading or issuing commands does not resolve GATT
ownership safely.

## Connection policy controls

S1 `jtmspro/xqeob8h6` and V1 `ms/7a4xvbtt` expose three local controls:

| Entity | Meaning |
| --- | --- |
| Connection Mode | Always connected retains paired GATT; On demand starts disconnected and leases one session for an explicit command. |
| Home Assistant BLE Control | Enabled permits HA control; disabled persists suspension, releases GATT after active work finishes, blocks commands, and suppresses reconnects. |
| Bluetooth Connection | On only for an authenticated and paired GATT session; it remains available as a diagnostic while off or suspended. |

On demand uses a fixed 15-second idle disconnect. It does not reconnect for an
advertisement alone, and local access events can be missed while disconnected.
Use On demand for S1 unless continuous access-event monitoring is required.
Use Always connected for access-event monitoring and any future Passage Mode
Guard. Existing saved policy choices are not rewritten. Repeated connection and
pairing work has an energy cost; after three failed S1 sessions, background
reconnects use a 15-minute cooldown that resets only after a 15-minute stable
authenticated session. This limits connection pressure but makes no unsupported
battery-capacity or lifetime claim.

To let the Tuya app take the peripheral, turn **Home Assistant BLE Control**
off. Wait for **Bluetooth Connection** to turn off, use the app, close or
disconnect the app, and turn HA control on again. In Always connected mode HA
will make a bounded reconnection attempt; in On demand mode it remains idle
until the next explicit command. The **Connection settings** path in the
integration Options Flow works without advertisements, BLE access, cloud login,
or re-entering credentials.

## Reporting a problem

Follow [Logging and privacy](logging-and-privacy.md). Report only the time,
module, attempted operation, sanitized error class, Home Assistant version, and
integration version. Never publish credentials, complete identifiers, raw logs,
captures, frames, templates, or lock datapoint values.
