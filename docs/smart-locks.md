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
| Unlock | Uses complete DP70/DP71 templates from the same authenticated device |
| State | Read-only DP47; `false` is secure/uncoupled and `true` is access-enabled/coupled |
| Auto-Lock | Configuration only |
| Auto-Lock Delay | Configuration only |
| Motor State | Read-only diagnostic binary sensor |

The templates are validated, device-scoped, and stored in a private regular
file with mode `0600`. There is no global, product-wide, or cross-device
fallback. Missing, incomplete, foreign, noncanonical, or ambiguous material
fails before a Bluetooth write.

The S1 transport retains its confirmed response and retry behavior. Do not copy
template material between devices and do not publish it.

For both products, the Motor State binary sensor mirrors the Boolean DP47 report:
off corresponds to secure/uncoupled and on corresponds to access-enabled/coupled.
It is diagnostic state only and never writes the device. Battery, alarm,
last-unlock method, signal strength, and other configuration or diagnostic
entities depend on the product metadata and remain separate from lock control.

## Bluetooth ownership

A Tuya BLE peripheral normally accepts one active GATT client. The Tuya app can
therefore prevent Home Assistant from connecting, and Home Assistant can prevent
the app from connecting. Close the inactive client and wait for its connection
to end; repeatedly reloading or issuing commands does not resolve GATT
ownership safely.

## Reporting a problem

Follow [Logging and privacy](logging-and-privacy.md). Report only the time,
module, attempted operation, sanitized error class, Home Assistant version, and
integration version. Never publish credentials, complete identifiers, raw logs,
captures, frames, templates, or lock datapoint values.
