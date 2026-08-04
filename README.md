# Home Assistant support for Tuya BLE devices

[![Validate](https://github.com/c7fen/ha_tuya_ble-s1/actions/workflows/validate.yml/badge.svg)](https://github.com/c7fen/ha_tuya_ble-s1/actions/workflows/validate.yml)

## Overview

This repository is a maintained fork of
[PlusPlus-ua/ha_tuya_ble](https://github.com/PlusPlus-ua/ha_tuya_ble).
It adds device support, Home Assistant compatibility fixes, focused tests, and
security hardening while providing local Bluetooth communication for selected
Tuya BLE devices.

The integration was inspired by code from
[@redphx](https://github.com/redphx/poc-tuya-ble-fingerbot).

## Installation

### HACS

[![Open your Home Assistant instance and open this repository in HACS.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=c7fen&repository=ha_tuya_ble-s1&category=integration)

This fork is installed as a custom HACS repository; these instructions do not
assume that it is present in the default HACS catalog.

1. Use the button above to open this repository in HACS.
2. If needed, add `https://github.com/c7fen/ha_tuya_ble-s1` as a custom
   repository with the **Integration** category, then open it in HACS.
3. Select **Download** for **Tuya BLE**.
4. Restart Home Assistant.
5. Go to **Settings → Devices & services**.
6. Select **Add Integration**, search for **Tuya BLE**, and complete the
   configuration flow.

### Manual installation

Copy this repository's `custom_components/tuya_ble` directory to
`/config/custom_components/tuya_ble` in Home Assistant. Do not replace the
entire `/config/custom_components` directory. Restart Home Assistant, then go
to **Settings → Devices & services**, select **Add Integration**, and configure
**Tuya BLE**.

## Prerequisites and configuration

The configuration flow requires these five values:

- Country
- Tuya IoT Access ID
- Tuya IoT Access Secret
- Tuya Smart or Smart Life account name
- Tuya Smart or Smart Life account password

The device must already be registered in that app account, and the app account
must be linked to the appropriate Tuya Cloud project. A connectable Bluetooth
adapter or Bluetooth proxy capable of active GATT connections must be
available to Home Assistant.

The integration uses Tuya Cloud during setup to obtain the device credentials.
After those credentials have been obtained, normal device communication is
local over Bluetooth. Home Assistant's
[Tuya integration documentation](https://www.home-assistant.io/integrations/tuya/)
provides general Tuya account and cloud-project background, but the official
Home Assistant Tuya integration does not automatically supply this custom
integration's configuration values.

Supported discoverable devices may be found automatically. You can also start
the integration's configuration flow manually from **Devices & services**.

## Supported devices

Entity availability depends on the product-specific mapping and the datapoints
reported by each device; the list does not imply that every possible product
feature is exposed.

- Fingerbots (category ID `szjqr`)
  - Fingerbot (product IDs `ltak7e1p`, `y6kttvd6`, `yrnk7mnn`, `nvr2rocq`,
    `bnt7wajf`, `rvdceqjh`, `5xhbk964`), powered by a CR2 battery.
  - Adaprox Fingerbot (product ID `y6kttvd6`), with a built-in USB-C rechargeable
    battery.
  - Fingerbot Plus (product IDs `blliqpsj`, `ndvkgsrm`, `yiihr7zh`, `neq16kgd`),
    with a sensor button for manual control.
  - CubeTouch 1s (product ID `3yqdo5yt`), with a built-in USB-C rechargeable
    battery.
  - CubeTouch II (product ID `xhf790if`), with a built-in USB-C rechargeable
    battery.

  Fingerbot Plus has product-specific programming entities for a series of
  actions: Program, Repeat forever, Repeats count, Idle position, and program
  text. Program text uses `position[/time];...`, where position is a percentage
  and the optional time is in seconds.

- Temperature and humidity sensors (category ID `wsdcg`)
  - Soil moisture sensor (product ID `ojzlzzsw`).
- CO2 sensors (category ID `co2bj`)
  - CO2 Detector (product ID `59s19z5m`).
- Smart Locks (category ID `ms`)
  - Smart Lock (product IDs `ludzroix`, `isk2p555`, `yy2bmcoh`).
  - Smart Lock (product ID `mqc2hevy`).
  - V1 Smart Lock / Lock P1 (product ID `7a4xvbtt`).
- Smart Locks (category ID `jtmspro`)
  - S1-TY-BLE-PRO (product ID `xqeob8h6`).
- Climate (category ID `wk`)
  - Thermostatic Radiator Valve (product IDs `drlajpqc`, `nhj2j7su`).
- Smart water bottle (category ID `znhsb`)
  - Smart water bottle (product ID `cdlandip`).
- Irrigation computer (category ID `ggq`)
  - Irrigation computer (product IDs `6pahkcau`, `hfgdqhho`).

### Smart-lock entity presentation

The S1 and V1 use the same translated names, icons, and entity categories for
shared concepts. Their real control capabilities remain intentionally
different: S1 provides a stateful, bidirectional `LockEntity`, while V1
provides a one-way `ButtonEntity` that only sends the lock command.

| Visible name | S1 platform | V1 platform | Icon | Home Assistant section |
| --- | --- | --- | --- | --- |
| Lock | `lock` (Lock and Unlock) | `button` (Lock only) | `mdi:lock` | Controls |
| Authentication Mode | `select` | — | `mdi:account-key` | Configuration |
| Auto-Lock | `switch` | `switch` | `mdi:lock-clock` | Configuration |
| Auto-Lock Delay | `number` | `number` | `mdi:timer-lock` | Configuration |
| Alarm | `sensor` | `sensor` | `mdi:alert` | Diagnostics |
| Battery | `sensor` | `sensor` | Battery device-class icon | Diagnostics |
| Door State | `sensor` | — | `mdi:door` | Diagnostics; disabled by default |
| Last Unlock Method | `sensor` | `sensor` | `mdi:account-lock-open` | Diagnostics |
| Motor State | `binary_sensor` | `binary_sensor` | `mdi:engine` | Diagnostics |
| Signal Strength | `sensor` | `sensor` | Signal-strength device-class icon | Diagnostics; disabled by default |

### S1-TY-BLE-PRO

The `jtmspro/xqeob8h6` product has the following product-specific local BLE
entities:

| Entity | Datapoint | Home Assistant semantics |
| --- | ---: | --- |
| Lock | 46, 70, 71 | Stateful control: DP 46 locks; the existing DP 70/71 sequence unlocks |
| Battery | 8 | Diagnostic percentage sensor |
| Alarm | 21 | Complete 14-value product-specific diagnostic enum |
| Last Unlock Method | 12, 15, 16, 19, 62, 63 | Current-batch enum |
| Auto-Lock | 33 | Configuration switch |
| Auto-Lock Delay | 36 | Configuration number from 1 to 1800 seconds |
| Authentication Mode | 34 | Single or fingerprint-and-card select |
| Door State | 40 | Read-only enum; disabled by default |
| Motor State | 47 | Read-only diagnostic binary sensor |
| Signal Strength | BLE RSSI | Existing diagnostic sensor, disabled by default |

The existing S1 lock and unlock implementation is unchanged. In particular,
the `finger_card` authentication mode means fingerprint **and** card, not one
or the other. Door State reflects the product's reported status value; some
hardware or installations may continue to report `unknown`, and it is not used
as the LockEntity state. Its possible values are `unknown`, `open`, and
`closed`. Last Unlock Method covers fingerprint, card, mechanical key, BLE,
phone remote, and voice remote.

DP 47 is exposed only as read-only motor status; it cannot be operated through
Home Assistant switch services. During S1 setup, an existing Tuya BLE Motor
State registry entry is migrated from `switch` to `binary_sensor` before the
new platform entity is registered. The integration unique ID remains
unchanged, and Home Assistant reuses the object-ID portion when it is
collision-free. User-assigned name, icon, area, disabled and hidden state,
labels, aliases, and user categories are retained. Switch-domain options and
switch device-class overrides are deliberately not copied because they are not
valid binary-sensor customization. If both old and new entries exist after a
partial migration, the binary-sensor entry is kept, its own target-domain
options and device-class override remain authoritative, and other missing
customization is merged from the old entry before the old switch entry is
removed.

The entity domain necessarily changes, for example from
`switch.s1_motor_state` to `binary_sensor.s1_motor_state`. Automations,
scripts, dashboards, or voice-assistant configuration that directly reference
the old S1 Motor State `switch.*` entity ID may need to be updated.

Sound, voice, LED, and other optical controls were not present in the supplied
product-specific diagnostics and are not added. S1 iBeacon functionality is
also deliberately deferred.

### V1 Smart Lock / Lock P1

The `ms/7a4xvbtt` product has product-specific local BLE mappings for the
following entities:

| Entity | Datapoint | Home Assistant semantics |
| --- | ---: | --- |
| Battery | 8 | Diagnostic percentage sensor; `-1` is reported as unknown |
| Alarm | 21 | Wrong fingerprint, password, card, or low battery |
| Last Unlock Method | 12, 13, 14, 15, 19, 55, 62 | Current-batch enum |
| Auto-Lock | 33 | Configuration switch |
| Auto-Lock Delay | 36 | Configuration number from 5 to 1800 seconds |
| Motor State | 47 | Read-only diagnostic binary sensor |
| Lock | 46 | One-way stateless button that writes `true` once |
| Signal Strength | BLE RSSI | Existing diagnostic sensor, disabled by default |

For both smart-lock mappings, a full status snapshot alone does not invent or
overwrite Last Unlock Method. The value changes only when the current device
update batch contains one unambiguous unlock method; repeated events using the
same method can still be recorded.

DP 47 is exposed only as motor status. The available diagnostics do not prove
that either boolean value is a durable physical locked/unlocked state.

Local unlock is deliberately not implemented for this product. Its evidenced
DP 60/61 flow requires a separately paired remote-unlock key that this
integration cannot derive from the available device credentials. A reference
implementation reports that toggling DP 33 can move some Lock P1 hardware, but
that behavior is experimental and conflicts with the product metadata, which
defines DP 33 as the Auto-Lock setting. This integration therefore never uses
DP 33 as a lock/unlock command and does not expose a misleading V1 LockEntity.

DP 31 sound/beep control is not supported for this product. Sound and LED
controls were not present in its product diagnostics. Temporary-password and
offline-password management are also not implemented.

## Security and physical safety

- Never publish Tuya IoT Access Secrets, account passwords, local keys, UUIDs,
  Device IDs, complete BLE addresses, or raw lock-protocol payloads.
- Review and sanitize Home Assistant diagnostics and logs before sharing them.
- Test lock, Auto-Lock, authentication-mode, and motor commands with the door
  open and another authorized access method available.
- V1 supports local locking through its momentary Lock action, but it
  does not support local unlock. Undocumented datapoints are not exposed as
  controls.

## Project support

Use the [GitHub issue tracker](https://github.com/c7fen/ha_tuya_ble-s1/issues)
for bugs and support requests. A useful bug report includes:

- Home Assistant Core version
- Tuya BLE integration version
- Device category and Product ID
- Sanitized relevant logs
- Reproduction steps and the expected and observed behavior

Do not include credentials, local keys, complete device identifiers, full BLE
addresses, or raw lock-protocol payloads in an issue.

## License

This integration is distributed under the [MIT License](LICENSE). This
maintained fork preserves the original authorship and license notices; the
current fork maintainer is not presented as the original author.
