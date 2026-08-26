# Tuya BLE for Home Assistant

[![GitHub release](https://img.shields.io/github/v/release/c7fen/ha_tuya_ble?include_prereleases)](https://github.com/c7fen/ha_tuya_ble/releases)
[![HACS custom](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://github.com/c7fen/ha_tuya_ble#installation)
[![CI](https://github.com/c7fen/ha_tuya_ble/actions/workflows/ci.yml/badge.svg)](https://github.com/c7fen/ha_tuya_ble/actions/workflows/ci.yml)

This repository is the maintained downstream fork at
[`c7fen/ha_tuya_ble`](https://github.com/c7fen/ha_tuya_ble). It is based on the
community operational upstream
[`ha-tuya-ble/ha_tuya_ble`](https://github.com/ha-tuya-ble/ha_tuya_ble) and keeps
unaffected upstream product registrations and behavior intact.

The integration provides local Bluetooth control and reporting for registered
Tuya BLE products. Home Assistant **2026.5 or newer** is required. A Tuya
Device ID and Local Key are normally obtained through an authorized Tuya cloud
account during setup; some protocol-v2 devices also require a SecKey. Treat all
of these values as credentials.

## Installation

### HACS

1. Open the repository in HACS with the button below, or add
   `https://github.com/c7fen/ha_tuya_ble` as a custom integration repository.
2. Install Tuya BLE.
3. Restart Home Assistant, then add the integration under **Settings > Devices
   & services**.

[![Open your Home Assistant instance and open this repository in HACS.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=c7fen&repository=ha_tuya_ble&category=integration)

HACS normally favors stable releases. During the beta programme, explicitly
show and select beta versions in HACS's version selector and verify the shown
version before downloading. Create a full Home Assistant backup first. Do not
remove the integration to switch release channels, and do not edit HACS or Home
Assistant `.storage` files. Stable `v0.9.0` remains available while
`v0.10.0b1` is tested as a prerelease.

### Manual installation

Download a release archive from the
[releases page](https://github.com/c7fen/ha_tuya_ble/releases), and copy
`custom_components/tuya_ble` into the Home Assistant configuration directory as
`custom_components/tuya_ble`. Restart Home Assistant after the copy.

For development only, clone the maintained repository:

```shell
git clone https://github.com/c7fen/ha_tuya_ble.git
```

Do not mix files from different tags. HACS is preferred because it tracks the
selected release and updates the integration atomically.

## Usage and safety

Home Assistant discovers supported connectable devices. The Tuya mobile app and
Home Assistant compete for an exclusive GATT connection, so close the app before
expecting reliable Home Assistant communication. Never test a smart lock unless
the door is open, alternate authorized access is available, and nobody depends
on the current lock state.

### BLE connection policy

S1-TY-BLE-PRO and V1 / Lock P1 devices expose local connection controls:

- **Connection Mode**: **Always connected** retains an authenticated GATT
   session and is recommended for access-event monitoring and any future
   Passage Mode Guard. **On demand** keeps the device disconnected while idle
   and opens one temporary session for an explicit Home Assistant command.
- **Home Assistant BLE Control**: turn this config switch off to persistently
   release GATT for the Tuya app. The config entry and these local controls stay
   loaded, ordinary device commands are blocked, and no automatic reconnect is
   attempted. Re-enable it from the entity or the integration Options Flow to
   restore control.
- **Bluetooth Connection**: this diagnostic is on only while an authenticated
   and paired GATT session is active. A raw or unpaired link is reported off.

S1 On-Demand sessions retain the exact authenticated session for a configurable
15–105 seconds after the latest confirmed current-session activity; the default
is 15 seconds. No periodic keep-alive is sent. V1 and unrelated products do not
use this S1 timer. On-demand mode can reduce persistent GATT ownership and may
help rarely used devices, but repeated connections and pairing also consume
energy; no battery-life percentage is promised. Events received while Home
Assistant is disconnected can be missed, so Always connected is the recommended
mode for access-event monitoring. The Tuya app and Home Assistant normally
cannot use the same peripheral simultaneously, and on-demand mode does not
guarantee simultaneous app and HA access.

Use the integration's **Configure** action and choose **Connection settings**
to change these options without re-entering Tuya credentials. The settings do
not require a current advertisement or a BLE connection, so they remain a
recovery path while the app owns GATT or HA control is suspended. See the
[smart-lock guide](docs/smart-locks.md) for the exact state and hardware-safety
semantics.

### V1 / Lock P1

The registered V1 product `ms/7a4xvbtt` is a Home Assistant `LockEntity`:

- **Lock** uses the product-specific DP46 secure/uncouple action.
- **Unlock** constructs the product-specific DP6 access/couple command.
- State comes only from read-only DP47.
- **Open** is unsupported.
- DP33 remains Auto-Lock configuration; it is not a directional lock command.
- A command is not replayed after an ambiguous transport error. Inspect the
  physical state before deciding whether to issue another command.

Upgrading changes the former V1 button domain to `lock`. The registry migration
preserves owned customizations when it can do so unambiguously, but automations
that call the old button service must be updated.

### S1-TY-BLE-PRO

The registered S1 product `jtmspro/xqeob8h6` exposes a `LockEntity`. Unlock is
available only with complete DP70/DP71 templates observed from that same
authenticated device. Templates are device-scoped, validated, and kept in a
private mode-`0600` Home Assistant Store record. There is no product-wide or
global fallback. Missing, incomplete, foreign, or ambiguous material fails
closed before a Bluetooth command is written.

S1 Motor State is a read-only `binary_sensor`, not a switch. Its registry
migration is ownership-safe, but automations that refer to the old switch
entity ID may require an update.

S1 Lock and Unlock are at-most-once operations. An ambiguous transport error
does not replay DP46, DP70, DP71, or a previously encrypted packet after
reconnect; inspect the physical state before issuing another action.

The [smart-lock guide](docs/smart-locks.md) documents entities, state semantics,
GATT exclusivity, ambiguous errors, and safe hardware procedures. The
[logging and privacy guide](docs/logging-and-privacy.md) explains how to report
problems without publishing identifiers or lock material. Security concerns
belong in the private route described by [the security policy](SECURITY.md),
not in a public issue.

### Hardware-validation scope

The V1 bidirectional contract was physically validated on the exact feature
runtime with repeated Lock and Unlock cycles, one motor action per command,
distinct expected directions, restart persistence, and DP33/DP47 boundaries.
That gate also included one representative S1 Lock/Unlock smoke cycle.

The S1 release work has owner-provided physical evidence, but not every one of
the four available S1 devices was retested at every exact release head. The
`v0.9.0b1` exact-runtime gate covered one of those four devices. This project
does not generalize that result to untested firmware or product variants.

## Supported registered products

This table is generated from the current product registrations in
`devices.py`. A registration means the integration has an explicit mapping; it
does not promise that every firmware revision or every exposed function has
been physically tested.

| Category | Registered Product IDs and names |
| --- | --- |
| `cl` | `4pbr8eig` (Blind Controller), `dy4dh1q0` (AOK AM24 Venetian Blinds Motor), `kcy0x4pi` (Curtain Controller), `v3fzfd2y` (AOK AM25 Roller Blinds Motor), `vlwf3ud6` (Blind Controller) |
| `co2bj` | `59s19z5m` (CO2 Detector) |
| `cxjmb` | `pnxl0r3l` (Window Cleaner Robot) |
| `dcb` | `ajrhf1aj` (PARKSIDE Smart battery 8Ah), `z5ztlw3k` (PARKSIDE Smart battery 4Ah) |
| `dd` | `0qgrjxum` (RGB Strip Light), `6jxcdae1` (Sunset Lamp), `nvfrtxlq` (LGB102 Magic Strip Lights), `umzu0c2y` (Floor Lamp) |
| `dj` | `bpqbwf8y` (LED BULB B509Z2) |
| `ggq` | `6pahkcau` (Irrigation computer), `hfgdqhho` (Irrigation computer), `jntxv3q4` (YZD02B dual irrigation timer) |
| `jsq` | `if1nolcm` (DT-T2190A Aroma Diffuser) |
| `jtmspro` | `ajk32biq` (B16), `akwn32dw` (Drawer Smart Lock), `ebd5e0uauqx0vfsp` (CentralAcesso), `hc7n0urm` (A1 Ultra-JM), `hs21i377` (Smart Cylinder Lock), `kholoaew` (Smart Lock), `oyqux5vv` (LA-01 Smart lock), `pyawczjj` (CS-9 Smart Fingerprint Lock), `qicggi0m` (XCase NX-4964 Lock Box), `rlyxv7pe` (A1 PRO MAX), `stugc8dl` (HU06 Smart Lock), `xicdxood` (Raycube K7 Pro+), `xqeob8h6` (S1-TY-BLE-PRO), `y2yaegze` (Drawer Lock CTL20H), `yfqp0shy` (Gainsborough Liberty BLE Lock (GGC01HA)), `z7lj676i` (Smart Cylinder Lock) |
| `kg` | `4ctjfrzq` (Switch Robot), `bs3ubslo` (Fingerbot Plus), `gnpbj0bq` (Fingerbot Plus), `mknd4lci` (Fingerbot Plus), `riecov42` (Fingerbot Plus) |
| `ms` | `6fibxtph` (Primebras Athenas Lock), `7a4xvbtt` (V1 Smart Lock), `99gv5nmz` (Foxgard Smart Fingerprint Door Lock), `a6nttc41` (Smart Lock), `gumrixyt` (Smart Lock), `isk2p555` (Smart Lock), `k53ok3u9` (Fingerprint Smart Lock), `kpn4zaf7` (Invisible induction lock), `ludzroix` (Smart Lock), `mqc2hevy` (Smart Lock), `okkyfgfs` (TEKXDD Fingerprint Smart Lock), `sidhzylo` (Smart Lock), `uamrw6h3` (Smart Lock), `wgv4haro` (Guard Dog Security Smart Lock), `yy2bmcoh` (Smart Lock) |
| `sfkzq` | `0axr5s0b` (Valve controller), `16wgjvck` (Aldi/Ferrex Smart Water Valve), `1fcnd8xk` (Water valve controller), `46zia2nz` (Water valve controller), `6pahkcau` (Irrigation computer), `d4vpmigg` (Valve controller), `e1poaiwa` (Valve controller), `fnlw6npo` (Irrigation computer), `hfgdqhho` (Irrigation computer), `jjqi2syk` (Irrigation computer), `ldcdnigc` (ZX-7378 Smart Irrigation Controller), `nxquc5lb` (Water valve controller), `ojrvmfkk` (Unistyle WT-04W Water Timer), `qycalacn` (Irrigation computer), `svhikeyq` (Valve controller), `tqzkwarw` (HCT-611 Water Timer) |
| `slj` | `mqqna0px` (RESTMO BT Water Meter) |
| `szjqr` | `3yqdo5yt` (CUBETOUCH 1s), `5xhbk964` (Fingerbot), `6jcvqwh0` (Fingerbot Plus), `blliqpsj` (Fingerbot Plus), `bnt7wajf` (Fingerbot), `h8kdwywx` (Fingerbot Plus), `ltak7e1p` (Fingerbot), `ndvkgsrm` (Fingerbot Plus), `neq16kgd` (Fingerbot Plus), `nvr2rocq` (Fingerbot), `riecov42` (Fingerbot Plus), `rvdceqjh` (Fingerbot), `xhf790if` (CubeTouch II), `y6kttvd6` (Fingerbot), `yiihr7zh` (Fingerbot Plus), `yn4x5fa7` (Nedis SmartLife Finger Robot), `yrnk7mnn` (Fingerbot) |
| `wk` | `drlajpqc` (Thermostatic Radiator Valve), `nhj2j7su` (Thermostatic Radiator Valve), `zmachryv` (Thermostatic Radiator Valve) |
| `wkf` | `llflaywg` (Thermostatic Radiator Valve) |
| `wsdcg` | `1jvidcsf` (Temperature Humidity Sensor), `6lbesej0` (Temperature Humidity Sensor SS302), `iv7hudlj` (Temperature Humidity Sensor), `jm6iasmb` (Temperature Humidity Sensor), `ojzlzzsw` (Soil moisture sensor), `tr0kabuq` (Temperature Humidity Sensor), `tv6peegl` (Soil Thermo-Hygrometer), `vlzqwckk` (Temperature Humidity Sensor), `vyfoip9h` (Temperature Humidity Sensor) |
| `wxkg` | `ja5osu5g` (Arlec Smart Button), `kpzc6pm8` (Arlec Smart Button) |
| `znhsb` | `cdlandip` (Smart water bottle) |
| `zwjcy` | `jabotj1z` (SRB-PM01 Soil Moisture Sensor) |

### Platform-only source mappings

The platform modules also contain these historical product-specific mapping
keys that are not registered in `devices.py`: `cl/qqdxfdht`, `cl/ulughw4g`,
`ggq/fnlw6npo`, `ggq/jjqi2syk`, `ggq/qycalacn`, `ms/bvclwu9b`,
`szjqr/okkyfgfs`, and `zwjcy/gvygg3m8`. They are retained as upstream source
state, but are not listed as supported registrations and are not a hardware or
reachability claim.

Dynamic cloud descriptions may support additional generic light functions, but
Bluetooth Mesh products are not compatible with this BLE integration.

## Development and support

Report reproducible downstream bugs through the
[issue tracker](https://github.com/c7fen/ha_tuya_ble/issues). Read
[CONTRIBUTING.md](CONTRIBUTING.md) before submitting code or device evidence.
Never post raw Home Assistant logs, Bluetooth captures, credentials, complete
identifiers, or lock datapoint payloads.

This downstream fork retains the work of the operational upstream maintainers
and historical contributors, including
[@PlusPlus-ua](https://github.com/PlusPlus-ua),
[@Snuffy2](https://github.com/Snuffy2),
[@kancelott](https://github.com/kancelott),
[@scastiello](https://github.com/scastiello),
[@CloCkWeRX](https://github.com/CloCkWeRX),
[@redphx](https://github.com/redphx), and
[@markusg1234](https://github.com/markusg1234). Current downstream maintenance
is led by [@c7fen](https://github.com/c7fen). See the
[upstream fork history](https://github.com/ha-tuya-ble/ha_tuya_ble/issues/1) for
additional provenance.

## Historical upstream Ukraine support message

The original project author, [@PlusPlus-ua](https://github.com/PlusPlus-ua),
published the following support appeal. It is preserved separately from current
downstream maintenance; this repository does not control or verify the donation
recipient.

> I am working on this integration in Ukraine. Our country was subjected to
> brutal aggression by Russia. The war still continues. The capital of Ukraine
> — Kyiv, where I live — and many other cities and villages are constantly under
> threat of rocket attacks. Our air defense forces are doing wonders, but they
> also need support. So if you want to help the development of this integration,
> donate some money and I will spend it to support our air defense.

The historical donation link is
[`buymeacoffee.com/3PaK6lXr4l`](https://www.buymeacoffee.com/3PaK6lXr4l).
