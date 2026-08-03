# Home Assistant support for Tuya BLE devices

## Overview

This integration supports Tuya devices connected via BLE.

_Inspired by code of [@redphx](https://github.com/redphx/poc-tuya-ble-fingerbot)_

## Installation

Place the `custom_components` folder in your configuration directory (or add its contents to an existing `custom_components` folder). Alternatively install via [HACS](https://hacs.xyz/).

[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=PlusPlus-ua&repository=ha_tuya_ble&category=integration)

## Usage

After adding to Home Assistant integration should discover all supported Bluetooth devices, or you can add discoverable devices manually.

The integration works locally, but connection to Tuya BLE device requires device ID and encryption key from Tuya IOT cloud. It could be obtained using the same credentials as in official Tuya integration. To obtain the credentials, please refer to official Tuya integration [documentation](https://www.home-assistant.io/integrations/tuya/)

## Supported devices list

* Fingerbots (category_id 'szjqr')
  + Fingerbot (product_ids 'ltak7e1p', 'y6kttvd6', 'yrnk7mnn', 'nvr2rocq', 'bnt7wajf', 'rvdceqjh', '5xhbk964'), original device, first in category, powered by CR2 battery.
  + Adaprox Fingerbot (product_id 'y6kttvd6'), built-in battery with USB type C charging.
  + Fingerbot Plus (product_ids 'blliqpsj', 'ndvkgsrm', 'yiihr7zh', 'neq16kgd'), almost same as original, has sensor button for manual control.
  + CubeTouch 1s (product_id '3yqdo5yt'), built-in battery with USB type C charging.
  + CubeTouch II (product_id 'xhf790if'), built-in battery with USB type C charging.

  All features available in Home Assistant, programming (series of actions) is implemented for Fingerbot Plus.
  For programming exposed entities 'Program' (switch), 'Repeat forever', 'Repeats count', 'Idle position' and 'Program' (text). Format of program text is: 'position\[/time\];...' where position is in percents, optional time is in seconds (zero if missing).

* Temperature and humidity sensors (category_id 'wsdcg')
  + Soil moisture sensor (product_id 'ojzlzzsw').

* CO2 sensors (category_id 'co2bj')
  + CO2 Detector (product_id '59s19z5m').

* Smart Locks (category_id 'ms')
  + Smart Lock (product_id 'ludzroix', 'isk2p555').
  + V1 Smart Lock / Lock P1 (product_id '7a4xvbtt').

* Smart Locks (category_id 'jtmspro')
  + S1-TY-BLE-PRO (product_id 'xqeob8h6').

* Climate (category_id 'wk')
  + Thermostatic Radiator Valve (product_ids 'drlajpqc', 'nhj2j7su').

* Smart water bottle (category_id 'znhsb')
  + Smart water bottle (product_id 'cdlandip')

* Irrigation computer (category_id 'ggq')
  + Irrigation computer (product_id '6pahkcau')

### S1-TY-BLE-PRO

The `jtmspro/xqeob8h6` product has the following product-specific local BLE
entities:

| Entity | Datapoint | Home Assistant semantics |
| --- | ---: | --- |
| Lock | 46, 70, 71 | Existing local LockEntity: DP 46 locks; the existing DP 70/71 sequence unlocks |
| Battery | 8 | Diagnostic percentage sensor |
| Alarm | 21 | Diagnostic enum with the complete 14-value product-specific order |
| Last Unlock Method | 12, 15, 16, 19, 62, 63 | Diagnostic enum for fingerprint, card, mechanical key, BLE, phone remote, or voice remote |
| Auto-Lock | 33 | Configuration switch |
| Auto-Lock Delay | 36 | Configuration number from 1 to 1800 seconds |
| Authentication Mode | 34 | Configuration select: single authentication or combined fingerprint-and-card authentication |
| Door State | 40 | Read-only diagnostic enum (`unknown`, `open`, `closed`), disabled by default |
| Motor State | 47 | Existing legacy writable switch; see the migration note below |
| Signal Strength | BLE RSSI | Existing diagnostic sensor, disabled by default |

The existing S1 lock and unlock implementation is unchanged. In particular,
the `finger_card` authentication mode means fingerprint **and** card, not one
or the other. Door State reflects the product's reported status value; some
hardware or installations may continue to report `unknown`, and it is not used
as the LockEntity state.

DP 47 is defined by the product metadata as a status value, but existing
installations already have it registered as a writable switch. Moving it to a
binary-sensor platform without a complete entity-registry migration would risk
leaving an orphaned switch and losing user customizations. The legacy switch is
therefore retained in this change. A follow-up may migrate it only with tested
cross-platform registry handling.

Sound, voice, LED, and other optical controls were not present in the supplied
product-specific diagnostics and are not added. S1 iBeacon functionality is
also deliberately deferred.

Perform initial Auto-Lock and delay testing with the physical door open, and
keep another mechanical or otherwise authorized access method available.

### V1 Smart Lock / Lock P1

The `ms/7a4xvbtt` product has product-specific local BLE mappings for the
following entities:

| Entity | Datapoint | Home Assistant semantics |
| --- | ---: | --- |
| Battery | 8 | Diagnostic percentage sensor; `-1` is reported as unknown |
| Alarm | 21 | Diagnostic enum: wrong fingerprint, wrong password, wrong card, or low battery |
| Last Unlock Method | 12, 13, 14, 15, 19, 55, 62 | Diagnostic enum based on the latest evidenced unlock event |
| Auto-Lock | 33 | Configuration switch |
| Auto-Lock Delay | 36 | Configuration number from 5 to 1800 seconds |
| Motor State | 47 | Read-only diagnostic binary sensor |
| Manual Lock | 46 | Stateless button that writes `true` once |
| Signal Strength | BLE RSSI | Existing diagnostic sensor, disabled by default |

DP 47 is exposed only as motor status. The available diagnostics do not prove
that either boolean value is a durable physical locked/unlocked state.

Local unlock is deliberately not implemented for this product. Its evidenced
DP 60/61 flow requires a separately paired remote-unlock key that this
integration cannot derive from the available device credentials. A reference
implementation reports that toggling DP 33 can move some Lock P1 hardware, but
that behaviour is experimental and conflicts with the product metadata, which
defines DP 33 as the Auto-Lock setting. This integration therefore never uses
DP 33 as a lock/unlock command and does not expose a misleading V1 LockEntity.

DP 31 sound/beep control is not supported for this product. Sound and LED
controls were not present in its product diagnostics. Temporary-password and
offline-password management are also not implemented.

For initial physical validation, keep the door open and keep another
mechanical or otherwise authorized access method available. Verify the
read-only entities first before triggering Manual Lock.

## Support project

I am working on this integration in Ukraine. Our country was subjected to brutal aggression by Russia. The war still continues. The capital of Ukraine - Kyiv, where I live, and many other cities and villages are constantly under threat of rocket attacks. Our air defense forces are doing wonders, but they also need support. So if you want to help the development of this integration, donate some money and I will spend it to support our air defense.
<br><br>
<p align="center">
  <a href="https://www.buymeacoffee.com/3PaK6lXr4l"><img src="https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png" alt="Buy me an air defense"></a>
</p>
