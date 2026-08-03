# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog],
and this project adheres to [Semantic Versioning].

## [Unreleased]

### Added

- Added product-specific S1-TY-BLE-PRO (`jtmspro/xqeob8h6`) entities for
  Auto-Lock, the 1-to-1800-second Auto-Lock delay, authentication mode, the
  complete alarm enum, last-unlock method, and read-only Door State.
- Added product-specific local BLE support for the V1 Smart Lock / Lock P1
  (`ms/7a4xvbtt`): battery, alarm, last-unlock method, Auto-Lock, Auto-Lock
  delay, read-only motor status, and a momentary Manual Lock action.
- Added focused product-mapping, privacy, current-batch unlock-event, and S1
  regression tests.

### Changed

- Kept the existing S1 DP 47 Motor State switch pending a deterministic,
  customization-preserving entity-registry migration to a read-only platform.
- Left the existing S1 DP 46 lock and DP 70/71 unlock paths unchanged.
- Corrected the maintained-fork attribution, HACS and manual installation
  instructions, cloud and local setup prerequisites, support guidance, and
  lock-safety documentation.
- Let Home Assistant assign platform-specific entity domains while retaining
  the existing integration unique IDs for entity-registry matching.

### Fixed

- Made `TuyaBLENumber` inherit Home Assistant's `NumberEntity` base class.
- Detect Last Unlock Method only from the current device callback batch, so
  full status snapshots no longer invent or overwrite an unlock method.
- Preserve repeated unlock events that report the same method and credential
  identifier while rejecting ambiguous multi-method callback batches.

### Security

- Deliberately left V1 unlock unsupported because no verifiable DP 60/61
  pairing-key source is available; DP 33 remains exclusively Auto-Lock.
- Removed raw, encrypted, and decrypted JTMSPRO payload data from logs.
- Moved routine successful JTMSPRO parser and notification metadata from
  `WARNING` to payload-free `DEBUG` messages.

## [0.1.0] - 2023-04-22

- Initial release

## [0.1.1] - 2023-04-26

### Added

- Added new product_id for Fingerbot Plus (#1)

### Fixed

- Fixed problem in options flow.

### Changed

- Updated strings.json

## [0.1.2] - 2023-04-26

### Changed

- Changed a way to obtain device credentials from Tuya IOT cloud, possible
  fix to (#2)

## [0.1.4] - 2023-04-30

### Added

- Added support of CUBETOUCH 1s, thanks @damiano75
- Added new product_ids for Fingerbot.
- Added new product_ids for Fingerbot Plus.
- First attempt to support Smart Lock device.

### Fixed

- Fixed possible disconnect of BLE device.

## [0.1.5] - 2023-06-01

### Added

- Added new product_ids for Fingerbot.
- Added event "fingerbot_button_pressed" which is fired on Fingerbot Plus
  touch button press.
- First attempt to add support of climate entity.

## [0.1.6] - 2023-06-01

### Added

- Added new product_ids for Fingerbot and Fingerbot Plus.

### Changed

- Updated sources to conform Python 3.11

## [0.1.7] - 2023-06-01

### Added

- Added new product_ids.
- Added full support of BLE TRV provided by @forabi
- Added support of programming mode for Fingerbot Plus, thanks @redphx for
  information.

### Changed

- Improved connection stability.

## [0.1.8] - 2023-07-09

### Added

- Added support of 'Irrigation computer', thanks to @SanMiggel.
- Added new product_ids for Smart locks, thanks to @drewpo28.

### Changed

- Connection to the device is postponed now. Previously some out of range
  device might prevents HA from fully booting.
- Improved connection stability.

[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html
