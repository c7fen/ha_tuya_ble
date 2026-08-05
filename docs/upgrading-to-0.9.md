# Upgrading to 0.9

## Before upgrading

Create and verify a full Home Assistant backup. Record the installed Tuya BLE
version and export affected automation YAML through Home Assistant's supported
UI or configuration workflow. Do not copy secrets into an issue or support
request.

Home Assistant 2026.5 or newer is required. Close the Tuya app before validating
Home Assistant connectivity.

## Repository and HACS

The maintained repository is now `c7fen/ha_tuya_ble`. The integration domain
and directory remain `tuya_ble`, so change the HACS custom-repository reference
without removing the integration or its config entries.

During the beta programme, use HACS's version selector to choose the exact
prerelease. Confirm the requested tag before downloading. HACS normally favors
stable releases, so a prerelease may not be selected automatically.

## Compatibility from v0.1.11b2

- Existing config entries remain compatible with the legacy `app_type` option
  and the additive `tuya_app_type` alias. Conflicting alias values fail closed.
- Existing complete, canonical, same-device S1 Store records remain compatible.
  They are not converted into global or product-wide material.
- The integration identity, config-entry ownership, devices, and unaffected
  entities remain under the `tuya_ble` domain.

## Entity-domain migrations

### V1 button to lock

The former V1 `manual_lock` button becomes a `lock` entity. The migration
preserves eligible user customizations when ownership is unambiguous. Update
automations that press the old button to call `lock.lock` or `lock.unlock` on
the resulting lock entity. V1 does not support `lock.open`.

### S1 Motor State switch to binary sensor

The obsolete writable-looking S1 Motor State switch becomes a read-only
`binary_sensor`. Update dashboards and automations that directly reference the
old switch entity ID. Never replace this diagnostic entity with a service call.

After the upgrade, review the entity registry for one expected entity per
function and verify that names, areas, labels, disabled state, and other user
customizations remain correct.

## Split HACS and on-disk versions

If HACS metadata reports a newer version than the integration manifest on disk,
do not edit Home Assistant or HACS `.storage` files. Create a new backup, then
use a newer supported HACS release installation or redownload path to install an
explicit available tag. Restart Home Assistant only after HACS completes, and
verify that the HACS version, on-disk manifest, and loaded runtime all agree.

If HACS cannot offer or accept the required version, stop and collect only
sanitized status information. Do not remove the integration merely to repair
metadata.

## Rollback

Rollback requires a known-good full backup or an owner-only integration copy
created before the update. Restore through supported Home Assistant/HACS
mechanisms, then restart only as needed. Confirm the on-disk manifest, loaded
runtime, registry, config entries, and HACS metadata. Never hand-edit `.storage`
and never reuse an old rollback directory as the sole recovery authority.
