# Logging and privacy

Tuya BLE credentials, complete device identifiers, and lock command material
are private security data. Do not post raw Home Assistant logs or Bluetooth
captures publicly without reviewing and sanitizing them first.

## Production log identity

Tuya BLE production logs use an opaque label assigned to a live device object.
The label is process-local, is not derived from a persistent device identifier,
and is deliberately expected to change after Home Assistant starts a new
process. It is not persisted in Home Assistant Store, diagnostics, or entity
state.

The label helps correlate events inside one running process only. It must not be
treated as a device identity or copied into long-lived inventories.

## Never publish

- complete Bluetooth addresses or address variants;
- Device IDs, UUIDs, Local Keys, SecKeys, account credentials, or tokens;
- raw Home Assistant logs before review;
- DP6, DP70, or DP71 values;
- HCI captures, packet bytes, frames, templates, encrypted data, or decrypted
  data; or
- stable hashes or fingerprints derived from any of the above.

Product category, public Product ID, Home Assistant version, integration
version, module name, operation name, and a sanitized error class are normally
sufficient for a first report.

## Retained S1 entity state

The S1 last-confirmed feature relies only on standard Home Assistant entity
state restoration for the scoped configuration and battery values. Its visible
metadata is limited to the retained value, a timezone-aware confirmation time,
and the non-sensitive freshness/source markers. It does not store or expose
Bluetooth addresses, device identifiers, packet material, raw datapoint
payloads, S1 unlock templates, credentials, or a stable device-derived label.
Do not paste entity history or attributes into a public report without the same
review and sanitization required for logs.

## Safe issue excerpt

Use a short, manually written summary rather than copied log output:

```text
Time window: 2026-01-01 12:00-12:02 local
Module: custom_components.tuya_ble.tuya_ble
Operation: disconnect cleanup
Result: sanitized transport error
Occurrences: 2
Integration version: 0.9.0b3
Home Assistant version: 2026.7.4
Identifiers, credentials, payloads, and raw logs removed: yes
```

Do not include the opaque process-local label in a public report. Retain any raw
evidence only in an owner-restricted location for the minimum time needed. A
possible vulnerability belongs in the private route described by
[SECURITY.md](../SECURITY.md).
