# Security policy

## Supported versions

| Version | Support |
| --- | --- |
| Latest stable release | Security fixes |
| Latest published prerelease | Beta validation and security fixes |
| Older releases | Upgrade required before investigation |

Home Assistant 2026.5 or newer is required for the 0.9 release line.

## Reporting a vulnerability

Use GitHub's private vulnerability-reporting route for this repository:
[privately report a security vulnerability](https://github.com/c7fen/ha_tuya_ble/security/advisories/new).
Do not open a public issue for a suspected vulnerability. If the private route
is unavailable, stop rather than posting sensitive evidence publicly and
contact the repository owner through a private GitHub channel.

Include only the minimum information needed to reproduce the issue. The
maintainers can arrange a private evidence exchange if necessary.

## Never publish

- credentials, account data, Device IDs, complete addresses, or UUIDs;
- Local Keys, SecKeys, tokens, or configuration secrets;
- raw Home Assistant logs, HCI captures, packet bytes, or frames;
- lock datapoint values, command payloads, device templates, encrypted data, or
  decrypted data; or
- persistent hashes or fingerprints of private identifiers.

Before sharing any text, replace private values with semantic placeholders,
remove traceback exception text that may contain an identifier, and recheck
attachments and image metadata. Prefer timestamps, module and operation names,
sanitized error classes, counts, versions, and public category/Product IDs.

Production logging uses nonpersistent process-local opaque labels. These labels
are diagnostic correlation aids, not safe public identifiers.

## Physical-access safety

Smart-lock testing can deny access. Keep the door open, retain alternate
authorized access, ensure nobody depends on the current state, and perform only
one deliberate action at a time. Integration agents must not operate a physical
lock. Never discover a control contract by spraying commands or replaying a
captured lock payload.
