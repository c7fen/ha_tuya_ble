# Contributing to Tuya BLE

Thank you for helping improve the integration. Contributions must preserve the
security and compatibility boundaries of this downstream fork and its
operational upstream.

## Start from the development branch

Create each contribution from the current `next` branch and open the pull
request against `next`. Do not develop directly on `main`; it is the controlled
stable-release branch. Keep one coherent behavioral outcome per pull request,
and do not force-push after a head has received exact-head review (see
[review terms](docs/releasing.md#review-terms)).

Use Conventional Commits titles. A basic device mapping normally uses `fix:`.

## Evidence for a device mapping

Provide the public Tuya category and Product ID, the model name, and the source
of the datapoint schema. Explain which existing category mapping is reused and
which behavior, if any, is unique. Preserve every unrelated upstream product
registration and platform mapping.

Do not publish or commit credentials, complete device addresses, Device IDs,
UUIDs, Local Keys, SecKeys, raw Home Assistant logs, HCI captures, raw
datapoint payloads, encrypted frames, decrypted frames, or copied lock command
values. Redact screenshots before attaching them. The complete rules are in
[Logging and privacy](docs/logging-and-privacy.md).

Protocol similarity is not authority for physical control. Do not spray
datapoints, values, or alternate command formats. A physical-control change
must be fail-closed and supported by repeatable evidence for that exact product.

## Tests and translations

A simple mapping does not need a mapping-only test. Add tests when existing
platform behavior, Bluetooth communication, registry migration, safety logic,
or another unique behavior changes. Tests must use clearly synthetic
identifiers and payloads.

Add or update translated strings for new user-facing entities and errors. Run:

```shell
black --check --diff .
codespell
pytest
```

Also require valid, consistently formatted JSON, `git diff --check`, HACS and
Hassfest validation, and the repository security scans. Describe the exact
environment and results in the pull request.

## Hardware evidence

The contributor, not the integration agent, performs physical actions. Follow
[Live validation and hardware evidence](docs/live-validation.md) for the
safety checklist, the evidence record, and stop conditions. Never claim
hardware validation for a different commit or untested product.

Registry-domain changes require ownership-safe, collision-safe, idempotent
migration tests and an upgrade note for affected automations.

## AI-assisted contributions

Disclose material AI assistance in the pull request. AI output may help draft
code or documentation, but it is not protocol evidence, hardware proof, source
provenance, or test evidence. The contributor remains responsible for every
change and claim.
