## Summary

Describe the single coherent outcome and its evidence.

## Evidence

- Reviewed head: full commit SHA that the validation below applies to.
- Hardware evidence: `None`, or the evidence record from
  `docs/live-validation.md` (exact tested commit, environment, UTC time, scope,
  result).

## Validation

- [ ] The branch was created from current `next` and targets `next`.
- [ ] `scripts/check.sh` passed the complete offline profile (exit 0) on the reviewed head; its header and summary are included below.
- [ ] HACS and Hassfest pass in CI.
- [ ] Behavior changes have tests; a simple mapping does not add a mapping-only test.
- [ ] New user-facing strings are translated.
- [ ] Unrelated upstream registrations and mappings are unchanged.

## Privacy and safety

- [ ] No credentials, complete addresses, Device IDs, UUIDs, Local Keys, SecKeys, raw logs, datapoint payloads, frames, templates, or HCI captures are included.
- [ ] No persistent address-derived log identity, command spraying, or unsafe fallback is introduced.
- [ ] Any physical-behavior claim matches the hardware evidence above and was performed by an authorized human with safe alternate access.
- [ ] Material AI assistance is disclosed below and is not presented as evidence.

## AI assistance

State `None` or describe material AI assistance and the human verification.
