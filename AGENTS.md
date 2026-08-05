# Repository agent policy

## Branch and release boundaries

- Use `next` as the development base and pull-request target.
- Do not commit or merge directly to `main`; it is the controlled stable branch.
- Keep release preparation separate from runtime behavior changes.
- Do not force-push, rebase, or amend a pushed or reviewed head.
- Release only after documentation, CI, security, exact-head review, and any
  required hardware gates pass.

## Device and behavior changes

- Do not add tests only for a simple device mapping. Add coverage when existing
  platform behavior, Bluetooth communication, registry behavior, safety logic,
  or another unique contract changes.
- Add translations for every new user-facing string.
- Preserve unrelated upstream product and platform mappings.
- Physical-control paths must fail closed. Never infer a lock command from a
  similar product, spray datapoints or values, or replay an ambiguous command.
- Bind hardware claims to the exact tested commit. Agents must not operate a
  physical lock.
- Entity-domain changes require ownership-safe, collision-safe, idempotent
  registry migration and documented automation impact.

## Privacy and security

- Never log or publish credentials, complete identifiers, raw device payloads,
  lock values, packet bytes, or captures.
- A device log identity must not be a stable persistent address-derived hash.
  Use only the reviewed process-local opaque-label contract.
- Synthetic test material must be visibly synthetic and must not resemble a
  real secret or retained capture.
- Keep device-scoped security material private, mode-restricted, and fail
  closed; never introduce a product-wide fallback.

## Validation and commits

- Run Black before committing.
- Keep JSON valid, well formatted, and consistent with repository conventions.
- Use Conventional Commits. A basic mapping normally uses `fix:`.
- Require relevant focused tests, full pytest, Codespell, JSON/YAML validation,
  `git diff --check`, HACS, Hassfest, Actionlint, and secret scanning before a
  release-facing merge.
- Documentation must describe the current behavior, safe upgrade path, privacy
  boundary, hardware scope, and release policy before a stable cutover.
