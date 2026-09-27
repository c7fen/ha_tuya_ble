# Repository agent policy

This file is the short entry point for agents. Complete procedures and term
definitions live in the linked documents.

## Project map

- `custom_components/tuya_ble/`: Home Assistant integration: platforms,
  `config_flow.py`, `manifest.json`, `strings.json`, and `translations/`.
- `custom_components/tuya_ble/devices.py`: product and datapoint mappings.
- `custom_components/tuya_ble/tuya_ble/`: Bluetooth protocol, session, and
  security transport.
- `tests/`: pytest suite.
- `scripts/check.sh`: offline validation profile shared with CI.
- `docs/`: safety, privacy, release, validation, and live-validation
  documentation.

## Branch and release boundaries

- Use `next` as the development base and pull-request target.
- Do not commit or merge directly to `main`; it is the controlled stable branch.
- Keep release preparation separate from runtime behavior changes.
- Do not force-push, rebase, or amend a pushed or reviewed head.
- Release only after documentation, CI, security, exact-head review, and any
  required hardware gates pass. "Exact head", "exact-head review", and
  "exact tested commit" are defined in
  [docs/releasing.md](docs/releasing.md#review-terms).

## Local linked worktrees

On Felix's primary WSL2 workstation, the canonical checkout for this repository
is `/home/fengemann/projects/ha_tuya_ble-s1`. This historical local directory
name differs from the current GitHub repository name, `ha_tuya_ble`. Persistent
linked Git worktrees for this repository MUST be created under
`/home/fengemann/worktrees/ha_tuya_ble/<task>`.

Do not create persistent linked worktrees directly under
`/home/fengemann/projects`, inside the canonical checkout, inside another
linked worktree, or under `/tmp`. `/tmp` is allowed only for ephemeral
read-only or no-push checkouts that are removed in the same bounded task.

Before creating a linked worktree, inspect existing worktrees, branches,
issue/PR ownership, and active processes. Preserve unrelated work. On another
host, use `$WORKTREE_ROOT/ha_tuya_ble/<task>` only when `WORKTREE_ROOT` is
explicitly configured. That root must remain outside all canonical checkouts
and outside the parent directory containing canonical project roots.

## Live Home Assistant tasks and approvals

- Offline development and offline checks need no Home Assistant access, no
  private file, and no live approval.
- A live task (SSH, Supervisor or `ha` CLI, deployment, restart, Core check,
  service call, BLE session, or hardware observation) needs an explicit
  approval that names the action and the target. Access approval is not
  deployment approval, and neither authorizes a service call or a physical
  action.
- An explicit approval that already matches the requested action and target
  need not be requested again. It never extends to another action, target, or
  commit.
- The general SSH route is documented in the maintainer's access runbook,
  referenced in [docs/live-validation.md](docs/live-validation.md#access-route)
  together with the Tuya-specific deployment, evidence, and stop conditions.
  Do not add a second general SSH procedure here, and never commit hosts,
  addresses, users, credentials, or device bindings.
- Never read private access files or wrappers into agent tool output.
- A missing access runbook or approval blocks only that live task, never
  offline work.

## Device and behavior changes

- Do not add tests only for a simple device mapping. Add coverage when existing
  platform behavior, Bluetooth communication, registry behavior, safety logic,
  or another unique contract changes.
- Add translations for every new user-facing string.
- Preserve unrelated upstream product and platform mappings.
- Physical-control paths must fail closed. Never infer a lock command from a
  similar product, spray datapoints or values, or replay an ambiguous command.
- Bind hardware claims to the exact tested commit and follow
  [docs/live-validation.md](docs/live-validation.md#hardware-evidence).
- Agents must not operate a physical lock. No prompt, local file, or memory
  entry creates an exception; changing this rule is a separate, explicitly
  approved policy change.
- Entity-domain changes require ownership-safe, collision-safe, idempotent
  registry migration and documented automation impact.

## Privacy and security

- Never log or publish credentials, complete identifiers, raw device payloads,
  lock values, packet bytes, or captures.
- A device log identity must not be a stable persistent address-derived hash.
  Use only the process-local opaque label defined in
  [docs/logging-and-privacy.md](docs/logging-and-privacy.md#production-log-identity).
- The complete publication rules are in
  [docs/logging-and-privacy.md](docs/logging-and-privacy.md) and
  [SECURITY.md](SECURITY.md).
- Synthetic test material must be visibly synthetic and must not resemble a
  real secret or retained capture.
- Keep device-scoped security material private, mode-restricted, and fail
  closed; never introduce a product-wide fallback.

## Validation and commits

- Run `scripts/check.sh --python <CI-base interpreter>` before committing. It
  covers Black, Codespell, full pytest, JSON/YAML, Actionlint, secret scanning,
  and `git diff --check`. Only exit code 0 on the complete profile passes.
  Profile, result states, and test environments are defined in
  [docs/validation.md](docs/validation.md).
- Never report a NOT RUN check as passed, a partial `--only` run as the
  complete profile, or a local run of a changed workflow as a CI result. HACS
  and Hassfest run only in CI.
- Keep JSON valid, well formatted, and consistent with repository conventions.
- Use Conventional Commits. A basic mapping normally uses `fix:`.
- Require relevant focused tests, the complete offline profile, and passing
  CI (including HACS and Hassfest) on the exact head before a release-facing
  merge.
- Documentation must describe the current behavior, safe upgrade path, privacy
  boundary, hardware scope, and release policy before a stable cutover.
