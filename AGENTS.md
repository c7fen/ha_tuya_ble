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

## Home Assistant access and tool routing

- Use SSH as the primary and default route for operations against a Home
  Assistant host. Do not use Playwright, Browser Use, Selenium, or frontend
  automation merely because a browser tool is available.

- Before starting Home Assistant work, read `AGENTS.local.md` when that local
  file exists. It contains environment-specific connection details that must
  not be committed to this public repository.

- Use the existing OpenSSH agent and known-host configuration. Use
  non-interactive public-key authentication with `BatchMode=yes` and a finite
  connection timeout.

- Never request, copy, generate, or replace an SSH private key or password.
  Never modify `authorized_keys`, the user's SSH configuration, or known
  hosts. Never disable host-key verification.

- For Home Assistant CLI or Supervisor-dependent commands, use a remote login
  shell, for example:

      ssh <home-assistant-target> \
        'bash -lc "ha core info --raw-json"'

  A direct non-login SSH command can lack `SUPERVISOR_TOKEN` and return
  unauthorized even when passwordless SSH itself works.

- Never print, persist, hash, export, or include `SUPERVISOR_TOKEN` in a
  command line, report, log, issue, pull request, or repository file. Do not
  dump the remote environment.

- If a direct `ha` command returns unauthorized, retry only through the
  verified login-shell route from `AGENTS.local.md`. Do not fall back to
  browser automation.

- If passwordless SSH or the verified login-shell route fails, stop before
  mutation and report the sanitized failure. Do not silently switch tools or
  authentication methods.

- Retrieving a Supervisor token from a container is not a normal fallback. It
  requires explicit task authorization, must remain in process memory, and
  must never be printed or persisted.

- Use browser automation only when the task explicitly concerns an external
  web portal that cannot be handled safely through SSH or an API. Browser
  automation is not the default route for the Home Assistant frontend.

- SSH access does not authorize physical actions. Agents must not call Lock,
  Unlock, Open, Auto-Lock, Button, or another actuating Home Assistant service
  unless the active task explicitly authorizes that exact action.

## Validation and commits

- Run Black before committing.
- Keep JSON valid, well formatted, and consistent with repository conventions.
- Use Conventional Commits. A basic mapping normally uses `fix:`.
- Require relevant focused tests, full pytest, Codespell, JSON/YAML validation,
  `git diff --check`, HACS, Hassfest, Actionlint, and secret scanning before a
  release-facing merge.
- Documentation must describe the current behavior, safe upgrade path, privacy
  boundary, hardware scope, and release policy before a stable cutover.
