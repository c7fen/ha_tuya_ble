# Repository agent policy

## Branch and release boundaries

- Use `next` as the development base and pull-request target.
- Do not commit or merge directly to `main`; it is the controlled stable branch.
- Keep release preparation separate from runtime behavior changes.
- Do not force-push, rebase, or amend a pushed or reviewed head.
- Release only after documentation, CI, security, exact-head review, and any
  required hardware gates pass.

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

## Home Assistant live access

- Before ANY live Home Assistant host, Supervisor, deployment, restart, Core
  check, or live-validation task, read and follow
  `.agents/skills/home-assistant-live-access/SKILL.md`.
- On Felix's primary workstation, environment-specific Home Assistant SSH
  details are stored only in the private, untracked `AGENTS.local.md` in the
  canonical checkout. Linked worktrees do not inherit that untracked file.
  Therefore, if `AGENTS.local.md` is absent in the current worktree, agents MUST
  check the canonical checkout above before claiming that the route is unknown
  or unavailable.
- Never commit, publish, or echo the private Home Assistant target, internal
  address, credentials, SSH-agent material, or Supervisor token from the local
  instructions.
- The verified workstation route uses SSH Key Agent authentication that requires
  an interactive SSH login. Do not substitute a one-shot non-interactive
  `ssh <target> "<command>"` path for live Home Assistant work when the local
  instructions specify the interactive route.
- After interactive login, use the verified login-shell workflow from the skill
  for Supervisor-backed `ha` commands. A direct non-login command environment
  is not sufficient evidence that Supervisor context is unavailable.
- Do not invent a replacement alias, browser fallback, or alternate route
  merely because the current linked worktree lacks the private local file.
- Do not invoke or invent a wrapper bootstrap merely because an untracked
  private file is absent from a linked worktree. First use the established
  private wrapper and canonical-checkout rules above.
- A separately authorized local-only wrapper bootstrap MAY consume a
  literal-only private recipe through the repository-owned
  `tools/home_assistant_live_access.py` helper. It must not echo its input,
  target, or wrapper text; it must require an owner-only directory, a regular
  non-symlink `0700` wrapper, the allowlisted private interactive SSH route,
  and static command validation. The bootstrap recipe is a separate local-only
  format; it does not parse or render `AGENTS.local.md`. This helper is not a
  live-access authority and must never make a network connection.
- Validate the private wrapper structurally before a live task. Treat an
  invalid wrapper, an invalid Repairs response, or an unavailable private route
  as an access/admission or collector outcome, never as an invocation result.
- Retained/public Repairs evidence is limited to exactly `shape_valid`,
  `relevant_count`, and `critical_count`; gate and decision metadata stay
  inside the orchestrator.

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
