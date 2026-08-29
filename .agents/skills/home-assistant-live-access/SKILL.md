---
name: home-assistant-live-access
description: Required procedure for any live Home Assistant host, Supervisor, deployment, restart, Core-check, or runtime-validation work in this repository. Resolves the private local SSH route safely, establishes the required interactive SSH Key Agent login, and enters a Supervisor-capable login shell without exposing private access data.
---

# Home Assistant live access

Use this skill for every task that touches the running Home Assistant host or
Supervisor, including read-only runtime inspection, deployment, Core checks,
restarts, integration reloads, service calls, and live validation.

## 1. Load the private local access instructions first

The exact Home Assistant SSH target is intentionally not committed to this public
repository.

1. Check for `AGENTS.local.md` in the current checkout.
2. If it is absent and this is Felix's primary WSL2 workstation, read the private
   `AGENTS.local.md` from the canonical checkout documented in the repository
   `AGENTS.md`.
3. Do not print, quote, copy, summarize, commit, or publish the private target or
   other access details from that file.
4. An untracked `AGENTS.local.md` is not inherited by linked Git worktrees. Its
   absence in a worktree therefore does **not** mean the Home Assistant route is
   unavailable.

Do not invent a replacement host, alias, route bootstrap, browser fallback, or
other access method before checking the canonical private local instructions.

## 2. SSH authentication is interactive

On the verified primary workstation, SSH authentication is supplied by the
existing SSH Key Agent and requires an **interactive SSH login**.

Use the exact SSH command/target from `AGENTS.local.md` and allocate an
interactive terminal/PTY. Keep that SSH session open for the bounded live task.

Do **not** replace it with a one-shot command such as:

```text
ssh <target> "ha ..."
```

and do not treat failure of a non-interactive SSH command as evidence that the
verified route is unavailable.

Do not inspect, export, copy, replace, or print private keys, SSH-agent sockets,
or SSH-agent environment variables.

## 3. Establish Supervisor context inside the interactive session

A direct/non-login command environment on this host may lack the Supervisor
context required by the Home Assistant `ha` CLI.

After the interactive SSH login succeeds, use a login Bash environment for
Supervisor-backed commands. Preferred patterns are:

```text
exec bash -li
```

for an interactive login shell, or, for one bounded command within the already
established interactive SSH session:

```text
bash -lic '<command>'
```

A safe read-only Supervisor-context check is conceptually:

```text
ha core info --raw-json
```

If a direct shell invocation lacks Supervisor context, first correct the login
shell as above. Do not conclude that Supervisor is unavailable and do not create
an alternate route merely because a non-login environment lacks the token.

## 4. Command execution model for agents

For agent/orchestrator execution:

1. Open one interactive SSH session using the private command from
   `AGENTS.local.md`.
2. Wait for the Home Assistant command-line prompt/banner before sending remote
   work.
3. Enter the verified login-shell workflow.
4. Execute the authorized bounded commands by sending them through that existing
   interactive session.
5. Keep authorization boundaries from the active task; this skill grants no
   deployment, restart, service-call, BLE, lock, or configuration permission by
   itself.
6. Close the interactive SSH session when the bounded task is complete.

Do not silently open additional sessions, retry device work, or broaden a live
operation merely to recover from orchestration problems.

## 5. Privacy and evidence

- The exact Home Assistant host/address and private route remain local-only.
- Do not copy private access details into PRs, issues, committed files, retained
  public logs, or sanitized evidence.
- Never print `SUPERVISOR_TOKEN`, Authorization headers, SSH-agent data, private
  keys, or environment dumps.
- Avoid `set -x` for live access work.
- Do not print private evidence/run paths unless a task explicitly requires a
  private local diagnostic and its disclosure is authorized.
- Public reports should describe the route only as the verified private
  interactive SSH route.

## 6. Fail-closed access decisions

Stop and request operator input only when the private local access instructions
are genuinely unavailable from both the current checkout and the documented
canonical checkout, or when the interactive SSH login itself fails.

The following are **not** valid reasons to declare the route unavailable:

- `AGENTS.local.md` missing only from a linked worktree;
- a non-interactive `ssh <target> "command"` attempt failing;
- a direct non-login shell lacking Supervisor context;
- an agent preferring a newly invented privacy-safe alias;
- browser automation being easier than the verified SSH route.
