---
name: home-assistant-live-access
description: Required procedure for any live Home Assistant host, Supervisor, deployment, restart, Core-check, Repairs, or runtime-validation work in this repository. Uses the private local interactive SSH route without rendering it into agent transcripts, establishes the required SSH Key Agent login, enters a Supervisor-capable login shell, and enforces fail-closed structured admission parsing.
---

# Home Assistant live access

Use this skill for every task that touches the running Home Assistant host or
Supervisor, including read-only runtime inspection, deployment, Core checks,
Repairs checks, restarts, integration reloads, service calls, and live
validation.

## 1. Private local access instructions are not transcript input

The exact Home Assistant SSH target is intentionally not committed to this public
repository.

An untracked `AGENTS.local.md` may exist in the canonical checkout. Linked Git
worktrees do not inherit that file.

**Critical privacy rule:** never read `AGENTS.local.md` through a file-reading,
terminal, connector, or agent tool whose response returns the file contents to
the model/transcript. Do not `cat`, `sed`, `head`, `tail`, or otherwise render
that private file into retained platform output.

Do not print, quote, copy, summarize, commit, or publish the private target or
other access details from that file.

If the current worktree lacks the private file, its absence does **not** mean the
route is unavailable. The canonical checkout documented in repository
`AGENTS.md` remains the local private source of truth, but its contents must be
consumed only through a non-echoing local mechanism.

## 2. Preferred non-echoing route wrapper

For agent/orchestrator live work, prefer an untracked local executable wrapper:

```text
$HOME/.local/bin/ha-tuya-ble-ssh
```

The wrapper is private local state, not repository content. It should contain or
resolve the already verified SSH command and finish with an `exec ssh ...`
interactive login. Recommended permissions are owner-only executable (`0700`)
under an owner-only parent directory.

The wrapper itself must never print the resolved target before launching SSH.

If the wrapper is absent, do **not** solve that by rendering `AGENTS.local.md`
into the transcript. A separately authorized local-only bootstrap may create
the wrapper from a literal-only private recipe using the repository-owned
`tools/home_assistant_live_access.py` helper. It must consume the recipe without
rendering it, create only an owner-only regular non-symlink `0700` file, accept
only the allowlisted private interactive SSH command shape, and statically
validate both the recipe AST and wrapper command. The helper is local-only: it
must not open a network connection or report a private target. If no such safe
local mechanism is available, ask the operator to create/update the wrapper
rather than exposing the private file.

The bootstrap recipe is deliberately separate from `AGENTS.local.md`; the
helper never parses that instruction file. Its generated/accepted wrapper is
only a direct `exec ssh <safe-private-alias>` command (an absolute SSH executable
and `-tt` are also permitted). No shell metacharacters, remote command, proxy,
or alternate route are allowed.

Do not invent a replacement host, public alias, browser fallback, or alternate
network route merely because a linked worktree lacks `AGENTS.local.md`.

## 3. SSH authentication is interactive

On the verified primary workstation, SSH authentication is supplied by the
existing SSH Key Agent and requires an **interactive SSH login**.

Launch the private wrapper with an interactive terminal/PTY and keep that SSH
session open for the bounded live task.

Do **not** replace it with a one-shot command such as:

```text
ssh <target> "ha ..."
```

and do not treat failure of a non-interactive SSH command as evidence that the
verified route is unavailable.

Do not inspect, export, copy, replace, or print private keys, SSH-agent sockets,
or SSH-agent environment variables.

## 4. Establish Supervisor context inside the interactive session

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

## 5. Strict structured Repairs admission

Repairs admission is fail-closed. When a supported Home Assistant response is
used to prove the Repairs gate, the collector must validate the actual response
shape before filtering or counting anything.

For the currently verified structured response, require:

- top-level value is an object/dictionary;
- the object contains key `issues`;
- `issues` is a list.

A missing key, null value, array at the top level, string, malformed JSON, or any
other response shape is an admission failure/indeterminate observation.

**Forbidden:** silently converting an unexpected response into an empty list,
for example logic equivalent to:

```text
issues = payload if isinstance(payload, list) else []
```

or:

```text
issues = payload.get("issues", [])
```

without first proving the key exists and is a list.

A minimal safe shape check is conceptually:

```python
payload = json.load(stream)
if not isinstance(payload, dict):
    raise ValueError("repairs_response_shape")
if "issues" not in payload or not isinstance(payload["issues"], list):
    raise ValueError("repairs_issues_shape")
issues = payload["issues"]
```

Task-specific filtering of `issues` must happen in-process. Retained/public
evidence should contain only allowlisted aggregate results such as shape-valid,
relevant-count, and critical-count. Do not dump issue objects merely to debug a
collector.

Use the same strict decoder at every admission point in one live run: initial,
post-activation, and post-rollback. Its only retained result is the allowlisted
shape-valid flag plus relevant and critical counts. Do not use separate
permissive parsing logic or an empty-list fallback at later gates.

Repository tooling represents the strict internal decode as `shape_valid` plus
the proven `issues` sequence. Invalid shapes set `shape_valid` false and retain
no substitute empty sequence. Gate name, classification, and failure code stay
inside the orchestration decision. Only `RepairsEvidence` may cross the
collector boundary, with exactly `shape_valid`, `relevant_count`, and
`critical_count`.

If the structured schema changes, stop with the distinct
`REPAIRS_RESPONSE_SHAPE_INVALID` collector/admission classification and correct
the decoder before any deployment/restart proceeds. Do not label a predecessor
admission failure as an invocation/service failure.

## 6. Command execution model for agents

For agent/orchestrator execution:

1. Open one interactive SSH session using the private local wrapper.
2. Wait for the Home Assistant command-line prompt/banner before sending remote
   work.
3. Enter the verified login-shell workflow.
4. Execute the authorized bounded commands by sending them through that existing
   interactive session.
5. Validate structured admission responses strictly before mutation gates.
6. Keep authorization boundaries from the active task; this skill grants no
   deployment, restart, service-call, BLE, lock, or configuration permission by
   itself.
7. Close the interactive SSH session when the bounded task is complete.

Do not silently open additional sessions, retry device work, or broaden a live
operation merely to recover from orchestration problems.

## 7. Privacy and evidence

- The exact Home Assistant host/address and private route remain local-only.
- Never render private instruction-file contents into platform tool output.
- Do not copy private access details into PRs, issues, committed files, retained
  public logs, or sanitized evidence.
- Never print `SUPERVISOR_TOKEN`, Authorization headers, SSH-agent data, private
  keys, or environment dumps.
- Avoid `set -x` for live access work.
- Do not print private evidence/run paths unless a task explicitly requires a
  private local diagnostic and its disclosure is authorized.
- Do not retain ConfigEntry IDs, device IDs, entity IDs, private absolute
  evidence paths, or any synthetic sentinels standing in for those values.
- Do not retain raw Repairs issue objects when aggregate admission counts are
  sufficient.
- Keep the synthetic transcript-privacy regression in
  `tests/test_home_assistant_live_access.py` passing. It covers private route
  and instruction content, ConfigEntry/device/entity identifiers, Supervisor
  token/header material, SSH-agent environment, private keys, and private
  absolute evidence paths without using real private data.
- Public reports should describe the route only as the verified private
  interactive SSH route.

## 8. Fail-closed access and admission decisions

Stop and request operator input only when the private local route cannot be
launched through the established non-echoing mechanism, or when the interactive
SSH login itself fails.

Stop with an admission/collector classification when a required structured
response does not match its proven schema.

The following are **not** valid reasons to declare the route unavailable:

- `AGENTS.local.md` missing only from a linked worktree;
- refusing to render the private local file into tool output;
- a non-interactive `ssh <target> "command"` attempt failing;
- a direct non-login shell lacking Supervisor context;
- an agent preferring a newly invented privacy-safe alias;
- browser automation being easier than the verified SSH route.
