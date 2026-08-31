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
It is a private target container only: retained automation must not invoke the
raw wrapper directly. Use the repository's privacy-filtering interactive PTY
session broker, which starts the wrapper privately and never forwards its
startup banner or close output to the transcript.

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

The broker launches the private wrapper with an actual interactive terminal/PTY
and keeps that SSH session open for the bounded live task. SSH Key Agent
authentication remains interactive; the broker is not a non-interactive
`ssh <target> "command"` replacement.

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

After the interactive SSH login succeeds, the broker privately sends the
login-shell command before reporting generic readiness:

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

The broker uses explicit private lifecycle states: `SSH_CHILD_STARTED`,
`REMOTE_INTERACTIVE_READY`, `LOGIN_SHELL_READY`, `SESSION_ACTIVE`, and
`CLOSED`. It captures initial output and connection-close messages privately,
uses bounded timeout/output limits, emits only `HA_INTERACTIVE_SESSION_READY`
after the login-shell state, and exposes only fixed structured operations. It
accepts only a pre-validated wrapper `Path`, executes that path with no
arguments in a controlling PTY, and has no raw terminal-output or generic
command passthrough. Every remote-shell, login-shell, and operation boundary
uses a fresh broker-owned nonce inside an exact control-delimited frame;
prompts, banners, echoed commands, ANSI text, and multiple machine results
cannot establish readiness or satisfy a result boundary.
Post-`exec bash -li` readiness is stricter than a fresh frame alone: the frame
is emitted only when the shell proves `BASH_VERSION`, interactive `$-` mode,
and `shopt -q login_shell` together. A shell that ignores the `exec` command is
an access failure, not a ready Supervisor context.

Before sending structured data, the broker disables terminal echo through a
broker-framed transition. The fixed remote program and source bundle then move
through bounded textual chunks. Transferred source, private paths, shell
prompts, helper output, and raw Supervisor responses remain inside the PTY.

## 5. Bounded full-preflight control plane

`FullPreflightLifecycleController` is the only public live-capable operation
surface. The lower broker exposes only session `open`, `close`, and generic
state; all Repairs, source, Core, restart, service-inventory, helper, and
restoration adapters require a controller-minted capability even when their
underscore-private names are reached directly. Each frozen capability is bound
by identity to the registered controller, lifecycle generation, exact source
generation, broker session, unique issuance identity, issuer ledger, and one
exact action, and is consumed by bounded dispatch before PTY output.
It cannot authorize another action, session, lifecycle, broker, or second use.
The broker has no ordinary raw PTY writer. Its only byte sink is a
name-mangled method accepting a frozen, issuer-bound packet constructed inside
the broker. Bootstrap/login writes use that sink only for fixed, state-bound
commands, and the name-mangled bounded dispatcher accepts only typed operation
enums. Do not invoke or expose an internal broker adapter directly. The
controller has no command-string, argv, stdin/stdout
bridge, remote-path, service-name, endpoint, environment-variable, arbitrary
helper-operation, caller nonce, or caller audit-label argument.

Capability issuance is itself state-bound by an immutable action-to-predecessor
table inside controller dispatch. Reaching a private dispatch method cannot mint
an action capability from the wrong lifecycle state; rejection happens before
permit consumption, capability issuance, callback execution, broker dispatch,
or PTY output. The second Core-check action is unreachable by the normal
controller: outer transport ambiguity is not proof that a first request did
not complete, so it enters recovery instead of replaying. Restore transfer
alone permits final candidate `A2_COLLECTED` or a recovery state; backup
fallback is recovery-only.

Private method names and internal token attributes are implementation details,
not a supported caller surface. This contract does not attempt an in-process
reflection arms race against code deliberately extracting a broker-owned raw
write token. Supported controller calls, direct broker calls without a minted
capability, and private dispatch calls from a wrong state all enforce the
bounded contract before PTY output.

The exact success sequence is:

```text
BASELINE
-> INITIAL_REPAIRS_PASS
-> BACKUP_VERIFIED
-> CANDIDATE_STAGED
-> CANDIDATE_INSTALLED
-> CANDIDATE_INVENTORY_VERIFIED
-> CANDIDATE_CORE_CHECKED
-> ACTIVATION_RESTART_CONSUMED
-> CANDIDATE_READY
-> RESEARCH_SERVICES_PRESENT
-> POST_ACTIVATION_REPAIRS_PASS
-> A0_COLLECTED
-> P0_COMPLETED
-> AP0_COLLECTED
-> NON_PROBE_PREFLIGHT_COMPLETED
-> A1_COLLECTED
-> RESEARCH_FINAL_VALIDATED
-> A2_COLLECTED
-> RESTORE_STAGED
-> PR41_RESTORED
-> RESTORE_INVENTORY_VERIFIED
-> RESTORE_CORE_CHECKED
-> REMOVAL_RESTART_CONSUMED
-> PR41_READY
-> RESEARCH_SERVICES_ABSENT
-> POST_RESTORE_REPAIRS_PASS
-> COMPLETE_NORMAL
```

`COMPLETE_NORMAL` requires that entire ordered history, including A2 and the
full PR #41 restoration proof, in one durable lifecycle generation. Successful
PR #41 restoration after any aborted or ambiguous research step terminates as
`RESTORED_AFTER_ABORT`. A restoration-stage failure terminates as
`RESTORE_FAILED`. If recovery begins before candidate installation reached a
submission-possible phase, run the state-neutral current-source inspection
before staging PR #41. Exact PR #41 terminates as `ABORTED_AT_BASELINE` without
transfer, installation, or restart; any other or indeterminate result keeps the
existing PR #41 recovery path. None of these recovery outcomes asserts research
success.

The controller owns one versioned durable continuity journal at a fixed,
repository-owned location under the shared Git metadata directory. No caller
or HA target selects its path. An adjacent lifecycle-root anchor is durably
created before the first journal. It binds the original lifecycle and PR #41
authority to the state-root directory identity and monotonically mirrors the
journal revision. A verified baseline-backup identity is added to the journal
and anchor in the same versioned transition. An anchor with a missing journal
is recovery-required state, never a fresh baseline; a journal with a missing
anchor is inconsistent state. Terminal journals and their anchors are retained.

This continuity guarantee assumes that the independently stored anchor remains
when the journal alone is lost. If an external actor destroys or corrupts both
the anchor and journal storage, no local software can infer the erased history;
protect and recover that state root as one durability domain.

The owner-private directory and regular files reject symlinks, unexpected
owner, mode, link count, oversized or malformed JSON, duplicate keys, unknown
fields, and invalid transition ledgers. The controller first opens one stable
state-root directory descriptor, acquires the owner-private non-blocking
`flock` through that descriptor, and only then loads the anchor and journal.
All later critical path operations remain relative to that same descriptor, so
pathname replacement cannot split lock and journal authority. Journal updates
increment one strict integer revision and use an owner-private temporary
regular file, file `fsync`, atomic replacement, and directory `fsync`.

Before any dispatch-capable callback, the journal durably records the exact
operation intent and tombstone. It then distinguishes dispatch started, result
durable, transition committed, ambiguity, and reconciliation. It retains
lifecycle/source generations, exact PR #45 and PR #41 authorities,
research-success and recovery flags, consumed actions, helper/restart
tombstones, Core-check attempts, nonce state, and sanitized evidence identities.
An operation that becomes ambiguous before a typed result also retains only a
fixed failure stage and generic class; exception text and private paths are not
journal data.
It never stores a target, token, raw response, PTY data, issue object, or device
identifier. Opening an unfinished post-mutation journal yields
`RECOVERY_REQUIRED`; research and candidate entrypoints are hidden on that
instance, and only bounded reconciliation plus the PR #41 restoration tail are
available. A fresh process cannot recreate a helper, restart, install, or
Core-check permit.

Every transition checks its exact predecessor and all local typed inputs before
PTY output. Immediately before a represented action dispatch, the controller
consumes an action-specific permit bound to the current controller generation
and broker session, then mints the matching one-shot broker capability.
The broker adapter validates the same action and bounded dispatch consumes the
capability before its first write. Success, rejection, malformed output,
transport failure, and exit 78 all leave the lifecycle permit and any dispatched
capability consumed. P0 also consumes its lifecycle
permit, while still requiring the exact local exit-65 `not_submitted` shape.
Successful `PREFLIGHT` requires the exact PR #45 response-only schema:
`result == "preflight_ok"`, integer protocol version `1`, and the supplied
controller nonce. It creates no receipt-ledger entry, so normal progression is
directly to A1. Failure or ambiguity enters recovery with no replay and no
receipt reconciliation. Activation and removal restarts use distinct permits
consumed before dispatch.

The private dispatcher accepts only `BoundedOperation`; the helper operation
enum contains only `PREFLIGHT`, `AUDIT`, and `RECEIPT`. It deliberately cannot
represent `PROBE`, Device Status, Device Info, pairing, a datapoint write, a
lock action, or a policy mutation. `RECEIPT` remains only in the shared strict
result parser; the broker and Non-Probe lifecycle cannot invoke it or use it as
transition evidence.

While PR #45 is active, the exact expected service names are
`phase_a_status_probe`, `phase_a_status_probe_preflight`,
`phase_a_status_probe_receipt`, and `phase_a_status_probe_audit`. The first is
inventoried but is never invocable through this control plane. All four must be
absent after PR #41 restoration.

Candidate source is bound to exact PR #45 commit
`a382c08cd4e8613dc214505bcb8a6f59f8da3022` and tree
`73246ecd71f0953c7bf8a73df78d6506bee29c8e`. Restoration source is bound to
exact PR #41 commit `4f73a9b008dcb89134bc41001c486f06d6056867` and tree
`463ed8553da01eae591de611e76e45392ad9e7bf`. Local and remote admission both
require the pinned canonical per-file manifest fingerprint, exact file count,
exact SHA-256 content digests, regular files only, no duplicates, no traversal,
and no unexpected helper file. Transfer framing rejects duplicate JSON members,
non-canonical Base64, malformed or non-lowercase digests, schema extras, and
content that does not match the exact manifest before writing it. The bounded
remote program is itself strict-Base64 decoded and SHA-256 bound before
execution.

The candidate helper is nested in a fixed hidden directory inside the Tuya BLE
integration deployment tree. Installation and restoration use one Linux atomic
directory exchange, so PR #41 restoration removes the research helper in the
same operation without touching another custom component. The fixed private
backup is independently verified and is only a fallback; exact PR #41 remains
the restoration authority. It is published once as a single no-clobber
directory package containing the integration tree and its identity metadata.
The package binds the lifecycle generation, PR #41 commit/tree, PR41 source
generation, immutable backup generation, canonical manifest identity, and
package digest. Each file and required directory is synced before atomic
`RENAME_NOREPLACE` publication and parent-directory sync. No sidecar metadata
exists and Candidate content cannot satisfy the PR #41 manifest. If publication
succeeds but its response is lost, a separate read-only reconciliation
operation verifies and adopts that exact package; creation is never replayed or
allowed to replace it.

Core check uses exactly `POST http://supervisor/core/check`. The remote adapter
preserves the authoritative response body's `check_passed` value; it never
synthesizes that field from HTTP status or `result`. Success requires a
completed request, 2xx status, JSON object, exact string `result == "ok"`, and
exact boolean `check_passed is true`, and no error condition. Parser and
controller boundaries both reject integer `1`, strings, null, and arbitrary
truthy objects. A completed FAIL or transport ambiguity is terminal for that
attempt; the controller never reconnects or retries it. The durable journal
records attempt state, so reconstruction cannot reset the budget. A completed generic `error_class` response is a
typed Core-check FAIL, not transport ambiguity. Restart uses the fixed
Supervisor Core restart endpoint, has no retry loop, and the broker rejects a
second submission for the same activated source state before PTY I/O.
Readiness polling is bounded and verifies Core reachability, the running API,
and `tuya_ble` in Core's loaded component set. Temporary service presence or
absence remains a separate exact-count aggregate gate; result booleans alone
are insufficient.

Helper results preserve exits 0, 65, 66, 67, and 78. Outcomes are validated per
operation and correlated to the exact controller-generated nonce. Exit 78 is
terminal ambiguity and never authorizes replay. Audit responses retain only protocol
version, opaque audit instance token, ordinal, overflow state, runtime duration,
the allowlisted counters, the documented four-field bounded events, and the
optional nonce. Snapshot comparison reports exact instance, ordinal, counter,
event, and overflow booleans without inventing semantic equivalence.

The controller owns A0, AP0, A1, and A2 and binds every evidence object to the
exact lifecycle, candidate source, producing action, monotonic evidence
generation, broker session, audit instance, and nonce. Evidence is claimed once
from the broker issuance ledger; an externally constructed lookalike or stale
object from another lifecycle, source, or session cannot advance state. A0 requires strict post-activation Repairs
admission and no history overflow; counters need not be absolute zero because
the audit instance predates startup work. A0->AP0, AP0->A1, A1->A2, and the
cumulative A0->A2 comparison must preserve the exact audit instance, event
ordinal, counters, events, and no-overflow state. Runtime duration is not an
I/O predicate. A2 is the final candidate snapshot immediately before PR #41
restoration.

Any dispatched candidate-install uncertainty or later research-stage failure
enters `ROLLBACK_REQUIRED`. From there, the only normal recovery is exact PR
#41 transfer, restore, inventory, authoritative Core check, one removal
restart, readiness, service absence, and strict final Repairs. The private
backup is a separately consumed last-resort fallback and never silently
substitutes for PR #41 proof. Its private remote marker distinguishes monotonic
intent, possible-dispatch, possible-application, and reconciled phases. Process
loss around the atomic exchange cannot authorize replay: a separate typed,
bounded, read-only reconciliation permit compares the bounded backup identity
with the live and stored trees. Loss of that reconciliation's own response
resumes the same reconciliation operation, with its attempt bound retained; it
does not recreate fallback authority. Final acceptance is a typed, no-default
proof requiring exact source inventory with no research files, authoritative
Core check, consumed/dispatched/accepted removal restart, full readiness
including `tuya_ble`, all four temporary services absent, and strict Repairs
shape/zero counts. Transfer, install, and inventory result counts must equal
the exact controller-owned bundle or manifest count; a self-consistent
different count is not admission.

If the bound PTY session was lost while the controller object survives,
rollback does not reconnect automatically.
The caller must explicitly bind one fresh, already active and validated broker
while the controller is in `ROLLBACK_REQUIRED`. The lifecycle generation and
all consumed permits remain unchanged. Only still-unused PR #41 rollback-tail
and backup-fallback permits are rebound to the fresh session. Candidate,
helper, restart, and Core-check permits are never reset or rebound.
The same broker, an inactive broker, or any previously seen session generation
is rejected locally before PTY output. A successful rebind registers the same
controller and lifecycle generation with a fresh broker issuer; it does not
make an old capability valid in the new session. After process reconstruction,
the durable journal instead exposes only recovery-safe entrypoints; it never
seamlessly resumes research.

The PR #45 audit helper and audit service exist only while the candidate source
is active. Collect every required helper-backed snapshot, including any A2
label, before exact PR #41 restoration begins. After restoration, prove source
identity, temporary-service absence, Core readiness, and final Repairs instead.
Do not fabricate a post-restore audit snapshot: exact PR #41 intentionally
contains neither the temporary helper nor its audit service.

## 6. Strict structured Repairs admission

Repairs admission is fail-closed. When a supported Home Assistant response is
used to prove the Repairs gate, the collector must validate the actual response
shape before filtering or counting anything.

The singular collector transport is `ha resolution info --raw-json`. Validate
the complete Supervisor envelope, not a guessed extracted payload. Require:

- top-level value is an object/dictionary;
- exact string `result` value `ok`;
- object `data`;
- key `issues` inside `data`;
- list `data.issues`.

A missing field, non-string or non-`ok` result, null/non-object data,
null/non-list issues, array at the top level, malformed JSON, or any other
response shape is an admission failure/indeterminate observation. The obsolete
top-level `{"issues": []}` shape is deliberately rejected.

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
if "result" not in payload or not isinstance(payload["result"], str):
    raise ValueError("repairs_response_shape")
if payload["result"] != "ok" or "data" not in payload:
    raise ValueError("repairs_response_shape")
if not isinstance(payload["data"], dict):
    raise ValueError("repairs_response_shape")
data = payload["data"]
if "issues" not in data or not isinstance(data["issues"], list):
    raise ValueError("repairs_issues_shape")
issues = data["issues"]
```

Issue classification/projection happens only inside the broker. The normal
controller interface accepts no caller-supplied classifier over full issue
objects. In the fixed fail-closed projection, every returned issue is
conservatively blocking; only an exact empty list can produce zero relevant and
critical counts. Retained/public evidence contains only the allowlisted
shape-valid, relevant-count, and critical-count fields. Do not dump issue
objects merely to debug a collector. Admission requires `shape_valid is True`,
exact non-boolean integer counts, and both counts exactly zero.

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

## 7. Command execution model for agents

For agent/orchestrator execution:

1. Start one interactive SSH session through the privacy-filtering PTY broker.
2. Let it privately consume the Home Assistant prompt/banner and establish the
   verified login shell.
3. Wait only for its generic readiness sentinel.
4. Use only the lifecycle controller method for the current admitted state;
   never call a broker adapter, bridge raw remote stdout, or request a general
   command channel.
5. Validate structured admission responses strictly before mutation gates.
6. Keep authorization boundaries from the active task; this skill grants no
   deployment, restart, service-call, BLE, lock, or configuration permission by
   itself.
7. Close the interactive SSH session when the bounded task is complete.

Do not silently open additional sessions, retry device work, or broaden a live
operation merely to recover from orchestration problems.

## 8. Privacy and evidence

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
- R24's fail-closed D0 stop was correct and made no source or device mutation.
  The confirmed correction target is a Supervisor schema-layer mismatch, not
  PR #45, BLE, a device, or the interactive invocation contract.

## 9. Fail-closed access and admission decisions

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
