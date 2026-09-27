# Live validation and hardware evidence

This document defines the Tuya BLE-specific conditions for live Home Assistant
work and for hardware evidence. It does not describe how to reach the Home
Assistant host.

Offline development and offline checks need none of this. A missing access
route, private file, or approval blocks only the live task that needs it.

## Approvals

A live task needs an explicit approval that names the action and the target.
Approval classes do not imply each other:

| Approval | Covers | Does not cover |
| --- | --- | --- |
| Access | Read-only inspection of the named host | Deployment, restart, configuration change, service call, BLE session |
| Deployment | Installing the named exact commit on the named test host, plus the Core check and restart named in the approval | Service calls, BLE commands, physical operation, any other commit |
| Physical operation | Owner-operated action by an authorized person | Never delegated to an agent |

An explicit approval that already matches the requested action and target does
not need to be requested again. It never extends to another action, target, or
commit.

Agents must not operate a physical lock. No prompt, local file, or memory entry
creates an exception.

## Access route

The general Home Assistant SSH route is documented in the maintainer's access
runbook, `docs/runbooks/home-assistant-ssh-access.md` in the private
`cirrus7/smart-home` repository. This document was reviewed against the
version merged by smart-home pull request 8:
[merge commit `7b2e278`](https://github.com/cirrus7/smart-home/blob/7b2e2784507f1f2538b63b603bdbfdef61d192dd/docs/runbooks/home-assistant-ssh-access.md).
Check the runbook's current default-branch version before a live task and
follow its agent rules. The runbook leaves Tuya-specific live tooling rules to
this repository.

This repository adds no second general SSH procedure and never contains hosts,
addresses, users, credentials, or device bindings. Never read private access
files or wrappers into agent tool output; use only the non-echoing mechanism
that the applicable, merged live tooling defines.

Use only live tooling that is merged into the branch you are working on. Do
not substitute an alternate route, browser automation, or disabled add-on
protection when the documented route is unavailable; report the live task as
not run instead.

## Before a deployment

- Name the exact commit by its full SHA and record its offline validation
  result from [Validation](validation.md).
- Resolve the target device only through the owner's private binding and the
  Home Assistant config-entry, device, and entity registries. Never infer it
  from ordering, name similarity, battery value, RSSI, or current state. All
  entities used in a test must belong to the same config entry and device.
- Know how to restore the previously installed integration files.

## Stop conditions

Stop and report without retrying when:

- an approval, the access route, the private binding, or the target identity
  is missing or ambiguous;
- the deployed files are not identical to the approved exact commit;
- the Home Assistant configuration check fails or the integration reports a
  new error after deployment;
- a command result is ambiguous, for example after a timeout or disconnect.
  The owner inspects the physical state before any further action; and
- continuing would expose credentials, complete identifiers, raw payloads,
  lock values, packet bytes, or captures.

## Evidence record

Record each live or hardware result with:

- the exact tested commit;
- the environment: Home Assistant version, integration version, and the
  relevant connection settings;
- the UTC time;
- the scope: product, number of devices, and number of actions; and
- the result: PASS, FAIL, NOT RUN with reason, or N/A with reason, as defined
  in [Validation](validation.md#results). A check that was not run is never
  reported as passed.

Evidence applies only to the exact tested commit. A merge commit or tag that
contains the same runtime files is a new object and must state how it relates
to the tested commit. Keep historical evidence with its original commit,
environment, time, scope, and result; do not rewrite historical outcomes, and
mark missing fields as not recorded instead of reconstructing them.

Raw evidence stays in an owner-restricted location. The repository receives
only sanitized summaries that follow
[Logging and privacy](logging-and-privacy.md).

## Hardware evidence

The contributor or owner, not the integration agent, performs physical actions.
Follow the checklist in
[Smart-lock behavior and safety](smart-locks.md#before-any-physical-test).
Record one user action per command, the number of physical actions, the
expected direction, and any ambiguous error. Never claim hardware validation
for a different commit or an untested product.
