# Owner-operated Refresh observer contract (R66P)

Product reference: PR47 `7cfcf9598941de253a24b7c30b06170a98b4ba86`.
This document changes observer interpretation, not the product, hardware-test
budget, authorization, ARM-before-PRESS order, worker, or restoration lifecycle.
Only the owner presses. No software result establishes physical non-movement.

## Three corrected mismatches

| Dimension | Former observer | PR47-aligned owner observer |
| --- | --- | --- |
| Outbound `other` | Every packet was called a protocol write | Preserve the total; distinguish matched automatic replies, forbidden control, and unclassified traffic |
| DP69-only | Required retained DPs and a changed status timestamp | Accept exact request/session completion with a valid batch; retained confirmation is not applicable without eligible DPs |
| Target identity | Any trial failure made continuity false | Compare validated private context independently of protocol/data outcome |

## Packet accounting

The five original counts retain their meaning. In particular, `other` still
counts every outbound message outside Device Info, Pair, Device Status and
DPS/DPS_V4. Additive `contract_evidence.version=2` subdivides that count by
protocol code, count and bounded classification; the strict decoder requires
the subdivision sum to equal `other`. Sequence numbers remain internal.

`MATCHED_AUTOMATIC_RESPONSE` requires a preceding incoming message with the same
code and sequence referenced by the outgoing response, inside the selected
refresh window after session binding, with no intervening connection boundary.
Each incoming reference is consumed once. PR47 `_handle_command_or_response()`
and its session-owned `_schedule_response()` establish these exact same-code
reply paths:

- TIME1_REQ and TIME2_REQ: time responses;
- DP, SIGN_DP, TIME_DP and SIGN_TIME_DP: V3 report acknowledgements;
- DP_V4 and TIME_DP_V4: V4 report acknowledgements when the handler requests one.

These names have the `FUN_RECEIVE_` prefix. This is a closed list, not permission
for every receive-prefixed code or any packet carrying `response_to`. Matching
metadata proves the bounded reply association, not payload content. V4 flags
are not retained by the observer; the exact product handler owns that check.
Replies before a proven session boundary, missing/mismatched references and
unknown traffic remain `UNCLASSIFIED_OUTBOUND_TRAFFIC`, never an invented write.

Outbound `FUN_SENDER_DPS`/`FUN_SENDER_DPS_V4` remain
`PROTOCOL_WRITE_DETECTED`. Unbind, reset and the five OTA sender operations are
`FORBIDDEN_CONTROL_DETECTED`, regardless of response references. Both classes
and unclassified traffic block progression. The compatibility property
`zero_write` means no forbidden or unclassified traffic; it does not mean no
outbound bytes. A permitted time response still sends information to the device.

## Protocol completion is not retained-value confirmation

PR47 `async_refresh_s1_status()` emits its session-bound COMPLETED marker only
after its exact request ACK and a valid exact-session batch belonging to its
observation generation. The observer requires one accepted lifecycle, matching
bound/terminal session ordinals, one in-session Device Status request and DP
metadata after that request. Cold additionally requires Device Info and Pair;
Retained requires neither and uses REUSED_SESSION. Missing batches, failed or
mismatched terminals, wrong provenance and session discontinuity cannot pass.

This trusts the pinned product's generation contract; it does not turn batch
chronology into proof that every DP was caused by the request.

Only received DP8/33/34/36 with their respective VALUE/BOOL/ENUM/VALUE types
make retained confirmation applicable. Only those IDs are checked for existing
`value_source=current_session` evidence. Missing IDs or wrong types do not
promote old values. Visible timestamps have second precision and need not
strictly increase. DP69-only therefore has request/session provenance but no
retained confirmation, no fresh battery/configuration claim, and no required
Last Status Update change. This agrees with PR47's
`test_non_retained_batch_completes_without_advancing_status_time` and partial
promotion tests. Version 2 explicitly distinguishes applicability, applicable
IDs and confirmation validity from request/session provenance.

## Identity, persistence and historical evidence

The first validated owner event may bind an approved target. Later contexts must
still match the original salt, approved set and bound fingerprint. An independent
protocol/data failure does not undo that comparison. Ownership, precondition or
context failures remain unproven; `target_bound` alone is insufficient. A newly
constructed controller does not invent proof of a later operation's identity.

Version 2 evidence survives the strict public serializer, decoder, journal,
aggregate zero-write gate and hardware completion. Rows without it retain the
old conservative interpretation; no historical packet types or confirmations
are backfilled. The separate legacy automated R65 validator is not the R66
owner observer and must not be used for this hardware workflow.

R66O remains a historical formal FAIL: its request completed and the owner
reported no physical action, but the two `other` packet types were not retained
(`R66O_OTHER_PACKET_TYPES=NOT_RETAINED`). The synthetic Cold/DP69-only test with
two matched automatic replies proves only that synthetic case, not R66O's
unknown packet identities or a retrospective hardware PASS.

Before any later hardware run, require its own current onsite admission and
exact-head authority. Keep the existing 10 Cold / 5 Retained / 10 release limits,
same persistent process, no replay and same-lifecycle exact PR41 restoration.
Collect the owner's physical observations separately; any failure or uncertainty
stops further presses. Lock/Unlock follow-up remains separately unauthorized.
