# S1 Device Status observation (Phase A)

This integration contains passive, metadata-only research instrumentation for
characterising the S1 Device Status exchange. It observes requests that the
existing protocol path already sends; the observation layer itself does not add
a request, retry, reconnect, polling task, entity, or service. The exact S1
`Refresh Status` button uses this same metadata-only layer to bind its one
explicit request to one current-session ACK and DP-batch boundary.

The request generation is owned by the exact BLE session and the actual
outgoing request sequence. Device Status ACK correlation is exact when the
inbound response has the matching session, `response_to` sequence, and Device
Status response code. Inbound DP batches are observed at the parser boundary,
so one decoded protocol message remains one batch. Their order relative to the
ACK is recorded.

A later retained-session request supersedes the prior generation only for
subsequent DP-batch chronology. Each request retains ownership of its own
terminal ACK success, failure, or timeout event until its response wait ends;
the terminal event is never reassigned to a newer generation.

Chronological association is not causal attribution. An observed DP batch is
not reported as a proven Device Status response by this instrumentation alone;
final classification requires the later hardware inventory.

Only sanitized metadata is exposed: observation ordinal, request origin,
event kind, batch ordinal, DP IDs, DP types, encoded value lengths, exact-session
provenance, ACK result, and before/after-ACK chronology. DP values, packet
payloads, raw bytes, credentials, BLE addresses, Home Assistant identifiers,
and persistent records are excluded.

The current production mode is On Demand. The later cold trial uses exactly
one explicit `TuyaBLEDevice.update()`, resulting in one Device Status request;
the automatic request is not expected in that mode. Always-Connected retains
its existing one-shot automatic status request and marker semantics. A second
explicit `update()` in a retained session creates a new observation generation
without resetting the automatic marker.

The observation contract was the repository-only Phase-A prerequisite. Its
later remote inventory does not make a DP batch proof of physical state, and
the Refresh Status implementation likewise makes no motor-movement claim.
A separate SHA-bound live-validation gate remains required.
