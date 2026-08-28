# S1 Device Status observation (Phase A)

This integration contains passive, metadata-only research instrumentation for
characterising the S1 Device Status exchange. It observes requests that the
existing protocol path already sends; it does not add a request, retry,
reconnect, polling task, entity, service, or `Refresh Status` button.

The request generation is owned by the exact BLE session and the actual
outgoing request sequence. Device Status ACK correlation is exact when the
inbound response has the matching session and `response_to` sequence. Inbound
DP batches are observed at the parser boundary, so one decoded protocol
message remains one batch. Their order relative to the ACK is recorded.

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

This is a repository-only prerequisite. It has not been deployed and provides
no physical or Home Assistant evidence. A separate SHA-bound deployment and
physical Phase-A inventory gate is required.
