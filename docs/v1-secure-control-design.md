# V1 secure coupling control: protocol decision record

## Current status

Bidirectional V1 control is implemented and was hardware validated in the
`v0.9.0b2` runtime. The functional b2 installation passed, but that deployment
was rolled back after a separate mandatory logging-privacy gate found a stable,
address-derived log pseudonym. The logging remediation follows in `v0.9.0b3`;
it does not change the command contract documented here.

The current contract for `ms/7a4xvbtt` is:

- **Lock / secure / uncouple:** one product-specific DP46 action.
- **Unlock / access / couple:** one product-specific DP6 action constructed
  semantically for each request.
- **State:** read-only DP47. `false` means secure/uncoupled and `true` means
  access-enabled/coupled. Missing, malformed, or wrongly typed state remains
  unknown.
- **Open:** unsupported.
- **Auto-Lock:** DP33 remains configuration only.
- **At-most-once transport:** a command is never automatically replayed after
  an ambiguous BLE transport error. The operator must inspect physical state
  before deciding whether to retry.

The implementation stores no captured frame, copied lock payload, or
device-specific command secret. It creates fresh Tuya BLE protocol framing for
each operation through the ordinary authenticated device session. The private
capture material authorized for the investigation was deleted after the
semantic evidence and independent reviews were complete; it was never
committed, published, or copied into Home Assistant storage.

## Evidence and safety boundary

Private direct-BLE observation established two repeatable action families:
DP46 for secure/uncouple and DP6 for access/couple. Two complete app cycles
produced exactly one motor action per tap in the expected physical direction.
No raw frame, command value, Bluetooth identifier, account identifier, or key
is retained in this record.

The product-specific code-to-DP mapping is authoritative for this firmware.
Numeric datapoint IDs from another product family are not evidence that the
same IDs have the same meaning here. The implementation does not try alternate
encodings, spray commands, or fall back to control paths inferred from other
locks.

Successful control requires the correlated protocol-v3 sender-DPS response in
the expected form. A different response family, timeout, malformed response,
reported failure, disconnect, or unsupported protocol version fails the Home
Assistant service call. Response correlation and serialization prevent a
second in-flight command from being mistaken for confirmation of the first.

Fresh local framing prevents this integration from reusing captured
ciphertext. It does not claim that the physical device can detect a replay
performed by some other actor.

## Entity and registry contract

The former V1 `button` entity with unique-ID suffix `manual_lock` migrates to a
`lock` entity owned by the same config entry and device. The migration
preserves valid user customizations when ownership and target identity are
unambiguous. It rejects foreign, conflicting, or ambiguous registry state,
verifies the target before removing the source, rolls back a newly created
target on failure, and is idempotent.

Automations that called the old button service must call `lock.lock` or
`lock.unlock` on the migrated entity. `lock.open` is not exposed. DP47 remains
a read-only diagnostic binary sensor and DP33 remains the Auto-Lock switch.

## Exact hardware evidence

The feature head `5bfbd7c0b9a67cd1416ee3a21b6acdc5ea4a968c` passed:

- V1 Lock / secure / uncouple;
- V1 Unlock / access / couple;
- exactly one physical motor action per command;
- distinct expected motor directions and sounds;
- DP33 remaining Auto-Lock only;
- DP47 remaining read-only;
- restart persistence; and
- one representative S1 Lock/Unlock smoke cycle.

The agent did not operate a lock. The device owner performed the actions with
the door open and alternate authorized access available.

## Rejected alternatives

- DP33 is configuration and is not a directional motor command.
- DP47 is device state and remains read-only.
- Guessing a second DP46 meaning was rejected because observed access did not
  use that path.
- DP70/DP71 are part of the separately bounded S1 same-device template design,
  not V1 evidence.
- Cloud actuation, captured-ciphertext replay, and command spraying are outside
  the local, fail-closed contract.

## Archived appendix: DP60/DP61 investigation

This appendix records why an earlier self-provisioned-key proposal was blocked.
It is historical research, not the current implementation status.

Before direct product-specific observation, reference material suggested DP60
and DP61 for some gateway-oriented lock flows. The material did not establish
that a direct BLE client was authorized to generate or install the relevant
key, that the V1 firmware accepted that flow, or that persistence could be
acknowledged safely. Public fork experiments also used conflicting writable
state and Auto-Lock workarounds without reproducible DP60/DP61 success.

The proposal was therefore rejected. No DP60/DP61 builder, parser, Store,
entity, registry migration, device key, or runtime write was added. Later
direct-BLE evidence selected the narrow DP46/DP6/DP47 contract above, so the
historical key-authority questions are not part of the active design.
