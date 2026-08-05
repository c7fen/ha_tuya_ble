# V1 secure coupling control: protocol decision record

## 2026-08-05 additive decision: observed direct-BLE access command

This section records new evidence obtained after the historical blocked decision
below. It selects a product-specific implementation path for `ms/7a4xvbtt` on
top of exact `next` commit
`04017422e1ad71e20cb0b785d013bafba711c73b`. The older research and rejected
DP60/DP61 design remain in this document as the previous evidence boundary.

### Selected path and evidence provenance

The selected design is **Path B: product-specific Tuya-app command evidence**.
The device owner authorized a private Android Bluetooth HCI snoop after passive
Home Assistant, MQTT, and cloud observation exposed only inbound reports. The
owner performed every physical action with the door open. The integration and
investigator did not invoke a lock service or write a device datapoint.

Two complete app cycles produced the same semantics:

| Action | Direct-BLE message | Product datapoint | Type | Value length | Physical result |
| --- | --- | ---: | --- | ---: | --- |
| Secure | protocol-v3 sender-DPS | 46 | Boolean | 1 byte | uncouple |
| Access | protocol-v3 sender-DPS | 6 | Raw | 2 bytes | couple |

Each of the four commands was caused by exactly one app tap and produced exactly
one motor action. Both Access values had the same non-reversible fingerprint and
the same two-field semantic shape. Both Secure values had the same Boolean
meaning already implemented by the DP46 button. The session sequence number and
AES-CBC IV changed normally between commands, so captured ciphertext is neither
reused nor replayable.

Every captured message was reassembled from the write characteristic, decrypted
privately through the integration's existing per-device Tuya BLE login/session
derivation, and accepted only after CRC validation. The device returned a
successful response to each exact sender-DPS request before emitting its
corresponding reports. The two Access operations were followed by the observed
DP19 Bluetooth-unlock event and DP47 coupled state. The two Secure operations
were followed by DP46 manual-lock and DP47 uncoupled state reports.

A fresh read-only query of the exact device specification did not list DP6 in
either functions or status. Tuya's current Bluetooth Lock DP Reference explains
that direct app Bluetooth unlock moved from the original DP6 generation to DP71,
but it does not publish the original two-field DP6 layout. The repeated,
product-specific capture is therefore the layout authority for this V1 firmware.
No DP60/DP61 material, DP70/DP71 instruction, member ID, timestamp, ticket,
remote-open key, or device-specific payload field participated in Access.

### Selected runtime contract

- **Lock / secure:** issue exactly one protocol-v3 DP46 Boolean `true` update.
- **Unlock / access:** issue exactly one protocol-v3 DP6 Raw update built from
  the observed two enabled fields.
- **State:** read DP47 only. `false` means physically secure/uncoupled and
  `true` means physically access-enabled/coupled. Missing, non-Boolean, or
  wrongly typed values remain unknown.
- **Open:** unsupported.
- **Auto-Lock:** DP33 remains configuration only.
- **Auto-Lock Delay:** DP36 remains configuration only.
- **Motor State:** DP47 remains a read-only diagnostic entity.

The DP6 value is constructed semantically for each request and passed through
the ordinary Tuya BLE packet builder. It is not stored as captured ciphertext.
The builder supplies a fresh sequence number and IV under the current
device-scoped session key. No new Store, product-wide secret, embedded device
material, or cloud request is required.

The two individual DP6 field names remain undocumented. This uncertainty does
not create an alternative wire length or value: both complete cycles used the
same exact two-field action and the same success/report sequence. The
implementation does not send alternatives or retry a different format.

### Entity migration and automation impact

The existing V1 `button` entity uses the stable unique-ID suffix `manual_lock`.
It migrates to a `lock` entity with the same integration unique ID, exact config
entry ownership, and device association. The migration preserves valid user
name, icon, area, aliases, labels, hidden/disabled state, categories, and valid
lock-target options. It rejects ambiguous, foreign, conflicting-device, or
conflicting-subentry state; verifies the target before removing the old button;
rolls back a newly created target after failure; and is idempotent.

Automations that call the old button service must be updated to call
`lock.lock` or `lock.unlock` on the migrated entity. `lock.open` is not exposed.
The entity ID's domain necessarily changes from `button` to `lock`; a preserved
custom name does not prevent that domain change.

### Privacy handling

The Android bug report and derived BTSnoop are held only in a private local
directory with owner-only permissions. No raw report, Bluetooth address,
device/account identifier, key, complete encrypted frame, or complete decrypted
value is committed, posted, or included in this record. Keys were read into one
private analysis process and never persisted by the decoder. Raw capture
deletion is deferred until protocol, security, and compatibility review are
complete.

### Rejected alternatives after observation

- DP33 remains rejected because changing Auto-Lock changed configuration and
  caused a configuration side effect; it is not a directional motor command.
- DP46 `false` remains rejected because neither app Access cycle used it.
- Writable DP47 remains rejected because every observation used it as device
  state only.
- DP60/DP61 remain rejected because neither valid cycle used them and their
  cloud ownership/lifecycle concerns remain unresolved.
- DP70/DP71, `ble_unlock_check`, `getRemoteOpenKey`, cloud actuation, captured
  ciphertext replay, and command spraying remain rejected because none was
  required by the exact V1 app command.

### Hardware validation plan

The implementation remains hardware-unverified until one exact reviewed feature
head is deployed after a full Home Assistant backup. With the door open, the
owner must verify two complete Lock/Unlock cycles, one motor action per command,
the distinct physical directions and sounds, DP33 configuration-only behavior,
DP47 read-only behavior, restart persistence, registry uniqueness, and one S1
smoke cycle because shared response-status parsing is tightened. The agent must
not operate the lock.

## Status and decision

This record is bound to migration head
`546e2cfe5f245c0bdbbd6d705b4df9b08a990aec` and the sanitized product identity
`ms/7a4xvbtt`.

Runtime implementation is blocked by the protocol safety gate. The current
official Bluetooth lock reference describes a DP60 wire shape, but its DP61
shape is conditional and it does not establish that a locally generated key may be installed by a
direct Bluetooth client or that the gateway-oriented DP61 command is accepted
over the direct Bluetooth transport used by this integration. The same
reference says that the cloud normally provisions and rotates the DP60 key and
that direct Bluetooth unlocking uses DP71 instead of DP61. Implementing the
requested self-provisioning flow would therefore turn an unproven transport and
key-authority assumption into a physical access-control command.

No DP60 or DP61 builder, parser, Store, entity, registry migration, or runtime
write is added by this branch. The existing conservative V1 contract remains
unchanged.

## Current defect and physical meaning

The current V1 action writes `manual_lock` (DP46) as `true` once. On the
reported coupling cylinder, this performs the security action: the external
knob is uncoupled and can no longer drive the cylinder. Repeating the action
does not restore access.

The Tuya app exposes a distinct access action that couples the external knob so
it can drive the cylinder. The two motor directions sound different. This
defect predates the upstream migration and is not a regression in the migration
branch.

Terminology in this record is physical rather than inferred from a Boolean:

- **Lock / secure** means uncouple the external knob.
- **Unlock / access** means couple the external knob.

No hardware action was performed while producing this record.

## Sanitized diagnostic evidence

The supplied diagnostics were not copied into the repository. Only the
following non-secret product facts are retained here:

| Code | Product DP | Type | Contract used in this record |
| --- | ---: | --- | --- |
| `automatic_lock` | 33 | Boolean | Auto-Lock configuration only |
| `auto_lock_time` | 36 | Integer | Auto-Lock delay, 5 to 1800 seconds |
| `manual_lock` | 46 | Boolean | One-way secure action, `true` only |
| `lock_motor_state` | 47 | Boolean | Read-only device status |
| `remote_no_pd_setkey` | 60 | Raw | Candidate remote-key configuration |
| `remote_no_dp_key` | 61 | Raw | Candidate keyed remote action |

The product-specific code-to-DP mapping is authoritative for this device.
Numeric IDs from another Tuya product family are not evidence that the same
numeric ID has the same meaning here.

## Existing implementation and response provenance

The migration branch deliberately keeps V1 out of the generic `LockEntity`
path. It exposes a stateless DP46 `ButtonEntity`, DP33 Auto-Lock, DP36 Auto-Lock
Delay, read-only DP47 Motor State, battery, alarm, last-unlock method, and the
disabled-by-default signal-strength diagnostic.

The transport can distinguish inbound data from local cache mutation:

- inbound parsing marks a datapoint as `received_from_device`;
- `set_value()` clears that marker before sending a local write;
- inbound parsing constructs a fresh callback-list batch and delivers it
  synchronously through the device callbacks;
- the coordinator exposes that batch only while synchronously notifying its
  listeners and clears its `last_updates` reference afterward and at connection
  state boundaries.

The cached datapoint object is a different lifetime. Reconnect and disconnect
do not clear its persistent `received_from_device` marker. A waiter must consume
and copy a matching datapoint from the fresh callback argument itself; it must
never infer freshness by rereading a cached datapoint whose marker survived a
connection boundary.

This is sufficient to reject a locally mutated DP value as confirmation. It is
not sufficient to prove that the product accepts the candidate command or to
establish absolute request causality. The DP60/DP61 response carries a status
and member ID but no request nonce, and the BLE packet acknowledgement is a
different transport-level correlation. A delayed device-originated response
for the same member could therefore arrive after a new request boundary. A safe
future implementation would need a device-scoped monotonic inbound sequence, a
per-device operation lock, exact DP/type checks, and a protocol-supported way
to exclude a stale same-member response.

The existing S1 Store is useful only as an architectural example. S1 stores
device-originated, device-scoped templates and never manufactures missing
security material. V1 self-provisioning would be a different security contract
and must not reuse the S1 data or runtime key.

Home Assistant's Store can be configured with `private=True` and
`atomic_writes=True`, and it serializes physical writes. However, the inspected
Home Assistant 2026.7.4 implementation logs and swallows serialization or write
errors. Awaiting `async_save()` therefore does not provide a hard durable-write
acknowledgement. This is an additional unresolved persistence contract for a
flow that promises readiness only after confirmed device and storage success.

## Public fork and implementation findings

Public V1 implementations provide experimental history, not a protocol
contract:

- The jpmreis fork progressed through writable DP47, DP46, a DP33 workaround,
  a DP33-backed `LockEntity`, inverted DP47 state, and DP33 toggling. Those
  changes document attempts to obtain bidirectional behavior, but they do not
  document a DP60/DP61 provisioning exchange or a successful, independently
  reproducible keyed unlock.
- Upstream PR #185 copied the older V1 mapping into the active upstream. It did
  not add a DP60/DP61 protocol or prove bidirectional V1 hardware behavior.
- `make-all/tuya-local` documents that the eight-digit code is set during
  pairing and says it can later be obtained by observing cloud unlock traffic.
  That is evidence that the key is device-specific; it is not evidence for Home
  Assistant generating and provisioning a replacement key locally.

The reported jpmreis DP33 behavior conflicts with the supplied product metadata,
which identifies DP33 as `automatic_lock`. It remains a rejected workaround.

### Exact jpmreis progression

| Commit | Change or claim | Classification |
| --- | --- | --- |
| [`4a93a1a`](https://github.com/jpmreis/ha_tuya_ble/commit/4a93a1a4930eb13566dba3aeede1c537ab718e87) | First PID mapping, including writable DP47 | Untested mapping reuse; contradicted by status-only product metadata |
| [`2e759a0`](https://github.com/jpmreis/ha_tuya_ble/commit/2e759a08f02021840a3db0482dbbd63ba0ee8c02) | Moves control to DP46 and exposes DP33/36 configuration plus DP47 status | Metadata-derived; its bidirectional DP46 assumption was later abandoned |
| [`9109887`](https://github.com/jpmreis/ha_tuya_ble/commit/9109887373acf687526d4d61e3c6790403acf3a8) | Reports that DP46 only locks and uses DP33 as a toggle workaround | The only direct hardware assertion in the lineage, but no trace/test and incompatible with `automatic_lock` metadata |
| [`fd6a8a5`](https://github.com/jpmreis/ha_tuya_ble/commit/fd6a8a5c5dbda8d4d1f4f7b59576f32315d80324) | Creates a DP33-backed `LockEntity` with DP47 state | Derived from the workaround; initially runtime-broken by unsupported datapoint access |
| [`0c6f8dc`](https://github.com/jpmreis/ha_tuya_ble/commit/0c6f8dc01ddff6f3f232d7395d1dec0e2e47c860) | Repairs the unsupported datapoint access | Confirms the first entity revision was not stable |
| [`dc963c2`](https://github.com/jpmreis/ha_tuya_ble/commit/dc963c274f16d1b7c2e252bdbc617f1e098ef8c7) | Inverts DP47 state and makes both directions toggle DP33 | Cannot select a deterministic physical direction; adds no DP60/61 evidence |
| [`44c4341`](https://github.com/jpmreis/ha_tuya_ble/commit/44c43414a0b24b8a3d743fb58592d97f4d1ada14) | Repairs the same unsupported access in the switch path | Further evidence of experimental rather than validated behavior |

[Upstream issue #130](https://github.com/ha-tuya-ble/ha_tuya_ble/issues/130)
contains an independent report that a manually extended mapping exposed an
unlock action while the device was awake. The exact patch and write were not
published, and the report does not mention DP60, DP61, key provisioning,
payloads, or response correlation. Inferring DP6 from the then-current generic
mapping would also conflict with the supplied product metadata.

[Upstream PR #185](https://github.com/ha-tuya-ble/ha_tuya_ble/pull/185)
merged the earliest mapping concept, not the later DP46/DP33 history. It adds no
DP60/61 protocol and no V1 hardware test. At the pinned upstream baseline it
leaves this PID on a generic writable-DP47 mapping, which the migration branch
intentionally replaces with the safer product-specific contract.

The inspected `make-all/tuya-local` implementation builds a generic 13-byte
DP61 command from a previously supplied code and fixed member ID. It does not
generate or provision DP60 and documents observing cloud/app material as the
historic source of the code. It therefore corroborates one public wire variant
but not the requested self-provisioning design.

GitHub indexed search and inspected fork branches found no distinct
product-specific DP60/61 implementation. A universal claim about every hidden
or unindexed branch is **UNPROVEN**; absence from the inspected public census is
not proof of global absence.

## Official protocol evidence

The primary source is Tuya's current Chinese **Bluetooth Lock DP Reference**,
because it identifies the Bluetooth family and the same standard code names.
The English **Residential Lock DP Reference** describes a related family and is
retained to expose, rather than hide, the conflicts.

| Question | Bluetooth lock reference | Related/general reference | Decision impact |
| --- | --- | --- | --- |
| DP60 request fields | 1-byte validity, 2-byte member ID, 4-byte start, 4-byte end, 2-byte use count, 8 ASCII key bytes; 21 bytes total | Same widths, but a related product assigns the codes to DP48/49 | Candidate shape is product-code based, not numeric-ID based |
| Validity flag | `0x00` invalid, `0x01` valid | The English page says the reverse, while its Chinese counterpart agrees with the Bluetooth page | Bluetooth-specific value is stronger, but the translation conflict must remain visible |
| Member/key ID | The DP tables allocate 2 bytes and show values 1 through 100, while the glossary describes a 1-byte cloud-assigned member ID | Described as not enabled | Zero and a locally selected ID are not defensible; padding and byte order are unproven |
| Timestamps | Unix timestamps; the validity appendix defines 4-byte big-endian integers, but the DP60 row does not expressly link to that appendix | Width only | Big-endian is strongly suggested, not product-specific proof for DP60 |
| Use count | `0x0000` through `0xFFFF`; zero is permanent | Width only | Zero is the documented permanent value in the Bluetooth family |
| DP60 response | 1-byte status plus 2-byte member ID; status 0 success, 1 failure | Same width, but ID described as not enabled | A response can be structurally matched to a nonzero member ID |
| DP61 request fields | 1-byte action, 2-byte member ID, 8 ASCII key bytes, and 2-byte method; 13 bytes normally, with a conditional 1-byte administrator flag only when the panel's electronic-double-lock feature requires it | Related sections vary between 2- and 4-byte method layouts | The sanitized product facts do not establish the conditional panel feature, so no single 13/14-byte Bluetooth shape is selected; sending alternatives is prohibited |
| DP61 response | 1-byte status plus 2-byte member ID; statuses 0 through 6 | Statuses 0 through 5 and an unused ID | Bluetooth status 6 adds electronic-lockout rejection |
| Lock action | DP61 lock is reserved/not used; DP46 is required | Related reference describes both action values | DP46 remains the only lock command |
| Transport | DP61 is remote unlock through a gateway; direct phone-to-lock Bluetooth uses DP71 | Not resolved | Direct-BLE DP61 support is unproven for this integration |
| Key authority | The cloud normally sends DP60 after pairing and controls irregular rotation | The cloud sends and the device stores the key | Arbitrary local self-generation is not specified |
| Key replacement | Cloud-controlled rotation is described | Not resolved | Whether a local write replaces the Tuya app's key or adds another member is unproven |

Official sources:

- [Bluetooth Lock DP Reference](https://developer.tuya.com/cn/docs/iot/ble?id=K9ow3vcpn71ua)
- [Residential Lock DP Reference](https://developer.tuya.com/en/docs/IoT/zigbee-doorlock-dp?id=K9fembhbeab0p)
- [Chinese Residential Lock DP Reference](https://developer.tuya.com/cn/docs/iot/zigbee-doorlock-dp?id=K9fembhbeab0p)
- [Voice Control Services](https://developer.tuya.com/en/docs/iot/doorlock-smart-speaker-skills?id=K9ofxdae61xyz)
- [Remote Unlocking APIs](https://developer.tuya.com/en/docs/cloud/doorlock-api-remoteopen?id=Kbe2nm6j9hcsj)
- [Official Android BLE lock sample](https://github.com/tuya/tuya-home-android-sdk-sample-kotlin/blob/021609b3c374844d9d5c12edebca24de2d940631/homesdk_sample/lock/src/main/java/com/tuya/lock/demo/ble/activity/BleLockDetailActivity.kt#L226-L231)
- [Official BLE Pro panel DP codes](https://github.com/tuya/tuya-panel-demo/blob/88b4de558d65f39d1f545850e5060939aa59a829/examples/smartLockBlePro/src/config/dpCodes.ts#L7-L35)

The cloud API does not close the local gap. It requires a cloud-issued ticket
and access-key-based decryption. No cloud call was made, and no cloud dependency
is proposed.

Static inspection of official `tuya-iot-py-sdk` 0.6.6 and
`tuya-device-sharing-sdk` 0.2.14 found only generic command/path APIs, not a
lock-specific persistent-key, provisioning, or local-BLE unlock API. Their
generic logging paths are also not designed to redact these key/ticket fields.
The inspected public high-level Android Smart Lock API and official sample keep
the direct BLE versus gateway split behind high-level operations and expose no
caller-supplied DP60 key material. This bounded public-API observation is not a
claim that every internal or generic Android SDK surface was exhaustively
proven absent.

## Candidate wire structures, not selected runtime formats

The following layouts are the strongest static candidates. They are recorded
for a future evidence review, not authorized for serialization by this branch.

### DP60 candidate request

| Offset | Width | Meaning |
| ---: | ---: | --- |
| 0 | 1 | Validity flag; Bluetooth reference says `1` means active |
| 1 | 2 | Member ID field; logical cloud-assigned range 1 through 100; wire padding and byte order unresolved |
| 3 | 4 | Valid-from Unix timestamp; big-endian strongly suggested by the validity appendix |
| 7 | 4 | Valid-until Unix timestamp; big-endian strongly suggested by the validity appendix |
| 11 | 2 | Maximum uses; zero means permanent; wire byte order unresolved |
| 13 | 8 | Exactly eight numeric ASCII bytes |

Candidate request length: 21 bytes.

Candidate response: 1-byte status followed by the 2-byte member ID. Only status
zero is success.

### DP61 candidate request

| Offset | Width | Meaning |
| ---: | ---: | --- |
| 0 | 1 | Action; `1` is unlock, while lock is reserved and must use DP46 |
| 1 | 2 | Cloud-assigned member ID; padding and wire byte order unresolved |
| 3 | 8 | Exactly eight numeric ASCII key bytes |
| 11 | 2 | Remote-unlock method; wire byte order unresolved |
| 13 | 1 | Conditional administrator flag, present only for the documented panel feature |

Candidate request length: 13 bytes without the conditional flag or 14 bytes
with it. The sanitized product facts do not establish which layout applies, so
neither length is selected for runtime use.

Candidate response: 1-byte status followed by the 2-byte member ID. The
Bluetooth family documents success, generic failure, an invalid or expired key,
use count exhausted, outside validity, key mismatch, and electronic-lockout
rejection. It does not define a distinct member-ID-mismatch status.

No value is selected for member ownership, method, or administrator authority.
No complete payload is included in this record.

## Rejected control paths

### DP33

DP33 is `automatic_lock` in the product diagnostics. Treating it as a motor
direction would overwrite configuration and repeat an experimental fork
workaround. It remains configuration-only.

### DP46 false

The product advertises `manual_lock` as a Boolean, but the only observed and
preserved action is `true`. There is no product-specific evidence that `false`
couples the knob. The current button sends `true` exactly once and does not
toggle.

### Writable DP47

DP47 is device status. A related reference may label the generic code send and
report, but this product supplies it as status and the migration intentionally
exposes it read-only. Writing a cached state would not prove physical movement.

### DP71 and captured templates

The official Bluetooth family uses DP71 for direct Bluetooth unlock, but its
current format is bound to host/sub-device IDs and a cloud-provided random
value. This product has not advertised the needed writable DP71 contract in the
sanitized facts. Reusing S1 templates, capturing an app payload, or inventing
those fields is prohibited.

## Remaining protocol ambiguity and smallest missing evidence

Runtime work remains blocked until public, product-applicable evidence answers
all of the following without a live trace or secret:

1. Does firmware for `ms/7a4xvbtt` accept DP60 from a direct Bluetooth client,
   rather than only through the cloud/gateway provisioning path?
2. May that client choose a new random key, or must the key and member identity
   be cloud-issued?
3. Which member ID is owned by the local Home Assistant record, and how can it
   avoid replacing or impersonating the Tuya app's member?
4. Does a successful DP60 write add a member, replace one member, or replace the
   single remote key?
5. Does this firmware accept the candidate DP61 gateway command over the direct
   Bluetooth transport used by the integration?
6. Does this product enable the panel feature that adds the conditional DP61
   administrator byte, making its payload 14 rather than 13 bytes?
7. Which DP61 method and administrator flag truthfully identify a local Home
   Assistant operation?
8. Is the device's reported DP60/DP61 member ID sufficient correlation when the
   cloud or app can rotate the key concurrently?
9. How can a delayed device-originated response for the same member be rejected
   when the response contains no request nonce and the transport acknowledgement
   does not correlate the later datapoint report?
10. How can Home Assistant assert durable persistence when its Store API logs
    and swallows a serialization or filesystem write failure?

An official product-family statement, public firmware/MCU contract tied to the
same standard-code generation, or a public implementation with documented
self-provisioning and direct-BLE success could satisfy this gap. Additional
user hardware data is neither requested nor required by this branch.

## Security model for a future implementation

If the missing evidence becomes available, the implementation must:

- generate exactly eight numeric ASCII digits with Python's `secrets` module;
- keep candidate material in memory until a new device-originated DP60 success;
- bind every record to the exact configured Tuya Device ID, category, product
  ID, member ID, validity, and format version;
- serialize provisioning and motor commands per device;
- accept only a response from a callback batch after the request boundary with
  the expected DP, Raw type, length, status, and member ID;
- preserve the previous confirmed record until replacement succeeds;
- make missing, malformed, conflicting, expired, or foreign records produce
  zero BLE writes;
- exclude keys and full payloads from `repr`, logs, diagnostics, entity state,
  attributes, exceptions, and translations;
- use Home Assistant Store with `private=True` and `atomic_writes=True`, while
  resolving its lack of a durable-write success signal;
- send one reviewed wire format once, with no retries, probing, spraying, or
  fallback formats.

Home Assistant Store is not a hardware-backed secret vault. Any future record
would require the same operational protection as other Tuya local credentials.

## Deferred provisioning and persistence lifecycle

The intended lifecycle is explicit, never automatic:

1. A disabled-by-default configuration button starts provisioning.
2. A per-device lock excludes every concurrent provisioning or motor command.
3. The code revalidates the exact product and writable Raw code mappings.
4. It generates an in-memory candidate and sends one DP60 request.
5. It waits for a new, matching, device-originated result.
6. It atomically persists the candidate only after confirmed success.
7. It clears temporary candidate material in `finally`.

Setup, restart, reconnect, and upgrade must never provision. Failed rotation
must keep the last confirmed record. The proposed Store identity is version 1,
key `tuya_ble_v1_remote_unlock_keys`, with serialized access and records keyed
by exact configured device ID.

This lifecycle is a design only; it is not implemented while key authority and
transport support are unresolved.

## Deferred entity and registry design

After the protocol gate is satisfied, the one-way V1 button may be replaced by
a product-specific `LockEntity` that preserves the `manual_lock` unique-ID
suffix. DP47 `false` would mean secure/uncoupled and DP47 `true` would mean
access/coupled, subject to product-specific confirmation. Lock would send DP46
`true` once. Unlock would require a valid same-device record and send DP61 once.
Open would remain unsupported.

The registry migration must be scoped to the current config entry and exact
`ms/7a4xvbtt` product. It must select only the existing button-domain
`manual_lock` entry, preserve collision-free object ID and user
customizations, validate config-entry/device/subentry ownership, create or
reuse the lock target, verify it, and remove the button only afterward. A newly
created target must be removed on failure. Ambiguity must stop setup before
platform forwarding. The domain would change from `button.<object_id>` to
`lock.<object_id>`, so automations could require an update.

No registry migration is implemented before a secure unlock path exists. S1
entity IDs and registry behavior remain unchanged.

## Existing V1 entities retained

The following behavior remains unchanged:

- DP33 Auto-Lock configuration switch;
- DP36 Auto-Lock Delay, 5 to 1800 seconds;
- DP47 read-only Motor State diagnostic;
- DP8 Battery;
- DP21 Alarm;
- product-specific Last Unlock Method;
- disabled-by-default Signal Strength;
- one-way DP46 `true` Lock button.

No speculative DP31, door-state, authentication-mode, sound, LED, password,
DP6, DP70/DP71, or DP33 motor entity is added.

## Tuya app interaction risk

The official Bluetooth reference says the cloud controls DP60 provisioning and
rotates the remote key. A locally selected member ID or key could replace the
app's key, collide with a cloud member, be overwritten later, or cause the
device and cloud to disagree. The available static evidence does not determine
whether DP60 adds or replaces credentials. This risk is a blocker, not merely a
future test note.

## Rollback plan

This branch changes documentation only, so rollback is removal of this design
record. The current one-way V1 behavior remains available.

For a future runtime implementation, rollback must restore the reviewed
migration behavior, remove the new entities and runtime use of the Store, and
leave any last confirmed on-device key untouched unless an independently
specified revocation protocol exists. Deleting a Home Assistant record does not
prove that device-side or cloud-side key material was revoked.

## Future hardware checklist (not executed)

1. Create a full Home Assistant backup.
2. Keep the door open and an alternate authorized access method available.
3. Record the exact tested commit.
4. Confirm V1 initially reports not initialized.
5. Confirm Unlock before provisioning makes zero physical action and returns a
   clear error.
6. Enable the disabled-by-default Provision Local Unlock entity.
7. Press it exactly once and confirm one attempt and READY status.
8. Do not share the generated key.
9. Test Lock once; confirm one DP46 action and an uncoupled knob.
10. Test Unlock once; confirm one DP61 action and a coupled knob.
11. Confirm the distinct expected motor sounds.
12. Confirm DP33 still changes only Auto-Lock and DP47 remains read-only.
13. Restart Home Assistant and confirm readiness persists.
14. Repeat one Lock and one Unlock.
15. Confirm there are no duplicate entities or reauthentication prompts.
16. Confirm sanitized logs contain no key or complete payload.
17. In a separate later test where the Home Assistant BLE connection can be
    safely disabled, check whether Tuya app remote control still works.
18. Record any Tuya app impact as a known limitation.

This checklist must not be executed until the static protocol blocker is
resolved and a separate action is authorized.

## Explicit non-claims

No Home Assistant instance, Tuya account, cloud endpoint, Tuya app, or physical
lock was accessed or operated. No key was generated or provisioned. No device
payload was sent. No deployment, restart, merge, release, tag, rebase, amend,
or force-push occurred. This record makes no hardware-success claim.
