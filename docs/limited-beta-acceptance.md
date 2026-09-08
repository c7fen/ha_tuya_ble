# Owner-approved limited beta acceptance

## Decision and exact references

R66S explicitly accepts the following bounded practical functional evidence
for preparation of beta 0.10.0b2, not for stable promotion or full hardware
acceptance. The original repetition and follow-up gates are deferred for this
beta only; technical correctness, safety/privacy, review, dependency and CI
conditions remain required. Final publication still needs concrete owner
approval. Issue [#37](https://github.com/c7fen/ha_tuya_ble/issues/37) remains open.

| Reference | Commit | Tree |
| --- | --- | --- |
| Development base | `8e301184be31d896580e51e9c643b2ce93942b0b` | `cfab7ec7fc2a2f772f8caab3b4b1afcee8b28de3` |
| PR41 product base | `4f73a9b008dcb89134bc41001c486f06d6056867` | `463ed8553da01eae591de611e76e45392ad9e7bf` |
| PR47 tested runtime | `7cfcf9598941de253a24b7c30b06170a98b4ba86` | `f289523beedb1abe38b28221b1880fa4dec2a7b9` |
| PR46 observer, not packaged | `57357f7ca8c78d82c8b259faa5f05a6bba8c3693` | `cb64ca8ec9222364475b2c19a239cf72187fb40f` |

## Retained R66R evidence (not a new live measurement)

One selected S1, On Demand, test hold 105 seconds:

- R01-COLD: owner press and request observed; NEW_SESSION; Device Info 1,
  Pair 1, Device Status 1, datapoint writes 0, other 2. Both extra messages
  were matched automatic responses: FUN_RECEIVE_DP and FUN_RECEIVE_TIME1_REQ.
  DP69 (DT_RAW, encoded length 3) completed the protocol; retained confirmation
  was not applicable, so no new battery/configuration confirmation is claimed.
- R01-RETAINED: owner press and request observed; REUSED_SESSION; Device Info 0,
  Pair 0, Device Status 1, datapoint writes 0, other 0. DP metadata covered
  8/28/31/33/34/36/47/89/90; current-session confirmation of 8/33/34/36 was valid.
- Actual private-target comparison passed for both trials and release.
  Cold collection to retained ARM took 0.757 seconds.
- Normal release observed, no automatic reconnect observed.
- The owner reported no motor movement, mechanical change or unexpected lock
  action for the two presses. This is owner evidence, not inferred from DP47.

R02-COLD remains separate: the owner reported another press, but no event or
request was observed during the completed 60-second window. The immutable
observer result is OWNER_PRESS_NOT_OBSERVED, with ambiguous=false for result
delivery and all packet counts zero. Association of the reported physical
press is unproven; its product outcome remains unassessed/ambiguous, neither a
further PASS nor a demonstrated product defect. No physical observation was
recorded for that press. No historical flags or outcomes are rewritten.

The stored completion records exact PR41 restoration (37/37, no missing,
extra or changed files, matching manifest), backup NONE, healthy loaded Core,
Refresh runtime inactive, valid Repairs 0/0, full restore proof and
COMPLETE_NORMAL. The owner confirmed hold restoration from 105 to the original
15 seconds. These are retained reported results, not current HA measurements.
Original R66R and R66Q2 reports, including R66Q2's earlier COLD-PASS, are preserved.

## Explicit limits

- The 10-COLD/5-RETAINED/10-release matrix was not completed.
- The separate owner-operated Lock/Unlock follow-up was not executed.
- There is no complete retained-pair hardware proof at the default 15 seconds.
- No long-term, battery, success-rate, other-device or stable claim follows.
- R66O historical failures are not retrospectively converted to passes.

R66S performs no Home Assistant, Supervisor, BLE or physical operation. The
release candidate must preserve every tested runtime file byte-for-byte except
the individually disclosed manifest version. No tooling/research dependency is
inferred from PR numbers. A release merge/tag is a new metadata/history object,
not itself the object that was physically tested.
