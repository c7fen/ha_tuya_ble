"""Behavioral contracts for the Phase-A S1 status observation gap."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

from bleak.backends.device import BLEDevice

from custom_components.tuya_ble.const import ConnectionMode
from custom_components.tuya_ble.tuya_ble.tuya_ble import (
    ConnectionSessionToken,
    TuyaBLEDataPointType,
    TuyaBLEDevice,
)


class _SyntheticClient:
    is_connected = True


def _device() -> tuple[TuyaBLEDevice, ConnectionSessionToken]:
    device = TuyaBLEDevice(
        Mock(),
        BLEDevice("synthetic-s1", "00:00:00:00:00:37", {}),
        connection_mode=ConnectionMode.ON_DEMAND.value,
    )
    device._device_info = SimpleNamespace(category="jtmspro", product_id="xqeob8h6")
    client = _SyntheticClient()
    token = ConnectionSessionToken(client, 1)
    device._client = client
    device._connection_token = token
    device._connection_epoch = token.epoch
    device._notifications_active = True
    device._is_paired = True
    return device, token


def test_status_request_has_private_exact_session_observation_generation():
    device, token = _device()
    events = []
    device.register_status_observer(events.append)

    generation = device._start_status_observation(token, "explicit", 7)

    assert generation.ordinal == 1
    assert generation.origin == "explicit"
    assert generation.session_token is token
    assert [event.kind for event in events] == ["REQUEST_CREATED"]
    assert events[0].observation_ordinal == 1
    assert "00:00:00:00:00:37" not in repr(events[0])


def test_one_inbound_message_is_one_metadata_only_dp_batch():
    device, token = _device()
    events = []
    device.register_status_observer(events.append)
    device._start_status_observation(token, "explicit", 7)

    # id, type, encoded length, value; the value is a distinctive forbidden
    # sentinel and must never occur in observation metadata.
    data = bytes((8, TuyaBLEDataPointType.DT_VALUE.value, 2, 0x7A, 0xC3))
    device._parse_datapoints_v3(token, 1.0, 0, data, 0)

    batch = events[-1]
    assert batch.kind == "DP_BATCH"
    assert batch.batch_ordinal == 1
    assert batch.dp_ids == (8,)
    assert batch.dp_types == (TuyaBLEDataPointType.DT_VALUE.name,)
    assert batch.encoded_value_lengths == (2,)
    assert batch.exact_session is True
    assert "7ac3" not in repr(batch).lower()


def test_separate_inbound_messages_have_separate_batches():
    device, token = _device()
    events = []
    device.register_status_observer(events.append)
    device._start_status_observation(token, "explicit", 7)

    for dp_id in (8, 34):
        data = bytes((dp_id, TuyaBLEDataPointType.DT_VALUE.value, 1, 1))
        device._parse_datapoints_v3(token, 1.0, 0, data, 0)

    batches = [event for event in events if event.kind == "DP_BATCH"]
    assert [(event.batch_ordinal, event.dp_ids) for event in batches] == [
        (1, (8,)),
        (2, (34,)),
    ]


def test_observation_exposes_chronology_not_device_status_causality():
    device, token = _device()
    events = []
    device.register_status_observer(events.append)
    device._start_status_observation(token, "explicit", 7)
    device._parse_datapoints_v3(
        token,
        1.0,
        0,
        bytes((8, TuyaBLEDataPointType.DT_VALUE.value, 1, 1)),
        0,
    )

    batch = events[-1]
    assert batch.kind == "DP_BATCH"
    assert batch.ack_phase in {"before_ack", "after_ack"}
    assert batch.ack_result is None
    assert "response" not in batch.kind.lower()
    assert "caus" not in repr(batch).lower()


def test_active_generation_rejects_structurally_valid_old_session_batch():
    device, active_session = _device()
    old_session = ConnectionSessionToken(_SyntheticClient(), 0)
    events = []
    device.register_status_observer(events.append)
    device._start_status_observation(active_session, "explicit", 7)

    # Seed the active generation and its Issue-36 confirmation state so the
    # stale batch cannot be mistaken for an unknown or otherwise invalid DP.
    data = bytes((8, TuyaBLEDataPointType.DT_VALUE.value, 1, 42))
    device._parse_datapoints_v3(active_session, 1.0, 0, data, 0)
    before_events = list(events)
    before_confirmation = device.last_confirmed_s1_state.get(8)
    assert before_confirmation is not None

    # This is a valid DP batch, but its exact session owner is retired/old.
    stale_data = bytes((8, TuyaBLEDataPointType.DT_VALUE.value, 1, 99))
    device._parse_datapoints_v3(old_session, 2.0, 0, stale_data, 0)

    assert events == before_events
    assert device._status_observation is not None
    assert device._status_observation.session_token is active_session
    assert device._status_observation.batch_ordinal == 1
    assert device.last_confirmed_s1_state.get(8) == before_confirmation


def test_retained_second_request_supersedes_only_the_previous_generation():
    device, token = _device()
    events = []
    device.register_status_observer(events.append)

    first = device._start_status_observation(token, "explicit", 7)
    second = device._start_status_observation(token, "explicit", 8)

    assert first.ordinal == 1
    assert second.ordinal == 2
    assert [event.kind for event in events] == [
        "REQUEST_CREATED",
        "OBSERVATION_SUPERSEDED",
        "OBSERVATION_ENDED",
        "REQUEST_CREATED",
    ]
    assert device._status_attempted_token is None


def test_session_invalidation_ends_generation_and_stale_batch_is_ignored():
    device, token = _device()
    events = []
    device.register_status_observer(events.append)
    device._start_status_observation(token, "explicit", 7)

    device._invalidate_session_data(token)
    device._parse_datapoints_v3(
        token,
        1.0,
        0,
        bytes((8, TuyaBLEDataPointType.DT_VALUE.value, 1, 1)),
        0,
    )

    assert [event.kind for event in events] == [
        "REQUEST_CREATED",
        "SESSION_INVALIDATED",
        "OBSERVATION_ENDED",
    ]
    assert device._status_observation is None
