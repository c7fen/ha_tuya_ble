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
