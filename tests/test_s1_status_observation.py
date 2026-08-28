"""Behavioral contracts for the Phase-A S1 status observation gap."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from bleak.backends.device import BLEDevice

from custom_components.tuya_ble.const import ConnectionMode
from custom_components.tuya_ble.tuya_ble.const import TuyaBLECode
from custom_components.tuya_ble.tuya_ble.exceptions import TuyaBLEDeviceError
from custom_components.tuya_ble.tuya_ble.tuya_ble import (
    ConnectionSessionToken,
    TuyaBLEDataPointType,
    TuyaBLEDevice,
)


class _SyntheticClient:
    is_connected = True


def _device(
    *, mode: ConnectionMode = ConnectionMode.ON_DEMAND
) -> tuple[TuyaBLEDevice, ConnectionSessionToken]:
    device = TuyaBLEDevice(
        Mock(),
        BLEDevice("synthetic-s1", "00:00:00:00:00:37", {}),
        connection_mode=mode.value,
    )
    device._device_info = SimpleNamespace(category="jtmspro", product_id="xqeob8h6")
    client = _SyntheticClient()
    token = ConnectionSessionToken(client, 1)
    device._client = client
    device._connection_token = token
    device._connection_epoch = token.epoch
    device._notifications_active = True
    device._is_paired = True
    device._schedule_idle_disconnect_locked = Mock()
    return device, token


def _install_status_response_transport(
    device: TuyaBLEDevice,
    token: ConnectionSessionToken,
) -> AsyncMock:
    """Answer each synthetic status write with its matching status response."""
    device._build_packets = Mock(return_value=[b"synthetic-status-request"])
    status_calls: list[TuyaBLECode] = []

    async def respond(
        session_token: ConnectionSessionToken, _: list[bytes], **__: object
    ) -> None:
        assert session_token is token
        response_key = next(iter(device._input_expected_responses))
        status_calls.append(TuyaBLECode.FUN_SENDER_DEVICE_STATUS)
        device._handle_command_or_response(
            1,
            response_key[1],
            TuyaBLECode.FUN_SENDER_DEVICE_STATUS,
            b"\x00",
            session_token=token,
        )

    transport = AsyncMock(side_effect=respond)
    device._int_send_packet_while_connected = transport
    transport.status_calls = status_calls
    return transport


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


async def test_explicit_status_waiter_rejects_wrong_response_code() -> None:
    """A matching sequence alone must not complete the public update request."""
    device, token = _device()
    events = []
    device.register_status_observer(events.append)
    device._build_packets = Mock(return_value=[b"synthetic-status-request"])

    async def respond_with_wrong_then_correct(
        session_token: ConnectionSessionToken, _: list[bytes], **__: object
    ) -> None:
        assert session_token is token
        response_key, future = next(iter(device._input_expected_responses.items()))
        device._handle_command_or_response(
            1,
            response_key[1],
            TuyaBLECode.FUN_SENDER_DPS,
            b"\x00",
            session_token=token,
        )
        assert future.done() is False
        assert not [event for event in events if event.kind == "ACK_SUCCESS"]
        device._handle_command_or_response(
            2,
            response_key[1],
            TuyaBLECode.FUN_SENDER_DEVICE_STATUS,
            b"\x00",
            session_token=token,
        )

    device._int_send_packet_while_connected = AsyncMock(
        side_effect=respond_with_wrong_then_correct
    )

    await device.update()

    assert [event.kind for event in events] == [
        "REQUEST_CREATED",
        "REQUEST_HANDED_TO_TRANSPORT",
        "ACK_SUCCESS",
    ]


async def test_automatic_status_waiter_rejects_wrong_response_code() -> None:
    """The once-per-session automatic request has the same response contract."""
    device, token = _device(mode=ConnectionMode.ALWAYS_CONNECTED)
    events = []
    device.register_status_observer(events.append)
    device._build_packets = Mock(return_value=[b"synthetic-status-request"])

    async def respond_with_wrong_then_correct(
        session_token: ConnectionSessionToken, _: list[bytes], **__: object
    ) -> None:
        assert session_token is token
        response_key, future = next(iter(device._input_expected_responses.items()))
        device._handle_command_or_response(
            1,
            response_key[1],
            TuyaBLECode.FUN_SENDER_DPS,
            b"\x00",
            session_token=token,
        )
        assert future.done() is False
        assert not [event for event in events if event.kind == "ACK_SUCCESS"]
        device._handle_command_or_response(
            2,
            response_key[1],
            TuyaBLECode.FUN_SENDER_DEVICE_STATUS,
            b"\x00",
            session_token=token,
        )

    device._int_send_packet_while_connected = AsyncMock(
        side_effect=respond_with_wrong_then_correct
    )

    assert await device._request_status_while_connected(token) is True
    assert device._status_attempted_token is token
    assert [event.kind for event in events] == [
        "REQUEST_CREATED",
        "REQUEST_HANDED_TO_TRANSPORT",
        "ACK_SUCCESS",
    ]


async def test_overlapping_explicit_status_terminal_events_keep_request_owner() -> None:
    """A superseded request still owns its later transport terminal outcome."""
    device, token = _device()
    events = []
    writes_started = 0
    both_writes_started = asyncio.Event()
    device.register_status_observer(events.append)
    device._build_packets = Mock(return_value=[b"synthetic-status-request"])

    async def hold_response_waits(
        session_token: ConnectionSessionToken, _: list[bytes], **__: object
    ) -> None:
        nonlocal writes_started
        assert session_token is token
        writes_started += 1
        if writes_started == 2:
            both_writes_started.set()

    device._int_send_packet_while_connected = AsyncMock(side_effect=hold_response_waits)
    request_a = asyncio.create_task(device.update())
    request_b = asyncio.create_task(device.update())
    await both_writes_started.wait()

    response_keys = sorted(device._input_expected_responses, key=lambda key: key[1])
    assert [key[1] for key in response_keys] == [1, 2]
    device._input_expected_responses[response_keys[0]].set_exception(
        TuyaBLEDeviceError(1)
    )
    await asyncio.sleep(0)
    device._handle_command_or_response(
        2,
        response_keys[1][1],
        TuyaBLECode.FUN_SENDER_DEVICE_STATUS,
        b"\x00",
        session_token=token,
    )

    with pytest.raises(TuyaBLEDeviceError):
        await request_a
    await request_b

    terminal_events = [
        event for event in events if event.kind in {"ACK_SUCCESS", "ACK_FAILURE"}
    ]
    assert [(event.observation_ordinal, event.kind) for event in terminal_events] == [
        (1, "ACK_FAILURE"),
        (2, "ACK_SUCCESS"),
    ]
    assert [event.batch_ordinal for event in terminal_events] == [None, None]


async def test_automatic_marker_survives_real_explicit_update_without_extra_request() -> (
    None
):
    """Automatic/explicit interaction never resets the automatic request marker."""
    device, token = _device(mode=ConnectionMode.ALWAYS_CONNECTED)
    transport = _install_status_response_transport(device, token)

    assert await device._request_status_while_connected(token) is True
    assert device._status_attempted_token is token
    await device.update()
    assert await device._request_status_while_connected(token) is False

    assert transport.await_count == 2
    assert transport.status_calls == [
        TuyaBLECode.FUN_SENDER_DEVICE_STATUS,
        TuyaBLECode.FUN_SENDER_DEVICE_STATUS,
    ]
    assert device._status_attempted_token is token


async def test_real_status_paths_add_no_observation_transport_traffic() -> None:
    """One explicit and one automatic path each write exactly one status request."""
    explicit_device, explicit_token = _device()
    explicit_transport = _install_status_response_transport(
        explicit_device, explicit_token
    )
    await explicit_device.update()

    automatic_device, automatic_token = _device(mode=ConnectionMode.ALWAYS_CONNECTED)
    automatic_transport = _install_status_response_transport(
        automatic_device, automatic_token
    )
    assert await automatic_device._request_status_while_connected(automatic_token)
    assert (
        await automatic_device._request_status_while_connected(automatic_token)
    ) is False

    assert explicit_transport.await_count == 1
    assert explicit_transport.status_calls == [TuyaBLECode.FUN_SENDER_DEVICE_STATUS]
    assert automatic_transport.await_count == 1
    assert automatic_transport.status_calls == [TuyaBLECode.FUN_SENDER_DEVICE_STATUS]
