"""Safety contracts for V1 / Lock P1 bidirectional coupling control."""

from __future__ import annotations

import asyncio
import base64
import logging
from unittest.mock import AsyncMock, Mock, patch

import pytest
from bleak.backends.device import BLEDevice
from bleak.exc import BleakDBusError, BleakError
from homeassistant.components.lock import LockEntityFeature
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ServiceValidationError

from custom_components.tuya_ble.devices import (
    TuyaBLECoordinator,
    TuyaBLEProductInfo,
)
from custom_components.tuya_ble.lock import (
    V1_ACCESS_FIELD_COUNT,
    V1_COMMAND_ERROR_TRANSLATION_KEY,
    V1_DP_ACCESS,
    V1_DP_LOCK,
    V1_DP_MOTOR_STATE,
    TuyaBLEV1Lock,
    _build_v1_access_value,
)
from custom_components.tuya_ble.tuya_ble import (
    TuyaBLEDataPointType,
    TuyaBLEDevice,
)
from custom_components.tuya_ble.const import (
    UNEXPECTED_RECONNECT_MIN_SECONDS,
    ConnectionPolicyState,
)
from custom_components.tuya_ble.tuya_ble.const import TuyaBLECode
from custom_components.tuya_ble.tuya_ble.exceptions import (
    TuyaBLECommandUnconfirmedError,
    TuyaBLEDataFormatError,
    TuyaBLEDataLengthError,
    TuyaBLEDeviceError,
)
from custom_components.tuya_ble.tuya_ble.manager import TuyaBLEDeviceCredentials
from custom_components.tuya_ble.tuya_ble.security import TuyaBLESecurityMaterial
from custom_components.tuya_ble.tuya_ble.tuya_ble import ConnectionSessionToken

SYNTHETIC_DEVICE_ID = "synthetic-v1-device"
SYNTHETIC_ADDRESS = "00:00:00:00:00:02"


def _make_device() -> TuyaBLEDevice:
    ble_device = BLEDevice(
        name="Synthetic V1",
        address=SYNTHETIC_ADDRESS,
        details={},
        rssi=-50,
    )
    device = TuyaBLEDevice(Mock(), ble_device)
    device._device_info = TuyaBLEDeviceCredentials(
        uuid="synthetic-v1-uuid",
        local_key="synthetic-key-02",
        device_id=SYNTHETIC_DEVICE_ID,
        category="ms",
        product_id="7a4xvbtt",
        device_name="Synthetic V1",
        product_model="SYNTHETIC",
        product_name="Synthetic V1",
        functions=[],
        status_range=[],
    )
    device._protocol_version = 3
    device._ensure_connected = AsyncMock()
    device._send_datapoints = AsyncMock()
    device._send_datapoints_once = AsyncMock()
    return device


def _install_synthetic_session(
    device: TuyaBLEDevice, client: Mock | None = None
) -> ConnectionSessionToken:
    """Install one exact synthetic V1 session for transport-focused tests."""
    if client is None:
        client = Mock(is_connected=True)
    token = device._claim_connection_session(client)
    device._is_paired = True
    device._notifications_active = True
    device._connected_notified_token = token
    return token


def _make_entity(hass: HomeAssistant) -> tuple[TuyaBLEV1Lock, TuyaBLEDevice]:
    device = _make_device()
    entity = TuyaBLEV1Lock(
        hass,
        TuyaBLECoordinator(hass, device),
        device,
        TuyaBLEProductInfo("V1 Smart Lock"),
    )
    entity.async_write_ha_state = Mock()
    return entity, device


def test_v1_access_builder_has_exact_protocol_v3_structure() -> None:
    """The observed access action has one exact DP/type/length/field layout."""
    device = _make_device()
    access_value = _build_v1_access_value()
    access = device.datapoints.get_or_create(
        V1_DP_ACCESS, TuyaBLEDataPointType.DT_RAW, access_value
    )

    encoded = device._encode_datapoints([access.id], 1)

    assert len(access_value) == V1_ACCESS_FIELD_COUNT
    assert all(field == int(True) for field in access_value)
    assert len(encoded) == 3 + V1_ACCESS_FIELD_COUNT
    assert encoded[0] == V1_DP_ACCESS
    assert encoded[1] == TuyaBLEDataPointType.DT_RAW.value
    assert encoded[2] == V1_ACCESS_FIELD_COUNT
    assert encoded[3:] == access_value


def test_v1_access_packets_use_fresh_iv_without_payload_replay() -> None:
    """Repeated semantic actions retain structure but rebuild session ciphertext."""
    device = _make_device()
    access_value = _build_v1_access_value()
    device.datapoints.get_or_create(
        V1_DP_ACCESS, TuyaBLEDataPointType.DT_RAW, access_value
    )
    data = device._encode_datapoints([V1_DP_ACCESS], 1)
    device._protocol_version = 3
    device._security_material = TuyaBLESecurityMaterial("synthetic-key-02")
    device._session_key = bytes(range(16))

    with patch(
        "custom_components.tuya_ble.tuya_ble.tuya_ble.secrets.token_bytes",
        side_effect=(bytes([17]) * 16, bytes([34]) * 16),
    ) as random_bytes:
        first = device._build_packets(1, TuyaBLECode.FUN_SENDER_DPS, data)
        second = device._build_packets(2, TuyaBLECode.FUN_SENDER_DPS, data)

    assert random_bytes.call_count == 2
    assert [len(fragment) for fragment in first] == [20, 20, 14]
    assert [len(fragment) for fragment in second] == [20, 20, 14]
    assert first != second


async def test_v1_lock_and_unlock_each_write_one_evidenced_datapoint(
    hass: HomeAssistant,
) -> None:
    """Secure and Access cannot toggle, spray, or write configuration/state DPs."""
    entity, device = _make_entity(hass)
    writes: list[tuple[int, TuyaBLEDataPointType, object]] = []

    async def record_send(datapoint_ids: list[int]) -> None:
        assert len(datapoint_ids) == 1
        datapoint = device.datapoints[datapoint_ids[0]]
        writes.append((datapoint.id, datapoint.type, datapoint.value))

    device._send_datapoints_once.side_effect = record_send

    await entity.async_lock()
    await entity.async_unlock()

    assert writes[0] == (V1_DP_LOCK, TuyaBLEDataPointType.DT_BOOL, True)
    assert writes[1][0:2] == (V1_DP_ACCESS, TuyaBLEDataPointType.DT_RAW)
    assert isinstance(writes[1][2], bytes)
    assert len(writes[1][2]) == V1_ACCESS_FIELD_COUNT
    assert all(field == int(True) for field in writes[1][2])
    assert [write[0] for write in writes] == [V1_DP_LOCK, V1_DP_ACCESS]
    assert device._send_datapoints_once.await_count == 2
    device._send_datapoints.assert_not_awaited()
    assert 33 not in device.datapoints.__dict__()
    assert V1_DP_MOTOR_STATE not in device.datapoints.__dict__()
    assert entity.supported_features == LockEntityFeature(0)
    assert entity.entity_description.key == "manual_lock"
    assert entity.entity_description.translation_key == "lock"
    assert entity.unique_id == f"{SYNTHETIC_DEVICE_ID}-manual_lock"
    assert entity.is_locking is False
    assert entity.is_unlocking is False


@pytest.mark.parametrize(
    ("operation", "dp_id"),
    (("lock", V1_DP_LOCK), ("unlock", V1_DP_ACCESS)),
)
async def test_v1_cold_start_negotiates_protocol_before_one_command(
    hass: HomeAssistant,
    operation: str,
    dp_id: int,
) -> None:
    """A cold-start lease completes Device-Info negotiation before V1 validation."""
    entity, device = _make_entity(hass)
    device._protocol_version = 2

    async def negotiate_v3() -> None:
        device._protocol_version = 3

    device._ensure_connected.side_effect = negotiate_v3
    writes: list[int] = []

    async def record_command(datapoint_ids: list[int]) -> None:
        writes.extend(datapoint_ids)

    device._send_datapoints_once.side_effect = record_command

    await getattr(entity, f"async_{operation}")()

    assert device._ensure_connected.await_count == 1
    assert writes == [dp_id]
    assert device._send_datapoints_once.await_count == 1


@pytest.mark.parametrize(
    ("operation", "dp_id"),
    (("lock", V1_DP_LOCK), ("unlock", V1_DP_ACCESS)),
)
async def test_v1_cold_start_non_v3_performs_zero_command_writes(
    hass: HomeAssistant,
    operation: str,
    dp_id: int,
) -> None:
    """A non-v3 negotiated session fails after connection without a V1 command."""
    entity, device = _make_entity(hass)
    device._protocol_version = 2

    with pytest.raises(ServiceValidationError) as raised:
        await getattr(entity, f"async_{operation}")()

    assert device._ensure_connected.await_count == 1
    device._send_datapoints_once.assert_not_awaited()
    assert device.datapoints[dp_id] is None
    assert raised.value.translation_key == V1_COMMAND_ERROR_TRANSLATION_KEY


@pytest.mark.parametrize(
    ("value", "dp_type", "expected"),
    (
        (False, TuyaBLEDataPointType.DT_BOOL, True),
        (True, TuyaBLEDataPointType.DT_BOOL, False),
        (0, TuyaBLEDataPointType.DT_BOOL, None),
        (None, TuyaBLEDataPointType.DT_BOOL, None),
        (False, TuyaBLEDataPointType.DT_RAW, None),
    ),
)
async def test_v1_state_uses_only_boolean_device_motor_state(
    hass: HomeAssistant,
    value: object,
    dp_type: TuyaBLEDataPointType,
    expected: bool | None,
) -> None:
    """Only read-only DP47 Boolean state determines the physical lock state."""
    entity, device = _make_entity(hass)
    token = _install_synthetic_session(device)
    device.datapoints._update_from_device(
        V1_DP_MOTOR_STATE, 1.0, 0, dp_type, value, token
    )

    assert entity.is_locked is expected
    device._send_datapoints.assert_not_awaited()
    device._send_datapoints_once.assert_not_awaited()


async def test_v1_motor_state_requires_its_replacement_session_dp47(
    hass: HomeAssistant,
) -> None:
    """An unrelated replacement datapoint cannot refresh cached V1 DP47."""
    entity, device = _make_entity(hass)
    old_client = Mock(is_connected=True)
    old_token = _install_synthetic_session(device, old_client)
    device.datapoints._update_from_device(
        V1_DP_MOTOR_STATE,
        1.0,
        0,
        TuyaBLEDataPointType.DT_BOOL,
        True,
        old_token,
    )
    assert entity.is_locked is False

    old_client.is_connected = False
    replacement_token = _install_synthetic_session(device, Mock(is_connected=True))
    device.datapoints._update_from_device(
        8,
        2.0,
        0,
        TuyaBLEDataPointType.DT_VALUE,
        74,
        replacement_token,
    )
    assert entity.is_locked is None

    device.datapoints._update_from_device(
        V1_DP_MOTOR_STATE,
        3.0,
        0,
        TuyaBLEDataPointType.DT_BOOL,
        False,
        replacement_token,
    )
    assert entity.is_locked is True
    entity._coordinator.shutdown()


@pytest.mark.parametrize(
    ("operation", "dp_id", "conflicting_type", "conflicting_value"),
    (
        ("lock", V1_DP_LOCK, TuyaBLEDataPointType.DT_RAW, b"synthetic"),
        ("lock", V1_DP_LOCK, TuyaBLEDataPointType.DT_BOOL, b"synthetic"),
        ("unlock", V1_DP_ACCESS, TuyaBLEDataPointType.DT_BOOL, False),
        ("unlock", V1_DP_ACCESS, TuyaBLEDataPointType.DT_RAW, True),
    ),
)
async def test_v1_conflicting_command_type_fails_before_any_write(
    hass: HomeAssistant,
    operation: str,
    dp_id: int,
    conflicting_type: TuyaBLEDataPointType,
    conflicting_value: object,
) -> None:
    """A malformed live slot cannot reinterpret V1 command data."""
    entity, device = _make_entity(hass)
    token = _install_synthetic_session(device)
    device.datapoints._update_from_device(
        dp_id, 1.0, 0, conflicting_type, conflicting_value, token
    )

    with pytest.raises(ServiceValidationError) as raised:
        await getattr(entity, f"async_{operation}")()

    device._send_datapoints.assert_not_awaited()
    device._send_datapoints_once.assert_not_awaited()
    assert raised.value.translation_domain == "tuya_ble"
    assert raised.value.translation_key == V1_COMMAND_ERROR_TRANSLATION_KEY
    rendered = str(raised.value)
    assert SYNTHETIC_DEVICE_ID not in rendered
    assert SYNTHETIC_ADDRESS not in rendered
    assert "synthetic" not in rendered
    assert entity.is_locking is False
    assert entity.is_unlocking is False


async def test_v1_access_value_is_absent_from_exposed_surfaces(
    hass: HomeAssistant, caplog: pytest.LogCaptureFixture
) -> None:
    """The action value stays out of logs, attributes, repr, and diagnostics."""
    entity, device = _make_entity(hass)
    caplog.set_level(logging.DEBUG)

    await entity.async_unlock()

    access_value = _build_v1_access_value()
    access = device.datapoints[V1_DP_ACCESS]
    assert access is not None
    exposed = "\n".join(
        (
            caplog.text,
            repr(entity),
            repr(access),
            repr(entity.extra_state_attributes),
            repr(device.datapoint_log_payload()),
            repr(device.status),
        )
    )
    protected_forms = {
        repr(access_value),
        access_value.hex(),
        base64.b64encode(access_value).decode(),
        SYNTHETIC_ADDRESS,
        SYNTHETIC_DEVICE_ID,
    }
    assert all(value not in exposed for value in protected_forms)
    assert not entity.extra_state_attributes
    assert device.status == {}


async def test_v1_commands_are_serialized_without_interleaving(
    hass: HomeAssistant,
) -> None:
    """Concurrent Secure and Access requests cannot overlap or spray writes."""
    entity, device = _make_entity(hass)
    writes: list[int] = []
    first_started = asyncio.Event()
    release_first = asyncio.Event()

    async def controlled_send(datapoint_ids: list[int]) -> None:
        writes.extend(datapoint_ids)
        if len(writes) == 1:
            first_started.set()
            await release_first.wait()

    device._send_datapoints_once.side_effect = controlled_send
    first = asyncio.create_task(entity.async_lock())
    await first_started.wait()
    second = asyncio.create_task(entity.async_unlock())
    await asyncio.sleep(0)
    assert writes == [V1_DP_LOCK]

    release_first.set()
    await asyncio.gather(first, second)

    assert writes == [V1_DP_LOCK, V1_DP_ACCESS]


@pytest.mark.parametrize("operation", ("lock", "unlock"))
async def test_v1_transient_state_resets_after_transport_error(
    hass: HomeAssistant, operation: str
) -> None:
    """A transport exception cannot leave a stale transition state."""
    entity, device = _make_entity(hass)
    device._send_datapoints_once.side_effect = RuntimeError(
        "synthetic transport failure"
    )

    with pytest.raises(RuntimeError, match="synthetic transport failure"):
        await getattr(entity, f"async_{operation}")()

    assert entity.is_locking is False
    assert entity.is_unlocking is False


@pytest.mark.parametrize("protocol_version", (0, 2, 4, 5))
@pytest.mark.parametrize("operation", ("lock", "unlock"))
async def test_v1_rejects_non_v3_protocol_before_creating_or_sending_datapoint(
    hass: HomeAssistant, protocol_version: int, operation: str
) -> None:
    """V1 commands are unavailable unless protocol v3 is negotiated."""
    entity, device = _make_entity(hass)
    device._protocol_version = protocol_version
    dp_id = V1_DP_LOCK if operation == "lock" else V1_DP_ACCESS

    with pytest.raises(ServiceValidationError) as raised:
        await getattr(entity, f"async_{operation}")()

    assert device.datapoints[dp_id] is None
    device._send_datapoints_once.assert_not_awaited()
    device._send_datapoints.assert_not_awaited()
    assert raised.value.translation_domain == "tuya_ble"
    assert raised.value.translation_key == V1_COMMAND_ERROR_TRANSLATION_KEY


@pytest.mark.parametrize(
    ("dp_id", "dp_type", "value"),
    (
        (V1_DP_LOCK, TuyaBLEDataPointType.DT_BOOL, True),
        (V1_DP_ACCESS, TuyaBLEDataPointType.DT_RAW, _build_v1_access_value()),
    ),
)
@pytest.mark.parametrize("transport_error_kind", ("bleak", "dbus"))
async def test_v1_ambiguous_transport_error_never_replays_command(
    dp_id: int,
    dp_type: TuyaBLEDataPointType,
    value: bytes | bool,
    transport_error_kind: str,
) -> None:
    """Both physical directions fail closed without a background packet replay."""
    device = _make_device()
    device.datapoints.get_or_create(dp_id, dp_type, value)
    _install_synthetic_session(device)
    device._ensure_connected = AsyncMock()
    device._build_packets = Mock(return_value=[b"synthetic-fragment"])
    transport_error = (
        BleakDBusError("synthetic.dbus.Error", ["synthetic transport error"])
        if transport_error_kind == "dbus"
        else BleakError("synthetic ambiguous transport error")
    )
    device._int_send_packets_locked = AsyncMock(side_effect=transport_error)
    device._reconnect = AsyncMock()

    with patch("custom_components.tuya_ble.tuya_ble.tuya_ble.BLEAK_BACKOFF_TIME", 0):
        with pytest.raises(BleakError):
            await TuyaBLEDevice._send_datapoints_once(device, [dp_id])
    await asyncio.sleep(0)

    device._reconnect.assert_not_awaited()
    assert not hasattr(device, "_deferred_resend_packets")
    assert not hasattr(device, "_resend_task")
    assert device._input_expected_responses == {}


@pytest.mark.parametrize("operation", ("lock", "unlock"))
async def test_v1_connected_write_failure_keeps_one_semantic_attempt(
    hass: HomeAssistant, operation: str
) -> None:
    """V1 commands do not replay when a still-connected GATT write is ambiguous."""
    entity, device = _make_entity(hass)
    client = Mock()
    client.is_connected = True
    client.stop_notify = AsyncMock()
    client.write_gatt_char = AsyncMock(
        side_effect=BleakError("synthetic ambiguous V1 write failure")
    )

    async def disconnect() -> None:
        client.is_connected = False

    client.disconnect = AsyncMock(side_effect=disconnect)
    token = _install_synthetic_session(device, client)
    device._disconnected_callbacks.clear()
    device._connection_state_callbacks.clear()
    device._schedule_reconnect = Mock()
    device._schedule_reconnect_locked = Mock()

    async def send_once(_: list[int]) -> None:
        await device._send_packets_locked(token, [b"synthetic-v1-command"])

    device._send_datapoints_once = send_once

    with pytest.raises(BleakError, match="synthetic ambiguous V1 write failure"):
        await getattr(entity, f"async_{operation}")()

    client.write_gatt_char.assert_awaited_once()
    assert not hasattr(device, "_deferred_resend_packets")
    assert not hasattr(device, "_resend_task")
    assert client.disconnect.await_count == 1


@pytest.mark.parametrize("operation", ("lock", "unlock"))
async def test_v1_verified_loss_recovers_future_session_without_replay(
    hass: HomeAssistant,
    operation: str,
) -> None:
    """A V1 at-most-once command still restores the next Always session."""
    entity, device = _make_entity(hass)
    del device._send_datapoints_once
    client = Mock()
    client.is_connected = True
    client.stop_notify = AsyncMock()

    async def lose_connection(*_: object) -> None:
        client.is_connected = False
        raise BleakError("synthetic V1 physical loss")

    client.write_gatt_char = AsyncMock(side_effect=lose_connection)
    client.disconnect = AsyncMock()
    token = _install_synthetic_session(device, client)
    device._build_packets = Mock(return_value=[b"synthetic-v1-command"])
    device._disconnected_callbacks.clear()
    device._schedule_reconnect_locked = Mock()
    state_changes: list[bool] = []
    device.register_connection_state_callback(state_changes.append)

    with pytest.raises(BleakError, match="physical loss"):
        await getattr(entity, f"async_{operation}")()

    assert client.write_gatt_char.await_count == 1
    assert device._client is None
    assert device.is_gatt_connected is False
    assert device.policy_state is ConnectionPolicyState.ALWAYS_CONNECTED_CONNECTING
    assert device._pending_release is None
    assert entity.is_locking is False
    assert entity.is_unlocking is False
    assert state_changes == [False]
    device._schedule_reconnect_locked.assert_called_once_with(
        UNEXPECTED_RECONNECT_MIN_SECONDS
    )
    assert not hasattr(device, "_deferred_resend_packets")
    assert not hasattr(device, "_resend_task")

    device._disconnected(client, token)

    assert state_changes == [False]
    device._schedule_reconnect_locked.assert_called_once_with(
        UNEXPECTED_RECONNECT_MIN_SECONDS
    )


async def test_unverified_generic_transport_error_does_not_schedule_recovery() -> None:
    """Recovery remains reserved for a verified physical transport loss."""
    device = _make_device()
    packets = [b"synthetic-fragment"]
    token = _install_synthetic_session(device)
    device._int_send_packets_locked = AsyncMock(
        side_effect=BleakError("synthetic generic transport error")
    )
    device._schedule_reconnect = Mock()

    with pytest.raises(BleakError, match="synthetic generic transport error"):
        await device._send_packets_locked(token, packets)

    device._schedule_reconnect.assert_not_called()
    assert not hasattr(device, "_deferred_resend_packets")
    assert not hasattr(device, "_resend_task")


async def test_v1_response_timeout_is_an_unconfirmed_failure() -> None:
    """An absent acknowledgement cannot be reported as command success."""
    device = _make_device()
    device.datapoints.get_or_create(V1_DP_LOCK, TuyaBLEDataPointType.DT_BOOL, True)
    _install_synthetic_session(device)
    device._ensure_connected = AsyncMock()
    device._build_packets = Mock(return_value=[b"synthetic-fragment"])
    device._int_send_packets_locked = AsyncMock()

    with patch("custom_components.tuya_ble.tuya_ble.tuya_ble.RESPONSE_WAIT_TIMEOUT", 0):
        with pytest.raises(TuyaBLECommandUnconfirmedError):
            await TuyaBLEDevice._send_datapoints_once(device, [V1_DP_LOCK])

    assert device._input_expected_responses == {}


async def test_v1_malformed_response_is_an_unconfirmed_failure() -> None:
    """A correlated malformed acknowledgement remains a failed service call."""
    device = _make_device()
    device.datapoints.get_or_create(V1_DP_LOCK, TuyaBLEDataPointType.DT_BOOL, True)
    token = _install_synthetic_session(device)
    device._ensure_connected = AsyncMock()
    device._build_packets = Mock(return_value=[b"synthetic-fragment"])

    async def emit_malformed_response(
        session_token: ConnectionSessionToken, _: list[bytes]
    ) -> None:
        assert session_token is token
        response_to = next(iter(device._input_expected_responses))[1]
        with pytest.raises(TuyaBLEDataLengthError):
            device._handle_command_or_response(
                2,
                response_to,
                TuyaBLECode.FUN_SENDER_DPS,
                b"",
                session_token=token,
            )

    device._int_send_packets_locked = AsyncMock(side_effect=emit_malformed_response)

    with patch("custom_components.tuya_ble.tuya_ble.tuya_ble.RESPONSE_WAIT_TIMEOUT", 0):
        with pytest.raises(TuyaBLECommandUnconfirmedError):
            await TuyaBLEDevice._send_datapoints_once(device, [V1_DP_LOCK])

    assert device._input_expected_responses == {}


@pytest.mark.parametrize("status", (0, 1))
async def test_v1_requires_correlated_zero_status_response(status: int) -> None:
    """Only the observed correlated zero status confirms a strict V1 command."""
    device = _make_device()
    device.datapoints.get_or_create(V1_DP_LOCK, TuyaBLEDataPointType.DT_BOOL, True)
    token = _install_synthetic_session(device)
    device._ensure_connected = AsyncMock()
    device._build_packets = Mock(return_value=[b"synthetic-fragment"])

    async def emit_response(
        session_token: ConnectionSessionToken, _: list[bytes]
    ) -> None:
        assert session_token is token
        response_to = next(iter(device._input_expected_responses))[1]
        device._handle_command_or_response(
            2,
            response_to,
            TuyaBLECode.FUN_SENDER_DPS,
            bytes([status]),
            session_token=token,
        )

    device._int_send_packets_locked = AsyncMock(side_effect=emit_response)

    if status == 0:
        await TuyaBLEDevice._send_datapoints_once(device, [V1_DP_LOCK])
    else:
        with pytest.raises(TuyaBLEDeviceError):
            await TuyaBLEDevice._send_datapoints_once(device, [V1_DP_LOCK])

    assert device._input_expected_responses == {}


async def test_v1_wrong_status_response_family_cannot_confirm_command() -> None:
    """A correlated zero device-status response is not a sender-DPS response."""
    device = _make_device()
    device.datapoints.get_or_create(V1_DP_LOCK, TuyaBLEDataPointType.DT_BOOL, True)
    token = _install_synthetic_session(device)
    device._ensure_connected = AsyncMock()
    device._build_packets = Mock(return_value=[b"synthetic-fragment"])

    async def emit_wrong_response(
        session_token: ConnectionSessionToken, _: list[bytes]
    ) -> None:
        assert session_token is token
        response_key, future = next(iter(device._input_expected_responses.items()))
        response_to = response_key[1]
        assert (
            device._input_expected_response_codes[response_key]
            is TuyaBLECode.FUN_SENDER_DPS
        )
        device._handle_command_or_response(
            2,
            response_to,
            TuyaBLECode.FUN_SENDER_DEVICE_STATUS,
            bytes([0]),
            session_token=token,
        )
        assert not future.done()

    device._int_send_packets_locked = AsyncMock(side_effect=emit_wrong_response)

    with patch("custom_components.tuya_ble.tuya_ble.tuya_ble.RESPONSE_WAIT_TIMEOUT", 0):
        with pytest.raises(TuyaBLECommandUnconfirmedError):
            await TuyaBLEDevice._send_datapoints_once(device, [V1_DP_LOCK])

    assert device._input_expected_responses == {}
    assert device._input_expected_response_codes == {}


async def test_v1_correlated_inbound_report_cannot_confirm_command() -> None:
    """A valid inbound DP report is processed but cannot confirm a V1 write."""
    device = _make_device()
    device.datapoints.get_or_create(V1_DP_LOCK, TuyaBLEDataPointType.DT_BOOL, True)
    token = _install_synthetic_session(device)
    device._ensure_connected = AsyncMock()
    device._build_packets = Mock(return_value=[b"synthetic-fragment"])
    device._send_response = AsyncMock()

    async def emit_inbound_report(
        session_token: ConnectionSessionToken, _: list[bytes]
    ) -> None:
        assert session_token is token
        response_key, future = next(iter(device._input_expected_responses.items()))
        response_to = response_key[1]
        assert (
            device._input_expected_response_codes[response_key]
            is TuyaBLECode.FUN_SENDER_DPS
        )
        device._handle_command_or_response(
            2,
            response_to,
            TuyaBLECode.FUN_RECEIVE_DP,
            bytes(
                [
                    V1_DP_MOTOR_STATE,
                    TuyaBLEDataPointType.DT_BOOL.value,
                    1,
                    1,
                ]
            ),
            session_token=token,
        )
        assert not future.done()

    device._int_send_packets_locked = AsyncMock(side_effect=emit_inbound_report)

    with patch("custom_components.tuya_ble.tuya_ble.tuya_ble.RESPONSE_WAIT_TIMEOUT", 0):
        with pytest.raises(TuyaBLECommandUnconfirmedError):
            await TuyaBLEDevice._send_datapoints_once(device, [V1_DP_LOCK])
    await asyncio.sleep(0)

    assert device.datapoints[V1_DP_MOTOR_STATE].value is True
    device._send_response.assert_awaited_once_with(
        token, TuyaBLECode.FUN_RECEIVE_DP, bytes(0), 2
    )
    assert device._input_expected_responses == {}
    assert device._input_expected_response_codes == {}


async def test_v1_expected_disconnect_fails_before_transport() -> None:
    """An expected disconnect is not silently accepted as command success."""
    device = _make_device()
    device.datapoints.get_or_create(V1_DP_LOCK, TuyaBLEDataPointType.DT_BOOL, True)
    device._expected_disconnect = True
    device._ensure_connected = AsyncMock()
    device._build_packets = Mock(return_value=[b"synthetic-fragment"])

    with pytest.raises(TuyaBLECommandUnconfirmedError):
        await TuyaBLEDevice._send_datapoints_once(device, [V1_DP_LOCK])

    device._ensure_connected.assert_not_awaited()
    device._build_packets.assert_not_called()
    assert device._input_expected_responses == {}


async def test_v1_protocol_drift_during_connect_fails_before_command_write() -> None:
    """A reconnect that negotiates a different protocol cannot send V1 data."""
    device = _make_device()
    device.datapoints.get_or_create(V1_DP_LOCK, TuyaBLEDataPointType.DT_BOOL, True)

    async def negotiate_protocol_v4() -> None:
        device._protocol_version = 4

    device._ensure_connected = AsyncMock(side_effect=negotiate_protocol_v4)
    device._build_packets = Mock(return_value=[b"synthetic-fragment"])

    with pytest.raises(TuyaBLECommandUnconfirmedError):
        await TuyaBLEDevice._send_datapoints_once(device, [V1_DP_LOCK])

    device._build_packets.assert_not_called()
    assert device._input_expected_responses == {}


async def test_v1_failed_command_restores_prior_datapoint_provenance() -> None:
    """A failed strict write cannot leave a command value looking confirmed."""
    device = _make_device()
    token = _install_synthetic_session(device)
    device.datapoints._update_from_device(
        V1_DP_LOCK,
        1.0,
        0,
        TuyaBLEDataPointType.DT_BOOL,
        False,
        token,
    )
    datapoint = device.datapoints[V1_DP_LOCK]
    device._send_datapoints_once.side_effect = TuyaBLECommandUnconfirmedError()

    with pytest.raises(TuyaBLECommandUnconfirmedError):
        await datapoint.set_value_once(True)

    assert datapoint.value is False
    assert datapoint.changed_by_device is False
    assert datapoint.received_from_device is True


def test_protocol_v3_sender_dps_response_status_is_enforced() -> None:
    """V1 command acknowledgement accepts zero and rejects device errors."""

    async def exercise() -> None:
        device = _make_device()
        token = _install_synthetic_session(device)
        loop = asyncio.get_running_loop()

        success = loop.create_future()
        device._input_expected_responses[(token, 1)] = success
        device._handle_command_or_response(
            2,
            1,
            TuyaBLECode.FUN_SENDER_DPS,
            bytes([0]),
            session_token=token,
        )
        assert await success == 0

        failure = loop.create_future()
        device._input_expected_responses[(token, 3)] = failure
        device._handle_command_or_response(
            4,
            3,
            TuyaBLECode.FUN_SENDER_DPS,
            bytes([1]),
            session_token=token,
        )
        with pytest.raises(TuyaBLEDeviceError):
            await failure

        malformed = loop.create_future()
        device._input_expected_responses[(token, 5)] = malformed
        with pytest.raises(TuyaBLEDataLengthError):
            device._handle_command_or_response(
                6,
                5,
                TuyaBLECode.FUN_SENDER_DPS,
                b"",
                session_token=token,
            )
        assert not malformed.done()

    asyncio.run(exercise())


def test_v1_access_builder_has_no_variable_or_external_input() -> None:
    """The selected action cannot accept tickets, timestamps, or alternate shapes."""
    first = _build_v1_access_value()
    second = _build_v1_access_value()

    assert first == second
    assert first is not second
    with pytest.raises(TypeError):
        _build_v1_access_value(True)  # type: ignore[call-arg]
    with pytest.raises((TuyaBLEDataFormatError, TypeError)):
        TuyaBLEDevice._unpack_int(b"", 0)
