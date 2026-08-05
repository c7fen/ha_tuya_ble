"""Safety contracts for V1 / Lock P1 bidirectional coupling control."""

from __future__ import annotations

import asyncio
import base64
import logging
from unittest.mock import AsyncMock, Mock, patch

import pytest
from bleak.backends.device import BLEDevice
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
from custom_components.tuya_ble.tuya_ble.const import TuyaBLECode
from custom_components.tuya_ble.tuya_ble.exceptions import (
    TuyaBLEDataFormatError,
    TuyaBLEDataLengthError,
    TuyaBLEDeviceError,
)
from custom_components.tuya_ble.tuya_ble.manager import TuyaBLEDeviceCredentials
from custom_components.tuya_ble.tuya_ble.security import TuyaBLESecurityMaterial

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
    device._send_datapoints = AsyncMock()
    return device


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

    device._send_datapoints.side_effect = record_send

    await entity.async_lock()
    await entity.async_unlock()

    assert writes[0] == (V1_DP_LOCK, TuyaBLEDataPointType.DT_BOOL, True)
    assert writes[1][0:2] == (V1_DP_ACCESS, TuyaBLEDataPointType.DT_RAW)
    assert isinstance(writes[1][2], bytes)
    assert len(writes[1][2]) == V1_ACCESS_FIELD_COUNT
    assert all(field == int(True) for field in writes[1][2])
    assert [write[0] for write in writes] == [V1_DP_LOCK, V1_DP_ACCESS]
    assert 33 not in device.datapoints.__dict__()
    assert V1_DP_MOTOR_STATE not in device.datapoints.__dict__()
    assert entity.supported_features == LockEntityFeature(0)
    assert entity.entity_description.key == "manual_lock"
    assert entity.entity_description.translation_key == "lock"
    assert entity.unique_id == f"{SYNTHETIC_DEVICE_ID}-manual_lock"
    assert entity.is_locking is False
    assert entity.is_unlocking is False


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
    device.datapoints._update_from_device(V1_DP_MOTOR_STATE, 1.0, 0, dp_type, value)

    assert entity.is_locked is expected
    device._send_datapoints.assert_not_awaited()


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
    device.datapoints._update_from_device(
        dp_id, 1.0, 0, conflicting_type, conflicting_value
    )

    with pytest.raises(ServiceValidationError) as raised:
        await getattr(entity, f"async_{operation}")()

    device._send_datapoints.assert_not_awaited()
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

    device._send_datapoints.side_effect = controlled_send
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
    device._send_datapoints.side_effect = RuntimeError("synthetic transport failure")

    with pytest.raises(RuntimeError, match="synthetic transport failure"):
        await getattr(entity, f"async_{operation}")()

    assert entity.is_locking is False
    assert entity.is_unlocking is False


def test_protocol_v3_sender_dps_response_status_is_enforced() -> None:
    """V1 command acknowledgement accepts zero and rejects device errors."""

    async def exercise() -> None:
        device = _make_device()
        loop = asyncio.get_running_loop()

        success = loop.create_future()
        device._input_expected_responses[1] = success
        device._handle_command_or_response(2, 1, TuyaBLECode.FUN_SENDER_DPS, bytes([0]))
        assert await success == 0

        failure = loop.create_future()
        device._input_expected_responses[3] = failure
        device._handle_command_or_response(4, 3, TuyaBLECode.FUN_SENDER_DPS, bytes([1]))
        with pytest.raises(TuyaBLEDeviceError):
            await failure

        malformed = loop.create_future()
        device._input_expected_responses[5] = malformed
        with pytest.raises(TuyaBLEDataLengthError):
            device._handle_command_or_response(6, 5, TuyaBLECode.FUN_SENDER_DPS, b"")
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
