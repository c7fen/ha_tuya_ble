"""Tests for per-device BLE connection policy and control entities."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, Mock, patch

import pytest
from bleak.backends.device import BLEDevice
from homeassistant.components.binary_sensor import BinarySensorDeviceClass
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ServiceValidationError
from homeassistant.helpers.entity import EntityCategory

from custom_components.tuya_ble.binary_sensor import (
    TuyaBLEConnectionSensor,
    async_setup_entry as async_setup_binary_sensors,
)
from custom_components.tuya_ble.config_flow import TuyaBLEOptionsFlow
from custom_components.tuya_ble.const import (
    CONF_BLE_CONTROL_ENABLED,
    CONF_CONNECTION_MODE,
    ConnectionMode,
    ConnectionPolicyState,
    DEFAULT_ON_DEMAND_IDLE_DISCONNECT_SECONDS,
    DOMAIN,
    EffectiveConnectionPolicy,
)
from custom_components.tuya_ble.devices import (
    TuyaBLECoordinator,
    TuyaBLEData,
    TuyaBLEProductInfo,
)
from custom_components.tuya_ble.lock import TuyaBLES1Lock, TuyaBLEV1Lock
from custom_components.tuya_ble.select import TuyaBLEConnectionModeSelect
from custom_components.tuya_ble.switch import TuyaBLEControlSwitch
from custom_components.tuya_ble.tuya_ble import TuyaBLEDevice
from custom_components.tuya_ble.tuya_ble.exceptions import (
    TuyaBLEControlSuspendedError,
)
from custom_components.tuya_ble.tuya_ble.manager import TuyaBLEDeviceCredentials


SYNTHETIC_ADDRESS = "00:00:00:00:00:21"
SYNTHETIC_DEVICE_ID = "synthetic-policy-device"


def _make_device(
    *,
    mode: ConnectionMode = ConnectionMode.ALWAYS_CONNECTED,
    enabled: bool = True,
    persist_options=None,
) -> TuyaBLEDevice:
    device = TuyaBLEDevice(
        Mock(),
        BLEDevice(
            name="Synthetic policy device",
            address=SYNTHETIC_ADDRESS,
            details={},
        ),
        connection_mode=mode.value,
        ble_control_enabled=enabled,
        persist_options=persist_options,
    )
    device._device_info = TuyaBLEDeviceCredentials(
        uuid="synthetic-policy-uuid",
        local_key="synthetic-policy-key",
        device_id=SYNTHETIC_DEVICE_ID,
        category="jtmspro",
        product_id="xqeob8h6",
        device_name="Synthetic policy device",
        product_model="SYNTHETIC",
        product_name="Synthetic policy device",
        functions=[],
        status_range=[],
    )
    return device


def _make_data(hass: HomeAssistant, device: TuyaBLEDevice) -> TuyaBLEData:
    coordinator = TuyaBLECoordinator(hass, device)
    return TuyaBLEData(
        title="Synthetic policy device",
        device=device,
        product=TuyaBLEProductInfo("S1-TY-BLE-PRO"),
        manager=Mock(),
        coordinator=coordinator,
    )


def test_defaults_and_effective_policy() -> None:
    device = TuyaBLEDevice(
        Mock(),
        None,
        address=SYNTHETIC_ADDRESS,
    )

    assert device.connection_mode is ConnectionMode.ALWAYS_CONNECTED
    assert device.ble_control_enabled is True
    assert device.effective_policy is EffectiveConnectionPolicy.ALWAYS_CONNECTED
    assert (
        device.policy_state is ConnectionPolicyState.ALWAYS_CONNECTED_CONNECTING
    )
    assert device.is_connection_active is False


async def test_deferred_initialize_loads_without_advertisement() -> None:
    manager = Mock()
    manager.get_device_credentials = AsyncMock(
        return_value=TuyaBLEDeviceCredentials(
            uuid="synthetic-policy-uuid",
            local_key="synthetic-policy-key",
            device_id=SYNTHETIC_DEVICE_ID,
            category="jtmspro",
            product_id="xqeob8h6",
            device_name="Synthetic policy device",
            product_model="SYNTHETIC",
            product_name="Synthetic policy device",
            functions=[],
            status_range=[],
        )
    )
    device = TuyaBLEDevice(
        manager,
        None,
        address=SYNTHETIC_ADDRESS,
        connection_mode=ConnectionMode.ON_DEMAND.value,
    )

    await device.initialize()

    assert device.category == "jtmspro"
    assert device.product_id == "xqeob8h6"
    manager.get_device_credentials.assert_awaited_once_with(SYNTHETIC_ADDRESS, False)


async def test_overlapping_leases_do_not_disconnect_early() -> None:
    device = _make_device(mode=ConnectionMode.ON_DEMAND)
    device._ensure_connected = AsyncMock()
    device._execute_disconnect = AsyncMock()

    with patch(
        "custom_components.tuya_ble.tuya_ble.tuya_ble.DEFAULT_ON_DEMAND_IDLE_DISCONNECT_SECONDS",
        0.01,
    ):
        first = device.connection_lease("first")
        second = device.connection_lease("second")
        await first.__aenter__()
        await second.__aenter__()
        await first.__aexit__(None, None, None)
        await asyncio.sleep(0.02)
        device._execute_disconnect.assert_not_awaited()
        assert device.active_lease_count == 1
        await second.__aexit__(None, None, None)
        await asyncio.sleep(0.02)

    device._execute_disconnect.assert_awaited_once()
    assert device.active_lease_count == 0
    await device.stop()


async def test_new_lease_cancels_idle_disconnect() -> None:
    device = _make_device(mode=ConnectionMode.ON_DEMAND)
    device._ensure_connected = AsyncMock()
    device._execute_disconnect = AsyncMock()

    with patch(
        "custom_components.tuya_ble.tuya_ble.tuya_ble.DEFAULT_ON_DEMAND_IDLE_DISCONNECT_SECONDS",
        0.05,
    ):
        async with device.connection_lease("first"):
            pass
        async with device.connection_lease("second"):
            await asyncio.sleep(0.06)
        await asyncio.sleep(0)

    device._execute_disconnect.assert_not_awaited()
    await device.stop()


async def test_lease_cancellation_and_exception_release_count() -> None:
    device = _make_device(mode=ConnectionMode.ON_DEMAND)
    device._ensure_connected = AsyncMock()

    with pytest.raises(RuntimeError):
        async with device.connection_lease("exception"):
            raise RuntimeError("synthetic failure")
    assert device.active_lease_count == 0

    async def cancel_inside() -> None:
        async with device.connection_lease("cancel"):
            raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await cancel_inside()
    assert device.active_lease_count == 0
    await device.stop()


async def test_suspension_persists_before_disconnect_and_blocks_new_leases() -> None:
    events: list[str] = []

    async def persist(updates: dict[str, object]) -> None:
        assert updates == {CONF_BLE_CONTROL_ENABLED: False}
        events.append("persist")

    device = _make_device(persist_options=persist)

    async def disconnect() -> None:
        events.append("disconnect")

    device._execute_disconnect = disconnect
    await device.async_update_connection_policy(ble_control_enabled=False)

    assert events == ["persist", "disconnect"]
    assert device.effective_policy is EffectiveConnectionPolicy.SUSPENDED
    with pytest.raises(TuyaBLEControlSuspendedError):
        async with device.connection_lease("blocked"):
            pass
    assert device.active_lease_count == 0


async def test_suspension_waits_for_existing_lease() -> None:
    device = _make_device()
    device._ensure_connected = AsyncMock()
    device._execute_disconnect = AsyncMock()
    lease = device.connection_lease("long operation", defer_connection=True)
    await lease.__aenter__()

    suspension = asyncio.create_task(
        device.async_update_connection_policy(ble_control_enabled=False)
    )
    await asyncio.sleep(0)
    device._execute_disconnect.assert_not_awaited()
    await lease.__aexit__(None, None, None)
    await suspension

    device._execute_disconnect.assert_awaited_once()
    assert device.active_lease_count == 0


async def test_mode_change_while_suspended_does_not_connect() -> None:
    device = _make_device(enabled=False)
    device._ensure_connected = AsyncMock()

    await device.async_update_connection_policy(
        connection_mode=ConnectionMode.ON_DEMAND.value
    )
    assert device.connection_mode is ConnectionMode.ON_DEMAND
    assert device.effective_policy is EffectiveConnectionPolicy.SUSPENDED

    await device.async_update_connection_policy(ble_control_enabled=True)
    assert device.effective_policy is EffectiveConnectionPolicy.ON_DEMAND
    device._ensure_connected.assert_not_awaited()


async def test_policy_entities_are_available_while_disconnected(
    hass: HomeAssistant,
) -> None:
    device = _make_device(enabled=False)
    data = _make_data(hass, device)
    mode = TuyaBLEConnectionModeSelect(
        hass, data.coordinator, device, data.product
    )
    control = TuyaBLEControlSwitch(hass, data.coordinator, device, data.product)
    connection = TuyaBLEConnectionSensor(
        hass, data.coordinator, device, data.product
    )

    assert mode.available is True
    assert control.available is True
    assert control.is_on is False
    assert connection.available is True
    assert connection.is_on is False
    assert mode.entity_category is EntityCategory.CONFIG
    assert control.entity_category is EntityCategory.CONFIG
    assert connection.entity_category is EntityCategory.DIAGNOSTIC
    assert connection.device_class is BinarySensorDeviceClass.CONNECTIVITY


async def test_target_connection_entity_is_added_only_for_s1_and_v1(
    hass: HomeAssistant,
) -> None:
    from pytest_homeassistant_custom_component.common import MockConfigEntry

    entry = MockConfigEntry(domain=DOMAIN, title="Synthetic policy")
    entry.add_to_hass(hass)
    device = _make_device()
    data = _make_data(hass, device)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = data
    added: list[object] = []

    await async_setup_binary_sensors(hass, entry, added.extend)

    assert any(isinstance(entity, TuyaBLEConnectionSensor) for entity in added)
    assert len(added) == 2
    assert isinstance(added[0], TuyaBLEConnectionSensor)
    assert isinstance(added[1], object)


async def test_s1_lock_lease_wraps_both_unlock_writes(
    hass: HomeAssistant,
) -> None:
    device = _make_device()
    device._send_datapoints = AsyncMock()
    device._ensure_connected = AsyncMock()
    coordinator = TuyaBLECoordinator(hass, device)
    store = Mock()
    store.templates_for.return_value = (
        b"synthetic-dp70",
        b"synthetic-dp71-template-000",
    )
    entity = TuyaBLES1Lock(
        hass,
        coordinator,
        device,
        TuyaBLEProductInfo("S1-TY-BLE-PRO"),
        store,
    )
    entity.async_write_ha_state = Mock()
    with patch("custom_components.tuya_ble.lock.asyncio.sleep", AsyncMock()):
        await entity.async_unlock()
    assert device.active_lease_count == 0
    assert device._send_datapoints.await_count == 2
    assert entity.is_unlocking is False


async def test_suspended_lock_commands_perform_zero_writes(
    hass: HomeAssistant,
) -> None:
    device = _make_device(enabled=False)
    device._send_datapoints = AsyncMock()
    device._send_datapoints_once = AsyncMock()
    coordinator = TuyaBLECoordinator(hass, device)
    v1_entity = TuyaBLEV1Lock(
        hass,
        coordinator,
        device,
        TuyaBLEProductInfo("V1 Smart Lock"),
    )
    v1_entity.async_write_ha_state = Mock()

    with pytest.raises(ServiceValidationError):
        await v1_entity.async_lock()
    with pytest.raises(ServiceValidationError):
        await v1_entity.async_unlock()

    assert device._send_datapoints.await_count == 0
    assert device._send_datapoints_once.await_count == 0


async def test_options_flow_connection_settings_preserve_credentials(
    hass: HomeAssistant,
) -> None:
    from pytest_homeassistant_custom_component.common import MockConfigEntry

    entry = MockConfigEntry(
        domain=DOMAIN,
        title="Synthetic policy",
        data={"address": SYNTHETIC_ADDRESS},
        options={
            "access_id": "synthetic-access-id",
            "access_secret": "synthetic-access-secret",
            "username": "synthetic-user",
            "password": "synthetic-password",
        },
    )
    entry.add_to_hass(hass)
    device = _make_device()
    device._persist_options = AsyncMock()
    data = _make_data(hass, device)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = data

    flow = TuyaBLEOptionsFlow(entry)
    flow.hass = hass
    result = await flow.async_step_connection_settings(
        {
            CONF_CONNECTION_MODE: ConnectionMode.ON_DEMAND.value,
            CONF_BLE_CONTROL_ENABLED: False,
        }
    )

    assert result["type"] == "create_entry"
    assert result["data"]["access_id"] == "synthetic-access-id"
    assert result["data"][CONF_CONNECTION_MODE] == ConnectionMode.ON_DEMAND.value
    assert result["data"][CONF_BLE_CONTROL_ENABLED] is False
    device._persist_options.assert_awaited_once_with(
        {
            CONF_CONNECTION_MODE: ConnectionMode.ON_DEMAND.value,
            CONF_BLE_CONTROL_ENABLED: False,
        }
    )