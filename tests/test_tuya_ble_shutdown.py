"""Test for tuya_ble bluetooth shutdown handling."""

import asyncio
from unittest.mock import Mock, AsyncMock, patch
import pytest
from bleak.backends.device import BLEDevice
from bleak.exc import BleakError
from custom_components.tuya_ble.tuya_ble import TuyaBLEDevice
from custom_components.tuya_ble.cloud import HASSTuyaBLEDeviceManager
from pytest_homeassistant_custom_component.common import MockConfigEntry
from homeassistant.core import HomeAssistant
from custom_components.tuya_ble.const import DOMAIN

CONFIG = {
    "1234": {
        "address": "11:22:33:44:55:66",
        "device_id": "767823809c9c1f458745",
        "protocol_version": "3.3",
        "local_key": "wV[NcWGUSFF`dSgO",
        "friendly_name": "Local 3G",
    }
}


async def test_ensure_connected_bluetooth_shutdown(hass: HomeAssistant) -> None:
    """Test that _ensure_connected terminates immediately on bluetooth shutdown error."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={
            "devices": CONFIG,
            "address": "11:22:33:44:55:66",
        },
        title="Mock TuyaBLE",
    )
    entry.add_to_hass(hass)

    ble_device = BLEDevice(
        name="bob", address="11:22:33:44:55:66", details="", rssi=-50
    )
    manager = HASSTuyaBLEDeviceManager(hass, entry.options.copy())
    device = TuyaBLEDevice(manager, ble_device)
    await device.initialize()

    # We patch establish_connection to raise BleakError("Bluetooth is already shutdown")
    with patch(
        "custom_components.tuya_ble.tuya_ble.tuya_ble.establish_connection",
        side_effect=BleakError("Bluetooth is already shutdown"),
    ) as mock_establish:
        with pytest.raises(BleakError, match="Bluetooth is already shutdown"):
            await device._ensure_connected()

        # Assert establish_connection was only called once, not 100 times!
        assert mock_establish.call_count == 1


async def test_reconnect_bluetooth_shutdown(hass: HomeAssistant) -> None:
    """Test that _reconnect does not schedule another task on bluetooth shutdown."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={
            "devices": CONFIG,
            "address": "11:22:33:44:55:66",
        },
        title="Mock TuyaBLE",
    )
    entry.add_to_hass(hass)

    ble_device = BLEDevice(
        name="bob", address="11:22:33:44:55:66", details="", rssi=-50
    )
    manager = HASSTuyaBLEDeviceManager(hass, entry.options.copy())
    device = TuyaBLEDevice(manager, ble_device)
    await device.initialize()

    # Mock _ensure_connected to raise BleakError("Bluetooth is already shutdown")
    with patch.object(
        device,
        "_ensure_connected",
        side_effect=BleakError("Bluetooth is already shutdown"),
    ):
        with patch("asyncio.create_task") as mock_create_task:
            await device._reconnect()
            # Assert create_task was never called to reschedule _reconnect
            mock_create_task.assert_not_called()


async def test_shutdown_write_keeps_a_connected_client_under_release_ownership(
    hass: HomeAssistant,
) -> None:
    """A shutdown error does not forget a client that still reports connected."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={
            "devices": CONFIG,
            "address": "11:22:33:44:55:66",
        },
        title="Mock TuyaBLE",
    )
    entry.add_to_hass(hass)

    ble_device = BLEDevice(
        name="bob", address="11:22:33:44:55:66", details="", rssi=-50
    )
    manager = HASSTuyaBLEDeviceManager(hass, entry.options.copy())
    device = TuyaBLEDevice(manager, ble_device)
    await device.initialize()

    client = Mock()
    client.is_connected = True
    client.stop_notify = AsyncMock()
    client.write_gatt_char = AsyncMock(
        side_effect=BleakError("Bluetooth is already shutdown")
    )

    async def disconnect() -> None:
        client.is_connected = False

    client.disconnect = AsyncMock(side_effect=disconnect)
    device._client = client
    device._is_paired = True
    device._physical_connection_active = True
    device._notifications_active = True
    device._state_data_fresh = True
    device._schedule_reconnect = Mock()
    device._schedule_reconnect_locked = Mock()

    async with device.connection_lease(
        "synthetic shutdown write", defer_connection=True
    ):
        with pytest.raises(BleakError, match="Bluetooth is already shutdown"):
            await device._send_packets_locked([b"\x00"])

        assert device._client is client
        assert client.is_connected is True
        assert device.is_connection_active is False
        assert device.state_data_fresh is False
        assert device._pending_release is not None
        assert not hasattr(device, "_deferred_resend_packets")
        assert not hasattr(device, "_resend_task")
        device._schedule_reconnect.assert_not_called()

    client.disconnect.assert_awaited_once()
    assert client.is_connected is False


async def test_shutdown_write_marks_an_already_disconnected_client_lost(
    hass: HomeAssistant,
) -> None:
    """The shutdown branch clears only a client whose physical loss is verified."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={"devices": CONFIG, "address": "11:22:33:44:55:66"},
        title="Mock TuyaBLE",
    )
    entry.add_to_hass(hass)
    ble_device = BLEDevice(
        name="bob", address="11:22:33:44:55:66", details="", rssi=-50
    )
    device = TuyaBLEDevice(
        HASSTuyaBLEDeviceManager(hass, entry.options.copy()), ble_device
    )
    await device.initialize()

    client = Mock()
    client.is_connected = True

    async def shutdown_after_physical_loss(*_: object) -> None:
        client.is_connected = False
        raise BleakError("Bluetooth is already shutdown")

    client.write_gatt_char = AsyncMock(side_effect=shutdown_after_physical_loss)
    device._client = client
    device._is_paired = True
    device._physical_connection_active = True
    device._notifications_active = True
    device._schedule_reconnect = Mock()

    async with device.connection_lease(
        "synthetic shutdown loss", defer_connection=True
    ):
        with pytest.raises(BleakError, match="Bluetooth is already shutdown"):
            await device._send_packets_locked([b"\x00"])

    assert device._client is None
    assert device.is_gatt_connected is False
    assert device._pending_release is None
    assert not hasattr(device, "_deferred_resend_packets")
    device._schedule_reconnect.assert_not_called()
