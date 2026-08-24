"""Test for dynamic GATT characteristic selection."""

from unittest.mock import AsyncMock, Mock, call, patch

import pytest
from bleak.backends.device import BLEDevice
from homeassistant.core import HomeAssistant
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.tuya_ble.cloud import HASSTuyaBLEDeviceManager
from custom_components.tuya_ble.const import DOMAIN
from custom_components.tuya_ble.tuya_ble import TuyaBLEDevice
from custom_components.tuya_ble.tuya_ble.const import TuyaBLECode
from custom_components.tuya_ble.tuya_ble.manager import TuyaBLEDeviceCredentials

CONFIG = {
    "1234": {
        "address": "11:22:33:44:55:66",
        "device_id": "767823809c9c1f458745",
        "protocol_version": "3.3",
        "local_key": "wV[NcWGUSFF`dSgO",
        "friendly_name": "Local 3G",
    }
}


def _session_handshake_sender(device: TuyaBLEDevice) -> AsyncMock:
    """Return a sender that completes pairing for the claimed exact session."""

    async def send_packet(
        code: TuyaBLECode,
        data: bytes,
        response_to: int,
        wait_for_response: bool,
        expected_response_code: TuyaBLECode | None = None,
        *,
        session_token: object | None = None,
    ) -> bool:
        assert session_token is device._connection_token
        if code is TuyaBLECode.FUN_SENDER_PAIR:
            device._is_paired = True
        _ = data, response_to, wait_for_response, expected_response_code
        return True

    return AsyncMock(side_effect=send_packet)


def _assert_session_bound_notification(
    device: TuyaBLEDevice,
    client: Mock,
    characteristic: str,
    expected_kwargs: dict[str, object] | None = None,
) -> None:
    """Assert start-notify received a callback bound to the exact session."""
    notify_call = client.start_notify.await_args
    assert notify_call is not None
    assert notify_call.args[0] == characteristic
    assert notify_call.kwargs == (expected_kwargs or {})

    callback = notify_call.args[1]
    token = device._connection_token
    assert token is not None
    payload = bytearray()
    with patch.object(device, "_notification_handler") as notification_handler:
        callback(7, payload)
    notification_handler.assert_called_once_with(token, 7, payload)


@pytest.mark.asyncio
async def test_gatt_characteristic_selection_classic(hass: HomeAssistant) -> None:
    """Test that classic GATT characteristics are selected when present."""
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

    credentials = TuyaBLEDeviceCredentials(
        uuid="12345678901234567890",
        local_key="wV[NcWGUSFF`dSgO",
        device_id="767823809c9c1f458745",
        category="ms",
        product_id="kpn4zaf7",
        device_name="Mock Lock",
        product_model="BSTUOKEY",
        product_name="BSTUOKEY",
        functions=[],
        status_range=[],
    )

    with patch.object(manager, "get_device_credentials", return_value=credentials):
        device = TuyaBLEDevice(manager, ble_device)
        await device.initialize()

        # Mock Client
        client = Mock()
        client.is_connected = True
        client.start_notify = AsyncMock()

        # Get characteristic mock setup: classic notify exists, fd50 notify does not
        def get_char(uuid):
            if uuid == "00002b10-0000-1000-8000-00805f9b34fb":
                return Mock()
            return None

        client.services.get_characteristic = Mock(side_effect=get_char)
        send_packet = _session_handshake_sender(device)

        with (
            patch(
                "custom_components.tuya_ble.tuya_ble.tuya_ble.establish_connection",
                return_value=client,
            ),
            patch.object(device, "_send_packet_while_connected", send_packet),
        ):
            await device._ensure_connected()

            assert (
                device._characteristic_notify == "00002b10-0000-1000-8000-00805f9b34fb"
            )
            assert (
                device._characteristic_write == "00002b11-0000-1000-8000-00805f9b34fb"
            )
            _assert_session_bound_notification(
                device,
                client,
                "00002b10-0000-1000-8000-00805f9b34fb",
            )


@pytest.mark.asyncio
async def test_gatt_characteristic_selection_fd50(hass: HomeAssistant) -> None:
    """Test that FD50 GATT characteristics are selected when present."""
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

    credentials = TuyaBLEDeviceCredentials(
        uuid="12345678901234567890",
        local_key="wV[NcWGUSFF`dSgO",
        device_id="767823809c9c1f458745",
        category="ms",
        product_id="kpn4zaf7",
        device_name="Mock Lock",
        product_model="BSTUOKEY",
        product_name="BSTUOKEY",
        functions=[],
        status_range=[],
    )

    with patch.object(manager, "get_device_credentials", return_value=credentials):
        device = TuyaBLEDevice(manager, ble_device)
        await device.initialize()
        device._protocol_version = 4

        # Mock Client
        client = Mock()
        client.is_connected = True
        client.start_notify = AsyncMock()

        # Get characteristic mock setup: fd50 notify exists, classic notify does not
        def get_char(uuid):
            if uuid == "00000002-0000-1001-8001-00805f9b07d0":
                return Mock()
            return None

        client.services.get_characteristic = Mock(side_effect=get_char)
        send_packet = _session_handshake_sender(device)

        with (
            patch(
                "custom_components.tuya_ble.tuya_ble.tuya_ble.establish_connection",
                return_value=client,
            ),
            patch.object(device, "_send_packet_while_connected", send_packet),
        ):
            await device._ensure_connected()

            assert (
                device._characteristic_notify == "00000002-0000-1001-8001-00805f9b07d0"
            )
            assert (
                device._characteristic_write == "00000001-0000-1001-8001-00805f9b07d0"
            )
            _assert_session_bound_notification(
                device,
                client,
                "00000002-0000-1001-8001-00805f9b07d0",
            )
            packets = device._build_packets(
                1,
                TuyaBLECode.FUN_SENDER_DEVICE_INFO,
                b"",
            )
            assert packets[0][2] == 0x40


@pytest.mark.asyncio
async def test_yzd02b_fd50_device_info_handshake(hass: HomeAssistant) -> None:
    """Test the product-scoped TuyaOS login framing required by YZD02B."""
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
    credentials = TuyaBLEDeviceCredentials(
        uuid="12345678901234567890",
        local_key="wV[NcWGUSFF`dSgO",
        device_id="767823809c9c1f458745",
        category="ggq",
        product_id="jntxv3q4",
        device_name="Dual smart irrigation timer",
        product_model="YZD02B",
        product_name="Dual smart irrigation timer",
        functions=[],
        status_range=[],
    )

    with patch.object(manager, "get_device_credentials", return_value=credentials):
        device = TuyaBLEDevice(manager, ble_device)
        await device.initialize()
        device._protocol_version = 4

        client = Mock()
        client.is_connected = True
        client.start_notify = AsyncMock()
        client.services.get_characteristic = Mock(
            side_effect=lambda uuid: (
                Mock() if uuid == "00000002-0000-1001-8001-00805f9b07d0" else None
            )
        )
        send_packet = _session_handshake_sender(device)

        with (
            patch(
                "custom_components.tuya_ble.tuya_ble.tuya_ble.establish_connection",
                return_value=client,
            ),
            patch.object(device, "_send_packet_while_connected", send_packet),
        ):
            await device._ensure_connected()

        _assert_session_bound_notification(
            device,
            client,
            "00000002-0000-1001-8001-00805f9b07d0",
            {"bluez": {"use_start_notify": True}},
        )
        token = device._connection_token
        assert token is not None
        assert send_packet.await_args_list[0] == call(
            TuyaBLECode.FUN_SENDER_DEVICE_INFO,
            b"\x00\xf3",
            0,
            True,
            session_token=token,
        )

        packets = device._build_packets(
            1,
            TuyaBLECode.FUN_SENDER_DEVICE_INFO,
            b"\x00\xf3",
        )
        assert packets[0][2] == 0x20
