"""Tests for product-scoped S1 Device Info protocol bootstrapping."""

from __future__ import annotations

from unittest.mock import AsyncMock, Mock, patch

import pytest
from bleak.backends.device import BLEDevice
from bleak_retry_connector import BleakError

from custom_components.tuya_ble.const import ConnectionMode, ConnectionPolicyState
from custom_components.tuya_ble.tuya_ble import TuyaBLEDevice
from custom_components.tuya_ble.tuya_ble.const import (
    CHARACTERISTIC_NOTIFY_FD50,
    TuyaBLECode,
)
from custom_components.tuya_ble.tuya_ble.manager import TuyaBLEDeviceCredentials
from custom_components.tuya_ble.tuya_ble.security import TuyaBLESecurityMaterial


SYNTHETIC_LOCAL_KEY = "SYNTHETICKEY0001"
S1_PRODUCT = ("jtmspro", "xqeob8h6")
V1_PRODUCT = ("ms", "7a4xvbtt")


def _make_device(
    category: str = S1_PRODUCT[0],
    product_id: str = S1_PRODUCT[1],
    *,
    mode: ConnectionMode = ConnectionMode.ALWAYS_CONNECTED,
) -> TuyaBLEDevice:
    device = TuyaBLEDevice(
        Mock(),
        BLEDevice(
            name="Synthetic bootstrap device",
            address="00:00:00:00:00:FE",
            details={},
        ),
        connection_mode=mode.value,
    )
    device._device_info = TuyaBLEDeviceCredentials(
        uuid="synthetic-uuid",
        local_key=SYNTHETIC_LOCAL_KEY,
        device_id="synthetic-device",
        category=category,
        product_id=product_id,
        device_name="Synthetic bootstrap device",
        product_model="SYNTHETIC",
        product_name="Synthetic bootstrap device",
        functions=[],
        status_range=[],
    )
    material = TuyaBLESecurityMaterial(SYNTHETIC_LOCAL_KEY)
    device._security_material = material
    device._local_key = material.pairing_login_key
    device._login_key = material.login_key
    return device


def _header_major(
    device: TuyaBLEDevice,
    code: TuyaBLECode = TuyaBLECode.FUN_SENDER_DEVICE_INFO,
    data: bytes = b"",
) -> int:
    with patch(
        "custom_components.tuya_ble.tuya_ble.tuya_ble.secrets.token_bytes",
        return_value=b"\x11" * 16,
    ):
        packets = device._build_packets(1, code, data)
    _, pos = device._unpack_int(packets[0], 0)
    _, pos = device._unpack_int(packets[0], pos)
    return packets[0][pos] >> 4


def _device_info_response() -> bytes:
    response = bytearray(46)
    response[0:6] = bytes((1, 0, 3, 3, 0, 1))
    response[6:12] = b"RANDOM"
    response[12:14] = bytes((1, 0))
    response[14:46] = b"A" * 32
    return bytes(response)


class _SyntheticBootstrapPeer:
    """Synthetic peer with one explicit accepted Device Info header major."""

    def __init__(
        self,
        device: TuyaBLEDevice,
        *,
        accepted_device_info_major: int | None,
    ) -> None:
        self.device = device
        self.accepted_device_info_major = accepted_device_info_major
        self.is_connected = True
        self.services = Mock()
        self.services.get_characteristic.return_value = object()
        self.stop_notify = AsyncMock()
        self.disconnect = AsyncMock(side_effect=self._disconnect)
        self.start_notify = AsyncMock(side_effect=self._start_notify)
        self.write_gatt_char = AsyncMock(side_effect=self._write)
        self.callback = None
        self.expected_length = 0
        self.received_length = 0
        self.request_index = 0
        self.request_majors: list[int] = []
        self.command_writes = 0

    async def _disconnect(self) -> None:
        self.is_connected = False

    async def _start_notify(self, _characteristic, callback, **_kwargs) -> None:
        self.callback = callback

    async def _write(self, _characteristic, packet: bytes, _response: bool) -> None:
        packet_num, pos = self.device._unpack_int(packet, 0)
        if packet_num == 0:
            self.expected_length, pos = self.device._unpack_int(packet, pos)
            self.request_majors.append(packet[pos] >> 4)
            pos += 1
            self.received_length = 0
        self.received_length += len(packet) - pos
        if self.received_length < self.expected_length:
            return

        response_to = self.device._current_seq_num - 1
        if self.request_index == 0:
            if self.request_majors[-1] == self.accepted_device_info_major:
                peer = _make_device()
                peer._protocol_version = 3
                packets = peer._build_packets(
                    101,
                    TuyaBLECode.FUN_SENDER_DEVICE_INFO,
                    _device_info_response(),
                    response_to=response_to,
                )
                for response_packet in packets:
                    self.callback(0, response_packet)
        elif self.request_index == 1:
            packets = self.device._build_packets(
                102,
                TuyaBLECode.FUN_SENDER_PAIR,
                b"\x00",
                response_to=response_to,
            )
            for response_packet in packets:
                self.callback(0, response_packet)
        else:
            self.command_writes += 1
        self.request_index += 1


async def _connect_to_peer(
    device: TuyaBLEDevice,
    peer: _SyntheticBootstrapPeer,
) -> None:
    with (
        patch(
            "custom_components.tuya_ble.tuya_ble.tuya_ble.establish_connection",
            new=AsyncMock(return_value=peer),
        ),
        patch(
            "custom_components.tuya_ble.tuya_ble.tuya_ble.RESPONSE_WAIT_TIMEOUT",
            0.01,
        ),
        patch(
            "custom_components.tuya_ble.tuya_ble.tuya_ble.secrets.token_bytes",
            return_value=b"\x11" * 16,
        ),
    ):
        async with device.connection_lease(
            "synthetic bootstrap", defer_connection=True
        ):
            await device._ensure_connected()


def test_clean_s1_device_info_uses_product_scoped_major_three() -> None:
    """A clean exact S1 requests Device Info with header major 3."""
    device = _make_device()

    assert device._protocol_version == 2
    assert _header_major(device) == 3
    assert device._protocol_version == 2


def test_s1_handshake_hint_does_not_prematurely_change_negotiated_major() -> None:
    """Building the hinted request leaves negotiated runtime state truthful."""
    device = _make_device()

    _header_major(device)

    assert device._protocol_version == 2


def test_s1_device_info_response_negotiates_reported_major_three() -> None:
    """A valid response remains the only source of the negotiated major."""
    device = _make_device()

    device._handle_command_or_response(
        1,
        0,
        TuyaBLECode.FUN_SENDER_DEVICE_INFO,
        _device_info_response(),
    )

    assert device._protocol_version == 3


async def test_clean_s1_completes_major_three_only_peer_bootstrap() -> None:
    """The real setup flow completes against an exact-major synthetic peer."""
    device = _make_device()
    peer = _SyntheticBootstrapPeer(device, accepted_device_info_major=3)

    await _connect_to_peer(device, peer)

    assert peer.request_majors == [3, 3]
    assert peer.request_index == 2
    assert peer.command_writes == 0
    assert device._protocol_version == 3
    assert device.is_connection_active is True
    assert device.current_session_epoch is not None


async def test_rejected_device_info_never_pairs_writes_or_replays() -> None:
    """Failure before readiness leaves no command or deferred transport work."""
    device = _make_device(mode=ConnectionMode.ON_DEMAND)
    peer = _SyntheticBootstrapPeer(device, accepted_device_info_major=None)

    with pytest.raises(BleakError):
        await _connect_to_peer(device, peer)

    assert peer.request_majors == [3]
    assert peer.request_index == 1
    assert peer.command_writes == 0
    assert device.is_connection_active is False
    assert device.current_session_epoch is None
    assert device.active_lease_count == 0
    assert device.policy_state is ConnectionPolicyState.ON_DEMAND_IDLE
    assert device._input_expected_responses == {}
    assert device._startup_task is None
    assert device._reconnect_task is None
    assert device._idle_disconnect_task is None
    assert device._disconnect_retry_task is None
    assert not device._session_setup_task_tokens
    assert not device._status_task_tokens
    assert not device._response_tasks


def test_generic_v2_device_info_bootstrap_remains_major_two() -> None:
    """The product hint cannot leak into a generic v2 clean runtime."""
    device = _make_device("synthetic-generic", "synthetic-v2-product")

    assert _header_major(device) == 2
    assert device._protocol_version == 2


def test_fd50_device_info_remains_forced_to_major_two() -> None:
    """The existing FD50 major-2 exception has precedence over runtime state."""
    device = _make_device("ggq", "jntxv3q4")
    device._protocol_version = 4
    device._characteristic_notify = CHARACTERISTIC_NOTIFY_FD50

    assert _header_major(device, data=b"\x00\xf3") == 2
    assert device._protocol_version == 4


def test_generic_v4_device_info_bootstrap_remains_major_four() -> None:
    """An unrelated negotiated v4 runtime retains existing wire metadata."""
    device = _make_device("synthetic-generic", "synthetic-v4-product")
    device._protocol_version = 4

    assert _header_major(device) == 4
    assert device._protocol_version == 4


def test_v1_clean_device_info_bootstrap_remains_major_two() -> None:
    """The S1 hint cannot change the exact V1 product bootstrap."""
    device = _make_device(*V1_PRODUCT)

    assert _header_major(device) == 2
    assert device._protocol_version == 2
