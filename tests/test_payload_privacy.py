"""Regression tests for Tuya BLE payload privacy."""

from __future__ import annotations

import ast
import asyncio
import base64
import hashlib
import logging
import re
import string
import traceback
from collections.abc import Iterable
from pathlib import Path
from struct import pack
from unittest.mock import AsyncMock, Mock, patch

import pytest
from bleak.backends.device import BLEDevice
from bleak.exc import BleakError
from Crypto.Cipher import AES

from custom_components.tuya_ble.tuya_ble import (
    TuyaBLEDataPointType,
    TuyaBLEDevice,
)
from custom_components.tuya_ble.tuya_ble.const import TuyaBLECode
from custom_components.tuya_ble.tuya_ble.manager import TuyaBLEDeviceCredentials
from custom_components.tuya_ble.tuya_ble.tuya_ble import ConnectionSessionToken

SYNTHETIC_BLE_ADDRESS = "02:00:00:00:00:01"
SYNTHETIC_DEVICE_ID = "synthetic-privacy-device-id"
SYNTHETIC_UUID = "synthetic-privacy-uuid"
SYNTHETIC_LOCAL_KEY = "synthetic-privacy-local-key"
SYNTHETIC_SEC_KEY = "synthetic-privacy-sec-key"
KNOWN_UNSAFE_PAYLOAD_FINGERPRINTS = frozenset(
    {
        "129dd97116d1f060b4d3fd83e02ee0ad8e44728dbc1d0af96e3522bef3aaa5d7",
        "cb7996566ac58361883a50f62f54f3b76884445ec395563f0e1036e92eae7a5a",
        "e05bd8f8cc379092d17d9a22f26b1c3001c584cec273d54dfaf7641e01fe6167",
    }
)
PRODUCTION_ROOT = Path(__file__).parents[1] / "custom_components" / "tuya_ble"


def _make_device(address: str = SYNTHETIC_BLE_ADDRESS) -> TuyaBLEDevice:
    ble_device = BLEDevice(
        name="payload-privacy-test",
        address=address,
        details="",
        rssi=-50,
    )
    return TuyaBLEDevice(object(), ble_device)


def _install_synthetic_session(
    device: TuyaBLEDevice, client: Mock | None = None
) -> tuple[Mock, ConnectionSessionToken]:
    """Install one exact synthetic session for privacy-focused transport tests."""
    if client is None:
        client = Mock(is_connected=True)
    token = device._claim_connection_session(client)
    device._is_paired = True
    device._notifications_active = True
    device._connected_notified_token = token
    return client, token


def _protected_identifier_forms(device: TuyaBLEDevice) -> set[str]:
    """Return synthetic identifier forms that must never reach logs."""
    address = device.address
    compact_address = address.replace(":", "")
    old_digest = hashlib.sha256(
        f"tuya-ble-log-v1:{address.upper()}".encode()
    ).hexdigest()
    return {
        address,
        address.lower(),
        address.upper(),
        compact_address,
        compact_address.lower(),
        compact_address.upper(),
        address.replace(":", "-"),
        address.replace(":", "_"),
        address.replace(":", "."),
        old_digest,
        old_digest[:12],
        f"tuya-ble-{old_digest[:12]}",
        SYNTHETIC_DEVICE_ID,
        SYNTHETIC_UUID,
        SYNTHETIC_LOCAL_KEY,
        SYNTHETIC_SEC_KEY,
    }


def _set_synthetic_credentials(device: TuyaBLEDevice) -> None:
    device._device_info = TuyaBLEDeviceCredentials(
        uuid=SYNTHETIC_UUID,
        local_key=SYNTHETIC_LOCAL_KEY,
        sec_key=SYNTHETIC_SEC_KEY,
        device_id=SYNTHETIC_DEVICE_ID,
        category="synthetic-category",
        product_id="synthetic-product",
        device_name="Synthetic privacy device",
        product_model="SYNTHETIC",
        product_name="Synthetic privacy device",
        functions=[],
        status_range=[],
    )


def _decoded_candidates(value: object) -> Iterable[bytes]:
    """Yield common literal encodings without exposing their contents."""
    if isinstance(value, bytes):
        yield value
        try:
            text = value.decode("ascii")
        except UnicodeDecodeError:
            return
    elif isinstance(value, str):
        yield value.encode()
        text = value
    elif isinstance(value, list | tuple) and all(
        isinstance(item, int) and 0 <= item <= 255 for item in value
    ):
        yield bytes(value)
        return
    else:
        return

    compact = "".join(text.split())
    if (
        compact
        and len(compact) % 2 == 0
        and all(character in string.hexdigits for character in compact)
    ):
        yield bytes.fromhex(compact)

    try:
        decoded = base64.b64decode(text, validate=True)
    except (ValueError, UnicodeEncodeError):
        return
    if decoded:
        yield decoded


def _source_literal_candidates(source: str) -> Iterable[bytes]:
    tree = ast.parse(source)
    for node in ast.walk(tree):
        try:
            value = ast.literal_eval(node)
        except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
            continue
        yield from _decoded_candidates(value)


def test_production_source_cannot_reproduce_known_unlock_payloads() -> None:
    """Known complete device payloads must not be recoverable from source literals."""
    matches: set[tuple[str, str]] = set()
    for path in PRODUCTION_ROOT.rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        relative_path = str(path.relative_to(PRODUCTION_ROOT))

        for fingerprint in KNOWN_UNSAFE_PAYLOAD_FINGERPRINTS:
            if fingerprint in source:
                matches.add((relative_path, fingerprint))

        for candidate in _source_literal_candidates(source):
            fingerprint = hashlib.sha256(candidate).hexdigest()
            if fingerprint in KNOWN_UNSAFE_PAYLOAD_FINGERPRINTS:
                matches.add((relative_path, fingerprint))

    assert not matches, f"Known unsafe payload fingerprints remain: {sorted(matches)}"


def test_production_logger_calls_do_not_interpolate_sensitive_objects() -> None:
    """Production logger calls must use metadata, never identifiers or exceptions."""
    sensitive_attributes = {
        "address",
        "device_id",
        "local_key",
        "sec_key",
        "uuid",
    }
    sensitive_names = {"client", "err", "error", "exception", "ex"}
    findings: list[str] = []
    logger_calls = 0

    for path in PRODUCTION_ROOT.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        parents = {
            child: parent
            for parent in ast.walk(tree)
            for child in ast.iter_child_nodes(parent)
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr == "log_identity":
                ancestor = parents.get(node)
                while ancestor is not None and not (
                    isinstance(ancestor, ast.Call)
                    and isinstance(ancestor.func, ast.Attribute)
                    and isinstance(ancestor.func.value, ast.Name)
                    and ancestor.func.value.id == "_LOGGER"
                ):
                    ancestor = parents.get(ancestor)
                if ancestor is None:
                    findings.append(f"{path.name}:{node.lineno}:log_identity consumer")
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "_LOGGER"
            ):
                continue
            logger_calls += 1
            arguments = [*node.args, *(keyword.value for keyword in node.keywords)]
            for argument in arguments:
                for child in ast.walk(argument):
                    if isinstance(child, ast.Attribute) and (
                        child.attr in sensitive_attributes
                        or (
                            child.attr == "name"
                            and isinstance(child.value, ast.Name)
                            and child.value.id in {"device", "self"}
                        )
                    ):
                        findings.append(f"{path.name}:{node.lineno}:{child.attr}")
                    if isinstance(child, ast.Name) and child.id in sensitive_names:
                        findings.append(f"{path.name}:{node.lineno}:{child.id}")
            for keyword in node.keywords:
                if keyword.arg in {"exc_info", "stack_info"}:
                    findings.append(f"{path.name}:{node.lineno}:{keyword.arg}")

    assert logger_calls
    assert not findings, f"Sensitive logger arguments remain: {sorted(findings)}"


def test_log_identity_is_opaque_and_bound_to_one_object_lifecycle() -> None:
    """A log label is stable per object but changes for each object lifecycle."""
    first_device = _make_device()
    same_address_new_object = _make_device()
    different_device = _make_device("02:00:00:00:00:02")

    first_label = first_device.log_identity
    assert first_label == first_device.log_identity
    assert (
        len(
            {
                first_label,
                same_address_new_object.log_identity,
                different_device.log_identity,
            }
        )
        == 3
    )
    assert re.fullmatch(r"tuya-ble-session-[ghjkmnpqrstuvwxyz]{16}", first_label)
    assert re.fullmatch(r"[0-9a-fA-F]+", first_label) is None
    assert re.search(r"[0-9a-fA-F]{12}", first_label) is None
    assert re.search(r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", first_label) is None
    assert all(
        value not in first_label for value in _protected_identifier_forms(first_device)
    )


@pytest.mark.asyncio
async def test_lifecycle_and_transport_logs_redact_synthetic_identifiers(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Lifecycle, command, timeout, reconnect, and exception logs stay opaque."""
    device = _make_device()
    _set_synthetic_credentials(device)
    protected_forms = _protected_identifier_forms(device)
    exception_text = "synthetic transport failure " + " ".join(protected_forms)
    caplog.set_level(
        logging.DEBUG,
        logger="custom_components.tuya_ble.tuya_ble.tuya_ble",
    )

    await device.start()
    with patch.object(device, "_send_packet", AsyncMock()):
        await device.update()

    _, token = _install_synthetic_session(device)
    device._build_packets = Mock(return_value=[b"synthetic-fragment"])
    with patch.object(device, "_int_send_packet_while_connected", AsyncMock()):
        await device._send_packet_while_connected(
            TuyaBLECode.FUN_SENDER_PAIR, b"synthetic-pairing-data", 0, False
        )
        await device._send_packet_while_connected(
            TuyaBLECode.FUN_SENDER_DPS, b"synthetic-datapoint-data", 0, False
        )
        with patch(
            "custom_components.tuya_ble.tuya_ble.tuya_ble.RESPONSE_WAIT_TIMEOUT",
            0,
        ):
            assert not await device._send_packet_while_connected(
                TuyaBLECode.FUN_SENDER_DEVICE_STATUS, b"", 0, True
            )

    device._int_send_packets_locked = AsyncMock(side_effect=BleakError(exception_text))
    device._reconnect = AsyncMock()
    with pytest.raises(BleakError) as raised:
        await device._send_packets_locked(token, [b"synthetic-fragment"])
    await asyncio.sleep(0)
    rendered_error = "".join(
        traceback.format_exception(
            type(raised.value), raised.value, raised.value.__traceback__
        )
    )
    assert raised.value.__cause__ is None
    assert raised.value.__suppress_context__
    assert all(value not in rendered_error for value in protected_forms)

    with patch.object(
        device,
        "_ensure_connected",
        AsyncMock(
            side_effect=BleakError(
                f"Bluetooth is already shutdown: {SYNTHETIC_BLE_ADDRESS}"
            )
        ),
    ):
        await TuyaBLEDevice._reconnect(device)

    token.client.is_connected = False
    device._mark_connection_lost(token)
    current_client = Mock(is_connected=True)
    _, current_token = _install_synthetic_session(device, current_client)
    device._disconnected(current_client, current_token)
    device._cancel_reconnect_locked()
    _, notification_token = _install_synthetic_session(device)
    device._input_expected_packet_num = 1
    device._notification_handler(notification_token, 0, device._pack_int(2))

    log_text = caplog.text
    assert device.log_identity in log_text
    for expected_message in (
        "Starting",
        "Updating",
        "FUN_SENDER_PAIR",
        "FUN_SENDER_DPS",
        "timeout receiving response",
        "Transport error without command replay",
        "Bluetooth is already shutdown",
        "unexpectedly disconnected",
        "Packet received",
        "Missing packet",
    ):
        assert expected_message in log_text
    assert all(value not in log_text for value in protected_forms)


@pytest.mark.parametrize("failing_operation", ("stop_notify", "disconnect"))
@pytest.mark.asyncio
async def test_disconnect_transport_errors_redact_synthetic_identifiers(
    failing_operation: str,
) -> None:
    """Foreign disconnect errors cannot bypass redaction through a traceback."""
    device = _make_device()
    _set_synthetic_credentials(device)
    protected_forms = _protected_identifier_forms(device)
    exception_text = "synthetic disconnect failure " + " ".join(protected_forms)
    client = Mock(is_connected=True)
    client.stop_notify = AsyncMock()
    client.disconnect = AsyncMock()
    getattr(client, failing_operation).side_effect = BleakError(exception_text)
    _install_synthetic_session(device, client)

    with pytest.raises(BleakError) as raised:
        await device._execute_disconnect()

    rendered_error = "".join(
        traceback.format_exception(
            type(raised.value), raised.value, raised.value.__traceback__
        )
    )
    assert raised.value.__cause__ is None
    assert raised.value.__suppress_context__
    assert all(value not in rendered_error for value in protected_forms)


def test_payload_values_and_encodings_never_enter_protocol_logs(caplog) -> None:
    """Protocol logs retain metadata without raw, encoded, or credential material."""
    device = _make_device()
    complete_ble_address = device.address
    log_identity = device.log_identity
    assert log_identity == device.log_identity
    assert complete_ble_address not in log_identity
    marker_text = "SYNTHETIC-PAYLOAD-DO-NOT-LOG-" + "".join(
        chr(ord("A") + index % 26) for index in range(24)
    )
    marker = marker_text.encode()
    local_key = "synthetic-key-01"
    sec_key = "synthetic-sec-01"
    uuid = "synthetic-uuid"
    device_id = "synthetic-device-id"
    device._device_info = TuyaBLEDeviceCredentials(
        uuid=uuid,
        local_key=local_key,
        sec_key=sec_key,
        device_id=device_id,
        category="jtmspro",
        product_id="synthetic-product",
        device_name="Synthetic lock",
        product_model="SYNTHETIC",
        product_name="Synthetic lock",
        functions=[],
        status_range=[],
    )
    caplog.set_level(
        logging.DEBUG,
        logger="custom_components.tuya_ble.tuya_ble.tuya_ble",
    )

    _, token = _install_synthetic_session(device)
    incoming = bytes((70, TuyaBLEDataPointType.DT_RAW.value, len(marker))) + marker
    device._parse_datapoints_v3(token, 0, 0, incoming, 0)
    outgoing = device.datapoints.get_or_create(71, TuyaBLEDataPointType.DT_RAW, marker)
    device._encode_datapoints([71], 1)

    key = bytes((index * 7 + 3) % 256 for index in range(16))
    iv = bytes((index * 11 + 5) % 256 for index in range(16))
    decrypted = bytearray(pack(">IIHH", 1, 0, 0x7FFE, len(marker)) + marker)
    decrypted += pack(">H", device._calc_crc16(decrypted))
    while len(decrypted) % 16:
        decrypted += b"\x00"
    encrypted = AES.new(key, AES.MODE_CBC, iv).encrypt(decrypted)
    device._session_key = key
    protected_message = bytes((5,)) + iv + encrypted
    packet = (
        device._pack_int(0)
        + device._pack_int(len(protected_message))
        + bytes((0x30,))
        + protected_message
    )
    device._notification_handler(token, 0, packet)

    assert marker_text not in repr(outgoing)
    assert marker_text not in repr(device.datapoint_log_payload())

    log_text = caplog.text
    assert "id: 70" in log_text
    assert "id: 71" in log_text
    assert "Packet received" in log_text
    assert log_identity in log_text
    protected_forms = {
        complete_ble_address,
        marker_text,
        marker.hex(),
        base64.b64encode(marker).decode(),
        encrypted.hex(),
        base64.b64encode(encrypted).decode(),
        local_key,
        sec_key,
        uuid,
        device_id,
    }
    assert all(value not in log_text for value in protected_forms)
