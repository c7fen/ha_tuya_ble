"""Regression tests for Tuya BLE payload privacy."""

from __future__ import annotations

import ast
import base64
from collections.abc import Iterable
import hashlib
import logging
from pathlib import Path
import string
from struct import pack

from bleak.backends.device import BLEDevice
from Crypto.Cipher import AES

from custom_components.tuya_ble.tuya_ble import (
    TuyaBLEDataPointType,
    TuyaBLEDevice,
)
from custom_components.tuya_ble.tuya_ble.manager import TuyaBLEDeviceCredentials


KNOWN_UNSAFE_PAYLOAD_FINGERPRINTS = frozenset(
    {
        "129dd97116d1f060b4d3fd83e02ee0ad8e44728dbc1d0af96e3522bef3aaa5d7",
        "cb7996566ac58361883a50f62f54f3b76884445ec395563f0e1036e92eae7a5a",
        "e05bd8f8cc379092d17d9a22f26b1c3001c584cec273d54dfaf7641e01fe6167",
    }
)
PRODUCTION_ROOT = Path(__file__).parents[1] / "custom_components" / "tuya_ble"


def _make_device() -> TuyaBLEDevice:
    ble_device = BLEDevice(
        name="payload-privacy-test",
        address="11:22:33:44:55:66",
        details="",
        rssi=-50,
    )
    return TuyaBLEDevice(object(), ble_device)


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

    incoming = bytes((70, TuyaBLEDataPointType.DT_RAW.value, len(marker))) + marker
    device._parse_datapoints_v3(0, 0, incoming, 0)
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
    device._notification_handler(0, packet)

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
