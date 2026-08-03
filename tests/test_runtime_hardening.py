"""Regression tests for lock-event and protocol-log hardening."""

from __future__ import annotations

import asyncio
import inspect
import logging
from datetime import timedelta
from struct import pack
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest
from Crypto.Cipher import AES
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.entity_platform import EntityPlatform

from custom_components.tuya_ble import (
    binary_sensor,
    button,
    devices,
    number,
    select,
    sensor,
    switch,
)
from custom_components.tuya_ble.const import DOMAIN
from custom_components.tuya_ble.tuya_ble import TuyaBLEDevice
from custom_components.tuya_ble.tuya_ble.const import TuyaBLECode
from custom_components.tuya_ble.tuya_ble.exceptions import TuyaBLEDataLengthError

V1_DEVICE = SimpleNamespace(category="ms", product_id="7a4xvbtt")
S1_DEVICE = SimpleNamespace(category="jtmspro", product_id="xqeob8h6")
LOCK_PRODUCTS = (V1_DEVICE, S1_DEVICE)

SYNTHETIC_ADDRESS = "AA:BB:CC:DD:EE:FF"
PRIVATE_MARKER = b"SUPER_SECRET_PAYLOAD_MARKER_7B8D"
SESSION_KEY = bytes(range(16))
IV = bytes(range(16, 32))


def _mapping_by_key(items):
    return {item.description.key: item for item in items}


def _unlock_methods(device):
    return _mapping_by_key(sensor.get_mapping_by_device(device))[
        "last_unlock_method"
    ].unlock_methods


class BatchDatapoint:
    """Synthetic datapoint from exactly one device callback batch."""

    def __init__(
        self,
        dp_id: int,
        value=1,
        *,
        changed_by_device: bool = False,
        timestamp: float = 1234.0,
    ) -> None:
        self.id = dp_id
        self.value = value
        self.changed_by_device = changed_by_device
        self.timestamp = timestamp


class LastUnlockHarness:
    """Drive the Last Unlock Method entity with coordinator callback batches."""

    def __init__(self, unlock_methods) -> None:
        self.coordinator = SimpleNamespace(
            available=True,
            last_update_datapoints=(),
            last_update_sequence=0,
        )
        self.writes: list[bool] = []
        self.entity: Any = SimpleNamespace(
            _unlock_methods=unlock_methods,
            _coordinator=self.coordinator,
            _last_update_sequence=0,
            _last_coordinator_available=True,
            _attr_native_value=None,
            _attr_extra_state_attributes={},
            async_write_ha_state=lambda: self.writes.append(True),
        )

    def emit(self, *datapoints: BatchDatapoint) -> None:
        self.coordinator.last_update_sequence += 1
        self.coordinator.last_update_datapoints = datapoints
        sensor.TuyaBLELastUnlockSensor._handle_coordinator_update(self.entity)


def test_passive_coordinator_publishes_only_the_current_callback_batch() -> None:
    """The coordinator replaces its batch before notifying entity listeners."""
    coordinator: Any = object.__new__(devices.TuyaBLEPassiveCoordinator)
    coordinator._device = SimpleNamespace(category="unknown", product_id="unknown")
    coordinator._disconnected = False
    coordinator._unsub_disconnect = None
    coordinator._last_update_datapoints = ()
    coordinator._last_update_sequence = 0
    observed = []
    coordinator.async_update_listeners = lambda: observed.append(
        (coordinator.last_update_sequence, coordinator.last_update_datapoints)
    )
    first = BatchDatapoint(12, 1)
    second = BatchDatapoint(15, 2)

    devices.TuyaBLEPassiveCoordinator._async_handle_update(
        coordinator, cast(Any, [first])
    )
    devices.TuyaBLEPassiveCoordinator._async_handle_update(
        coordinator, cast(Any, [second])
    )

    assert observed == [(1, (first,)), (2, (second,))]
    assert coordinator.last_update_sequence == 2
    assert coordinator.last_update_datapoints == (second,)


@pytest.mark.parametrize("product", LOCK_PRODUCTS, ids=("v1", "s1"))
def test_full_initial_snapshot_does_not_invent_unlock_method(product) -> None:
    """Equal-timestamp cached snapshot values do not become an event."""
    unlock_methods = _unlock_methods(product)
    harness = LastUnlockHarness(unlock_methods)

    harness.emit(*(BatchDatapoint(dp_id, timestamp=42.0) for dp_id in unlock_methods))

    assert harness.entity._attr_native_value is None
    assert harness.entity._attr_extra_state_attributes == {}
    assert harness.writes == []


@pytest.mark.parametrize("product", LOCK_PRODUCTS, ids=("v1", "s1"))
def test_full_status_snapshot_preserves_recorded_event(product) -> None:
    """A later ambiguous status snapshot cannot overwrite a real event."""
    unlock_methods = _unlock_methods(product)
    harness = LastUnlockHarness(unlock_methods)
    harness.emit(BatchDatapoint(19, 7))
    previous_attributes = harness.entity._attr_extra_state_attributes.copy()

    harness.emit(*(BatchDatapoint(dp_id, 0) for dp_id in unlock_methods))

    assert harness.entity._attr_native_value == "ble"
    assert harness.entity._attr_extra_state_attributes == previous_attributes
    assert len(harness.writes) == 1


@pytest.mark.parametrize("product", LOCK_PRODUCTS, ids=("v1", "s1"))
@pytest.mark.parametrize(
    ("dp_id", "method"),
    ((12, "fingerprint"), (15, "card"), (19, "ble")),
)
def test_single_unlock_datapoint_reports_method(product, dp_id, method) -> None:
    """One mapped datapoint is the unambiguous event for its callback batch."""
    harness = LastUnlockHarness(_unlock_methods(product))

    harness.emit(BatchDatapoint(dp_id, 8))

    assert harness.entity._attr_native_value == method
    assert harness.entity._attr_extra_state_attributes == {
        "method": method,
        "value": 8,
    }


@pytest.mark.parametrize("product", LOCK_PRODUCTS, ids=("v1", "s1"))
def test_repeated_same_credential_remains_a_new_event(product) -> None:
    """A new single-DP callback is accepted even when its value is unchanged."""
    harness = LastUnlockHarness(_unlock_methods(product))

    harness.emit(BatchDatapoint(12, 9, changed_by_device=False))
    harness.emit(BatchDatapoint(12, 9, changed_by_device=False))

    assert harness.entity._attr_native_value == "fingerprint"
    assert harness.entity._attr_extra_state_attributes["value"] == 9
    assert len(harness.writes) == 2
    entity = object.__new__(sensor.TuyaBLELastUnlockSensor)
    assert entity.force_update is True


@pytest.mark.parametrize("product", LOCK_PRODUCTS, ids=("v1", "s1"))
def test_one_changed_candidate_resolves_multi_datapoint_batch(product) -> None:
    """Exactly one changed candidate disambiguates a multi-method callback."""
    harness = LastUnlockHarness(_unlock_methods(product))

    harness.emit(
        BatchDatapoint(12, 3),
        BatchDatapoint(15, 4, changed_by_device=True),
    )

    assert harness.entity._attr_native_value == "card"
    assert harness.entity._attr_extra_state_attributes["value"] == 4


@pytest.mark.parametrize("product", LOCK_PRODUCTS, ids=("v1", "s1"))
def test_multiple_changed_candidates_preserve_prior_state(product) -> None:
    """Multiple changed methods are ambiguous and never use mapping order."""
    harness = LastUnlockHarness(_unlock_methods(product))
    harness.emit(BatchDatapoint(19, 5))

    harness.emit(
        BatchDatapoint(12, 6, changed_by_device=True),
        BatchDatapoint(15, 7, changed_by_device=True),
    )

    assert harness.entity._attr_native_value == "ble"
    assert harness.entity._attr_extra_state_attributes == {
        "method": "ble",
        "value": 5,
    }
    assert len(harness.writes) == 1


@pytest.mark.parametrize("product", LOCK_PRODUCTS, ids=("v1", "s1"))
def test_unmapped_batch_preserves_prior_state(product) -> None:
    """A callback without an unlock datapoint leaves the event unchanged."""
    harness = LastUnlockHarness(_unlock_methods(product))
    harness.emit(BatchDatapoint(12, 2))

    harness.emit(BatchDatapoint(250, 99, changed_by_device=True))

    assert harness.entity._attr_native_value == "fingerprint"
    assert harness.entity._attr_extra_state_attributes == {
        "method": "fingerprint",
        "value": 2,
    }
    assert len(harness.writes) == 1


@pytest.mark.parametrize("product", LOCK_PRODUCTS, ids=("v1", "s1"))
def test_last_unlock_attributes_never_expose_raw_bytes(product) -> None:
    """A malformed raw value cannot become a sensor state attribute."""
    harness = LastUnlockHarness(_unlock_methods(product))

    harness.emit(BatchDatapoint(12, PRIVATE_MARKER))

    assert harness.entity._attr_native_value == "fingerprint"
    assert harness.entity._attr_extra_state_attributes == {"method": "fingerprint"}


def _protocol_device() -> TuyaBLEDevice:
    device = TuyaBLEDevice(
        cast(Any, None),
        cast(
            Any,
            SimpleNamespace(address=SYNTHETIC_ADDRESS, name="Synthetic lock"),
        ),
    )
    device._session_key = SESSION_KEY
    return device


def _encrypted_input(
    device: TuyaBLEDevice,
    code: TuyaBLECode | int,
    data: bytes,
    *,
    trailing_plaintext: bytes = PRIVATE_MARKER,
) -> bytearray:
    numeric_code = code.value if isinstance(code, TuyaBLECode) else code
    raw = bytearray(pack(">IIHH", 1, 0, numeric_code, len(data)))
    raw += data
    raw += pack(">H", device._calc_crc16(bytes(raw)))
    raw += trailing_plaintext
    while len(raw) % 16:
        raw += b"\x00"
    encrypted = AES.new(SESSION_KEY, AES.MODE_CBC, IV).encrypt(raw)
    return bytearray(b"\x05" + IV + encrypted)


def _assert_private_values_absent(caplog) -> None:
    rendered = caplog.text
    assert PRIVATE_MARKER.decode() not in rendered
    assert PRIVATE_MARKER.hex() not in rendered.lower()
    assert SYNTHETIC_ADDRESS not in rendered


def test_successful_parser_is_debug_only_and_payload_free(caplog) -> None:
    """A valid packet logs only safe DEBUG metadata."""
    caplog.set_level(
        logging.DEBUG,
        logger="custom_components.tuya_ble.tuya_ble.tuya_ble",
    )
    device = _protocol_device()
    device._input_buffer = _encrypted_input(
        device,
        TuyaBLECode.FUN_SENDER_DEVICE_STATUS,
        b"\x00",
    )

    device._parse_input()

    assert device._input_buffer is None
    assert not [
        record for record in caplog.records if record.levelno >= logging.WARNING
    ]
    assert "JTMSPRO command" in caplog.text
    _assert_private_values_absent(caplog)


def test_successful_notification_is_debug_only_and_payload_free(caplog) -> None:
    """Notification assembly and parsing never log its bytes or address."""
    caplog.set_level(
        logging.DEBUG,
        logger="custom_components.tuya_ble.tuya_ble.tuya_ble",
    )
    device = _protocol_device()
    encrypted_input = _encrypted_input(
        device,
        TuyaBLECode.FUN_SENDER_DEVICE_STATUS,
        b"\x00",
    )
    notification = bytearray()
    notification += device._pack_int(0)
    notification += device._pack_int(len(encrypted_input))
    notification += b"\x20"
    notification += encrypted_input

    device._notification_handler(1, notification)

    assert device._input_buffer is None
    assert not [
        record for record in caplog.records if record.levelno >= logging.WARNING
    ]
    assert "JTMSPRO notification" in caplog.text
    _assert_private_values_absent(caplog)


def test_parser_failure_logs_safe_metadata_only(caplog) -> None:
    """A parser exception identifies its phase without logging input bytes."""
    caplog.set_level(
        logging.DEBUG,
        logger="custom_components.tuya_ble.tuya_ble.tuya_ble",
    )
    device = _protocol_device()
    invalid_encrypted = PRIVATE_MARKER
    if len(invalid_encrypted) % 16 == 0:
        invalid_encrypted += b"!"
    device._input_buffer = bytearray(b"\x05" + IV + invalid_encrypted)

    with pytest.raises(TuyaBLEDataLengthError):
        device._parse_input()

    assert any(record.levelno >= logging.ERROR for record in caplog.records)
    assert "phase=key-selection" in caplog.text
    _assert_private_values_absent(caplog)


def test_unknown_command_logs_code_and_length_but_not_data(caplog) -> None:
    """Unknown commands retain diagnostics without exposing command bytes."""
    caplog.set_level(
        logging.DEBUG,
        logger="custom_components.tuya_ble.tuya_ble.tuya_ble",
    )
    device = _protocol_device()
    device._input_buffer = _encrypted_input(
        device,
        0x7BAD,
        PRIVATE_MARKER,
        trailing_plaintext=b"",
    )

    device._parse_input()

    assert "code=0x7bad" in caplog.text
    assert f"data_len={len(PRIVATE_MARKER)}" in caplog.text
    _assert_private_values_absent(caplog)


def test_protocol_source_rejects_raw_logging_regressions() -> None:
    """Known raw-value logging forms stay absent from protocol code."""
    source = "\n".join(
        inspect.getsource(method)
        for method in (
            TuyaBLEDevice._parse_input,
            TuyaBLEDevice._notification_handler,
            TuyaBLEDevice._parse_datapoints_v3,
            TuyaBLEDevice._send_datapoints_v3,
        )
    )

    for forbidden in (
        "input_buffer.hex(",
        "encrypted.hex(",
        "raw.hex(",
        "data.hex(",
        "buffer_hex",
        "value: %s",
        "dp.value",
    ):
        assert forbidden not in source


class DomainDatapoints:
    """Minimal datapoint collection for entity construction."""

    def __getitem__(self, dp_id):
        return None

    def has_id(self, dp_id, dp_type=None):
        return True


class DomainCoordinator:
    """Minimal passive coordinator used during platform entity creation."""

    available = True
    last_update_datapoints = ()
    last_update_sequence = 0

    def async_add_listener(self, update_callback, context=None):
        return lambda: None


def _domain_device(category: str, product_id: str, suffix: str):
    return SimpleNamespace(
        address=f"synthetic:device:{suffix}",
        category=category,
        product_id=product_id,
        device_id=f"synthetic-device-{suffix}",
        name="Synthetic lock",
        product_model="Synthetic model",
        hardware_version="test",
        device_version="test",
        protocol_version="test",
        datapoints=DomainDatapoints(),
    )


def _new_platform(hass: HomeAssistant, domain: str) -> EntityPlatform:
    return EntityPlatform(
        hass=hass,
        logger=logging.getLogger(f"test.{domain}"),
        domain=domain,
        platform_name=DOMAIN,
        platform=None,
        scan_interval=timedelta(seconds=30),
        entity_namespace=None,
    )


def _skip_entity_finish(entity: Any) -> None:
    """Keep the domain smoke test focused on registry assignment."""
    entity.add_to_platform_finish = AsyncMock()


def test_new_entities_use_platform_domains_and_preserve_registry_ids(
    tmp_path, caplog
) -> None:
    """HA 2026.7.4 assigns platform domains without mismatch warnings."""

    async def exercise() -> None:
        hass = HomeAssistant(str(tmp_path))
        dr.async_setup(hass)
        await dr.async_load(hass, load_empty=True)
        await er.async_load(hass, load_empty=True)
        coordinator: Any = DomainCoordinator()
        v1_device = _domain_device("ms", "7a4xvbtt", "v1")
        s1_device = _domain_device("jtmspro", "xqeob8h6", "s1")
        v1_product = devices.get_product_info_by_ids("ms", "7a4xvbtt")
        s1_product = devices.get_product_info_by_ids("jtmspro", "xqeob8h6")
        assert v1_product is not None
        assert s1_product is not None

        v1_switch = _mapping_by_key(switch.get_mapping_by_device(v1_device))[
            "automatic_lock"
        ]
        entities = (
            (
                "switch",
                switch.TuyaBLESwitch(
                    hass, coordinator, v1_device, v1_product, v1_switch
                ),
            ),
            (
                "number",
                number.TuyaBLENumber(
                    hass,
                    coordinator,
                    v1_device,
                    v1_product,
                    number.get_mapping_by_device(v1_device)[0],
                ),
            ),
            (
                "button",
                button.TuyaBLEButton(
                    hass,
                    coordinator,
                    v1_device,
                    v1_product,
                    button.get_mapping_by_device(v1_device)[0],
                ),
            ),
            (
                "binary_sensor",
                binary_sensor.TuyaBLEBinarySensor(
                    hass,
                    coordinator,
                    v1_device,
                    v1_product,
                    binary_sensor.get_mapping_by_device(v1_device)[0],
                ),
            ),
            (
                "select",
                select.TuyaBLESelect(
                    hass,
                    coordinator,
                    s1_device,
                    s1_product,
                    select.get_mapping_by_device(s1_device)[0],
                ),
            ),
        )

        registry = er.async_get(hass)
        for expected_domain, entity in entities:
            assert entity.entity_id is None
            _skip_entity_finish(entity)
            platform = _new_platform(hass, expected_domain)
            await platform._async_add_entity(entity, False, registry, None)
            assert entity.entity_id.startswith(f"{expected_domain}.")

        preserved_device = _domain_device("ms", "7a4xvbtt", "preserved")
        preserved_entity = switch.TuyaBLESwitch(
            hass,
            coordinator,
            preserved_device,
            v1_product,
            v1_switch,
        )
        assert preserved_entity.unique_id is not None
        existing = registry.async_get_or_create(
            "switch",
            DOMAIN,
            preserved_entity.unique_id,
            suggested_object_id="preserved_existing_name",
        )
        _skip_entity_finish(preserved_entity)
        await _new_platform(hass, "switch")._async_add_entity(
            preserved_entity,
            False,
            registry,
            None,
        )
        assert preserved_entity.entity_id == existing.entity_id

    caplog.set_level(logging.WARNING)
    asyncio.run(exercise())

    assert "wrong domain" not in caplog.text.lower()
