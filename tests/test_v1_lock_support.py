"""Contract tests for the Tuya BLE V1 and existing S1 smart locks."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from homeassistant.components.number import NumberEntity, NumberMode
from homeassistant.components.sensor import SensorDeviceClass, SensorStateClass
from homeassistant.const import PERCENTAGE, UnitOfTime
from homeassistant.helpers.entity import EntityCategory

from custom_components.tuya_ble import (
    binary_sensor,
    button,
    devices,
    lock,
    number,
    select,
    sensor,
    switch,
)
from custom_components.tuya_ble.tuya_ble import TuyaBLEDataPointType

V1_DEVICE = SimpleNamespace(category="ms", product_id="7a4xvbtt")
S1_DEVICE = SimpleNamespace(category="jtmspro", product_id="xqeob8h6")
OTHER_MS_DEVICE = SimpleNamespace(category="ms", product_id="not-v1")


def _mapping_by_key(items):
    return {item.description.key: item for item in items}


def test_product_registration_is_product_specific() -> None:
    """V1 resolves centrally while the existing S1 registration stays intact."""
    v1_product = devices.get_product_info_by_ids("ms", "7a4xvbtt")
    assert v1_product is not None
    assert v1_product.name == "V1 Smart Lock"
    assert v1_product.lock == devices.TuyaBLELockInfo(
        alarm_lock=21,
        unlock_ble=19,
        unlock_fingerprint=12,
        unlock_password=13,
    )

    s1_product = devices.get_product_info_by_ids("jtmspro", "xqeob8h6")
    assert s1_product is not None
    assert s1_product.name == "S1-TY-BLE-PRO"

    assert devices.get_product_info_by_ids("ms", "not-v1") is None


def test_v1_sensor_contract() -> None:
    """V1 sensors use only the datapoints and meanings in its diagnostics."""
    mappings = _mapping_by_key(sensor.get_mapping_by_device(V1_DEVICE))
    assert set(mappings) == {"alarm_lock", "battery", "last_unlock_method"}

    battery_mapping = mappings["battery"]
    assert battery_mapping.dp_id == 8
    assert battery_mapping.dp_type is TuyaBLEDataPointType.DT_VALUE
    assert battery_mapping.description.device_class is SensorDeviceClass.BATTERY
    assert battery_mapping.description.native_unit_of_measurement == PERCENTAGE
    assert battery_mapping.description.state_class is SensorStateClass.MEASUREMENT
    assert battery_mapping.description.entity_category is EntityCategory.DIAGNOSTIC

    alarm_mapping = mappings["alarm_lock"]
    assert alarm_mapping.dp_id == 21
    assert alarm_mapping.dp_type is TuyaBLEDataPointType.DT_ENUM
    assert alarm_mapping.description.options == [
        "wrong_finger",
        "wrong_password",
        "wrong_card",
        "low_battery",
    ]

    last_unlock_mapping = mappings["last_unlock_method"]
    assert list(last_unlock_mapping.unlock_methods.items()) == [
        (12, "fingerprint"),
        (13, "password"),
        (14, "dynamic"),
        (15, "card"),
        (19, "ble"),
        (55, "temporary"),
        (62, "phone_remote"),
    ]
    assert last_unlock_mapping.description.device_class is SensorDeviceClass.ENUM


@pytest.mark.parametrize(
    ("raw_value", "expected"),
    [(-1, None), (0, 0), (50, 50), (100, 100), (101, None), (None, None)],
)
def test_v1_battery_special_value(raw_value, expected) -> None:
    """The documented -1 value never becomes a misleading percentage."""
    fake_sensor = SimpleNamespace(
        _device=SimpleNamespace(datapoints={8: SimpleNamespace(value=raw_value)}),
        _attr_native_value="stale",
    )

    sensor.v1_battery_getter(fake_sensor)

    assert fake_sensor._attr_native_value == expected


def test_v1_configuration_and_motor_mappings() -> None:
    """Auto-Lock, delay, and motor status retain their native HA semantics."""
    switch_mappings = _mapping_by_key(switch.get_mapping_by_device(V1_DEVICE))
    assert set(switch_mappings) == {"automatic_lock"}
    auto_lock = switch_mappings["automatic_lock"]
    assert auto_lock.dp_id == 33
    assert auto_lock.dp_type is TuyaBLEDataPointType.DT_BOOL
    assert auto_lock.description.entity_category is EntityCategory.CONFIG
    switch_entity = SimpleNamespace(
        _device=SimpleNamespace(datapoints={33: SimpleNamespace(value=True)})
    )
    assert auto_lock.getter(switch_entity, None) is True
    switch_entity._device.datapoints[33].value = None
    assert auto_lock.getter(switch_entity, None) is None

    number_mappings = _mapping_by_key(number.get_mapping_by_device(V1_DEVICE))
    assert set(number_mappings) == {"auto_lock_time"}
    auto_lock_time = number_mappings["auto_lock_time"]
    assert auto_lock_time.dp_id == 36
    assert auto_lock_time.dp_type is TuyaBLEDataPointType.DT_VALUE
    assert auto_lock_time.description.native_min_value == 5
    assert auto_lock_time.description.native_max_value == 1800
    assert auto_lock_time.description.native_step == 1
    assert auto_lock_time.description.native_unit_of_measurement is UnitOfTime.SECONDS
    assert auto_lock_time.description.entity_category is EntityCategory.CONFIG
    assert auto_lock_time.mode is NumberMode.BOX
    assert issubclass(number.TuyaBLENumber, NumberEntity)
    number_entity = SimpleNamespace(
        _device=SimpleNamespace(datapoints={36: SimpleNamespace(value=1800)})
    )
    assert auto_lock_time.getter(number_entity, None) == 1800
    number_entity._device.datapoints[36].value = 1801
    assert auto_lock_time.getter(number_entity, None) is None

    binary_mappings = _mapping_by_key(binary_sensor.get_mapping_by_device(V1_DEVICE))
    assert set(binary_mappings) == {"lock_motor_state"}
    motor_state = binary_mappings["lock_motor_state"]
    assert motor_state.dp_id == 47
    assert motor_state.dp_type is TuyaBLEDataPointType.DT_BOOL
    assert motor_state.description.entity_category is EntityCategory.DIAGNOSTIC
    assert motor_state.description.device_class is None
    binary_entity = SimpleNamespace(
        _device=SimpleNamespace(datapoints={47: SimpleNamespace(value=False)}),
        _attr_is_on="stale",
    )
    motor_state.getter(binary_entity)
    assert binary_entity._attr_is_on is False
    binary_entity._device.datapoints[47].value = None
    motor_state.getter(binary_entity)
    assert binary_entity._attr_is_on is None


def test_v1_manual_lock_button_only_writes_true() -> None:
    """The momentary DP 46 command never toggles or writes false."""

    class FakeDatapoint:
        value = False

        def __init__(self) -> None:
            self.writes = []

        async def set_value(self, value) -> None:
            self.writes.append(value)

    class FakeDatapoints:
        def __init__(self, datapoint) -> None:
            self.datapoint = datapoint
            self.get_or_create_calls = []

        def get_or_create(self, dp_id, dp_type, value):
            self.get_or_create_calls.append((dp_id, dp_type, value))
            return self.datapoint

    class FakeHass:
        def create_task(self, awaitable):
            self.awaitable = awaitable

    mapping = button.get_mapping_by_device(V1_DEVICE)
    assert len(mapping) == 1
    manual_lock = mapping[0]
    assert manual_lock.description.key == "manual_lock"
    assert manual_lock.dp_id == 46
    assert manual_lock.dp_type is TuyaBLEDataPointType.DT_BOOL
    assert manual_lock.press_value is True

    datapoint = FakeDatapoint()
    datapoints = FakeDatapoints(datapoint)
    hass = FakeHass()
    fake_entity = SimpleNamespace(
        _mapping=manual_lock,
        _device=SimpleNamespace(datapoints=datapoints),
        _hass=hass,
    )

    button.TuyaBLEButton.press(fake_entity)
    asyncio.run(hass.awaitable)

    assert datapoints.get_or_create_calls == [(46, TuyaBLEDataPointType.DT_BOOL, True)]
    assert datapoint.writes == [True]


def test_v1_excludes_speculative_entities_and_unlock() -> None:
    """V1 has no DP 31, raw-security, writable DP 47, or unlock entity."""
    assert select.get_mapping_by_device(V1_DEVICE) == []
    assert lock.get_mapping_by_device(V1_DEVICE) == []
    assert switch.get_mapping_by_device(OTHER_MS_DEVICE) == []
    assert button.get_mapping_by_device(OTHER_MS_DEVICE) == []
    assert number.get_mapping_by_device(OTHER_MS_DEVICE) == []
    assert binary_sensor.get_mapping_by_device(OTHER_MS_DEVICE) == []

    writable_dp_ids = {
        item.dp_id
        for platform_mapping in (
            button.get_mapping_by_device(V1_DEVICE),
            number.get_mapping_by_device(V1_DEVICE),
            switch.get_mapping_by_device(V1_DEVICE),
        )
        for item in platform_mapping
    }
    assert writable_dp_ids == {33, 36, 46}
    assert 31 not in writable_dp_ids
    assert 47 not in writable_dp_ids


def test_existing_s1_lock_sequences_are_unchanged() -> None:
    """The production S1 still uses its existing DP 70/71 and DP 46 paths."""
    mappings = lock.get_mapping_by_device(S1_DEVICE)
    assert len(mappings) == 1
    assert mappings[0].description.key == "ble_unlock_lock"

    calls = []
    fake_lock = SimpleNamespace(
        _attr_is_unlocking=False,
        _attr_is_locking=False,
        async_write_ha_state=lambda: None,
        _get_dp70_bytes=lambda: b"synthetic-dp70",
        _get_dp71_template_bytes=lambda: b"unused",
        _build_dp71_payload=lambda: b"synthetic-dp71",
    )

    async def send_raw(dp_id, value):
        calls.append(("raw", dp_id, value))

    async def send_bool(dp_id, value):
        calls.append(("bool", dp_id, value))

    fake_lock._send_raw_dp_bytes = send_raw
    fake_lock._send_bool_dp = send_bool

    with patch.object(lock.asyncio, "sleep", new=AsyncMock()):
        asyncio.run(lock.TuyaBLELock._unlock_sequence(fake_lock))
    asyncio.run(lock.TuyaBLELock._lock_sequence(fake_lock))

    assert calls == [
        ("raw", 70, b"synthetic-dp70"),
        ("raw", 71, b"synthetic-dp71"),
        ("bool", 46, True),
    ]


def test_v1_translation_and_manifest_contract() -> None:
    """Entity states are translated and the integration patch version is bumped."""
    root = Path(__file__).parents[1]
    translation = json.loads(
        (root / "custom_components/tuya_ble/translations/en.json").read_text()
    )
    manifest = json.loads(
        (root / "custom_components/tuya_ble/manifest.json").read_text()
    )

    assert translation["entity"]["sensor"]["alarm_lock"]["state"] == {
        "low_battery": "Low battery",
        "wrong_card": "Wrong card",
        "wrong_finger": "Wrong fingerprint",
        "wrong_password": "Wrong password",
    }
    assert set(translation["entity"]["sensor"]["last_unlock_method"]["state"]) == {
        "ble",
        "card",
        "dynamic",
        "fingerprint",
        "password",
        "phone_remote",
        "temporary",
    }
    assert manifest["version"] == "0.1.11b1"
