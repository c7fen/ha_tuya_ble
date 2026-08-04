"""Contract tests for the product-specific S1 smart-lock entities."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from homeassistant.components.number import NumberEntity, NumberMode
from homeassistant.components.sensor import SensorDeviceClass, SensorEntity
from homeassistant.const import UnitOfTime
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

S1_DEVICE = SimpleNamespace(category="jtmspro", product_id="xqeob8h6")
V1_DEVICE = SimpleNamespace(category="ms", product_id="7a4xvbtt")
OTHER_JTMS_DEVICE = SimpleNamespace(category="jtmspro", product_id="not-s1")

S1_ALARM_OPTIONS = [
    "wrong_finger",
    "wrong_password",
    "wrong_card",
    "wrong_face",
    "tongue_bad",
    "too_hot",
    "unclosed_time",
    "tongue_not_out",
    "pry",
    "key_in",
    "low_battery",
    "power_off",
    "shock",
    "defense",
]

S1_LAST_UNLOCK_METHODS = {
    12: "fingerprint",
    15: "card",
    16: "key",
    19: "ble",
    62: "phone_remote",
    63: "voice_remote",
}


def _mapping_by_key(items):
    return {item.description.key: item for item in items}


class FakeDatapoint:
    """Synthetic datapoint that records local write values."""

    def __init__(
        self,
        value=None,
        *,
        timestamp=None,
        dp_id=None,
        changed_by_device=False,
    ) -> None:
        self.id = dp_id
        self.value = value
        self.timestamp = timestamp
        self.changed_by_device = changed_by_device
        self.writes = []

    async def set_value(self, value) -> None:
        self.writes.append(value)


class FakeDatapoints:
    """Small datapoint collection matching the integration's used API."""

    def __init__(self, values=None) -> None:
        self.values = values or {}
        self.get_or_create_calls = []

    def __getitem__(self, dp_id):
        return self.values.get(dp_id)

    def get_or_create(self, dp_id, dp_type, value):
        self.get_or_create_calls.append((dp_id, dp_type, value))
        return self.values.setdefault(dp_id, FakeDatapoint(value))

    def has_id(self, dp_id, dp_type=None):
        return dp_id in self.values


class FakeHass:
    """Collect integration-created coroutines so tests can execute them."""

    def __init__(self) -> None:
        self.awaitables = []

    def create_task(self, awaitable) -> None:
        self.awaitables.append(awaitable)

    def run_tasks(self) -> None:
        while self.awaitables:
            asyncio.run(self.awaitables.pop(0))


def test_s1_product_recognition_remains_product_specific() -> None:
    """S1 and V1 retain their central product registrations."""
    s1_product = devices.get_product_info_by_ids("jtmspro", "xqeob8h6")
    assert s1_product is not None
    assert s1_product.name == "S1-TY-BLE-PRO"

    v1_product = devices.get_product_info_by_ids("ms", "7a4xvbtt")
    assert v1_product is not None
    assert v1_product.name == "V1 Smart Lock"

    assert devices.get_product_info_by_ids("jtmspro", "not-s1") is None


def test_s1_sensor_contract() -> None:
    """S1 exposes the exact alarm, last-unlock, and Door State metadata."""
    mappings = _mapping_by_key(sensor.get_mapping_by_device(S1_DEVICE))
    assert set(mappings) == {
        "alarm_lock",
        "battery",
        "closed_opened",
        "last_unlock_method",
    }

    alarm = mappings["alarm_lock"]
    assert alarm.dp_id == 21
    assert alarm.dp_type is TuyaBLEDataPointType.DT_ENUM
    assert alarm.description.translation_key == "s1_alarm_lock"
    assert alarm.description.device_class is SensorDeviceClass.ENUM
    assert alarm.description.entity_category is EntityCategory.DIAGNOSTIC
    assert alarm.description.options == S1_ALARM_OPTIONS
    assert alarm.description.options[2] == "wrong_card"

    last_unlock = mappings["last_unlock_method"]
    assert last_unlock.unlock_methods == S1_LAST_UNLOCK_METHODS
    assert list(last_unlock.unlock_methods) == [12, 15, 16, 19, 62, 63]
    assert last_unlock.description.translation_key == "s1_last_unlock_method"
    assert last_unlock.description.options == list(S1_LAST_UNLOCK_METHODS.values())
    assert not {"password", "dynamic", "temporary"} & set(
        last_unlock.description.options
    )

    door = mappings["closed_opened"]
    assert door.dp_id == 40
    assert door.dp_type is TuyaBLEDataPointType.DT_ENUM
    assert door.description.device_class is SensorDeviceClass.ENUM
    assert door.description.entity_category is EntityCategory.DIAGNOSTIC
    assert door.description.entity_registry_enabled_default is False
    assert door.description.options == ["unknown", "open", "closed"]
    assert issubclass(sensor.TuyaBLESensor, SensorEntity)


@pytest.mark.parametrize(
    ("raw_value", "expected"),
    [(2, "wrong_card"), (13, "defense"), (99, 99)],
)
def test_s1_alarm_enum_decoding_preserves_unknown_values(raw_value, expected) -> None:
    """Known alarm indexes decode in order and unknown indexes remain raw."""
    alarm = _mapping_by_key(sensor.get_mapping_by_device(S1_DEVICE))["alarm_lock"]
    fake_sensor = SimpleNamespace(
        entity_description=alarm.description,
        _mapping=alarm,
        _attr_native_value=None,
    )

    sensor.TuyaBLESensor._handle_enum_value(fake_sensor, None, raw_value)

    assert fake_sensor._attr_native_value == expected


def test_s1_last_unlock_starts_unknown_and_uses_current_update_batch() -> None:
    """No method is invented before an S1 unlock datapoint callback arrives."""
    coordinator = SimpleNamespace(
        available=True,
        last_update_datapoints=(),
        last_update_sequence=0,
    )
    writes = []
    fake_sensor: Any = SimpleNamespace(
        _unlock_methods=S1_LAST_UNLOCK_METHODS,
        _coordinator=coordinator,
        _last_update_sequence=0,
        _last_coordinator_available=True,
        _attr_native_value=None,
        _attr_extra_state_attributes={},
        async_write_ha_state=lambda: writes.append(True),
    )

    sensor.TuyaBLELastUnlockSensor._handle_coordinator_update(fake_sensor)
    assert fake_sensor._attr_native_value is None
    assert fake_sensor._attr_extra_state_attributes == {}

    coordinator.last_update_sequence = 1
    coordinator.last_update_datapoints = (
        FakeDatapoint(1, dp_id=16, changed_by_device=True),
    )
    sensor.TuyaBLELastUnlockSensor._handle_coordinator_update(fake_sensor)
    assert fake_sensor._attr_native_value == "key"
    assert fake_sensor._attr_extra_state_attributes == {"method": "key", "value": 1}
    assert len(writes) == 1


def test_s1_auto_lock_switch_contract_and_writes() -> None:
    """Only S1 gets the Boolean DP 33 Auto-Lock configuration switch."""
    mapping_items = switch.get_mapping_by_device(S1_DEVICE)
    assert sum(item.description.key == "automatic_lock" for item in mapping_items) == 1
    mappings = _mapping_by_key(mapping_items)
    assert set(mappings) == {"automatic_lock"}

    auto_lock = mappings["automatic_lock"]
    assert auto_lock.dp_id == 33
    assert auto_lock.dp_type is TuyaBLEDataPointType.DT_BOOL
    assert auto_lock.description.entity_category is EntityCategory.CONFIG
    assert switch.get_mapping_by_device(OTHER_JTMS_DEVICE) == []

    datapoints = FakeDatapoints({33: FakeDatapoint(True)})
    hass = FakeHass()
    fake_entity = SimpleNamespace(
        _mapping=auto_lock,
        _product=None,
        _device=SimpleNamespace(datapoints=datapoints),
        _hass=hass,
    )
    assert auto_lock.getter(fake_entity, None) is True
    datapoints.values[33].value = None
    assert auto_lock.getter(fake_entity, None) is None

    switch.TuyaBLESwitch.turn_on(fake_entity)
    switch.TuyaBLESwitch.turn_off(fake_entity)
    hass.run_tasks()

    assert datapoints.get_or_create_calls == [
        (33, TuyaBLEDataPointType.DT_BOOL, True),
        (33, TuyaBLEDataPointType.DT_BOOL, False),
    ]
    assert datapoints.values[33].writes == [True, False]


@pytest.mark.parametrize(
    ("raw_value", "expected"),
    [(1, 1.0), (1800, 1800.0), (0, None), (1801, None), (True, None)],
)
def test_s1_auto_lock_delay_readback_range(raw_value, expected) -> None:
    """S1 accepts only reported integer delays in its 1..1800 range."""
    mapping = number.get_mapping_by_device(S1_DEVICE)[0]
    fake_entity = SimpleNamespace(
        _device=SimpleNamespace(
            datapoints=FakeDatapoints({36: FakeDatapoint(raw_value)})
        )
    )

    assert mapping.getter(fake_entity, None) == expected


def test_s1_auto_lock_delay_contract_and_integer_write() -> None:
    """The S1 delay uses native HA number semantics without changing V1."""
    s1_mappings = number.get_mapping_by_device(S1_DEVICE)
    assert len(s1_mappings) == 1
    delay = s1_mappings[0]
    assert delay.description.key == "auto_lock_time"
    assert delay.dp_id == 36
    assert delay.dp_type is TuyaBLEDataPointType.DT_VALUE
    assert delay.description.native_min_value == 1
    assert delay.description.native_max_value == 1800
    assert delay.description.native_step == 1
    assert delay.description.native_unit_of_measurement is UnitOfTime.SECONDS
    assert delay.description.entity_category is EntityCategory.CONFIG
    assert delay.mode is NumberMode.BOX
    assert issubclass(number.TuyaBLENumber, NumberEntity)
    assert number.get_mapping_by_device(OTHER_JTMS_DEVICE) == []

    v1_delay = number.get_mapping_by_device(V1_DEVICE)[0]
    assert v1_delay.description.native_min_value == 5
    assert v1_delay.description.native_max_value == 1800

    datapoints = FakeDatapoints()
    fake_entity = SimpleNamespace(
        _mapping=delay,
        _product=None,
        _device=SimpleNamespace(datapoints=datapoints),
    )
    asyncio.run(number.TuyaBLENumber.async_set_native_value(fake_entity, 45))

    assert datapoints.get_or_create_calls == [(36, TuyaBLEDataPointType.DT_VALUE, 45)]
    assert datapoints.values[36].writes == [45]


def test_s1_authentication_select_contract_and_enum_write() -> None:
    """Only S1 gets the exact two-option DP 34 authentication mode."""
    mappings = select.get_mapping_by_device(S1_DEVICE)
    assert len(mappings) == 1
    authentication = mappings[0]
    assert authentication.description.key == "unlock_switch"
    assert authentication.dp_id == 34
    assert authentication.dp_type is TuyaBLEDataPointType.DT_ENUM
    assert authentication.description.options == ["single_unlock", "finger_card"]
    assert authentication.description.entity_category is EntityCategory.CONFIG
    assert select.get_mapping_by_device(OTHER_JTMS_DEVICE) == []
    assert select.get_mapping_by_device(V1_DEVICE) == []

    datapoints = FakeDatapoints()
    hass = FakeHass()
    fake_entity = SimpleNamespace(
        _mapping=authentication,
        _attr_options=authentication.description.options,
        _device=SimpleNamespace(datapoints=datapoints),
        _hass=hass,
    )
    select.TuyaBLESelect.select_option(fake_entity, "finger_card")
    hass.run_tasks()

    assert datapoints.get_or_create_calls == [(34, TuyaBLEDataPointType.DT_ENUM, 1)]
    assert datapoints.values[34].writes == [1]
    assert select.TuyaBLESelect.current_option.fget(fake_entity) == "finger_card"


def test_door_state_does_not_drive_s1_lock_state() -> None:
    """The existing LockEntity continues to derive state only from DP 47."""
    datapoints = FakeDatapoints({40: FakeDatapoint(1), 47: FakeDatapoint(False)})
    fake_lock = SimpleNamespace(_device=SimpleNamespace(datapoints=datapoints))

    assert lock.TuyaBLELock.is_locked.fget(fake_lock) is True
    datapoints.values[40].value = 2
    assert lock.TuyaBLELock.is_locked.fget(fake_lock) is True
    datapoints.values[47].value = True
    assert lock.TuyaBLELock.is_locked.fget(fake_lock) is False
    datapoints.values[47].value = None
    assert lock.TuyaBLELock.is_locked.fget(fake_lock) is None


def test_s1_motor_state_is_read_only_without_duplicate_entity() -> None:
    """S1 DP 47 is one read-only diagnostic binary sensor."""
    assert "lock_motor_state" not in _mapping_by_key(
        switch.get_mapping_by_device(S1_DEVICE)
    )
    binary_mappings = _mapping_by_key(binary_sensor.get_mapping_by_device(S1_DEVICE))
    assert set(binary_mappings) == {"lock_motor_state"}
    motor = binary_mappings["lock_motor_state"]
    assert motor.dp_id == 47
    assert motor.dp_type is TuyaBLEDataPointType.DT_BOOL
    assert motor.description.icon == "mdi:engine"
    assert motor.description.entity_category is EntityCategory.DIAGNOSTIC
    assert motor.getter is binary_sensor.motor_state_getter


def test_s1_excludes_out_of_scope_and_security_datapoints() -> None:
    """No excluded control or raw security datapoint becomes a new entity."""
    assert button.get_mapping_by_device(S1_DEVICE) == []
    writable_dp_ids = {
        item.dp_id
        for platform_mapping in (
            number.get_mapping_by_device(S1_DEVICE),
            select.get_mapping_by_device(S1_DEVICE),
            switch.get_mapping_by_device(S1_DEVICE),
        )
        for item in platform_mapping
    }
    assert writable_dp_ids == {33, 34, 36}
    assert not writable_dp_ids & {22, 24, 25, 31, 44, 70, 71, 73, 86, 87, 88, 90}


def test_preexisting_s1_entity_keys_remain_stable() -> None:
    """Existing S1 entities keep their exact unique IDs."""
    descriptions = [
        lock.get_mapping_by_device(S1_DEVICE)[0].description,
        _mapping_by_key(binary_sensor.get_mapping_by_device(S1_DEVICE))[
            "lock_motor_state"
        ].description,
    ]

    sensor_mappings = _mapping_by_key(sensor.get_mapping_by_device(S1_DEVICE))
    descriptions.extend(
        [
            sensor_mappings["alarm_lock"].description,
            sensor_mappings["battery"].description,
        ]
    )

    class FakeStates:
        @staticmethod
        def async_available(entity_id) -> bool:
            return True

    fake_hass = SimpleNamespace(states=FakeStates())
    fake_device = SimpleNamespace(
        category="jtmspro",
        product_id="xqeob8h6",
        name="S1",
        address="synthetic:device:address",
        hardware_version="test",
        product_model="S1",
        device_version="test",
        protocol_version="test",
        device_id="unit-test-device",
    )
    product = devices.get_product_info_by_ids("jtmspro", "xqeob8h6")
    unique_ids = [
        devices.TuyaBLEEntity(
            fake_hass,
            SimpleNamespace(),
            fake_device,
            product,
            description,
        ).unique_id
        for description in descriptions
    ]

    assert unique_ids == [
        "unit-test-device-ble_unlock_lock",
        "unit-test-device-lock_motor_state",
        "unit-test-device-alarm_lock",
        "unit-test-device-battery",
    ]


def test_s1_translations_and_manifest_contract() -> None:
    """S1 state labels are complete in both English catalogs without a bump."""
    root = Path(__file__).parents[1]
    strings = json.loads((root / "custom_components/tuya_ble/strings.json").read_text())
    translation = json.loads(
        (root / "custom_components/tuya_ble/translations/en.json").read_text()
    )
    manifest = json.loads(
        (root / "custom_components/tuya_ble/manifest.json").read_text()
    )

    expected_alarm_states = {
        "wrong_finger": "Wrong fingerprint",
        "wrong_password": "Wrong password",
        "wrong_card": "Wrong card",
        "wrong_face": "Wrong face",
        "tongue_bad": "Latch fault",
        "too_hot": "Temperature too high",
        "unclosed_time": "Door left open",
        "tongue_not_out": "Latch not extended",
        "pry": "Tamper detected",
        "key_in": "Key inserted",
        "low_battery": "Low battery",
        "power_off": "Power loss",
        "shock": "Shock detected",
        "defense": "Armed alarm",
    }
    expected_last_unlock_states = {
        "fingerprint": "Fingerprint",
        "card": "Card",
        "key": "Mechanical key",
        "ble": "Bluetooth",
        "phone_remote": "Phone remote",
        "voice_remote": "Voice remote",
    }
    expected_door_states = {
        "unknown": "Unknown",
        "open": "Open",
        "closed": "Closed",
    }

    for catalog in (strings, translation):
        entities = catalog["entity"]
        assert entities["select"]["unlock_switch"]["state"] == {
            "single_unlock": "Single authentication",
            "finger_card": "Fingerprint and card",
        }
        assert entities["sensor"]["s1_alarm_lock"]["state"] == (expected_alarm_states)
        assert entities["sensor"]["s1_last_unlock_method"]["state"] == (
            expected_last_unlock_states
        )
        assert entities["sensor"]["closed_opened"]["state"] == expected_door_states

    assert manifest["version"] == "0.1.11b2"
