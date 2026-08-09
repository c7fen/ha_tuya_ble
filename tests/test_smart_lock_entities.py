"""Behavioral contracts for the product-specific S1 and V1 entities."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from homeassistant.components.number import NumberMode
from homeassistant.components.sensor import SensorDeviceClass
from homeassistant.const import PERCENTAGE
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
LEGACY_MS_DEVICE = SimpleNamespace(category="ms", product_id="yy2bmcoh")

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

V1_LAST_UNLOCK_METHODS = {
    12: "fingerprint",
    13: "password",
    14: "dynamic",
    15: "card",
    19: "ble",
    55: "temporary",
    62: "phone_remote",
}


def _mapping_by_key(items: list[Any]) -> dict[str, Any]:
    return {item.description.key: item for item in items}


class FakeDatapoint:
    """Synthetic datapoint recording local writes."""

    def __init__(self, value: Any = None) -> None:
        self.value = value
        self.writes: list[Any] = []

    async def set_value(self, value: Any) -> None:
        self.value = value
        self.writes.append(value)


class FakeDatapoints:
    """Small datapoint collection matching the platform APIs under test."""

    def __init__(self, values: dict[int, FakeDatapoint] | None = None) -> None:
        self.values = values or {}
        self.get_or_create_calls: list[tuple[int, TuyaBLEDataPointType, Any]] = []

    def __getitem__(self, dp_id: int) -> FakeDatapoint | None:
        return self.values.get(dp_id)

    def get_or_create(
        self, dp_id: int, dp_type: TuyaBLEDataPointType, value: Any
    ) -> FakeDatapoint:
        self.get_or_create_calls.append((dp_id, dp_type, value))
        return self.values.setdefault(dp_id, FakeDatapoint(value))


class FakeHass:
    """Collect and execute integration-created tasks."""

    def __init__(self) -> None:
        self.awaitables: list[Any] = []

    def create_task(self, awaitable) -> None:
        self.awaitables.append(awaitable)

    def drain(self) -> None:
        while self.awaitables:
            asyncio.run(self.awaitables.pop(0))


def test_product_registration_preserves_legacy_products_and_safe_v1_shape() -> None:
    """Legacy-only products resolve while V1 cannot enter the generic lock path."""
    v1_product = devices.get_product_info_by_ids("ms", "7a4xvbtt")
    assert v1_product is not None
    assert v1_product.name == "V1 Smart Lock"
    assert v1_product.lock is None

    s1_product = devices.get_product_info_by_ids("jtmspro", "xqeob8h6")
    assert s1_product is not None
    assert s1_product.name == "S1-TY-BLE-PRO"

    legacy_ms = devices.get_product_info_by_ids("ms", "yy2bmcoh")
    assert legacy_ms is not None
    assert legacy_ms.name == "Smart Lock"

    drawer_lock = devices.get_product_info_by_ids("jtmspro", "akwn32dw")
    assert drawer_lock is not None
    assert drawer_lock.name == "Drawer Smart Lock"


def test_s1_sensor_contract_preserves_exact_product_semantics() -> None:
    """S1 keeps its exact alarm order and product-specific diagnostic entities."""
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
    assert alarm.description.options == S1_ALARM_OPTIONS
    assert alarm.description.icon == "mdi:alert"
    assert alarm.description.entity_category is EntityCategory.DIAGNOSTIC
    assert alarm.requires_current_session is False

    battery = mappings["battery"]
    assert battery.dp_id == 8
    assert battery.description.device_class is SensorDeviceClass.BATTERY
    assert battery.description.native_unit_of_measurement == PERCENTAGE
    assert battery.description.entity_category is EntityCategory.DIAGNOSTIC
    assert battery.requires_current_session is True

    last_unlock = mappings["last_unlock_method"]
    assert last_unlock.unlock_methods == S1_LAST_UNLOCK_METHODS
    assert list(last_unlock.unlock_methods) == [12, 15, 16, 19, 62, 63]
    assert last_unlock.description.translation_key == "s1_last_unlock_method"
    assert last_unlock.description.options == list(S1_LAST_UNLOCK_METHODS.values())

    door = mappings["closed_opened"]
    assert door.dp_id == 40
    assert door.dp_type is TuyaBLEDataPointType.DT_ENUM
    assert door.description.options == ["unknown", "open", "closed"]
    assert door.description.entity_registry_enabled_default is False
    assert door.description.entity_category is EntityCategory.DIAGNOSTIC
    assert door.requires_current_session is True


def test_s1_current_configuration_has_exact_per_datapoint_provenance_scope() -> None:
    """Only S1 current-state/configuration mappings require the active epoch."""
    authentication = _mapping_by_key(select.get_mapping_by_device(S1_DEVICE))[
        "unlock_switch"
    ]
    auto_lock = _mapping_by_key(switch.get_mapping_by_device(S1_DEVICE))[
        "automatic_lock"
    ]
    auto_lock_delay = _mapping_by_key(number.get_mapping_by_device(S1_DEVICE))[
        "auto_lock_time"
    ]
    motor = _mapping_by_key(binary_sensor.get_mapping_by_device(S1_DEVICE))[
        "lock_motor_state"
    ]

    assert authentication.dp_id == 34
    assert authentication.requires_current_session is True
    assert auto_lock.dp_id == 33
    assert auto_lock.requires_current_session is True
    assert auto_lock_delay.dp_id == 36
    assert auto_lock_delay.requires_current_session is True
    assert motor.dp_id == 47
    assert motor.requires_current_session is True


def test_v1_contract_excludes_generic_and_speculative_entities() -> None:
    """V1 exposes only the evidenced action, settings, and diagnostics."""
    assert button.get_mapping_by_device(V1_DEVICE) == []
    assert lock.V1_DP_LOCK == 46
    assert lock.V1_DP_ACCESS == 6
    assert lock.V1_DP_MOTOR_STATE == 47

    sensors = _mapping_by_key(sensor.get_mapping_by_device(V1_DEVICE))
    assert set(sensors) == {"alarm_lock", "battery", "last_unlock_method"}
    assert sensors["alarm_lock"].description.options == [
        "wrong_finger",
        "wrong_password",
        "wrong_card",
        "low_battery",
    ]
    assert sensors["last_unlock_method"].unlock_methods == V1_LAST_UNLOCK_METHODS
    assert "lock_door_status" not in sensors
    assert "closed_opened" not in sensors

    switches = _mapping_by_key(switch.get_mapping_by_device(V1_DEVICE))
    assert set(switches) == {"automatic_lock"}
    assert switches["automatic_lock"].dp_id == 33
    assert switches["automatic_lock"].requires_current_session is True

    numbers = _mapping_by_key(number.get_mapping_by_device(V1_DEVICE))
    assert set(numbers) == {"auto_lock_time"}
    assert numbers["auto_lock_time"].dp_id == 36
    assert numbers["auto_lock_time"].requires_current_session is True

    binary_sensors = _mapping_by_key(binary_sensor.get_mapping_by_device(V1_DEVICE))
    assert set(binary_sensors) == {"lock_motor_state"}
    assert binary_sensors["lock_motor_state"].dp_id == 47
    assert binary_sensors["lock_motor_state"].requires_current_session is True
    assert binary_sensors["lock_motor_state"].description.device_class is None

    assert select.get_mapping_by_device(V1_DEVICE) == []
    writable_dp_ids = {
        item.dp_id
        for platform_mappings in (
            button.get_mapping_by_device(V1_DEVICE),
            number.get_mapping_by_device(V1_DEVICE),
            switch.get_mapping_by_device(V1_DEVICE),
        )
        for item in platform_mappings
    }
    assert writable_dp_ids == {33, 36}


def test_shared_entity_presentation_and_platform_types_match() -> None:
    """Shared S1 and V1 capabilities retain one presentation contract."""
    s1_switch = _mapping_by_key(switch.get_mapping_by_device(S1_DEVICE))[
        "automatic_lock"
    ]
    v1_switch = _mapping_by_key(switch.get_mapping_by_device(V1_DEVICE))[
        "automatic_lock"
    ]
    assert s1_switch.description.key == v1_switch.description.key == "automatic_lock"
    assert s1_switch.description.icon == v1_switch.description.icon == "mdi:lock-clock"
    assert (
        s1_switch.description.entity_category
        is v1_switch.description.entity_category
        is EntityCategory.CONFIG
    )

    s1_delay = _mapping_by_key(number.get_mapping_by_device(S1_DEVICE))[
        "auto_lock_time"
    ]
    v1_delay = _mapping_by_key(number.get_mapping_by_device(V1_DEVICE))[
        "auto_lock_time"
    ]
    assert s1_delay.description.icon == v1_delay.description.icon == "mdi:timer-lock"
    assert s1_delay.description.native_min_value == 1
    assert v1_delay.description.native_min_value == 5
    assert s1_delay.description.native_max_value == 1800
    assert v1_delay.description.native_max_value == 1800
    assert s1_delay.mode is v1_delay.mode is NumberMode.BOX

    for device in (S1_DEVICE, V1_DEVICE):
        sensor_mappings = _mapping_by_key(sensor.get_mapping_by_device(device))
        assert sensor_mappings["alarm_lock"].description.icon == "mdi:alert"
        assert (
            sensor_mappings["last_unlock_method"].description.icon
            == "mdi:account-lock-open"
        )
        assert (
            sensor_mappings["battery"].description.entity_category
            is EntityCategory.DIAGNOSTIC
        )
        motor = _mapping_by_key(binary_sensor.get_mapping_by_device(device))[
            "lock_motor_state"
        ]
        assert motor.description.icon == "mdi:engine"
        assert motor.description.entity_category is EntityCategory.DIAGNOSTIC

    assert sensor.rssi_mapping.description.key == "signal_strength"
    assert sensor.rssi_mapping.description.entity_category is EntityCategory.DIAGNOSTIC
    assert sensor.rssi_mapping.description.entity_registry_enabled_default is False


def test_shared_entity_translation_catalog_preserves_visible_names() -> None:
    """English entity names and enum states enforce the reviewed shared contract."""
    integration_root = Path(__file__).parents[1] / "custom_components" / "tuya_ble"
    strings = json.loads((integration_root / "strings.json").read_text())
    english = json.loads((integration_root / "translations" / "en.json").read_text())

    for catalog in (strings, english):
        entities = catalog["entity"]
        assert entities["button"]["lock"]["name"] == "Lock"
        assert entities["lock"]["lock"]["name"] == "Lock"
        assert entities["switch"]["automatic_lock"]["name"] == "Auto-Lock"
        assert entities["number"]["auto_lock_time"]["name"] == "Auto-Lock Delay"
        assert entities["sensor"]["battery"]["name"] == "Battery"
        assert entities["sensor"]["alarm_lock"]["name"] == "Alarm"
        assert entities["sensor"]["last_unlock_method"]["name"] == "Last Unlock Method"
        assert entities["binary_sensor"]["lock_motor_state"]["name"] == "Motor State"
        assert entities["sensor"]["signal_strength"]["name"] == "Signal Strength"
        assert entities["select"]["unlock_switch"]["name"] == "Authentication Mode"
        assert entities["sensor"]["closed_opened"]["name"] == "Door State"
        assert list(entities["sensor"]["s1_alarm_lock"]["state"]) == S1_ALARM_OPTIONS
        assert list(entities["sensor"]["s1_last_unlock_method"]["state"]) == list(
            S1_LAST_UNLOCK_METHODS.values()
        )
        assert list(entities["sensor"]["last_unlock_method"]["state"]) == list(
            V1_LAST_UNLOCK_METHODS.values()
        )


@pytest.mark.parametrize(
    ("raw_value", "expected"),
    [
        (-1, None),
        (0, 0),
        (50, 50),
        (100, 100),
        (101, None),
        (True, None),
        (None, None),
    ],
)
def test_v1_battery_rejects_invalid_percentages(raw_value: Any, expected: Any) -> None:
    """Invalid and sentinel battery values never become percentages."""
    entity = SimpleNamespace(
        _device=SimpleNamespace(datapoints={8: FakeDatapoint(raw_value)}),
        _attr_native_value="stale",
    )

    sensor.v1_battery_getter(entity)

    assert entity._attr_native_value == expected


@pytest.mark.parametrize("device", (S1_DEVICE, V1_DEVICE), ids=("s1", "v1"))
@pytest.mark.parametrize(
    ("raw_value", "expected"),
    [(True, True), (False, False), (1, None), (None, None)],
)
def test_motor_state_reports_only_boolean_values(
    device: SimpleNamespace, raw_value: Any, expected: bool | None
) -> None:
    """DP47 is a read-only diagnostic and absent values remain unknown."""
    motor = _mapping_by_key(binary_sensor.get_mapping_by_device(device))[
        "lock_motor_state"
    ]
    entity = SimpleNamespace(
        _device=SimpleNamespace(datapoints={47: FakeDatapoint(raw_value)}),
        _attr_is_on="stale",
    )

    motor.getter(entity)

    assert entity._attr_is_on is expected


@pytest.mark.parametrize(
    ("device", "minimum"),
    [(S1_DEVICE, 1), (V1_DEVICE, 5)],
    ids=("s1", "v1"),
)
def test_auto_lock_delay_readback_is_product_bounded(
    device: SimpleNamespace, minimum: int
) -> None:
    """Each lock accepts only integer delays in its evidenced range."""
    delay = number.get_mapping_by_device(device)[0]
    entity = SimpleNamespace(
        _mapping=delay,
        _device=SimpleNamespace(datapoints={36: FakeDatapoint(minimum)}),
    )
    assert delay.getter(entity, None) == float(minimum)

    entity._device.datapoints[36].value = minimum - 1
    assert delay.getter(entity, None) is None
    entity._device.datapoints[36].value = 1801
    assert delay.getter(entity, None) is None
    entity._device.datapoints[36].value = True
    assert delay.getter(entity, None) is None


def test_s1_configuration_entities_write_only_their_own_datapoints() -> None:
    """S1 settings use DP33, DP34, and DP36 with native platform semantics."""
    hass = FakeHass()
    datapoints = FakeDatapoints()

    auto_lock = switch.get_mapping_by_device(S1_DEVICE)[0]
    switch_entity = SimpleNamespace(
        _mapping=auto_lock,
        _product=devices.get_product_info_by_ids("jtmspro", "xqeob8h6"),
        _device=SimpleNamespace(datapoints=datapoints),
        _hass=hass,
    )
    switch.TuyaBLESwitch.turn_on(switch_entity)

    delay = number.get_mapping_by_device(S1_DEVICE)[0]
    number_entity = SimpleNamespace(
        _mapping=delay,
        _product=devices.get_product_info_by_ids("jtmspro", "xqeob8h6"),
        _device=SimpleNamespace(datapoints=datapoints),
        _hass=hass,
    )
    number.TuyaBLENumber.set_native_value(number_entity, 45)

    authentication = select.get_mapping_by_device(S1_DEVICE)[0]
    select_entity = SimpleNamespace(
        _mapping=authentication,
        _attr_options=authentication.description.options,
        _device=SimpleNamespace(datapoints=datapoints),
        _hass=hass,
    )
    select.TuyaBLESelect.select_option(select_entity, "finger_card")

    hass.drain()

    assert datapoints.get_or_create_calls == [
        (33, TuyaBLEDataPointType.DT_BOOL, True),
        (36, TuyaBLEDataPointType.DT_VALUE, 45),
        (34, TuyaBLEDataPointType.DT_ENUM, 1),
    ]
    assert datapoints.values[33].writes == [True]
    assert datapoints.values[36].writes == [45]
    assert datapoints.values[34].writes == [1]


def test_legacy_yy2bmcoh_retains_only_evidenced_platforms() -> None:
    """The legacy-only product keeps its battery, alarm, and DP31 setting."""
    sensors = _mapping_by_key(sensor.get_mapping_by_device(LEGACY_MS_DEVICE))
    assert set(sensors) == {"alarm_lock", "battery"}
    assert sensors["alarm_lock"].dp_id == 21
    assert sensors["alarm_lock"].description.options == [
        "wrong_finger",
        "wrong_password",
        "low_battery",
    ]
    assert sensors["battery"].dp_id == 8

    selects = _mapping_by_key(select.get_mapping_by_device(LEGACY_MS_DEVICE))
    assert set(selects) == {"beep_volume"}
    assert selects["beep_volume"].dp_id == 31
    assert selects["beep_volume"].dp_type is TuyaBLEDataPointType.DT_ENUM
    assert selects["beep_volume"].description.icon == "mdi:volume-high"
    assert selects["beep_volume"].description.entity_category is EntityCategory.CONFIG
    assert selects["beep_volume"].description.options == [
        "mute",
        "low",
        "normal",
        "high",
    ]
