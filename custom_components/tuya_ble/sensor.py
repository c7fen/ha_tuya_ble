"""The Tuya BLE integration."""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Callable

from homeassistant.components.sensor import (
    RestoreSensor,
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    CONCENTRATION_PARTS_PER_MILLION,
    PERCENTAGE,
    SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
    Platform,
    UnitOfElectricCurrent,
    UnitOfElectricPotential,
    UnitOfTemperature,
    UnitOfTime,
    UnitOfVolume,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import (
    BATTERY_CHARGED,
    BATTERY_CHARGING,
    BATTERY_NOT_CHARGING,
    BATTERY_STATE_HIGH,
    BATTERY_STATE_LOW,
    BATTERY_STATE_NORMAL,
    CO2_LEVEL_ALARM,
    CO2_LEVEL_NORMAL,
    DOMAIN,
)
from .devices import (
    TuyaBLECoordinator,
    TuyaBLEData,
    TuyaBLEEntity,
    TuyaBLEProductInfo,
)
from .last_confirmed import TuyaBLES1LastConfirmedEntity, _parse_restored_timestamp
from .tuya_ble import TuyaBLEDataPoint, TuyaBLEDataPointType, TuyaBLEDevice

_LOGGER = logging.getLogger(__name__)
SIGNAL_STRENGTH_DP_ID = -1
TuyaBLESensorIsAvailable = Callable[["TuyaBLESensor", TuyaBLEProductInfo], bool] | None


@dataclass
class TuyaBLESensorMapping:
    """Model a DP, description and default values"""

    dp_id: int
    description: SensorEntityDescription
    force_add: bool = True
    dp_type: TuyaBLEDataPointType | None = None
    getter: Callable[[TuyaBLESensor], None] | None = None
    coefficient: float = 1.0
    icons: list[str] | None = None
    is_available: TuyaBLESensorIsAvailable = None
    requires_current_session: bool = False
    last_confirmed: bool = False


@dataclass
class TuyaBLELastUnlockSensorMapping:
    """Describe the datapoints that can identify an unlock method."""

    unlock_methods: Mapping[int, str]
    description: SensorEntityDescription = field(
        default_factory=lambda: SensorEntityDescription(
            key="last_unlock_method",
            icon="mdi:account-lock-open",
            device_class=SensorDeviceClass.ENUM,
            entity_category=EntityCategory.DIAGNOSTIC,
        )
    )


@dataclass
class TuyaBLELastStatusUpdateMapping:
    """Describe the S1 aggregate confirmation timestamp diagnostic."""

    description: SensorEntityDescription = field(
        default_factory=lambda: SensorEntityDescription(
            key="last_status_update",
            device_class=SensorDeviceClass.TIMESTAMP,
            entity_category=EntityCategory.DIAGNOSTIC,
        )
    )
    force_add: bool = True


@dataclass
class TuyaBLEBatteryMapping(TuyaBLESensorMapping):
    description: SensorEntityDescription = field(
        default_factory=lambda: SensorEntityDescription(
            key="battery",
            device_class=SensorDeviceClass.BATTERY,
            native_unit_of_measurement=PERCENTAGE,
            suggested_display_precision=0,
            entity_category=EntityCategory.DIAGNOSTIC,
            state_class=SensorStateClass.MEASUREMENT,
        )
    )

    def __post_init__(self) -> None:
        if self.description.suggested_display_precision is None:
            self.description = replace(self.description, suggested_display_precision=0)


def _normalize_battery_percentage(value: object) -> int | float | None:
    if (
        not isinstance(value, int | float)
        or isinstance(value, bool)
        or not 0 <= value <= 100
    ):
        return None
    return int(value) if float(value).is_integer() else value


@dataclass
class TuyaBLETemperatureMapping(TuyaBLESensorMapping):
    description: SensorEntityDescription = field(
        default_factory=lambda: SensorEntityDescription(
            key="temperature",
            device_class=SensorDeviceClass.TEMPERATURE,
            native_unit_of_measurement=UnitOfTemperature.CELSIUS,
            state_class=SensorStateClass.MEASUREMENT,
        )
    )


def is_co2_alarm_enabled(self: TuyaBLESensor, product: TuyaBLEProductInfo) -> bool:
    """For a given sensor, read the datapoints and determine if co2 alarm is enabled"""
    result: bool = True
    datapoint = self._device.datapoints[13]
    if datapoint:
        result = bool(datapoint.value)
    return result


def battery_enum_getter(self: TuyaBLESensor) -> None:
    """For a given sensor, read the datapoints and determine battery info"""
    datapoint = self._device.datapoints[104]
    if datapoint:
        self._attr_native_value = datapoint.value * 20.0


def bstuokey_battery_getter(self: TuyaBLESensor) -> None:
    """Get battery percentage from string values for BSTUOKEY."""
    datapoint = self._device.datapoints[9]
    if datapoint and datapoint.value is not None:
        self._attr_native_value = {
            "high": 90,
            "medium": 60,
            "low": 30,
            "poweroff": 0,
        }.get(datapoint.value)


def v1_battery_getter(self: TuyaBLESensor) -> None:
    """Return V1 battery values only when they are valid percentages."""
    datapoint = self._device.datapoints[8]
    value = datapoint.value if datapoint is not None else None
    self._attr_native_value = (
        value
        if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 100
        else None
    )


@dataclass
class TuyaBLECategorySensorMapping:
    """Models a dict of products and their mappings"""

    products: (
        dict[str, list[TuyaBLESensorMapping | TuyaBLELastUnlockSensorMapping]] | None
    ) = None
    mapping: list[TuyaBLESensorMapping | TuyaBLELastUnlockSensorMapping] | None = None


@dataclass
class TuyaBLEWorkStateMapping(TuyaBLESensorMapping):
    description: SensorEntityDescription = field(
        default_factory=lambda: SensorEntityDescription(
            key="work_state",
            device_class=SensorDeviceClass.ENUM,
            options=[
                "auto",
                "manual",
                "idle",
            ],
        )
    )


@dataclass
class TuyaBLEAlarmLockStateMapping(TuyaBLESensorMapping):
    description: SensorEntityDescription = field(
        default_factory=lambda: SensorEntityDescription(
            key="alarm_lock",
            device_class=SensorDeviceClass.ENUM,
            options=[
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
            ],
        )
    )


mapping: dict[str, TuyaBLECategorySensorMapping] = {
    "co2bj": TuyaBLECategorySensorMapping(
        products={
            "59s19z5m": [  # CO2 Detector
                TuyaBLESensorMapping(
                    dp_id=1,
                    description=SensorEntityDescription(
                        key="carbon_dioxide_alarm",
                        icon="mdi:molecule-co2",
                        device_class=SensorDeviceClass.ENUM,
                        options=[
                            CO2_LEVEL_ALARM,
                            CO2_LEVEL_NORMAL,
                        ],
                    ),
                    is_available=is_co2_alarm_enabled,
                ),
                TuyaBLESensorMapping(
                    dp_id=2,
                    description=SensorEntityDescription(
                        key="carbon_dioxide",
                        device_class=SensorDeviceClass.CO2,
                        native_unit_of_measurement=CONCENTRATION_PARTS_PER_MILLION,
                        state_class=SensorStateClass.MEASUREMENT,
                    ),
                ),
                TuyaBLEBatteryMapping(dp_id=15),
                TuyaBLETemperatureMapping(dp_id=18),
                TuyaBLESensorMapping(
                    dp_id=19,
                    description=SensorEntityDescription(
                        key="humidity",
                        device_class=SensorDeviceClass.HUMIDITY,
                        native_unit_of_measurement=PERCENTAGE,
                        state_class=SensorStateClass.MEASUREMENT,
                    ),
                ),
            ]
        }
    ),
    "wxkg": TuyaBLECategorySensorMapping(
        products={
            **dict.fromkeys(
                ["kpzc6pm8", "ja5osu5g"],
                [
                    TuyaBLEBatteryMapping(dp_id=10),
                ],
            ),
        }
    ),
    "ms": TuyaBLECategorySensorMapping(
        products={
            **dict.fromkeys(
                [
                    "ludzroix",
                    "isk2p555",
                    "gumrixyt",
                    "uamrw6h3",
                    "okkyfgfs",
                    "sidhzylo",
                    "bvclwu9b",
                    "k53ok3u9",
                    "6fibxtph",
                    "99gv5nmz",
                ],  # Smart Lock
                [
                    TuyaBLEAlarmLockStateMapping(dp_id=21),
                    TuyaBLEBatteryMapping(dp_id=8),
                    TuyaBLESensorMapping(
                        dp_id=40,
                        description=SensorEntityDescription(
                            key="lock_door_status",
                            entity_category=EntityCategory.DIAGNOSTIC,
                            device_class=SensorDeviceClass.ENUM,
                            options=[
                                "door_status_unknown",
                                "door_status_open",
                                "door_status_closed",
                            ],
                        ),
                    ),
                ],
            ),
            "yy2bmcoh": [  # Legacy Smart Lock; only observed entities are mapped.
                TuyaBLESensorMapping(
                    dp_id=21,
                    description=SensorEntityDescription(
                        key="alarm_lock",
                        device_class=SensorDeviceClass.ENUM,
                        options=[
                            "wrong_finger",
                            "wrong_password",
                            "low_battery",
                        ],
                    ),
                    dp_type=TuyaBLEDataPointType.DT_ENUM,
                ),
                TuyaBLEBatteryMapping(
                    dp_id=8,
                    dp_type=TuyaBLEDataPointType.DT_VALUE,
                ),
            ],
            "7a4xvbtt": [  # V1 Smart Lock / Lock P1
                TuyaBLESensorMapping(
                    dp_id=21,
                    description=SensorEntityDescription(
                        key="alarm_lock",
                        icon="mdi:alert",
                        device_class=SensorDeviceClass.ENUM,
                        entity_category=EntityCategory.DIAGNOSTIC,
                        options=[
                            "wrong_finger",
                            "wrong_password",
                            "wrong_card",
                            "low_battery",
                        ],
                    ),
                    dp_type=TuyaBLEDataPointType.DT_ENUM,
                ),
                TuyaBLEBatteryMapping(
                    dp_id=8,
                    dp_type=TuyaBLEDataPointType.DT_VALUE,
                    getter=v1_battery_getter,
                ),
                TuyaBLELastUnlockSensorMapping(
                    unlock_methods={
                        12: "fingerprint",
                        13: "password",
                        14: "dynamic",
                        15: "card",
                        19: "ble",
                        55: "temporary",
                        62: "phone_remote",
                    },
                    description=SensorEntityDescription(
                        key="last_unlock_method",
                        icon="mdi:account-lock-open",
                        device_class=SensorDeviceClass.ENUM,
                        entity_category=EntityCategory.DIAGNOSTIC,
                        options=[
                            "fingerprint",
                            "password",
                            "dynamic",
                            "card",
                            "ble",
                            "temporary",
                            "phone_remote",
                        ],
                    ),
                ),
            ],
            "wgv4haro": [
                TuyaBLEAlarmLockStateMapping(dp_id=21),
                TuyaBLEBatteryMapping(dp_id=8),
                TuyaBLESensorMapping(
                    dp_id=12,  # Retrieve last fingerprint used
                    description=SensorEntityDescription(
                        key="unlock_fingerprint",
                        icon="mdi:fingerprint",
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=13,  # Retrieve last password used
                    description=SensorEntityDescription(
                        key="unlock_password",
                        icon="mdi:keyboard-outline",
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=14,  # Retrieve last dynamic password used
                    description=SensorEntityDescription(
                        key="unlock_dynamic",
                        icon="mdi:cellphone-key",
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=19,  # Retrieve last BLE used
                    description=SensorEntityDescription(
                        key="unlock_ble",
                        icon="mdi:bluetooth",
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=55,  # Retrieve last temporary password unlock used
                    description=SensorEntityDescription(
                        key="unlock_temp_pwd",
                        icon="mdi:lock-clock",
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=62,  # Retrieve last app unlock used
                    description=SensorEntityDescription(
                        key="unlock_app",
                        icon="mdi:cellphone-lock",
                    ),
                ),
            ],
            "mqc2hevy": [  # Smart Lock - YSG_T8_8G_htr
                # TODO: TuyaBLEAlarmLockStateMapping(dp_id=21) ?
                TuyaBLESensorMapping(
                    dp_id=21,
                    description=SensorEntityDescription(
                        key="alarm_lock",
                        icon="mdi:alert",
                        device_class=SensorDeviceClass.ENUM,
                        options=[
                            "wrong_finger",
                            "wrong_password",
                            "low_battery",
                        ],
                    ),
                ),
                TuyaBLEBatteryMapping(dp_id=8),
                TuyaBLESensorMapping(
                    dp_id=19,
                    description=SensorEntityDescription(
                        key="unlock_ble",
                        icon="mdi:bluetooth",
                        suggested_display_precision=0,
                        entity_category=EntityCategory.DIAGNOSTIC,
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=12,
                    description=SensorEntityDescription(
                        key="unlock_fingerprint",
                        icon="mdi:fingerprint",
                        suggested_display_precision=0,
                        entity_category=EntityCategory.DIAGNOSTIC,
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=62,
                    description=SensorEntityDescription(
                        key="unlock_phone_remote",
                        icon="mdi:cellphone-lock",
                        suggested_display_precision=0,
                        entity_category=EntityCategory.DIAGNOSTIC,
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=13,
                    description=SensorEntityDescription(
                        key="unlock_password",
                        icon="mdi:numeric-0-box-multiple-outline",
                        suggested_display_precision=0,
                        entity_category=EntityCategory.DIAGNOSTIC,
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=14,
                    description=SensorEntityDescription(
                        key="unlock_dynamic",
                        icon="mdi:lock-reset",
                        suggested_display_precision=0,
                        entity_category=EntityCategory.DIAGNOSTIC,
                    ),
                ),
            ],
            "a6nttc41": [  # ORION Smart Lock
                TuyaBLEBatteryMapping(dp_id=8),
                TuyaBLESensorMapping(
                    dp_id=19,
                    description=SensorEntityDescription(
                        key="unlock_ble",
                        icon="mdi:bluetooth",
                        suggested_display_precision=0,
                        entity_category=EntityCategory.DIAGNOSTIC,
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=12,
                    description=SensorEntityDescription(
                        key="unlock_fingerprint",
                        icon="mdi:fingerprint",
                        suggested_display_precision=0,
                        entity_category=EntityCategory.DIAGNOSTIC,
                    ),
                ),
            ],
            "kpn4zaf7": [
                TuyaBLEAlarmLockStateMapping(dp_id=21),
                TuyaBLEBatteryMapping(
                    dp_id=9,
                    getter=bstuokey_battery_getter,
                    dp_type=TuyaBLEDataPointType.DT_STRING,
                ),
                TuyaBLESensorMapping(
                    dp_id=15,  # Retrieve last card used
                    description=SensorEntityDescription(
                        key="unlock_card",
                        icon="mdi:nfc-variant",
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=19,  # Retrieve last bluetooth unlock used
                    description=SensorEntityDescription(
                        key="unlock_ble",
                        icon="mdi:bluetooth",
                    ),
                ),
            ],
        }
    ),
    "jtmspro": TuyaBLECategorySensorMapping(
        products={
            "xqeob8h6": [  # S1-TY-BLE-PRO
                TuyaBLESensorMapping(
                    dp_id=21,
                    description=SensorEntityDescription(
                        key="alarm_lock",
                        translation_key="s1_alarm_lock",
                        icon="mdi:alert",
                        device_class=SensorDeviceClass.ENUM,
                        entity_category=EntityCategory.DIAGNOSTIC,
                        options=[
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
                        ],
                    ),
                    dp_type=TuyaBLEDataPointType.DT_ENUM,
                ),
                TuyaBLEBatteryMapping(
                    dp_id=8,
                    dp_type=TuyaBLEDataPointType.DT_VALUE,
                    requires_current_session=True,
                    last_confirmed=True,
                ),
                TuyaBLELastUnlockSensorMapping(
                    unlock_methods={
                        12: "fingerprint",
                        15: "card",
                        16: "key",
                        19: "ble",
                        62: "phone_remote",
                        63: "voice_remote",
                    },
                    description=SensorEntityDescription(
                        key="last_unlock_method",
                        translation_key="s1_last_unlock_method",
                        icon="mdi:account-lock-open",
                        device_class=SensorDeviceClass.ENUM,
                        entity_category=EntityCategory.DIAGNOSTIC,
                        options=[
                            "fingerprint",
                            "card",
                            "key",
                            "ble",
                            "phone_remote",
                            "voice_remote",
                        ],
                    ),
                ),
                TuyaBLELastStatusUpdateMapping(),
                TuyaBLESensorMapping(
                    dp_id=40,
                    description=SensorEntityDescription(
                        key="closed_opened",
                        icon="mdi:door",
                        device_class=SensorDeviceClass.ENUM,
                        entity_category=EntityCategory.DIAGNOSTIC,
                        entity_registry_enabled_default=False,
                        options=[
                            "unknown",
                            "open",
                            "closed",
                        ],
                    ),
                    dp_type=TuyaBLEDataPointType.DT_ENUM,
                    requires_current_session=True,
                ),
            ],
            "y2yaegze": [
                TuyaBLEAlarmLockStateMapping(dp_id=21),
                TuyaBLESensorMapping(
                    dp_id=15,  # Retrieve last card used
                    description=SensorEntityDescription(
                        key="unlock_card",
                        icon="mdi:nfc-variant",
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=19,  # Retrieve last BLE used
                    description=SensorEntityDescription(
                        key="unlock_ble",
                        icon="mdi:bluetooth",
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=62,  # Retrieve last remote phone used
                    description=SensorEntityDescription(
                        key="unlock_phone_remote",
                        icon="mdi:cellphone-lock",
                        suggested_display_precision=0,
                        entity_category=EntityCategory.DIAGNOSTIC,
                    ),
                ),
                TuyaBLEBatteryMapping(dp_id=8),
            ],
            "hc7n0urm": [  # A1 Ultra-JM
                TuyaBLESensorMapping(
                    dp_id=21,  # Alarm event
                    description=SensorEntityDescription(
                        key="alarm_lock",
                        icon="mdi:alarm-light-outline",
                        device_class=SensorDeviceClass.ENUM,
                        options=[
                            "low_battery",
                            "power_off",
                        ],
                    ),
                ),
            ],
            **dict.fromkeys(
                [
                    "stugc8dl",  # HU06 Smart Lock
                    "xicdxood",  # Raycube K7 Pro+ / Impression ImSmart C502
                ],
                [
                    TuyaBLEAlarmLockStateMapping(dp_id=21),
                    TuyaBLESensorMapping(
                        dp_id=43,  # Retrieve last fingerprint used
                        description=SensorEntityDescription(
                            key="unlock_fingerprint",
                            icon="mdi:fingerprint",
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=13,  # Retrieve last code used
                        description=SensorEntityDescription(
                            key="unlock_password",
                            icon="mdi:keyboard-outline",
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=16,  # Retrieve last physical key unlock used
                        description=SensorEntityDescription(
                            key="unlock_key",
                            icon="mdi:key",
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=19,  # Retrieve last bluetooth unlock used
                        description=SensorEntityDescription(
                            key="unlock_ble",
                            icon="mdi:bluetooth",
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=62,  # Retrieve last app unlock used
                        description=SensorEntityDescription(
                            key="unlock_app",
                            icon="mdi:cellphone-lock",
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=63,  # Retrieve last voice unlock used
                        description=SensorEntityDescription(
                            key="unlock_voice",
                            icon="mdi:microphone",
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=105,  # Lock record
                        description=SensorEntityDescription(
                            key="lock_record",
                            icon="mdi:history",
                        ),
                    ),
                    TuyaBLEBatteryMapping(dp_id=8),
                    TuyaBLEBatteryMapping(
                        dp_id=103,
                        description=SensorEntityDescription(
                            key="keypad_battery",
                            device_class=SensorDeviceClass.BATTERY,
                            native_unit_of_measurement=PERCENTAGE,
                            entity_category=EntityCategory.DIAGNOSTIC,
                            state_class=SensorStateClass.MEASUREMENT,
                        ),
                    ),
                ],
            ),
            **dict.fromkeys(
                [
                    "rlyxv7pe",  # A1 PRO MAX - Experimental
                    "oyqux5vv",  # LA-01 - Experimental
                    "z7lj676i",  # Smart Cylinder Lock - Experimental
                    "hs21i377",  # Smart Cylinder Lock (LVD11_BK)
                    "kholoaew",  # Smart Lock
                    "pyawczjj",  # CS-9 Smart Fingerprint Lock - Experimental
                ],
                [
                    TuyaBLEAlarmLockStateMapping(dp_id=21),
                    TuyaBLESensorMapping(
                        dp_id=12,  # Retrieve last fingerprint used
                        description=SensorEntityDescription(
                            key="unlock_fingerprint",
                            icon="mdi:fingerprint",
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=15,  # Retrieve last card used
                        description=SensorEntityDescription(
                            key="unlock_card",
                            icon="mdi:nfc-variant",
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=13,  # Retrieve last code used
                        description=SensorEntityDescription(
                            key="unlock_password",
                            icon="mdi:keyboard-outline",
                        ),
                    ),
                    TuyaBLEBatteryMapping(dp_id=8),
                ],
            ),
            "ajk32biq": [
                TuyaBLEAlarmLockStateMapping(dp_id=21),
                TuyaBLESensorMapping(
                    dp_id=12,  # Retrieve last fingerprint used
                    description=SensorEntityDescription(
                        key="unlock_fingerprint",
                        icon="mdi:fingerprint",
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=15,  # Retrieve last card used
                    description=SensorEntityDescription(
                        key="unlock_card",
                        icon="mdi:nfc-variant",
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=13,  # Retrieve last code used
                    description=SensorEntityDescription(
                        key="unlock_password",
                        icon="mdi:keyboard-outline",
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=19,  # Retrieve last bluetooth unlock used
                    description=SensorEntityDescription(
                        key="unlock_ble",
                        icon="mdi:bluetooth",
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=14,  # Retrieve last dynamic password used
                    description=SensorEntityDescription(
                        key="unlock_dynamic",
                        icon="mdi:lock-reset",
                    ),
                ),
                TuyaBLEBatteryMapping(dp_id=8),
            ],
            "yfqp0shy": [
                TuyaBLEAlarmLockStateMapping(dp_id=21),
                TuyaBLESensorMapping(
                    dp_id=12,  # Retrieve last fingerprint used
                    description=SensorEntityDescription(
                        key="unlock_fingerprint",
                        icon="mdi:fingerprint",
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=15,  # Retrieve last card used
                    description=SensorEntityDescription(
                        key="unlock_card",
                        icon="mdi:nfc-variant",
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=13,  # Retrieve last code used
                    description=SensorEntityDescription(
                        key="unlock_password",
                        icon="mdi:keyboard-outline",
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=19,  # Retrieve last bluetooth unlock used
                    description=SensorEntityDescription(
                        key="unlock_ble",
                        icon="mdi:bluetooth",
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=14,  # Retrieve last dynamic password used
                    description=SensorEntityDescription(
                        key="unlock_dynamic",
                        icon="mdi:lock-reset",
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=16,  # Retrieve last physical key unlock used
                    description=SensorEntityDescription(
                        key="unlock_key",
                        icon="mdi:key",
                    ),
                ),
                TuyaBLEBatteryMapping(dp_id=8),
            ],
            "qicggi0m": [
                TuyaBLEAlarmLockStateMapping(dp_id=21),
                TuyaBLESensorMapping(
                    dp_id=13,  # Retrieve last code used
                    description=SensorEntityDescription(
                        key="unlock_password",
                        icon="mdi:keyboard-outline",
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=14,  # Retrieve last dynamic password used
                    description=SensorEntityDescription(
                        key="unlock_dynamic",
                        icon="mdi:lock-reset",
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=19,  # Retrieve last bluetooth unlock used
                    description=SensorEntityDescription(
                        key="unlock_ble",
                        icon="mdi:bluetooth",
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=55,  # Retrieve last temporary password unlock used
                    description=SensorEntityDescription(
                        key="unlock_temp_pwd",
                        icon="mdi:lock-clock",
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=62,  # Retrieve last app unlock used
                    description=SensorEntityDescription(
                        key="unlock_app",
                        icon="mdi:cellphone-lock",
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=63,  # Retrieve last voice unlock used
                    description=SensorEntityDescription(
                        key="unlock_voice",
                        icon="mdi:microphone",
                    ),
                ),
                TuyaBLEBatteryMapping(dp_id=8),
            ],
        }
    ),
    "szjqr": TuyaBLECategorySensorMapping(
        products={
            **dict.fromkeys(
                ["3yqdo5yt", "xhf790if", "okkyfgfs"],  # CubeTouch 1s and II
                [
                    TuyaBLESensorMapping(
                        dp_id=7,
                        description=SensorEntityDescription(
                            key="battery_charging",
                            device_class=SensorDeviceClass.ENUM,
                            entity_category=EntityCategory.DIAGNOSTIC,
                            options=[
                                BATTERY_NOT_CHARGING,
                                BATTERY_CHARGING,
                                BATTERY_CHARGED,
                            ],
                        ),
                        icons=[
                            "mdi:battery",
                            "mdi:power-plug-battery",
                            "mdi:battery-check",
                        ],
                    ),
                    TuyaBLEBatteryMapping(dp_id=8),
                ],
            ),
            **dict.fromkeys(
                [
                    "blliqpsj",
                    "ndvkgsrm",
                    "yiihr7zh",
                    "neq16kgd",
                    "6jcvqwh0",
                    "riecov42",
                    "h8kdwywx",
                ],  # Fingerbot Plus
                [
                    TuyaBLEBatteryMapping(dp_id=12),
                ],
            ),
            **dict.fromkeys(
                [
                    "ltak7e1p",
                    "y6kttvd6",
                    "yrnk7mnn",
                    "nvr2rocq",
                    "bnt7wajf",
                    "rvdceqjh",
                    "5xhbk964",
                ],  # Fingerbot
                [
                    TuyaBLEBatteryMapping(dp_id=12),
                ],
            ),
        },
    ),
    "kg": TuyaBLECategorySensorMapping(
        products={
            **dict.fromkeys(
                ["mknd4lci", "riecov42", "gnpbj0bq"],  # Fingerbot Plus
                [
                    TuyaBLEBatteryMapping(dp_id=105),
                ],
            ),
        },
    ),
    "wsdcg": TuyaBLECategorySensorMapping(
        products={
            "ojzlzzsw": [  # Soil moisture sensor
                TuyaBLETemperatureMapping(
                    dp_id=1,
                    coefficient=10.0,
                ),
                TuyaBLESensorMapping(
                    dp_id=2,
                    description=SensorEntityDescription(
                        key="moisture",
                        device_class=SensorDeviceClass.MOISTURE,
                        native_unit_of_measurement=PERCENTAGE,
                        state_class=SensorStateClass.MEASUREMENT,
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=3,
                    description=SensorEntityDescription(
                        key="battery_state",
                        icon="mdi:battery",
                        device_class=SensorDeviceClass.ENUM,
                        entity_category=EntityCategory.DIAGNOSTIC,
                        options=[
                            BATTERY_STATE_LOW,
                            BATTERY_STATE_NORMAL,
                            BATTERY_STATE_HIGH,
                        ],
                    ),
                    icons=[
                        "mdi:battery-alert",
                        "mdi:battery-50",
                        "mdi:battery-check",
                    ],
                ),
                TuyaBLEBatteryMapping(dp_id=4),
            ],
            "iv7hudlj": [  # Bluetooth Temperature Humidity Sensor
                TuyaBLETemperatureMapping(
                    dp_id=1,
                    coefficient=10.0,
                    description=SensorEntityDescription(
                        key="va_temperature",
                        device_class=SensorDeviceClass.TEMPERATURE,
                        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
                        state_class=SensorStateClass.MEASUREMENT,
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=2,
                    description=SensorEntityDescription(
                        key="va_moisture",
                        device_class=SensorDeviceClass.MOISTURE,
                        native_unit_of_measurement=PERCENTAGE,
                        state_class=SensorStateClass.MEASUREMENT,
                    ),
                ),
                TuyaBLEBatteryMapping(
                    dp_id=4,
                    description=SensorEntityDescription(
                        key="battery_percentage",
                        device_class=SensorDeviceClass.BATTERY,
                        native_unit_of_measurement=PERCENTAGE,
                        entity_category=EntityCategory.DIAGNOSTIC,
                        state_class=SensorStateClass.MEASUREMENT,
                    ),
                ),
            ],
            "6lbesej0": [  # Temperature Humidity Sensor SS302
                TuyaBLETemperatureMapping(
                    dp_id=1,
                    coefficient=10.0,
                    description=SensorEntityDescription(
                        key="temp_current",
                        device_class=SensorDeviceClass.TEMPERATURE,
                        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
                        state_class=SensorStateClass.MEASUREMENT,
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=2,
                    description=SensorEntityDescription(
                        key="humidity_value",
                        device_class=SensorDeviceClass.HUMIDITY,
                        native_unit_of_measurement=PERCENTAGE,
                        state_class=SensorStateClass.MEASUREMENT,
                    ),
                ),
                TuyaBLEBatteryMapping(
                    dp_id=4,
                    description=SensorEntityDescription(
                        key="battery_percentage",
                        device_class=SensorDeviceClass.BATTERY,
                        native_unit_of_measurement=PERCENTAGE,
                        entity_category=EntityCategory.DIAGNOSTIC,
                        state_class=SensorStateClass.MEASUREMENT,
                    ),
                ),
            ],
            **dict.fromkeys(
                ["6lbesej0", "vyfoip9h", "1jvidcsf"],
                [
                    TuyaBLETemperatureMapping(
                        dp_id=1,
                        coefficient=10.0,
                        description=SensorEntityDescription(
                            key="temp_current",
                            device_class=SensorDeviceClass.TEMPERATURE,
                            native_unit_of_measurement=UnitOfTemperature.CELSIUS,
                            state_class=SensorStateClass.MEASUREMENT,
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=2,
                        description=SensorEntityDescription(
                            key="humidity_value",
                            device_class=SensorDeviceClass.HUMIDITY,
                            native_unit_of_measurement=PERCENTAGE,
                            state_class=SensorStateClass.MEASUREMENT,
                        ),
                    ),
                    TuyaBLEBatteryMapping(
                        dp_id=4,
                        description=SensorEntityDescription(
                            key="battery_percentage",
                            device_class=SensorDeviceClass.BATTERY,
                            native_unit_of_measurement=PERCENTAGE,
                            entity_category=EntityCategory.DIAGNOSTIC,
                            state_class=SensorStateClass.MEASUREMENT,
                        ),
                    ),
                ],
            ),
            "jm6iasmb": [  # Bluetooth Temperature Humidity Sensor
                TuyaBLETemperatureMapping(
                    dp_id=1,
                    coefficient=10.0,
                    description=SensorEntityDescription(
                        key="va_temperature",
                        device_class=SensorDeviceClass.TEMPERATURE,
                        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
                        state_class=SensorStateClass.MEASUREMENT,
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=2,
                    description=SensorEntityDescription(
                        key="va_moisture",
                        device_class=SensorDeviceClass.MOISTURE,
                        native_unit_of_measurement=PERCENTAGE,
                        state_class=SensorStateClass.MEASUREMENT,
                    ),
                ),
                TuyaBLEBatteryMapping(
                    dp_id=4,
                    description=SensorEntityDescription(
                        key="battery_percentage",
                        device_class=SensorDeviceClass.BATTERY,
                        native_unit_of_measurement=PERCENTAGE,
                        entity_category=EntityCategory.DIAGNOSTIC,
                        state_class=SensorStateClass.MEASUREMENT,
                    ),
                ),
            ],
            "tv6peegl": [  # Soil moisture sensor
                TuyaBLETemperatureMapping(dp_id=101),
                TuyaBLESensorMapping(
                    dp_id=102,
                    description=SensorEntityDescription(
                        key="moisture",
                        device_class=SensorDeviceClass.MOISTURE,
                        native_unit_of_measurement=PERCENTAGE,
                        state_class=SensorStateClass.MEASUREMENT,
                    ),
                ),
            ],
            "vlzqwckk": [
                TuyaBLETemperatureMapping(
                    dp_id=1,
                    coefficient=10.0,
                    description=SensorEntityDescription(
                        key="va_temperature",
                        device_class=SensorDeviceClass.TEMPERATURE,
                        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
                        state_class=SensorStateClass.MEASUREMENT,
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=2,
                    description=SensorEntityDescription(
                        key="va_humidity",
                        device_class=SensorDeviceClass.HUMIDITY,
                        native_unit_of_measurement=PERCENTAGE,
                        state_class=SensorStateClass.MEASUREMENT,
                    ),
                ),
                TuyaBLEBatteryMapping(
                    dp_id=4,
                    description=SensorEntityDescription(
                        key="battery_percentage",
                        device_class=SensorDeviceClass.BATTERY,
                        native_unit_of_measurement=PERCENTAGE,
                        entity_category=EntityCategory.DIAGNOSTIC,
                        state_class=SensorStateClass.MEASUREMENT,
                    ),
                ),
            ],
            "tr0kabuq": [  # Bluetooth Temperature Humidity Sensor
                TuyaBLETemperatureMapping(
                    dp_id=1,
                    coefficient=10.0,
                    description=SensorEntityDescription(
                        key="temp_current",
                        device_class=SensorDeviceClass.TEMPERATURE,
                        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
                        state_class=SensorStateClass.MEASUREMENT,
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=2,
                    description=SensorEntityDescription(
                        key="humidity_value",
                        device_class=SensorDeviceClass.MOISTURE,
                        native_unit_of_measurement=PERCENTAGE,
                        state_class=SensorStateClass.MEASUREMENT,
                    ),
                ),
                TuyaBLEBatteryMapping(
                    dp_id=4,
                    description=SensorEntityDescription(
                        key="battery_percentage",
                        device_class=SensorDeviceClass.BATTERY,
                        native_unit_of_measurement=PERCENTAGE,
                        entity_category=EntityCategory.DIAGNOSTIC,
                        state_class=SensorStateClass.MEASUREMENT,
                    ),
                ),
            ],
        },
    ),
    "dcb": TuyaBLECategorySensorMapping(
        products={
            **dict.fromkeys(
                [
                    "z5ztlw3k",
                    "ajrhf1aj",
                ],  # PARKSIDE Smart battery
                [
                    TuyaBLEBatteryMapping(dp_id=16),
                    TuyaBLETemperatureMapping(dp_id=11),
                    TuyaBLESensorMapping(
                        dp_id=172,
                        description=SensorEntityDescription(
                            key="battery_temp_current",
                            device_class=SensorDeviceClass.TEMPERATURE,
                            native_unit_of_measurement=UnitOfTemperature.CELSIUS,
                            state_class=SensorStateClass.MEASUREMENT,
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=102,
                        description=SensorEntityDescription(
                            key="battery_status",
                            device_class=SensorDeviceClass.ENUM,
                            options=[
                                "Ready",
                                "Charging",
                                "Discharging",
                                "Full",
                                "Sleep",
                                "Error",
                            ],
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=2,
                        description=SensorEntityDescription(
                            key="charge_current",
                            device_class=SensorDeviceClass.CURRENT,
                            native_unit_of_measurement=UnitOfElectricCurrent.MILLIAMPERE,
                            state_class=SensorStateClass.MEASUREMENT,
                            entity_category=EntityCategory.DIAGNOSTIC,
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=3,
                        description=SensorEntityDescription(
                            key="charge_voltage",
                            device_class=SensorDeviceClass.VOLTAGE,
                            native_unit_of_measurement=UnitOfElectricPotential.MILLIVOLT,
                            state_class=SensorStateClass.MEASUREMENT,
                            entity_category=EntityCategory.DIAGNOSTIC,
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=101,
                        description=SensorEntityDescription(
                            key="discharging_current",
                            device_class=SensorDeviceClass.CURRENT,
                            native_unit_of_measurement=UnitOfElectricCurrent.MILLIAMPERE,
                            state_class=SensorStateClass.MEASUREMENT,
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=103,
                        description=SensorEntityDescription(
                            key="charge_to_full_time",
                            device_class=SensorDeviceClass.DURATION,
                            native_unit_of_measurement=UnitOfTime.MINUTES,
                            state_class=SensorStateClass.MEASUREMENT,
                            entity_category=EntityCategory.DIAGNOSTIC,
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=104,
                        description=SensorEntityDescription(
                            key="discharge_to_empty_time",
                            device_class=SensorDeviceClass.DURATION,
                            native_unit_of_measurement=UnitOfTime.SECONDS,
                            state_class=SensorStateClass.MEASUREMENT,
                            entity_category=EntityCategory.DIAGNOSTIC,
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=8,
                        description=SensorEntityDescription(
                            key="charge_times",
                            icon="mdi:counter",
                            state_class=SensorStateClass.TOTAL_INCREASING,
                            entity_category=EntityCategory.DIAGNOSTIC,
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=9,
                        description=SensorEntityDescription(
                            key="discharge_times",
                            icon="mdi:counter",
                            state_class=SensorStateClass.TOTAL_INCREASING,
                            entity_category=EntityCategory.DIAGNOSTIC,
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=14,
                        description=SensorEntityDescription(
                            key="use_time",
                            device_class=SensorDeviceClass.DURATION,
                            native_unit_of_measurement=UnitOfTime.MINUTES,
                            state_class=SensorStateClass.MEASUREMENT,
                            entity_category=EntityCategory.DIAGNOSTIC,
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=15,
                        description=SensorEntityDescription(
                            key="runtime_total",
                            device_class=SensorDeviceClass.DURATION,
                            native_unit_of_measurement=UnitOfTime.MINUTES,
                            state_class=SensorStateClass.TOTAL_INCREASING,
                            entity_category=EntityCategory.DIAGNOSTIC,
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=10,
                        description=SensorEntityDescription(
                            key="peak_current_times",
                            icon="mdi:counter",
                            state_class=SensorStateClass.TOTAL_INCREASING,
                            entity_category=EntityCategory.DIAGNOSTIC,
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=21,
                        description=SensorEntityDescription(
                            key="fault",
                            icon="mdi:alert-circle-outline",
                            entity_category=EntityCategory.DIAGNOSTIC,
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=107,
                        description=SensorEntityDescription(
                            key="over_voltage_times",
                            icon="mdi:counter",
                            state_class=SensorStateClass.TOTAL_INCREASING,
                            entity_category=EntityCategory.DIAGNOSTIC,
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=108,
                        description=SensorEntityDescription(
                            key="under_voltage_times",
                            icon="mdi:counter",
                            state_class=SensorStateClass.TOTAL_INCREASING,
                            entity_category=EntityCategory.DIAGNOSTIC,
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=109,
                        description=SensorEntityDescription(
                            key="overtemp_discharge_times",
                            icon="mdi:counter",
                            state_class=SensorStateClass.TOTAL_INCREASING,
                            entity_category=EntityCategory.DIAGNOSTIC,
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=110,
                        description=SensorEntityDescription(
                            key="overtemp_charge_times",
                            icon="mdi:counter",
                            state_class=SensorStateClass.TOTAL_INCREASING,
                            entity_category=EntityCategory.DIAGNOSTIC,
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=111,
                        description=SensorEntityDescription(
                            key="undertemp_discharge_times",
                            icon="mdi:counter",
                            state_class=SensorStateClass.TOTAL_INCREASING,
                            entity_category=EntityCategory.DIAGNOSTIC,
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=112,
                        description=SensorEntityDescription(
                            key="undertemp_charge_times",
                            icon="mdi:counter",
                            state_class=SensorStateClass.TOTAL_INCREASING,
                            entity_category=EntityCategory.DIAGNOSTIC,
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=113,
                        description=SensorEntityDescription(
                            key="short_circuit_times",
                            icon="mdi:counter",
                            state_class=SensorStateClass.TOTAL_INCREASING,
                            entity_category=EntityCategory.DIAGNOSTIC,
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=114,
                        description=SensorEntityDescription(
                            key="over_current_times",
                            icon="mdi:counter",
                            state_class=SensorStateClass.TOTAL_INCREASING,
                            entity_category=EntityCategory.DIAGNOSTIC,
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=19,
                        description=SensorEntityDescription(
                            key="product_type",
                            entity_category=EntityCategory.DIAGNOSTIC,
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=150,
                        description=SensorEntityDescription(
                            key="tool_product_type",
                            entity_category=EntityCategory.DIAGNOSTIC,
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=152,
                        description=SensorEntityDescription(
                            key="tool_rotation_speed",
                            icon="mdi:rotate-3d-variant",
                            state_class=SensorStateClass.MEASUREMENT,
                            entity_category=EntityCategory.DIAGNOSTIC,
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=153,
                        description=SensorEntityDescription(
                            key="tool_torque",
                            icon="mdi:screw-lag",
                            state_class=SensorStateClass.MEASUREMENT,
                            entity_category=EntityCategory.DIAGNOSTIC,
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=154,
                        description=SensorEntityDescription(
                            key="tool_runtime_total",
                            device_class=SensorDeviceClass.DURATION,
                            native_unit_of_measurement=UnitOfTime.MINUTES,
                            state_class=SensorStateClass.TOTAL_INCREASING,
                            entity_category=EntityCategory.DIAGNOSTIC,
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=156,
                        description=SensorEntityDescription(
                            key="tool_fault",
                            icon="mdi:alert-circle-outline",
                            entity_category=EntityCategory.DIAGNOSTIC,
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=157,
                        description=SensorEntityDescription(
                            key="tools_current",
                            device_class=SensorDeviceClass.CURRENT,
                            state_class=SensorStateClass.MEASUREMENT,
                            entity_category=EntityCategory.DIAGNOSTIC,
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=158,
                        description=SensorEntityDescription(
                            key="tool_ot_times",
                            state_class=SensorStateClass.TOTAL_INCREASING,
                            entity_category=EntityCategory.DIAGNOSTIC,
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=159,
                        description=SensorEntityDescription(
                            key="tool_locked_times",
                            state_class=SensorStateClass.TOTAL_INCREASING,
                            entity_category=EntityCategory.DIAGNOSTIC,
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=160,
                        description=SensorEntityDescription(
                            key="tool_oc_times",
                            state_class=SensorStateClass.TOTAL_INCREASING,
                            entity_category=EntityCategory.DIAGNOSTIC,
                        ),
                    ),
                ],
            ),
        },
    ),
    "zwjcy": TuyaBLECategorySensorMapping(
        products={
            **dict.fromkeys(
                [
                    "gvygg3m8",  # Smartlife Plant Sensor SGS01
                    "jabotj1z",  # SRB-PM01 Soil Moisture Sensor
                ],
                [
                    TuyaBLETemperatureMapping(
                        dp_id=5,
                        coefficient=10.0,
                        description=SensorEntityDescription(
                            key="temp_current",
                            device_class=SensorDeviceClass.TEMPERATURE,
                            native_unit_of_measurement=UnitOfTemperature.CELSIUS,
                            state_class=SensorStateClass.MEASUREMENT,
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=3,
                        description=SensorEntityDescription(
                            key="moisture",
                            device_class=SensorDeviceClass.MOISTURE,
                            native_unit_of_measurement=PERCENTAGE,
                            state_class=SensorStateClass.MEASUREMENT,
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=14,
                        description=SensorEntityDescription(
                            key="battery_state",
                            icon="mdi:battery",
                            device_class=SensorDeviceClass.ENUM,
                            entity_category=EntityCategory.DIAGNOSTIC,
                            options=[
                                BATTERY_STATE_LOW,
                                BATTERY_STATE_NORMAL,
                                BATTERY_STATE_HIGH,
                            ],
                        ),
                        icons=[
                            "mdi:battery-alert",
                            "mdi:battery-50",
                            "mdi:battery-check",
                        ],
                    ),
                    TuyaBLEBatteryMapping(
                        dp_id=15,
                        description=SensorEntityDescription(
                            key="battery_percentage",
                            device_class=SensorDeviceClass.BATTERY,
                            native_unit_of_measurement=PERCENTAGE,
                            entity_category=EntityCategory.DIAGNOSTIC,
                            state_class=SensorStateClass.MEASUREMENT,
                        ),
                    ),
                ],
            ),
        },
    ),
    "znhsb": TuyaBLECategorySensorMapping(
        products={
            "cdlandip": [  # Smart water bottle
                TuyaBLETemperatureMapping(dp_id=101),
                TuyaBLESensorMapping(
                    dp_id=102,
                    description=SensorEntityDescription(
                        key="water_intake",
                        device_class=SensorDeviceClass.WATER,
                        native_unit_of_measurement=UnitOfVolume.MILLILITERS,
                        state_class=SensorStateClass.MEASUREMENT,
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=104,
                    description=SensorEntityDescription(
                        key="battery",
                        device_class=SensorDeviceClass.BATTERY,
                        native_unit_of_measurement=PERCENTAGE,
                        entity_category=EntityCategory.DIAGNOSTIC,
                        state_class=SensorStateClass.MEASUREMENT,
                    ),
                    getter=battery_enum_getter,
                ),
            ],
        },
    ),
    "ggq": TuyaBLECategorySensorMapping(
        products={
            "6pahkcau": [  # Irrigation computer PARKSIDE PPB A1
                TuyaBLEBatteryMapping(dp_id=11),
                TuyaBLESensorMapping(
                    dp_id=6,
                    description=SensorEntityDescription(
                        key="time_left",
                        device_class=SensorDeviceClass.DURATION,
                        native_unit_of_measurement=UnitOfTime.MINUTES,
                        state_class=SensorStateClass.MEASUREMENT,
                    ),
                ),
            ],
            "jntxv3q4": [  # YZD02B dual irrigation timer
                TuyaBLEBatteryMapping(dp_id=11),
                TuyaBLESensorMapping(
                    dp_id=111,
                    description=SensorEntityDescription(
                        key="use_time_z1",
                        device_class=SensorDeviceClass.DURATION,
                        native_unit_of_measurement=UnitOfTime.SECONDS,
                        state_class=SensorStateClass.MEASUREMENT,
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=110,
                    description=SensorEntityDescription(
                        key="use_time_z2",
                        device_class=SensorDeviceClass.DURATION,
                        native_unit_of_measurement=UnitOfTime.SECONDS,
                        state_class=SensorStateClass.MEASUREMENT,
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=112,
                    dp_type=TuyaBLEDataPointType.DT_ENUM,
                    description=SensorEntityDescription(
                        key="work_state_z1",
                        device_class=SensorDeviceClass.ENUM,
                        options=["manual", "auto", "idle"],
                        entity_category=EntityCategory.DIAGNOSTIC,
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=113,
                    dp_type=TuyaBLEDataPointType.DT_ENUM,
                    description=SensorEntityDescription(
                        key="work_state_z2",
                        device_class=SensorDeviceClass.ENUM,
                        options=["manual", "auto", "idle"],
                        entity_category=EntityCategory.DIAGNOSTIC,
                    ),
                ),
            ],
            **dict.fromkeys(
                [
                    "hfgdqhho",
                    "qycalacn",
                    "fnlw6npo",
                    "jjqi2syk",
                ],  # Irrigation computer - dual outlet
                [
                    TuyaBLEBatteryMapping(dp_id=11),
                    TuyaBLESensorMapping(
                        dp_id=111,
                        description=SensorEntityDescription(
                            key="use_time_z1",
                            device_class=SensorDeviceClass.DURATION,
                            native_unit_of_measurement=UnitOfTime.SECONDS,
                            state_class=SensorStateClass.MEASUREMENT,
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=110,
                        description=SensorEntityDescription(
                            key="use_time_z2",
                            device_class=SensorDeviceClass.DURATION,
                            native_unit_of_measurement=UnitOfTime.SECONDS,
                            state_class=SensorStateClass.MEASUREMENT,
                        ),
                    ),
                ],
            ),
        },
    ),
    "sfkzq": TuyaBLECategorySensorMapping(
        products={
            "16wgjvck": [
                TuyaBLEBatteryMapping(dp_id=7),
                TuyaBLESensorMapping(
                    dp_id=7,
                    dp_type=TuyaBLEDataPointType.DT_VALUE,
                    description=SensorEntityDescription(
                        key="battery_percentage",
                        name="Battery Percentage",
                        device_class=SensorDeviceClass.BATTERY,
                        native_unit_of_measurement=PERCENTAGE,
                        state_class=SensorStateClass.MEASUREMENT,
                        entity_category=EntityCategory.DIAGNOSTIC,
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=8,
                    dp_type=TuyaBLEDataPointType.DT_ENUM,
                    description=SensorEntityDescription(
                        key="battery_state",
                        name="Battery State",
                        device_class=SensorDeviceClass.ENUM,
                        options=["low", "middle", "high"],
                        entity_category=EntityCategory.DIAGNOSTIC,
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=104,
                    dp_type=TuyaBLEDataPointType.DT_VALUE,
                    description=SensorEntityDescription(
                        key="battery_percentage_alt",
                        name="Battery Percentage (Alt)",
                        device_class=SensorDeviceClass.BATTERY,
                        native_unit_of_measurement=PERCENTAGE,
                        state_class=SensorStateClass.MEASUREMENT,
                        entity_category=EntityCategory.DIAGNOSTIC,
                    ),
                ),
            ],
            "tqzkwarw": [  # HCT-611 Water Timer
                TuyaBLEBatteryMapping(
                    dp_id=7,
                    coefficient=20.0,
                ),
                TuyaBLESensorMapping(
                    dp_id=8,
                    dp_type=TuyaBLEDataPointType.DT_ENUM,
                    description=SensorEntityDescription(
                        key="battery_state",
                        name="Battery State",
                        device_class=SensorDeviceClass.ENUM,
                        options=["low", "middle", "high"],
                        entity_category=EntityCategory.DIAGNOSTIC,
                    ),
                ),
                TuyaBLEWorkStateMapping(dp_id=12),
            ],
            "0axr5s0b": [  # Valve Controller
                TuyaBLEBatteryMapping(dp_id=7),
                TuyaBLESensorMapping(
                    # dp_id=15,
                    dp_id=11,
                    description=SensorEntityDescription(
                        key="time_left",
                        device_class=SensorDeviceClass.DURATION,
                        native_unit_of_measurement=UnitOfTime.SECONDS,
                        state_class=SensorStateClass.MEASUREMENT,
                    ),
                ),
            ],
            "ojrvmfkk": [  # Unistyle WT-04W Water Timer
                TuyaBLEBatteryMapping(dp_id=101),
                # Valve 1 remaining time (DP 103)
                TuyaBLESensorMapping(
                    dp_id=103,
                    description=SensorEntityDescription(
                        key="time_left_z1",
                        device_class=SensorDeviceClass.DURATION,
                        native_unit_of_measurement=UnitOfTime.SECONDS,
                        state_class=SensorStateClass.MEASUREMENT,
                    ),
                ),
                # Valve 2 remaining time (DP 124)
                TuyaBLESensorMapping(
                    dp_id=124,
                    description=SensorEntityDescription(
                        key="time_left_z2",
                        device_class=SensorDeviceClass.DURATION,
                        native_unit_of_measurement=UnitOfTime.SECONDS,
                        state_class=SensorStateClass.MEASUREMENT,
                    ),
                ),
                # Valve 1 status (DP 12)
                TuyaBLESensorMapping(
                    dp_id=12,
                    dp_type=TuyaBLEDataPointType.DT_ENUM,
                    description=SensorEntityDescription(
                        key="work_state_z1",
                        device_class=SensorDeviceClass.ENUM,
                        options=["auto", "manual", "idle", "working", "rain_delay"],
                    ),
                ),
                # Valve 2 status (DP 123)
                TuyaBLESensorMapping(
                    dp_id=123,
                    dp_type=TuyaBLEDataPointType.DT_ENUM,
                    description=SensorEntityDescription(
                        key="work_state_z2",
                        device_class=SensorDeviceClass.ENUM,
                        options=["auto", "manual", "idle", "working", "rain_delay"],
                    ),
                ),
            ],
            **dict.fromkeys(
                ["ldcdnigc", "e1poaiwa"],  # ZX-7378 / Rainpoint TTV102B
                [
                    TuyaBLESensorMapping(
                        dp_id=12,
                        dp_type=TuyaBLEDataPointType.DT_ENUM,
                        description=SensorEntityDescription(
                            key="work_state",
                            device_class=SensorDeviceClass.ENUM,
                            options=["auto", "manual", "idle"],
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=8,
                        dp_type=TuyaBLEDataPointType.DT_ENUM,
                        description=SensorEntityDescription(
                            key="battery_state",
                            name="Battery State",
                            device_class=SensorDeviceClass.ENUM,
                            options=["low", "middle", "high"],
                            entity_category=EntityCategory.DIAGNOSTIC,
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=7,
                        dp_type=TuyaBLEDataPointType.DT_VALUE,
                        description=SensorEntityDescription(
                            key="battery_percentage",
                            name="Battery Percentage",
                            device_class=SensorDeviceClass.BATTERY,
                            native_unit_of_measurement=PERCENTAGE,
                            state_class=SensorStateClass.MEASUREMENT,
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=15,
                        description=SensorEntityDescription(
                            key="use_time_one",
                            device_class=SensorDeviceClass.DURATION,
                            native_unit_of_measurement=UnitOfTime.SECONDS,
                            entity_category=EntityCategory.DIAGNOSTIC,
                            state_class=SensorStateClass.MEASUREMENT,
                        ),
                    ),
                ],
            ),
            "hfgdqhho": [  # Irrigation computer - SGW02/SGW08
                TuyaBLEBatteryMapping(dp_id=11),
                TuyaBLESensorMapping(
                    # dp_id=15,
                    dp_id=11,
                    description=SensorEntityDescription(
                        key="time_left",
                        device_class=SensorDeviceClass.DURATION,
                        native_unit_of_measurement=UnitOfTime.SECONDS,
                        state_class=SensorStateClass.MEASUREMENT,
                    ),
                ),
            ],
            **dict.fromkeys(
                ["46zia2nz", "1fcnd8xk", "nxquc5lb", "svhikeyq", "d4vpmigg"],
                [
                    TuyaBLEBatteryMapping(dp_id=7),
                    TuyaBLEWorkStateMapping(dp_id=12),
                    TuyaBLESensorMapping(
                        dp_id=15,
                        description=SensorEntityDescription(
                            key="use_time_one",
                            device_class=SensorDeviceClass.DURATION,
                            native_unit_of_measurement=UnitOfTime.SECONDS,
                            state_class=SensorStateClass.MEASUREMENT,
                        ),
                    ),
                    TuyaBLESensorMapping(
                        dp_id=9,
                        description=SensorEntityDescription(
                            key="time_use",
                            device_class=SensorDeviceClass.DURATION,
                            native_unit_of_measurement=UnitOfTime.SECONDS,
                            state_class=SensorStateClass.MEASUREMENT,
                        ),
                    ),
                ],
            ),
        },
    ),
    "cl": TuyaBLECategorySensorMapping(
        products={
            **dict.fromkeys(
                [
                    "4pbr8eig",
                    "qqdxfdht",
                    "kcy0x4pi",
                    "vlwf3ud6",
                    "v3fzfd2y",
                ],  # Blind Controller
                [
                    TuyaBLEBatteryMapping(dp_id=13),
                    TuyaBLESensorMapping(
                        dp_id=7,
                        description=SensorEntityDescription(
                            key="cover_work_state",
                            entity_category=EntityCategory.DIAGNOSTIC,
                            device_class=SensorDeviceClass.ENUM,
                            options=["STANDBY", "SUCCESS", "LEARNING"],
                        ),
                    ),
                ],
            ),
        }
    ),
    "cxjmb": TuyaBLECategorySensorMapping(
        products={
            "pnxl0r3l": [  # Window Cleaner Robot
                TuyaBLESensorMapping(
                    dp_id=4,
                    description=SensorEntityDescription(
                        key="status",
                        icon="mdi:robot",
                        device_class=SensorDeviceClass.ENUM,
                        options=[
                            "standby",
                            "cleaning",
                            "smart_clean",
                            "z_clean",
                            "n_clean",
                            "edge_clean",
                            "spot_clean",
                            "pause",
                            "stop",
                            "charge",
                        ],
                    ),
                ),
                TuyaBLESensorMapping(
                    dp_id=6,
                    description=SensorEntityDescription(
                        key="clean_time",
                        icon="mdi:timer-outline",
                        device_class=SensorDeviceClass.DURATION,
                        native_unit_of_measurement=UnitOfTime.MINUTES,
                        state_class=SensorStateClass.MEASUREMENT,
                    ),
                ),
            ],
        },
    ),
    "slj": TuyaBLECategorySensorMapping(
        products={
            "mqqna0px": [
                TuyaBLEBatteryMapping(dp_id=4),
                TuyaBLESensorMapping(
                    dp_id=5,
                    description=SensorEntityDescription(
                        key="flow_velocity",
                        icon="mdi:water-pump",
                        native_unit_of_measurement="L/min",
                        state_class=SensorStateClass.MEASUREMENT,
                    ),
                    coefficient=10.0,
                ),
                TuyaBLESensorMapping(
                    dp_id=2,
                    description=SensorEntityDescription(
                        key="water_once",
                        icon="mdi:water",
                        native_unit_of_measurement=UnitOfVolume.LITERS,
                        device_class=SensorDeviceClass.WATER,
                        state_class=SensorStateClass.TOTAL_INCREASING,
                    ),
                    coefficient=10.0,
                ),
                TuyaBLESensorMapping(
                    dp_id=1,
                    description=SensorEntityDescription(
                        key="water_use_data",
                        icon="mdi:water",
                        native_unit_of_measurement=UnitOfVolume.LITERS,
                        device_class=SensorDeviceClass.WATER,
                        state_class=SensorStateClass.TOTAL_INCREASING,
                    ),
                    coefficient=10.0,
                ),
                TuyaBLESensorMapping(
                    dp_id=101,
                    description=SensorEntityDescription(
                        key="day_water_usage",
                        icon="mdi:water",
                        native_unit_of_measurement=UnitOfVolume.LITERS,
                        device_class=SensorDeviceClass.WATER,
                        state_class=SensorStateClass.TOTAL_INCREASING,
                    ),
                    coefficient=10.0,
                ),
                TuyaBLESensorMapping(
                    dp_id=107,
                    description=SensorEntityDescription(
                        key="total_usage_after_reset",
                        icon="mdi:water",
                        native_unit_of_measurement=UnitOfVolume.LITERS,
                        device_class=SensorDeviceClass.WATER,
                        state_class=SensorStateClass.TOTAL_INCREASING,
                    ),
                    coefficient=10.0,
                ),
                TuyaBLESensorMapping(
                    dp_id=108,
                    description=SensorEntityDescription(
                        key="day_usage_after_reset",
                        icon="mdi:water",
                        native_unit_of_measurement=UnitOfVolume.LITERS,
                        device_class=SensorDeviceClass.WATER,
                        state_class=SensorStateClass.TOTAL_INCREASING,
                    ),
                    coefficient=10.0,
                ),
            ]
        }
    ),
    "jsq": TuyaBLECategorySensorMapping(
        products={
            "if1nolcm": [
                TuyaBLESensorMapping(
                    dp_id=6,
                    description=SensorEntityDescription(
                        key="time_remaining",
                        device_class=SensorDeviceClass.DURATION,
                        native_unit_of_measurement=UnitOfTime.MINUTES,
                        state_class=SensorStateClass.MEASUREMENT,
                        entity_category=EntityCategory.DIAGNOSTIC,
                    ),
                ),
            ],
        },
    ),
}


def rssi_getter(sensor: TuyaBLESensor) -> None:
    sensor._attr_native_value = sensor._device.rssi


rssi_mapping = TuyaBLESensorMapping(
    dp_id=SIGNAL_STRENGTH_DP_ID,
    description=SensorEntityDescription(
        key="signal_strength",
        device_class=SensorDeviceClass.SIGNAL_STRENGTH,
        native_unit_of_measurement=SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
    ),
    getter=rssi_getter,
)


def get_mapping_by_device(
    device: TuyaBLEDevice,
) -> list[TuyaBLESensorMapping | TuyaBLELastUnlockSensorMapping]:
    category = mapping.get(device.category)
    if category is not None and category.products is not None:
        product_mapping = category.products.get(device.product_id)
        if product_mapping is not None:
            return product_mapping
        if category.mapping is not None:
            return category.mapping

    return []


class TuyaBLESensor(TuyaBLEEntity, SensorEntity):
    """Representation of a Tuya BLE sensor."""

    platform = Platform.SENSOR

    def __init__(
        self,
        hass: HomeAssistant,
        coordinator: DataUpdateCoordinator,
        device: TuyaBLEDevice,
        product: TuyaBLEProductInfo,
        mapping: TuyaBLESensorMapping,
    ) -> None:
        super().__init__(hass, coordinator, device, product, mapping.description)
        self._mapping = mapping

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        datapoint = self._device.datapoints[self._mapping.dp_id]
        if self._mapping.requires_current_session and not (
            datapoint and datapoint.received_in_current_session
        ):
            self._attr_native_value = None
            self.async_write_ha_state()
            return
        if self._mapping.getter is not None:
            self._mapping.getter(self)
        else:
            if datapoint:
                if datapoint.type == TuyaBLEDataPointType.DT_ENUM:
                    if self.entity_description.options is not None:
                        if datapoint.value >= 0 and datapoint.value < len(
                            self.entity_description.options
                        ):
                            self._attr_native_value = self.entity_description.options[
                                datapoint.value
                            ]
                        else:
                            self._attr_native_value = datapoint.value
                    if self._mapping.icons is not None:
                        if datapoint.value >= 0 and datapoint.value < len(
                            self._mapping.icons
                        ):
                            self._attr_icon = self._mapping.icons[datapoint.value]
                elif datapoint.type == TuyaBLEDataPointType.DT_VALUE:
                    if isinstance(self._mapping, TuyaBLEBatteryMapping) and (
                        not isinstance(datapoint.value, int | float)
                        or isinstance(datapoint.value, bool)
                    ):
                        self._attr_native_value = None
                    else:
                        self._attr_native_value = (
                            datapoint.value / self._mapping.coefficient
                        )
                else:
                    self._attr_native_value = datapoint.value
        if isinstance(self._mapping, TuyaBLEBatteryMapping):
            self._attr_native_value = _normalize_battery_percentage(
                self._attr_native_value
            )
        self.async_write_ha_state()

    @property
    def available(self) -> bool:
        """Return if entity is available."""
        result = super().available
        if result and self._mapping.requires_current_session:
            datapoint = self._device.datapoints[self._mapping.dp_id]
            result = bool(datapoint and datapoint.received_in_current_session)
        if result and self._mapping.is_available:
            result = self._mapping.is_available(self, self._product)
        return result


class TuyaBLES1LastConfirmedSensor(
    TuyaBLESensor, TuyaBLES1LastConfirmedEntity, RestoreSensor
):
    """Restore the exact S1 Battery sensor only."""

    @property
    def native_value(self):
        """Return the safely retained S1 Battery value."""
        retained = self._last_confirmed_value
        return retained.value if retained is not None else None

    @callback
    def _handle_coordinator_update(self) -> None:
        """Publish retained S1 Battery state without generic sensor updates."""
        retained = self._last_confirmed_value
        self._attr_native_value = retained.value if retained is not None else None
        self.async_write_ha_state()

    @property
    def available(self) -> bool:
        """Keep a validated retained S1 value visible after disconnect."""
        return self._last_confirmed_value is not None


def _select_last_unlock_datapoint(
    unlock_methods: Mapping[int, str],
    update_batch: Sequence[TuyaBLEDataPoint],
) -> TuyaBLEDataPoint | None:
    """Select an unambiguous unlock event from the current callback batch."""
    candidates = [
        datapoint for datapoint in update_batch if datapoint.id in unlock_methods
    ]
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        changed_candidates = [
            datapoint for datapoint in candidates if datapoint.changed_by_device
        ]
        if len(changed_candidates) == 1:
            return changed_candidates[0]
    return None


class TuyaBLELastUnlockSensor(TuyaBLEEntity, SensorEntity):
    """Represent the last unambiguous unlock method in one callback batch."""

    platform = Platform.SENSOR
    _attr_force_update = True

    def __init__(
        self,
        hass: HomeAssistant,
        coordinator: TuyaBLECoordinator,
        device: TuyaBLEDevice,
        product: TuyaBLEProductInfo,
        mapping: TuyaBLELastUnlockSensorMapping,
    ) -> None:
        super().__init__(hass, coordinator, device, product, mapping.description)
        self._unlock_methods = mapping.unlock_methods
        self._attr_native_value = None
        self._attr_extra_state_attributes = {}
        self._last_connected = coordinator.connected

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle only datapoints in the coordinator's current callback batch."""
        connected = self._coordinator.connected
        availability_changed = connected != self._last_connected
        self._last_connected = connected
        update_batch = self._coordinator.last_updates
        if not update_batch:
            if availability_changed:
                self.async_write_ha_state()
            return

        datapoint = _select_last_unlock_datapoint(
            self._unlock_methods,
            update_batch,
        )
        if datapoint is None:
            if availability_changed:
                self.async_write_ha_state()
            return

        method = self._unlock_methods[datapoint.id]
        attributes: dict[str, str | int] = {"method": method}
        if isinstance(datapoint.value, int) and not isinstance(datapoint.value, bool):
            attributes["value"] = datapoint.value
        self._attr_native_value = method
        self._attr_extra_state_attributes = attributes
        self.async_write_ha_state()


class TuyaBLELastStatusUpdateSensor(TuyaBLEEntity, RestoreSensor):
    """Expose the latest scoped S1 confirmation without any BLE work."""

    platform = Platform.SENSOR

    def __init__(
        self,
        hass: HomeAssistant,
        coordinator: TuyaBLECoordinator,
        device: TuyaBLEDevice,
        product: TuyaBLEProductInfo,
        mapping: TuyaBLELastStatusUpdateMapping,
    ) -> None:
        super().__init__(hass, coordinator, device, product, mapping.description)
        self._restored_timestamp = None
        self._unsub_last_confirmed = None

    async def async_added_to_hass(self) -> None:
        """Restore the aggregate timestamp without initiating BLE work."""
        await super().async_added_to_hass()
        previous = await self.async_get_last_state()
        if previous is not None:
            self._restored_timestamp = _parse_restored_timestamp(previous.state)
        self._unsub_last_confirmed = (
            self._device.last_confirmed_s1_state.register_callback(
                self.async_write_ha_state
            )
        )
        self.async_write_ha_state()

    async def async_will_remove_from_hass(self) -> None:
        """Release the local presentation listener on unload."""
        unsubscribe = self._unsub_last_confirmed
        self._unsub_last_confirmed = None
        if unsubscribe is not None:
            unsubscribe()
        await super().async_will_remove_from_hass()

    @property
    def native_value(self):
        """Return the latest retained timestamp, if any."""
        latest = self._device.last_confirmed_s1_state.latest_confirmed_at
        if latest is None:
            return self._restored_timestamp
        if self._restored_timestamp is None:
            return latest
        return max(latest, self._restored_timestamp)

    @property
    def available(self) -> bool:
        """Stay visible after disconnect once a safe timestamp exists."""
        return self.native_value is not None


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the Tuya BLE sensors."""
    data: TuyaBLEData = hass.data[DOMAIN][entry.entry_id]
    mappings = get_mapping_by_device(data.device)
    entities: list[
        TuyaBLESensor | TuyaBLELastUnlockSensor | TuyaBLELastStatusUpdateSensor
    ] = [
        TuyaBLESensor(
            hass,
            data.coordinator,
            data.device,
            data.product,
            rssi_mapping,
        )
    ]
    for mapping in mappings:
        if isinstance(mapping, TuyaBLELastStatusUpdateMapping):
            entities.append(
                TuyaBLELastStatusUpdateSensor(
                    hass,
                    data.coordinator,
                    data.device,
                    data.product,
                    mapping,
                )
            )
            continue
        if isinstance(mapping, TuyaBLELastUnlockSensorMapping):
            entities.append(
                TuyaBLELastUnlockSensor(
                    hass,
                    data.coordinator,
                    data.device,
                    data.product,
                    mapping,
                )
            )
        elif mapping.force_add or data.device.datapoints.has_id(
            mapping.dp_id, mapping.dp_type
        ):
            entity_class = (
                TuyaBLES1LastConfirmedSensor
                if (data.device.category, data.device.product_id)
                == ("jtmspro", "xqeob8h6")
                and mapping.last_confirmed
                and mapping.dp_id == 8
                else TuyaBLESensor
            )
            entities.append(
                entity_class(
                    hass,
                    data.coordinator,
                    data.device,
                    data.product,
                    mapping,
                )
            )
    async_add_entities(entities)
