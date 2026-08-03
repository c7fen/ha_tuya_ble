"""The Tuya BLE integration."""
from __future__ import annotations

import logging
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
    RestoreSensor
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    CONCENTRATION_PARTS_PER_MILLION,
    PERCENTAGE,
    SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
    UnitOfTime,
    UnitOfTemperature,
    UnitOfVolume
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from homeassistant.components.bluetooth.passive_update_coordinator import PassiveBluetoothDataUpdateCoordinator
from .const import (
    BATTERY_STATE_HIGH,
    BATTERY_STATE_LOW,
    BATTERY_STATE_NORMAL,
    BATTERY_CHARGED,
    BATTERY_CHARGING,
    BATTERY_NOT_CHARGING,
    CO2_LEVEL_ALARM,
    CO2_LEVEL_NORMAL,
    DOMAIN,
)
from .devices import (
    TuyaBLEData,
    TuyaBLEEntity,
    TuyaBLEPassiveCoordinator,
    TuyaBLEProductInfo,
)
from .tuya_ble import TuyaBLEDataPoint, TuyaBLEDataPointType, TuyaBLEDevice
_LOGGER = logging.getLogger(__name__)
SIGNAL_STRENGTH_DP_ID = -1
TuyaBLESensorIsAvailable = Callable[["TuyaBLESensor", TuyaBLEProductInfo], bool] | None
@dataclass
class TuyaBLESensorMapping:
    dp_id: int
    description: SensorEntityDescription
    force_add: bool = True
    dp_type: TuyaBLEDataPointType | None = None
    getter: Callable[[TuyaBLESensor], None] | None = None
    coefficient: float = 1.0
    icons: list[str] | None = None
    is_available: TuyaBLESensorIsAvailable = None

@dataclass
class TuyaBLELastUnlockSensorMapping:
    unlock_methods: dict[int, str]
    description: SensorEntityDescription = field(
        default_factory=lambda: SensorEntityDescription(
            key="last_unlock_method",
            icon="mdi:account-lock-open",
            name="Last Unlock Method",
        )
    )
@dataclass
class TuyaBLEBatteryMapping(TuyaBLESensorMapping):
    description: SensorEntityDescription = field(
        default_factory=lambda: SensorEntityDescription(
            key="battery",
            device_class=SensorDeviceClass.BATTERY,
            native_unit_of_measurement=PERCENTAGE,
            entity_category=EntityCategory.DIAGNOSTIC,
            state_class=SensorStateClass.MEASUREMENT,
        )
    )
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
    result: bool = True
    datapoint = self._device.datapoints[13]
    if datapoint:
        result = bool(datapoint.value)
    return result
def battery_enum_getter(self: TuyaBLESensor) -> None:
    datapoint = self._device.datapoints[104]
    if datapoint:
        try:
            value = int(datapoint.value)
            self._attr_native_value = value * 20
        except (ValueError, TypeError):
            self._attr_native_value = None


def v1_battery_getter(self: TuyaBLESensor) -> None:
    """Return the V1 battery percentage, treating the documented -1 as unknown."""
    datapoint = self._device.datapoints[8]
    value = datapoint.value if datapoint is not None else None
    self._attr_native_value = (
        value
        if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 100
        else None
    )


@dataclass
class TuyaBLECategorySensorMapping:
    products: (
        dict[str, list[TuyaBLESensorMapping | TuyaBLELastUnlockSensorMapping]] | None
    ) = None
    mapping: list[TuyaBLESensorMapping | TuyaBLELastUnlockSensorMapping] | None = None


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
    "ms": TuyaBLECategorySensorMapping(
        products={
            **dict.fromkeys(
                ["ludzroix", "isk2p555", "yy2bmcoh"], # Smart Lock
                [
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
                    ),
                    TuyaBLEBatteryMapping(dp_id=8),
                ],
            ),
            "mqc2hevy": [ # Smart Lock - YSG_T8_8G_htr
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
                TuyaBLELastUnlockSensorMapping(
                    unlock_methods={
                        19: "ble",
                        12: "fingerprint",
                        62: "phone_remote",
                        13: "password",
                        14: "dynamic",
                        55: "temporary",
                        63: "voice_remote"
                    }
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
        }
    ),
    "jtmspro": TuyaBLECategorySensorMapping(
        products={
            "xqeob8h6": [
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
                TuyaBLEBatteryMapping(dp_id=8),
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
                ),
            ],
        },
    ),
    "szjqr": TuyaBLECategorySensorMapping(
        products={
            **dict.fromkeys(
                ["3yqdo5yt", "xhf790if"],  # CubeTouch 1s and II
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
                    "neq16kgd"
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
        },
    ),
    "zwjcy": TuyaBLECategorySensorMapping(
        products={
            "gvygg3m8": [  # Smartlife Plant Sensor SGS01
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
        },
    ),
    "znhsb": TuyaBLECategorySensorMapping(
        products={
            "cdlandip":  # Smart water bottle
            [
                TuyaBLETemperatureMapping(
                    dp_id=101,
                ),
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
            "6pahkcau": [  # Irrigation computer
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
            "hfgdqhho": [  # Irrigation computer - SGW02
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
        else:
            return []
    else:
        return []
class TuyaBLESensor(RestoreSensor, SensorEntity, TuyaBLEEntity):
    """Representation of a Tuya BLE sensor."""
    def __init__(
        self,
        hass: HomeAssistant,
        coordinator: TuyaBLEPassiveCoordinator,
        device: TuyaBLEDevice,
        product: TuyaBLEProductInfo,
        mapping: TuyaBLESensorMapping,
    ) -> None:
        super().__init__(hass, coordinator, device, product, mapping.description)
        self._mapping = mapping

    async def async_added_to_hass(self):
        """Restore state after HA restart."""
        await super().async_added_to_hass()
        if self._attr_native_value is not None:
            return
        last_sensor_data = await self.async_get_last_sensor_data()
        if last_sensor_data is not None:
            self._attr_native_value = last_sensor_data.native_value
            self._attr_native_unit_of_measurement = last_sensor_data.native_unit_of_measurement
            self.async_write_ha_state()

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        if self._mapping.getter is not None:
            self._mapping.getter(self)
            self.async_write_ha_state()
            return
        datapoint = self._device.datapoints[self._mapping.dp_id]
        if not datapoint or datapoint.value is None:
            return
        value = datapoint.value
        if isinstance(value, (int, float)) and hasattr(datapoint, "type"):
            if datapoint.type == TuyaBLEDataPointType.DT_ENUM:
                self._handle_enum_value(datapoint, value)
            elif datapoint.type == TuyaBLEDataPointType.DT_VALUE:
                result = value / self._mapping.coefficient
                # Округлять до int для батарейных сенсоров
                if getattr(self.entity_description, "device_class", None) == SensorDeviceClass.BATTERY:
                    self._attr_native_value = int(result)
                else:
                    self._attr_native_value = result
            else:
                self._attr_native_value = value
        elif isinstance(value, bool):
            self._attr_native_value = int(value)
        else:
            self._attr_native_value = str(value)
        self.async_write_ha_state()

    def _handle_enum_value(self, datapoint, value):
        if self.entity_description.options is not None and 0 <= value < len(self.entity_description.options):
            self._attr_native_value = self.entity_description.options[value]
        else:
            self._attr_native_value = value
        if self._mapping.icons is not None and 0 <= value < len(self._mapping.icons):
            self._attr_icon = self._mapping.icons[value]


def _select_last_unlock_datapoint(
    unlock_methods: Mapping[int, str],
    update_batch: Sequence[TuyaBLEDataPoint],
) -> TuyaBLEDataPoint | None:
    """Select an unambiguous unlock event from one device callback batch."""
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


class TuyaBLELastUnlockSensor(SensorEntity, TuyaBLEEntity):
    """Sensor reflecting the last unlock method and its data."""

    _attr_force_update = True

    def __init__(
        self,
        hass: HomeAssistant,
        coordinator: TuyaBLEPassiveCoordinator,
        device: TuyaBLEDevice,
        product: TuyaBLEProductInfo,
        mapping: TuyaBLELastUnlockSensorMapping,
    ) -> None:
        super().__init__(hass, coordinator, device, product, mapping.description)
        self._unlock_methods = mapping.unlock_methods
        self._attr_native_value = None
        self._attr_extra_state_attributes = {}
        self._last_update_sequence = coordinator.last_update_sequence
        self._last_coordinator_available = coordinator.available

    @callback
    def _handle_coordinator_update(self) -> None:
        update_sequence = self._coordinator.last_update_sequence
        coordinator_available = self._coordinator.available
        if update_sequence == self._last_update_sequence:
            if coordinator_available != self._last_coordinator_available:
                self._last_coordinator_available = coordinator_available
                self.async_write_ha_state()
            return

        self._last_update_sequence = update_sequence
        availability_changed = coordinator_available != self._last_coordinator_available
        self._last_coordinator_available = coordinator_available
        datapoint = _select_last_unlock_datapoint(
            self._unlock_methods,
            self._coordinator.last_update_datapoints,
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


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the Tuya BLE sensors."""
    data: TuyaBLEData = hass.data[DOMAIN][entry.entry_id]
    mappings = get_mapping_by_device(data.device)
    entities: list[TuyaBLESensor|TuyaBLELastUnlockSensor] = [
        TuyaBLESensor(
            hass,
            data.coordinator,
            data.device,
            data.product,
            rssi_mapping,
        )
    ]

    for mapping in mappings:
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
            entities.append(
                TuyaBLESensor(
                    hass,
                    data.coordinator,
                    data.device,
                    data.product,
                    mapping,
                )
            )
    async_add_entities(entities)
