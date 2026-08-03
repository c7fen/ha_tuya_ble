"""The Tuya BLE integration."""
from __future__ import annotations

from dataclasses import dataclass, field

from homeassistant.components.select import (
    SelectEntity,
    SelectEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfTemperature
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import (
    DOMAIN,
    FINGERBOT_MODE_PROGRAM,
    FINGERBOT_MODE_PUSH,
    FINGERBOT_MODE_SWITCH,
)
from .devices import (
    TuyaBLEData,
    TuyaBLEEntity,
    TuyaBLEPassiveCoordinator,
    TuyaBLEProductInfo,
)
from .tuya_ble import TuyaBLEDataPointType, TuyaBLEDevice


@dataclass
class TuyaBLESelectMapping:
    dp_id: int
    description: SelectEntityDescription
    force_add: bool = True
    dp_type: TuyaBLEDataPointType | None = None


@dataclass(frozen=True)
class TemperatureUnitDescription(SelectEntityDescription):
    key: str = "temperature_unit"
    icon: str = "mdi:thermometer"
    entity_category: EntityCategory = EntityCategory.CONFIG


@dataclass
class TuyaBLEFingerbotModeMapping(TuyaBLESelectMapping):
    description: SelectEntityDescription = field(
        default_factory=lambda: SelectEntityDescription(
            key="fingerbot_mode",
            entity_category=EntityCategory.CONFIG,
            options=[
                FINGERBOT_MODE_PUSH,
                FINGERBOT_MODE_SWITCH,
                FINGERBOT_MODE_PROGRAM,
            ],
        )
    )


@dataclass
class TuyaBLECategorySelectMapping:
    products: dict[str, list[TuyaBLESelectMapping]] | None = None
    mapping: list[TuyaBLESelectMapping] | None = None


mapping: dict[str, TuyaBLECategorySelectMapping] = {
    "co2bj": TuyaBLECategorySelectMapping(
        products={
            "59s19z5m": [
                TuyaBLESelectMapping(
                    dp_id=101,
                    description=TemperatureUnitDescription(
                        options=[
                            UnitOfTemperature.CELSIUS,
                            UnitOfTemperature.FAHRENHEIT,
                        ],
                    ),
                ),
            ],
        },
    ),
    "ms": TuyaBLECategorySelectMapping(
        products={
            **dict.fromkeys(
                ["ludzroix", "isk2p555", "yy2bmcoh"],
                [
                    TuyaBLESelectMapping(
                        dp_id=31,
                        description=SelectEntityDescription(
                            key="beep_volume",
                            icon="mdi:volume-high",
                            options=[
                                "mute",
                                "low",
                                "normal",
                                "high",
                            ],
                            entity_category=EntityCategory.CONFIG,
                        ),
                        dp_type=TuyaBLEDataPointType.DT_ENUM,
                    ),
                ],
            ),
            "mqc2hevy": [
                TuyaBLESelectMapping(
                    dp_id=31,
                    description=SelectEntityDescription(
                        key="beep_volume",
                        icon="mdi:volume-high",
                        options=[
                            "mute",
                            "low",
                            "normal",
                            "high",
                        ],
                        entity_category=EntityCategory.CONFIG,
                    ),
                    dp_type=TuyaBLEDataPointType.DT_ENUM,
                ),
                TuyaBLESelectMapping(
                    dp_id=28,
                    description=SelectEntityDescription(
                        key="language",
                        icon="mdi:translate",
                        options=[
                            "chinese_simplified",
                            "english",
                            "japanese",
                            "russian",
                            "german",
                            "spanish",
                            "french",
                            "korean",
                        ],
                        entity_category=EntityCategory.CONFIG,
                    ),
                    dp_type=TuyaBLEDataPointType.DT_ENUM,
                ),
                TuyaBLESelectMapping(
                    dp_id=68,
                    description=SelectEntityDescription(
                        key="special_function",
                        icon="mdi:tools",
                        options=[
                            "function1",
                            "function2",
                        ],
                        entity_category=EntityCategory.CONFIG,
                    ),
                ),
            ],
        },
    ),
    "jtmspro": TuyaBLECategorySelectMapping(
        products={
            "xqeob8h6": [
                TuyaBLESelectMapping(
                    dp_id=34,
                    description=SelectEntityDescription(
                        key="unlock_switch",
                        icon="mdi:account-key",
                        options=[
                            "single_unlock",
                            "finger_card",
                        ],
                        entity_category=EntityCategory.CONFIG,
                    ),
                    dp_type=TuyaBLEDataPointType.DT_ENUM,
                ),
            ],
        },
    ),
    "szjqr": TuyaBLECategorySelectMapping(
        products={
            **dict.fromkeys(
                ["3yqdo5yt", "xhf790if"],
                [
                    TuyaBLEFingerbotModeMapping(dp_id=2),
                ],
            ),
            **dict.fromkeys(
                ["blliqpsj", "ndvkgsrm", "yiihr7zh", "neq16kgd"],
                [
                    TuyaBLEFingerbotModeMapping(dp_id=8),
                ],
            ),
            **dict.fromkeys(
                ["ltak7e1p", "y6kttvd6", "yrnk7mnn", "nvr2rocq", "bnt7wajf", "rvdceqjh", "5xhbk964"],
                [
                    TuyaBLEFingerbotModeMapping(dp_id=8),
                ],
            ),
        },
    ),
    "wsdcg": TuyaBLECategorySelectMapping(
        products={
            "ojzlzzsw": [
                TuyaBLESelectMapping(
                    dp_id=9,
                    description=TemperatureUnitDescription(
                        options=[
                            UnitOfTemperature.CELSIUS,
                            UnitOfTemperature.FAHRENHEIT,
                        ],
                        entity_registry_enabled_default=False,
                    ),
                ),
            ],
        },
    ),
    "znhsb": TuyaBLECategorySelectMapping(
        products={
            "cdlandip": [
                TuyaBLESelectMapping(
                    dp_id=106,
                    description=TemperatureUnitDescription(
                        options=[
                            UnitOfTemperature.CELSIUS,
                            UnitOfTemperature.FAHRENHEIT,
                        ],
                    ),
                ),
                TuyaBLESelectMapping(
                    dp_id=107,
                    description=SelectEntityDescription(
                        key="reminder_mode",
                        options=[
                            "interval_reminder",
                            "alarm_reminder",
                        ],
                        entity_category=EntityCategory.CONFIG,
                    ),
                ),
            ],
        },
    ),
}


def get_mapping_by_device(device: TuyaBLEDevice) -> list[TuyaBLESelectMapping]:
    category = mapping.get(device.category)
    if category is not None and category.products is not None:
        product_mapping = category.products.get(device.product_id)
        if product_mapping is not None:
            return product_mapping
        if category.mapping is not None:
            return category.mapping
    return []


class TuyaBLESelect(TuyaBLEEntity, SelectEntity):
    """Representation of a Tuya BLE select."""

    def __init__(
        self,
        hass: HomeAssistant,
        coordinator: TuyaBLEPassiveCoordinator,
        device: TuyaBLEDevice,
        product: TuyaBLEProductInfo,
        mapping: TuyaBLESelectMapping,
    ) -> None:
        super().__init__(hass, coordinator, device, product, mapping.description)
        self._mapping = mapping
        self._attr_options = mapping.description.options

    @property
    def current_option(self) -> str | None:
        try:
            datapoint = self._device.datapoints[self._mapping.dp_id]
        except Exception:
            datapoint = None

        if datapoint is not None:
            value = getattr(datapoint, "value", None)
            if isinstance(value, int) and 0 <= value < len(self._attr_options):
                return self._attr_options[value]
            if value is not None:
                return str(value)
        return None

    def select_option(self, value: str) -> None:
        if value not in self._attr_options:
            return

        int_value = self._attr_options.index(value)

        datapoint = self._device.datapoints.get_or_create(
            self._mapping.dp_id,
            TuyaBLEDataPointType.DT_ENUM,
            int_value,
        )

        if not datapoint:
            return

        result = datapoint.set_value(int_value)
        if hasattr(result, "__await__"):
            self._hass.create_task(result)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    data: TuyaBLEData = hass.data[DOMAIN][entry.entry_id]
    mappings = get_mapping_by_device(data.device)

    entities: list[TuyaBLESelect] = []
    for mapping_item in mappings:
        if (
            mapping_item.force_add
            or data.device.datapoints.has_id(mapping_item.dp_id, mapping_item.dp_type)
        ):
            entities.append(
                TuyaBLESelect(
                    hass,
                    data.coordinator,
                    data.device,
                    data.product,
                    mapping_item,
                )
            )

    async_add_entities(entities)
