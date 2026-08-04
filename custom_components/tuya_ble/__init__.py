"""The Tuya BLE integration."""
from __future__ import annotations

import logging

from bleak_retry_connector import BLEAK_RETRY_EXCEPTIONS as BLEAK_EXCEPTIONS, get_device

from homeassistant.components import bluetooth
from homeassistant.components.bluetooth import BluetoothScanningMode
from homeassistant.components.bluetooth.match import ADDRESS, BluetoothCallbackMatcher
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_ADDRESS, EVENT_HOMEASSISTANT_STOP, Platform
from homeassistant.core import Event, HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryError, ConfigEntryNotReady
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.entity import EntityCategory

from .tuya_ble import TuyaBLEDevice

from .cloud import HASSTuyaBLEDeviceManager
from .const import DOMAIN
from .devices import (
    TuyaBLECoordinator,
    TuyaBLEData,
    TuyaBLEPassiveCoordinator,
    get_device_product_info,
)

PLATFORMS: list[Platform] = [
    Platform.BUTTON,
    Platform.CLIMATE,
    Platform.NUMBER,
    Platform.SENSOR,
    Platform.BINARY_SENSOR,
    Platform.SELECT,
    Platform.SWITCH,
    Platform.TEXT,
    Platform.LOCK
]

_LOGGER = logging.getLogger(__name__)

S1_CATEGORY = "jtmspro"
S1_PRODUCT_ID = "xqeob8h6"
MOTOR_STATE_KEY = "lock_motor_state"


@callback
def _async_migrate_s1_motor_state_entity(
    hass: HomeAssistant,
    entry: ConfigEntry,
    device: TuyaBLEDevice,
) -> None:
    """Move the S1 Motor State registry entry to the read-only platform."""
    if device.category != S1_CATEGORY or device.product_id != S1_PRODUCT_ID:
        return

    unique_id = f"{device.device_id}-{MOTOR_STATE_KEY}"
    registry = er.async_get(hass)
    old_entity_id = registry.async_get_entity_id(
        Platform.SWITCH, DOMAIN, unique_id
    )
    old_entries = [
        registry_entry
        for registry_entry in er.async_entries_for_config_entry(
            registry, entry.entry_id
        )
        if registry_entry.domain == Platform.SWITCH
        and registry_entry.platform == DOMAIN
        and registry_entry.unique_id.endswith(f"-{MOTOR_STATE_KEY}")
    ]
    if not old_entries and old_entity_id is None:
        return
    if (
        len(old_entries) != 1
        or old_entity_id is None
        or old_entries[0].entity_id != old_entity_id
    ):
        raise ConfigEntryError(
            "Cannot safely migrate the S1 Motor State entity because its "
            "switch registry entry is ambiguous"
        )

    old_entry = old_entries[0]
    if old_entry.config_entry_id != entry.entry_id:
        raise ConfigEntryError(
            "Cannot safely migrate the S1 Motor State entity because its "
            "switch registry entry is not owned by this config entry"
        )

    new_entity_id = registry.async_get_entity_id(
        Platform.BINARY_SENSOR, DOMAIN, unique_id
    )
    new_entry = registry.async_get(new_entity_id) if new_entity_id else None
    if new_entry is not None:
        if new_entry.config_entry_id not in (None, entry.entry_id):
            raise ConfigEntryError(
                "Cannot safely migrate the S1 Motor State entity because its "
                "binary-sensor registry entry belongs to another config entry"
            )
        if (
            old_entry.device_id is not None
            and new_entry.device_id is not None
            and old_entry.device_id != new_entry.device_id
        ):
            raise ConfigEntryError(
                "Cannot safely migrate the S1 Motor State entity because the "
                "old and new registry entries refer to different devices"
            )

    created_entity_id: str | None = None
    try:
        if new_entry is None:
            new_entry = registry.async_get_or_create(
                Platform.BINARY_SENSOR,
                DOMAIN,
                unique_id,
                suggested_object_id=old_entry.entity_id.partition(".")[2],
                disabled_by=old_entry.disabled_by,
                hidden_by=old_entry.hidden_by,
                config_entry=entry,
                config_subentry_id=old_entry.config_subentry_id,
                device_id=old_entry.device_id,
                entity_category=EntityCategory.DIAGNOSTIC,
                has_entity_name=True,
                original_icon="mdi:engine",
                translation_key=MOTOR_STATE_KEY,
            )
            created_entity_id = new_entry.entity_id

        if created_entity_id is not None:
            aliases = list(old_entry.aliases)
            area_id = old_entry.area_id
            categories = dict(old_entry.categories)
            device_class = None
            disabled_by = old_entry.disabled_by
            hidden_by = old_entry.hidden_by
            icon = old_entry.icon
            labels = set(old_entry.labels)
            name = old_entry.name
        else:
            aliases = list(new_entry.aliases)
            aliases.extend(
                alias for alias in old_entry.aliases if alias not in aliases
            )
            area_id = new_entry.area_id or old_entry.area_id
            categories = {**old_entry.categories, **new_entry.categories}
            device_class = new_entry.device_class
            disabled_by = new_entry.disabled_by or old_entry.disabled_by
            hidden_by = new_entry.hidden_by or old_entry.hidden_by
            icon = new_entry.icon or old_entry.icon
            labels = new_entry.labels | old_entry.labels
            name = new_entry.name or old_entry.name

        registry.async_update_entity(
            new_entry.entity_id,
            aliases=aliases,
            area_id=area_id,
            categories=categories,
            config_entry_id=entry.entry_id,
            config_subentry_id=(
                new_entry.config_subentry_id or old_entry.config_subentry_id
            ),
            device_class=device_class,
            device_id=new_entry.device_id or old_entry.device_id,
            disabled_by=disabled_by,
            entity_category=EntityCategory.DIAGNOSTIC,
            hidden_by=hidden_by,
            icon=icon,
            has_entity_name=True,
            labels=labels,
            name=name,
            original_device_class=None,
            original_icon="mdi:engine",
            original_name=None,
            supported_features=0,
            translation_key=MOTOR_STATE_KEY,
            unit_of_measurement=None,
        )
    except Exception:  # noqa: BLE001 - rollback must retain the old entry
        if created_entity_id is not None:
            registry.async_remove(created_entity_id)
        _LOGGER.error("Unable to safely migrate the S1 Motor State entity")
        raise ConfigEntryError(
            "Unable to safely migrate the S1 Motor State entity"
        ) from None

    registry.async_remove(old_entry.entity_id)
    _LOGGER.info("Migrated the S1 Motor State entity to binary_sensor")


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Tuya BLE from a config entry."""
    address: str = entry.data[CONF_ADDRESS]
    ble_device = bluetooth.async_ble_device_from_address(
        hass, address.upper(), True
    ) or await get_device(address)
    if not ble_device:
        raise ConfigEntryNotReady(
            f"Could not find Tuya BLE device with address {address}"
        )
    manager = HASSTuyaBLEDeviceManager(hass, entry.options.copy())
    device = TuyaBLEDevice(manager, ble_device)
    await device.initialize()
    product_info = get_device_product_info(device)
    if product_info is None:
        raise ConfigEntryNotReady(f"Could not determine product info for Tuya BLE device with address {address}")

    _async_migrate_s1_motor_state_entity(hass, entry, device)
    coordinator = TuyaBLEPassiveCoordinator(hass, _LOGGER, address, device)

    '''
    try:
        await device.update()
    except BLEAK_EXCEPTIONS as ex:
        raise ConfigEntryNotReady(
            f"Could not communicate with Tuya BLE device with address {address}"
        ) from ex
    '''
    hass.add_job(device.update())

    @callback
    def _async_update_ble(
        service_info: bluetooth.BluetoothServiceInfoBleak,
        change: bluetooth.BluetoothChange,
    ) -> None:
        """Update from a ble callback."""
        device.set_ble_device_and_advertisement_data(
            service_info.device, service_info.advertisement
        )

    entry.async_on_unload(
        bluetooth.async_register_callback(
            hass,
            _async_update_ble,
            BluetoothCallbackMatcher(address=address),
            BluetoothScanningMode.ACTIVE,
        )
    )

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = TuyaBLEData(
        entry.title,
        device,
        product_info,
        manager,
        coordinator,
    )

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(_async_update_listener))

    async def _async_stop(event: Event) -> None:
        """Close the connection."""
        await device.stop()

    entry.async_on_unload(
        hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, _async_stop)
    )
    return True


async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Handle options update."""
    data: TuyaBLEData = hass.data[DOMAIN][entry.entry_id]
    if entry.title != data.title:
        await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        data: TuyaBLEData = hass.data[DOMAIN].pop(entry.entry_id)
        await data.device.stop()

    return unload_ok
