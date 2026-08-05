"""The Tuya BLE integration."""

from __future__ import annotations

import logging
from typing import Any

from bleak_retry_connector import BLEAK_RETRY_EXCEPTIONS as BLEAK_EXCEPTIONS, get_device

from homeassistant.components import bluetooth
from homeassistant.components.binary_sensor import BinarySensorDeviceClass
from homeassistant.components.bluetooth.match import ADDRESS, BluetoothCallbackMatcher
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_ADDRESS, EVENT_HOMEASSISTANT_STOP, Platform
from homeassistant.core import Event, HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryError, ConfigEntryNotReady
from homeassistant.helpers import device_registry as dr, entity_registry as er
from homeassistant.helpers.entity import EntityCategory

from .tuya_ble import TuyaBLEDevice

from .cloud import HASSTuyaBLEDeviceManager, normalize_app_type_data
from .const import DOMAIN
from .devices import TuyaBLECoordinator, TuyaBLEData, get_device_product_info

PLATFORMS: list[Platform] = [
    Platform.BUTTON,
    Platform.CLIMATE,
    Platform.LOCK,
    Platform.NUMBER,
    Platform.SENSOR,
    Platform.BINARY_SENSOR,
    Platform.LIGHT,
    Platform.SELECT,
    Platform.SWITCH,
    Platform.TEXT,
    Platform.COVER,
    Platform.EVENT,
    Platform.VACUUM,
]

_LOGGER = logging.getLogger(__name__)

_S1_CATEGORY = "jtmspro"
_S1_PRODUCT_ID = "xqeob8h6"
_MOTOR_STATE_KEY = "lock_motor_state"


def _registry_entry_subentry_id(registry_entry: er.RegistryEntry) -> str | None:
    """Return the config subentry association on HA versions that support it."""
    return getattr(registry_entry, "config_subentry_id", None)


def _validate_registry_association(
    hass: HomeAssistant,
    entry: ConfigEntry,
    device: TuyaBLEDevice,
    registry_entry: er.RegistryEntry,
) -> None:
    """Validate config-entry, subentry, and device ownership for a migration."""
    if registry_entry.config_entry_id != entry.entry_id:
        raise ConfigEntryError(
            "Cannot safely migrate the S1 Motor State entity because a registry "
            "entry is not owned by this config entry"
        )

    config_subentry_id = _registry_entry_subentry_id(registry_entry)
    if config_subentry_id is not None:
        subentries = getattr(entry, "subentries", None)
        if subentries is None or config_subentry_id not in subentries:
            raise ConfigEntryError(
                "Cannot safely migrate the S1 Motor State entity because a "
                "registry entry has an invalid config subentry"
            )

    if registry_entry.device_id is None:
        return

    registry_device = dr.async_get(hass).async_get(registry_entry.device_id)
    if registry_device is None or entry.entry_id not in registry_device.config_entries:
        raise ConfigEntryError(
            "Cannot safely migrate the S1 Motor State entity because a registry "
            "entry has an invalid device association"
        )

    expected_address = device.address.upper()
    integration_identifiers = {
        identifier.upper()
        for domain, identifier in registry_device.identifiers
        if domain == DOMAIN
    }
    if expected_address not in integration_identifiers:
        raise ConfigEntryError(
            "Cannot safely migrate the S1 Motor State entity because a registry "
            "entry refers to a different device"
        )

    config_entries_subentries = getattr(
        registry_device, "config_entries_subentries", None
    )
    if config_subentry_id is not None and (
        config_entries_subentries is None
        or config_subentry_id
        not in config_entries_subentries.get(entry.entry_id, set())
    ):
        raise ConfigEntryError(
            "Cannot safely migrate the S1 Motor State entity because its config "
            "subentry and device associations conflict"
        )


def _validate_binary_sensor_target(registry_entry: er.RegistryEntry) -> None:
    """Reject target-domain state that cannot safely survive the migration."""
    if registry_entry.device_class is not None:
        try:
            BinarySensorDeviceClass(registry_entry.device_class)
        except (TypeError, ValueError) as err:
            raise ConfigEntryError(
                "Cannot safely migrate the S1 Motor State entity because the "
                "binary-sensor target has an invalid device class"
            ) from err

    if any(
        option_domain != Platform.BINARY_SENSOR
        for option_domain in registry_entry.options
    ):
        raise ConfigEntryError(
            "Cannot safely migrate the S1 Motor State entity because the "
            "binary-sensor target has invalid entity options"
        )


@callback
def _async_migrate_s1_motor_state_entity(
    hass: HomeAssistant,
    entry: ConfigEntry,
    device: TuyaBLEDevice,
) -> None:
    """Move the S1 Motor State registry entry to the read-only platform."""
    if device.category != _S1_CATEGORY or device.product_id != _S1_PRODUCT_ID:
        return

    unique_id = f"{device.device_id}-{_MOTOR_STATE_KEY}"
    registry = er.async_get(hass)
    old_entity_id = registry.async_get_entity_id(Platform.SWITCH, DOMAIN, unique_id)
    old_entries = [
        registry_entry
        for registry_entry in er.async_entries_for_config_entry(
            registry, entry.entry_id
        )
        if registry_entry.domain == Platform.SWITCH
        and registry_entry.platform == DOMAIN
        and registry_entry.unique_id.endswith(f"-{_MOTOR_STATE_KEY}")
    ]
    if not old_entries and old_entity_id is None:
        return
    if (
        len(old_entries) != 1
        or old_entity_id is None
        or old_entries[0].entity_id != old_entity_id
    ):
        raise ConfigEntryError(
            "Cannot safely migrate the S1 Motor State entity because its switch "
            "registry entry is ambiguous"
        )

    old_entry = old_entries[0]
    _validate_registry_association(hass, entry, device, old_entry)

    new_entity_id = registry.async_get_entity_id(
        Platform.BINARY_SENSOR, DOMAIN, unique_id
    )
    new_entry = registry.async_get(new_entity_id) if new_entity_id else None
    if new_entry is not None:
        _validate_registry_association(hass, entry, device, new_entry)
        _validate_binary_sensor_target(new_entry)
        if (
            old_entry.device_id is not None
            and new_entry.device_id is not None
            and old_entry.device_id != new_entry.device_id
        ):
            raise ConfigEntryError(
                "Cannot safely migrate the S1 Motor State entity because the old "
                "and new registry entries refer to different devices"
            )
        old_subentry_id = _registry_entry_subentry_id(old_entry)
        new_subentry_id = _registry_entry_subentry_id(new_entry)
        if (
            old_subentry_id is not None
            and new_subentry_id is not None
            and old_subentry_id != new_subentry_id
        ):
            raise ConfigEntryError(
                "Cannot safely migrate the S1 Motor State entity because the old "
                "and new registry entries refer to different config subentries"
            )

    created_entity_id: str | None = None
    try:
        if new_entry is None:
            create_kwargs: dict[str, Any] = {}
            old_subentry_id = _registry_entry_subentry_id(old_entry)
            if old_subentry_id is not None:
                create_kwargs["config_subentry_id"] = old_subentry_id
            new_entry = registry.async_get_or_create(
                Platform.BINARY_SENSOR,
                DOMAIN,
                unique_id,
                suggested_object_id=old_entry.entity_id.partition(".")[2],
                disabled_by=old_entry.disabled_by,
                hidden_by=old_entry.hidden_by,
                config_entry=entry,
                device_id=old_entry.device_id,
                entity_category=EntityCategory.DIAGNOSTIC,
                has_entity_name=True,
                original_icon="mdi:engine",
                translation_key=_MOTOR_STATE_KEY,
                **create_kwargs,
            )
            created_entity_id = new_entry.entity_id
            _validate_binary_sensor_target(new_entry)

        if isinstance(new_entry.aliases, set):
            merged_aliases: Any = set(new_entry.aliases)
            merged_aliases.update(old_entry.aliases)
        else:
            merged_aliases = list(new_entry.aliases)
            merged_aliases.extend(
                alias for alias in old_entry.aliases if alias not in merged_aliases
            )
        update_kwargs: dict[str, Any] = {}
        config_subentry_id = _registry_entry_subentry_id(new_entry) or (
            _registry_entry_subentry_id(old_entry)
        )
        if config_subentry_id is not None:
            update_kwargs["config_subentry_id"] = config_subentry_id

        updated_entry = registry.async_update_entity(
            new_entry.entity_id,
            aliases=merged_aliases,
            area_id=(
                new_entry.area_id
                if new_entry.area_id is not None
                else old_entry.area_id
            ),
            categories={**old_entry.categories, **new_entry.categories},
            config_entry_id=entry.entry_id,
            device_class=new_entry.device_class,
            device_id=(
                new_entry.device_id
                if new_entry.device_id is not None
                else old_entry.device_id
            ),
            disabled_by=(
                new_entry.disabled_by
                if new_entry.disabled_by is not None
                else old_entry.disabled_by
            ),
            entity_category=EntityCategory.DIAGNOSTIC,
            hidden_by=(
                new_entry.hidden_by
                if new_entry.hidden_by is not None
                else old_entry.hidden_by
            ),
            icon=new_entry.icon if new_entry.icon is not None else old_entry.icon,
            has_entity_name=True,
            labels=new_entry.labels | old_entry.labels,
            name=new_entry.name if new_entry.name is not None else old_entry.name,
            original_device_class=None,
            original_icon="mdi:engine",
            original_name=None,
            supported_features=0,
            translation_key=_MOTOR_STATE_KEY,
            unit_of_measurement=None,
            **update_kwargs,
        )
        verified_entry = registry.async_get(updated_entry.entity_id)
        expected_device_id = (
            new_entry.device_id
            if new_entry.device_id is not None
            else old_entry.device_id
        )
        if (
            verified_entry is None
            or verified_entry != updated_entry
            or verified_entry.domain != Platform.BINARY_SENSOR
            or verified_entry.platform != DOMAIN
            or verified_entry.unique_id != unique_id
            or registry.async_get_entity_id(Platform.BINARY_SENSOR, DOMAIN, unique_id)
            != verified_entry.entity_id
            or verified_entry.config_entry_id != entry.entry_id
            or verified_entry.device_id != expected_device_id
            or _registry_entry_subentry_id(verified_entry) != config_subentry_id
        ):
            raise ConfigEntryError(
                "Unable to verify the migrated S1 Motor State entity"
            )

        registry.async_remove(old_entry.entity_id)
        if registry.async_get(old_entry.entity_id) is not None:
            raise ConfigEntryError(
                "Unable to remove the obsolete S1 Motor State switch entity"
            )
    except Exception as err:
        if created_entity_id is not None:
            registry.async_remove(created_entity_id)
        _LOGGER.error("Unable to safely migrate the S1 Motor State entity")
        if isinstance(err, ConfigEntryError):
            raise
        raise ConfigEntryError(
            "Unable to safely migrate the S1 Motor State entity"
        ) from err

    _LOGGER.info("Migrated the S1 Motor State entity to binary_sensor")


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Tuya BLE from a config entry."""

    try:
        manager_data = normalize_app_type_data(dict(entry.options))
    except ValueError as err:
        raise ConfigEntryError(
            "Cannot load the Tuya BLE config entry because its application type "
            "configuration conflicts"
        ) from err

    address: str = entry.data[CONF_ADDRESS]
    ble_device = bluetooth.async_ble_device_from_address(
        hass, address.upper(), True
    ) or await get_device(address)
    if not ble_device:
        raise ConfigEntryNotReady("Could not find the configured Tuya BLE device")

    manager = HASSTuyaBLEDeviceManager(hass, manager_data)
    device = TuyaBLEDevice(manager, ble_device)
    await device.initialize()
    product_info = get_device_product_info(device)

    _async_migrate_s1_motor_state_entity(hass, entry, device)

    coordinator = TuyaBLECoordinator(hass, device)
    """
    try:
        await device.update()
    except BLEAK_EXCEPTIONS as ex:
        raise ConfigEntryNotReady(
            "Could not communicate with the configured Tuya BLE device"
        ) from ex
    """

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
            BluetoothCallbackMatcher({ADDRESS: address}),
            bluetooth.BluetoothScanningMode.ACTIVE,
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
