"""Presentation and registry-migration tests for the supported smart locks."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

import pytest
from homeassistant.components.binary_sensor import BinarySensorEntity
from homeassistant.components.button import ButtonEntity
from homeassistant.components.lock import LockEntity
from homeassistant.components.number import NumberEntity
from homeassistant.components.sensor import SensorDeviceClass, SensorEntity
from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import SOURCE_USER, ConfigEntries, ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryError
from homeassistant.helpers import (
    area_registry as ar,
)
from homeassistant.helpers import (
    device_registry as dr,
)
from homeassistant.helpers import (
    entity_registry as er,
)
from homeassistant.helpers import (
    label_registry as lr,
)
from homeassistant.helpers.entity import EntityCategory

from custom_components import tuya_ble as integration
from custom_components.tuya_ble import (
    binary_sensor,
    button,
    lock,
    number,
    select,
    sensor,
    switch,
)
from custom_components.tuya_ble.const import DOMAIN
from custom_components.tuya_ble.tuya_ble import TuyaBLEDataPointType

V1_DEVICE = SimpleNamespace(category="ms", product_id="7a4xvbtt")
S1_DEVICE = SimpleNamespace(category="jtmspro", product_id="xqeob8h6")
MOTOR_UNIQUE_ID = "unit-test-device-lock_motor_state"


def _mapping_by_key(items):
    return {item.description.key: item for item in items}


def _catalogs() -> tuple[dict, dict]:
    root = Path(__file__).parents[1] / "custom_components/tuya_ble"
    return tuple(
        json.loads((root / relative_path).read_text())
        for relative_path in ("strings.json", "translations/en.json")
    )


def _translated_name(catalog: dict, platform: str, description) -> str:
    translation_key = description.translation_key or description.key
    return catalog["entity"][platform][translation_key]["name"]


def test_lock_controls_share_name_icon_and_control_category() -> None:
    """The two real controls look alike without pretending equal capability."""
    v1_control = button.get_mapping_by_device(V1_DEVICE)[0]
    s1_control = lock.get_mapping_by_device(S1_DEVICE)[0]

    assert v1_control.description.key == "manual_lock"
    assert s1_control.description.key == "ble_unlock_lock"
    assert v1_control.description.translation_key == "lock"
    assert s1_control.description.translation_key == "lock"
    assert v1_control.description.icon == s1_control.description.icon == "mdi:lock"
    assert v1_control.description.entity_category is None
    assert s1_control.description.entity_category is None

    for catalog in _catalogs():
        assert _translated_name(catalog, "button", v1_control.description) == "Lock"
        assert _translated_name(catalog, "lock", s1_control.description) == "Lock"

    assert issubclass(button.TuyaBLEButton, ButtonEntity)
    assert not issubclass(button.TuyaBLEButton, (LockEntity, SwitchEntity))
    assert not hasattr(button.TuyaBLEButton, "unlock")
    assert not hasattr(button.TuyaBLEButton, "turn_on")
    assert issubclass(lock.TuyaBLELock, LockEntity)


def test_shared_configuration_presentation_preserves_delay_ranges() -> None:
    """Shared settings match visually while retaining their native ranges."""
    v1_auto_lock = _mapping_by_key(switch.get_mapping_by_device(V1_DEVICE))[
        "automatic_lock"
    ]
    s1_auto_lock = _mapping_by_key(switch.get_mapping_by_device(S1_DEVICE))[
        "automatic_lock"
    ]
    for item in (v1_auto_lock, s1_auto_lock):
        assert item.dp_id == 33
        assert item.dp_type is TuyaBLEDataPointType.DT_BOOL
        assert item.description.icon == "mdi:lock-clock"
        assert item.description.entity_category is EntityCategory.CONFIG
    assert issubclass(switch.TuyaBLESwitch, SwitchEntity)

    v1_delay = _mapping_by_key(number.get_mapping_by_device(V1_DEVICE))[
        "auto_lock_time"
    ]
    s1_delay = _mapping_by_key(number.get_mapping_by_device(S1_DEVICE))[
        "auto_lock_time"
    ]
    for item in (v1_delay, s1_delay):
        assert item.dp_id == 36
        assert item.dp_type is TuyaBLEDataPointType.DT_VALUE
        assert item.description.icon == "mdi:timer-lock"
        assert item.description.entity_category is EntityCategory.CONFIG
        assert item.description.native_max_value == 1800
    assert v1_delay.description.native_min_value == 5
    assert s1_delay.description.native_min_value == 1
    assert issubclass(number.TuyaBLENumber, NumberEntity)

    for catalog in _catalogs():
        assert (
            _translated_name(catalog, "switch", v1_auto_lock.description)
            == _translated_name(catalog, "switch", s1_auto_lock.description)
            == "Auto-Lock"
        )
        assert (
            _translated_name(catalog, "number", v1_delay.description)
            == _translated_name(catalog, "number", s1_delay.description)
            == "Auto-Lock Delay"
        )


def test_shared_diagnostics_have_canonical_presentation() -> None:
    """Shared diagnostics use exact names, categories, and native icon rules."""
    v1_sensors = _mapping_by_key(sensor.get_mapping_by_device(V1_DEVICE))
    s1_sensors = _mapping_by_key(sensor.get_mapping_by_device(S1_DEVICE))

    expected = {
        "alarm_lock": ("Alarm", "mdi:alert"),
        "battery": ("Battery", None),
        "last_unlock_method": ("Last Unlock Method", "mdi:account-lock-open"),
    }
    for key, (visible_name, icon) in expected.items():
        v1_description = v1_sensors[key].description
        s1_description = s1_sensors[key].description
        assert v1_description.icon == s1_description.icon == icon
        assert v1_description.entity_category is EntityCategory.DIAGNOSTIC
        assert s1_description.entity_category is EntityCategory.DIAGNOSTIC
        for catalog in _catalogs():
            assert _translated_name(catalog, "sensor", v1_description) == visible_name
            assert _translated_name(catalog, "sensor", s1_description) == visible_name

    assert v1_sensors["battery"].description.device_class is SensorDeviceClass.BATTERY
    assert s1_sensors["battery"].description.device_class is SensorDeviceClass.BATTERY
    assert issubclass(sensor.TuyaBLESensor, SensorEntity)

    signal = sensor.rssi_mapping.description
    assert signal.key == "signal_strength"
    assert signal.icon is None
    assert signal.device_class is SensorDeviceClass.SIGNAL_STRENGTH
    assert signal.entity_category is EntityCategory.DIAGNOSTIC
    assert signal.entity_registry_enabled_default is False
    for catalog in _catalogs():
        assert _translated_name(catalog, "sensor", signal) == "Signal Strength"


def test_motor_state_is_one_shared_read_only_diagnostic_mapping() -> None:
    """Neither product exposes DP 47 through a writable entity platform."""
    v1_motor = _mapping_by_key(binary_sensor.get_mapping_by_device(V1_DEVICE))[
        "lock_motor_state"
    ]
    s1_motor = _mapping_by_key(binary_sensor.get_mapping_by_device(S1_DEVICE))[
        "lock_motor_state"
    ]

    for item in (v1_motor, s1_motor):
        assert item.dp_id == 47
        assert item.dp_type is TuyaBLEDataPointType.DT_BOOL
        assert item.description.key == "lock_motor_state"
        assert item.description.icon == "mdi:engine"
        assert item.description.device_class is None
        assert item.description.entity_category is EntityCategory.DIAGNOSTIC
        assert item.description.entity_registry_enabled_default is True
        assert item.getter is binary_sensor.motor_state_getter

    assert _mapping_by_key(switch.get_mapping_by_device(S1_DEVICE)) == {
        "automatic_lock": switch.get_mapping_by_device(S1_DEVICE)[0]
    }
    assert issubclass(binary_sensor.TuyaBLEBinarySensor, BinarySensorEntity)
    assert not issubclass(binary_sensor.TuyaBLEBinarySensor, SwitchEntity)
    assert not hasattr(binary_sensor.TuyaBLEBinarySensor, "turn_on")
    assert not hasattr(binary_sensor.TuyaBLEBinarySensor, "turn_off")

    for catalog in _catalogs():
        assert (
            _translated_name(catalog, "binary_sensor", v1_motor.description)
            == _translated_name(catalog, "binary_sensor", s1_motor.description)
            == "Motor State"
        )


def test_product_specific_entities_and_options_remain_distinct() -> None:
    """Presentation alignment does not synthesize unsupported capabilities."""
    s1_selects = _mapping_by_key(select.get_mapping_by_device(S1_DEVICE))
    assert set(s1_selects) == {"unlock_switch"}
    assert s1_selects["unlock_switch"].dp_id == 34
    assert s1_selects["unlock_switch"].description.icon == "mdi:account-key"
    assert (
        s1_selects["unlock_switch"].description.entity_category is EntityCategory.CONFIG
    )
    for catalog in _catalogs():
        assert (
            _translated_name(catalog, "select", s1_selects["unlock_switch"].description)
            == "Authentication Mode"
        )
    assert select.get_mapping_by_device(V1_DEVICE) == []

    v1_sensors = _mapping_by_key(sensor.get_mapping_by_device(V1_DEVICE))
    s1_sensors = _mapping_by_key(sensor.get_mapping_by_device(S1_DEVICE))
    assert "closed_opened" not in v1_sensors
    door = s1_sensors["closed_opened"]
    assert door.description.icon == "mdi:door"
    assert door.description.entity_category is EntityCategory.DIAGNOSTIC
    assert door.description.entity_registry_enabled_default is False
    for catalog in _catalogs():
        assert _translated_name(catalog, "sensor", door.description) == "Door State"

    assert len(v1_sensors["alarm_lock"].description.options) == 4
    assert len(s1_sensors["alarm_lock"].description.options) == 14
    v1_unlock_options = set(v1_sensors["last_unlock_method"].description.options)
    s1_unlock_options = set(s1_sensors["last_unlock_method"].description.options)
    assert {"password", "dynamic", "temporary"} <= v1_unlock_options
    assert not {"password", "dynamic", "temporary"} & s1_unlock_options
    assert {"key", "voice_remote"} <= s1_unlock_options

    assert lock.get_mapping_by_device(V1_DEVICE) == []
    assert button.get_mapping_by_device(S1_DEVICE) == []

    v1_writable = {
        item.dp_id
        for mappings in (
            button.get_mapping_by_device(V1_DEVICE),
            number.get_mapping_by_device(V1_DEVICE),
            switch.get_mapping_by_device(V1_DEVICE),
        )
        for item in mappings
    }
    s1_writable = {
        item.dp_id
        for mappings in (
            number.get_mapping_by_device(S1_DEVICE),
            select.get_mapping_by_device(S1_DEVICE),
            switch.get_mapping_by_device(S1_DEVICE),
        )
        for item in mappings
    }
    assert v1_writable == {33, 36, 46}
    assert s1_writable == {33, 34, 36}
    assert 31 not in v1_writable | s1_writable
    assert 47 not in v1_writable | s1_writable
    entity_keys = {
        item.description.key.lower()
        for mappings in (
            button.get_mapping_by_device(V1_DEVICE),
            number.get_mapping_by_device(V1_DEVICE),
            select.get_mapping_by_device(V1_DEVICE),
            sensor.get_mapping_by_device(V1_DEVICE),
            switch.get_mapping_by_device(V1_DEVICE),
            binary_sensor.get_mapping_by_device(V1_DEVICE),
            button.get_mapping_by_device(S1_DEVICE),
            number.get_mapping_by_device(S1_DEVICE),
            select.get_mapping_by_device(S1_DEVICE),
            sensor.get_mapping_by_device(S1_DEVICE),
            switch.get_mapping_by_device(S1_DEVICE),
            binary_sensor.get_mapping_by_device(S1_DEVICE),
        )
        for item in mappings
    }
    assert all(
        excluded not in key
        for key in entity_keys
        for excluded in ("sound", "led", "ibeacon")
    )


async def _registry_context(tmp_path: Path, suffix: str = "primary") -> SimpleNamespace:
    hass = HomeAssistant(str(tmp_path / suffix))
    hass.config_entries = ConfigEntries(hass, {})
    entry = ConfigEntry(
        version=1,
        minor_version=1,
        domain=DOMAIN,
        title="Synthetic S1",
        data={},
        options={},
        source=SOURCE_USER,
        unique_id=f"synthetic-{suffix}",
        discovery_keys=MappingProxyType({}),
        subentries_data=(),
        entry_id=f"synthetic-entry-{suffix}",
    )
    hass.config_entries._entries[entry.entry_id] = entry

    await ar.async_load(hass, load_empty=True)
    await lr.async_load(hass, load_empty=True)
    dr.async_setup(hass)
    await dr.async_load(hass, load_empty=True)
    await er.async_load(hass, load_empty=True)

    area = ar.async_get(hass).async_create("Garage")
    label = lr.async_get(hass).async_create("Security")
    device_entry = dr.async_get(hass).async_get_or_create(
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, f"synthetic-device-{suffix}")},
    )
    return SimpleNamespace(
        hass=hass,
        entry=entry,
        registry=er.async_get(hass),
        area=area,
        label=label,
        device_entry=device_entry,
        product=SimpleNamespace(
            category="jtmspro",
            product_id="xqeob8h6",
            device_id="unit-test-device",
        ),
    )


def _create_old_motor_entry(context: SimpleNamespace):
    old_entry = context.registry.async_get_or_create(
        Platform.SWITCH,
        DOMAIN,
        MOTOR_UNIQUE_ID,
        suggested_object_id="custom_motor",
        get_initial_options=lambda: {"switch": {"synthetic_option": True}},
        config_entry=context.entry,
        device_id=context.device_entry.id,
    )
    return context.registry.async_update_entity(
        old_entry.entity_id,
        aliases=[er.COMPUTED_NAME, "Motor alias"],
        area_id=context.area.id,
        categories={"synthetic_scope": "lock"},
        disabled_by=er.RegistryEntryDisabler.USER,
        hidden_by=er.RegistryEntryHider.USER,
        icon="mdi:cog",
        labels={context.label.label_id},
        name="Garage motor",
    )


def test_registry_migration_preserves_customization_and_is_idempotent(tmp_path) -> None:
    """The supported HA registry API performs the complete domain migration."""

    async def exercise() -> None:
        context = await _registry_context(tmp_path)
        old_entry = _create_old_motor_entry(context)

        integration._async_migrate_s1_motor_state_entity(
            context.hass, context.entry, context.product
        )

        assert context.registry.async_get(old_entry.entity_id) is None
        new_entity_id = context.registry.async_get_entity_id(
            Platform.BINARY_SENSOR, DOMAIN, MOTOR_UNIQUE_ID
        )
        assert new_entity_id == "binary_sensor.custom_motor"
        new_entry = context.registry.async_get(new_entity_id)
        assert new_entry is not None
        assert new_entry.unique_id == MOTOR_UNIQUE_ID
        assert new_entry.platform == DOMAIN
        assert new_entry.config_entry_id == context.entry.entry_id
        assert new_entry.device_id == context.device_entry.id
        assert new_entry.name == "Garage motor"
        assert new_entry.icon == "mdi:cog"
        assert new_entry.area_id == context.area.id
        assert new_entry.disabled_by is er.RegistryEntryDisabler.USER
        assert new_entry.hidden_by is er.RegistryEntryHider.USER
        assert new_entry.labels == {context.label.label_id}
        assert new_entry.aliases == [er.COMPUTED_NAME, "Motor alias"]
        assert new_entry.categories == {"synthetic_scope": "lock"}
        assert new_entry.options == {"switch": {"synthetic_option": True}}
        assert new_entry.entity_category is EntityCategory.DIAGNOSTIC
        assert new_entry.translation_key == "lock_motor_state"
        assert new_entry.original_icon == "mdi:engine"
        assert new_entry.has_entity_name is True

        before = new_entry
        integration._async_migrate_s1_motor_state_entity(
            context.hass, context.entry, context.product
        )
        assert context.registry.async_get(new_entity_id) == before
        assert (
            context.registry.async_get_entity_id(
                Platform.SWITCH, DOMAIN, MOTOR_UNIQUE_ID
            )
            is None
        )

    asyncio.run(exercise())


@pytest.mark.parametrize(
    ("category", "product_id"),
    (("ms", "7a4xvbtt"), ("ms", "other-lock"), ("jtmspro", "other-lock")),
)
def test_registry_migration_ignores_other_products(
    tmp_path, category: str, product_id: str
) -> None:
    """V1 and unrelated product entries never enter the S1 migration."""

    async def exercise() -> None:
        context = await _registry_context(tmp_path, f"{category}-{product_id}")
        old_entry = _create_old_motor_entry(context)
        product = SimpleNamespace(
            category=category,
            product_id=product_id,
            device_id="unit-test-device",
        )

        integration._async_migrate_s1_motor_state_entity(
            context.hass, context.entry, product
        )

        assert context.registry.async_get(old_entry.entity_id) == old_entry
        assert (
            context.registry.async_get_entity_id(
                Platform.BINARY_SENSOR, DOMAIN, MOTOR_UNIQUE_ID
            )
            is None
        )

    asyncio.run(exercise())


def test_registry_migration_ignores_other_integrations(tmp_path) -> None:
    """A switch with the same suffix from another integration is untouched."""

    async def exercise() -> None:
        context = await _registry_context(tmp_path, "other-integration")
        other_entry = context.registry.async_get_or_create(
            Platform.SWITCH,
            "other_integration",
            MOTOR_UNIQUE_ID,
            suggested_object_id="other_motor",
        )

        integration._async_migrate_s1_motor_state_entity(
            context.hass, context.entry, context.product
        )

        assert context.registry.async_get(other_entry.entity_id) == other_entry
        assert (
            context.registry.async_get_entity_id(
                Platform.BINARY_SENSOR, DOMAIN, MOTOR_UNIQUE_ID
            )
            is None
        )

    asyncio.run(exercise())


def test_registry_migration_handles_already_migrated_entry(tmp_path) -> None:
    """An existing binary sensor without an old switch is a strict no-op."""

    async def exercise() -> None:
        context = await _registry_context(tmp_path, "already-migrated")
        current = context.registry.async_get_or_create(
            Platform.BINARY_SENSOR,
            DOMAIN,
            MOTOR_UNIQUE_ID,
            suggested_object_id="existing_motor",
            config_entry=context.entry,
            device_id=context.device_entry.id,
        )

        integration._async_migrate_s1_motor_state_entity(
            context.hass, context.entry, context.product
        )

        assert context.registry.async_get(current.entity_id) == current
        entries = [
            item
            for item in er.async_entries_for_config_entry(
                context.registry, context.entry.entry_id
            )
            if item.unique_id == MOTOR_UNIQUE_ID
        ]
        assert entries == [current]

    asyncio.run(exercise())


def test_registry_migration_converges_existing_old_and_new_entries(tmp_path) -> None:
    """A partial prior migration converges without arbitrary customization loss."""

    async def exercise() -> None:
        context = await _registry_context(tmp_path, "both-domains")
        old_entry = _create_old_motor_entry(context)
        second_label = lr.async_get(context.hass).async_create("Existing binary")
        current = context.registry.async_get_or_create(
            Platform.BINARY_SENSOR,
            DOMAIN,
            MOTOR_UNIQUE_ID,
            suggested_object_id="existing_binary_motor",
            config_entry=context.entry,
            device_id=context.device_entry.id,
        )
        current = context.registry.async_update_entity(
            current.entity_id,
            aliases=[er.COMPUTED_NAME, "Binary alias"],
            labels={second_label.label_id},
            name="Existing binary name",
        )

        integration._async_migrate_s1_motor_state_entity(
            context.hass, context.entry, context.product
        )

        assert context.registry.async_get(old_entry.entity_id) is None
        merged = context.registry.async_get(current.entity_id)
        assert merged is not None
        assert merged.name == "Existing binary name"
        assert merged.icon == "mdi:cog"
        assert merged.area_id == context.area.id
        assert merged.disabled_by is er.RegistryEntryDisabler.USER
        assert merged.hidden_by is er.RegistryEntryHider.USER
        assert merged.labels == {context.label.label_id, second_label.label_id}
        assert merged.aliases == [
            er.COMPUTED_NAME,
            "Binary alias",
            "Motor alias",
        ]
        assert merged.categories == {"synthetic_scope": "lock"}
        entries = [
            item
            for item in er.async_entries_for_config_entry(
                context.registry, context.entry.entry_id
            )
            if item.unique_id == MOTOR_UNIQUE_ID
        ]
        assert entries == [merged]

    asyncio.run(exercise())


def test_registry_migration_fails_closed_on_foreign_ownership(tmp_path) -> None:
    """A conflicting owner blocks setup before a duplicate can be registered."""

    async def exercise() -> None:
        context = await _registry_context(tmp_path, "foreign-owner")
        other_entry = ConfigEntry(
            version=1,
            minor_version=1,
            domain=DOMAIN,
            title="Other config entry",
            data={},
            options={},
            source=SOURCE_USER,
            unique_id="synthetic-other-owner",
            discovery_keys=MappingProxyType({}),
            subentries_data=(),
            entry_id="synthetic-entry-other-owner",
        )
        context.hass.config_entries._entries[other_entry.entry_id] = other_entry
        old_entry = context.registry.async_get_or_create(
            Platform.SWITCH,
            DOMAIN,
            MOTOR_UNIQUE_ID,
            suggested_object_id="foreign_motor",
            config_entry=other_entry,
        )

        with pytest.raises(ConfigEntryError):
            integration._async_migrate_s1_motor_state_entity(
                context.hass, context.entry, context.product
            )

        assert context.registry.async_get(old_entry.entity_id) == old_entry
        assert (
            context.registry.async_get_entity_id(
                Platform.BINARY_SENSOR, DOMAIN, MOTOR_UNIQUE_ID
            )
            is None
        )

    asyncio.run(exercise())
