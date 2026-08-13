"""Ownership and rollback tests for the S1 entity-registry migration."""

from __future__ import annotations

import asyncio
import inspect
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest
from homeassistant.components.binary_sensor import BinarySensorDeviceClass
from homeassistant.components.switch import SwitchDeviceClass
from homeassistant.config_entries import SOURCE_USER, ConfigEntries, ConfigEntry
from homeassistant.const import CONF_ADDRESS, Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryError
from homeassistant.helpers import area_registry as ar
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers import label_registry as lr
from homeassistant.helpers.entity import EntityCategory

from custom_components import tuya_ble as integration
from custom_components.tuya_ble import binary_sensor, lock
from custom_components.tuya_ble.const import DOMAIN
from custom_components.tuya_ble.devices import TuyaBLEData, get_product_info_by_ids

ADDRESS = "00:11:22:33:44:55"
MOTOR_UNIQUE_ID = "synthetic-device-lock_motor_state"
V1_UNIQUE_ID = "synthetic-v1-device-manual_lock"
_CONTEXT_DEVICE = object()


def _new_config_entry(
    suffix: str,
    *,
    subentries_data: tuple[dict, ...] = (),
) -> ConfigEntry:
    kwargs = {
        "version": 1,
        "minor_version": 1,
        "domain": DOMAIN,
        "title": f"Synthetic S1 {suffix}",
        "data": {CONF_ADDRESS: ADDRESS},
        "options": {},
        "source": SOURCE_USER,
        "unique_id": f"synthetic-{suffix}",
        "discovery_keys": MappingProxyType({}),
        "entry_id": f"synthetic-entry-{suffix}",
    }
    if "subentries_data" in inspect.signature(ConfigEntry).parameters:
        kwargs["subentries_data"] = subentries_data
    return ConfigEntry(**kwargs)


async def _registry_context(
    tmp_path: Path,
    suffix: str = "primary",
    *,
    subentries_data: tuple[dict, ...] = (),
    device_subentry_id: str | None = None,
) -> SimpleNamespace:
    hass = HomeAssistant(str(tmp_path / suffix))
    hass.config_entries = ConfigEntries(hass, {})
    entry = _new_config_entry(suffix, subentries_data=subentries_data)
    hass.config_entries._entries[entry.entry_id] = entry

    load_kwargs = (
        {"load_empty": True}
        if "load_empty" in inspect.signature(ar.async_load).parameters
        else {}
    )
    await ar.async_load(hass, **load_kwargs)
    await lr.async_load(hass, **load_kwargs)
    if hasattr(dr, "async_setup"):
        dr.async_setup(hass)
    await dr.async_load(hass, **load_kwargs)
    await er.async_load(hass, **load_kwargs)

    area = ar.async_get(hass).async_create("Garage")
    label = lr.async_get(hass).async_create("Security")
    device_kwargs = {}
    if device_subentry_id is not None:
        device_kwargs["config_subentry_id"] = device_subentry_id
    device_entry = dr.async_get(hass).async_get_or_create(
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, ADDRESS)},
        **device_kwargs,
    )
    return SimpleNamespace(
        hass=hass,
        entry=entry,
        registry=er.async_get(hass),
        device_registry=dr.async_get(hass),
        area=area,
        label=label,
        device_entry=device_entry,
        device=SimpleNamespace(
            category="jtmspro",
            product_id="xqeob8h6",
            device_id="synthetic-device",
            address=ADDRESS,
        ),
    )


def _create_old_motor_entry(
    context: SimpleNamespace,
    *,
    unique_id: str = MOTOR_UNIQUE_ID,
    config_entry: ConfigEntry | None = None,
    device_id: str | None | object = _CONTEXT_DEVICE,
    config_subentry_id: str | None = None,
):
    create_kwargs = {}
    if config_subentry_id is not None:
        create_kwargs["config_subentry_id"] = config_subentry_id
    old_entry = context.registry.async_get_or_create(
        Platform.SWITCH,
        DOMAIN,
        unique_id,
        suggested_object_id="custom_motor",
        get_initial_options=lambda: {"switch": {"synthetic_option": True}},
        config_entry=config_entry or context.entry,
        device_id=(
            context.device_entry.id if device_id is _CONTEXT_DEVICE else device_id
        ),
        **create_kwargs,
    )
    return context.registry.async_update_entity(
        old_entry.entity_id,
        aliases=["Motor alias"],
        area_id=context.area.id,
        categories={"old_scope": "lock", "shared_scope": "old"},
        device_class=SwitchDeviceClass.SWITCH,
        disabled_by=er.RegistryEntryDisabler.USER,
        hidden_by=er.RegistryEntryHider.USER,
        icon="mdi:cog",
        labels={context.label.label_id},
        name="Garage motor",
    )


def _create_old_v1_button_entry(
    context: SimpleNamespace,
    *,
    unique_id: str = V1_UNIQUE_ID,
    config_entry: ConfigEntry | None = None,
    device_id: str | None | object = _CONTEXT_DEVICE,
    config_subentry_id: str | None = None,
):
    """Create the b2 V1 manual-lock button shape with customizations."""
    create_kwargs = {}
    if config_subentry_id is not None:
        create_kwargs["config_subentry_id"] = config_subentry_id
    old_entry = context.registry.async_get_or_create(
        Platform.BUTTON,
        DOMAIN,
        unique_id,
        suggested_object_id="custom_v1_lock",
        get_initial_options=lambda: {"button": {"synthetic_option": True}},
        config_entry=config_entry or context.entry,
        device_id=(
            context.device_entry.id if device_id is _CONTEXT_DEVICE else device_id
        ),
        **create_kwargs,
    )
    return context.registry.async_update_entity(
        old_entry.entity_id,
        aliases=["V1 lock alias"],
        area_id=context.area.id,
        categories={"old_scope": "lock", "shared_scope": "old"},
        disabled_by=er.RegistryEntryDisabler.USER,
        hidden_by=er.RegistryEntryHider.USER,
        icon="mdi:lock-outline",
        labels={context.label.label_id},
        name="Garage V1 lock",
    )


def _create_v1_lock_target(
    context: SimpleNamespace,
    options: dict,
    *,
    platform: str = DOMAIN,
):
    """Create a visibly synthetic V1 lock migration target."""
    return context.registry.async_get_or_create(
        Platform.LOCK,
        platform,
        V1_UNIQUE_ID,
        suggested_object_id="synthetic_v1_target",
        get_initial_options=lambda: options,
        config_entry=context.entry,
        device_id=context.device_entry.id,
    )


def _v1_device() -> SimpleNamespace:
    """Return the exact V1 identity used by the registry migration."""
    return SimpleNamespace(
        category="ms",
        product_id="7a4xvbtt",
        device_id="synthetic-v1-device",
        address=ADDRESS,
    )


def _synthetic_runtime_device(
    category: str,
    product_id: str,
    device_id: str,
) -> SimpleNamespace:
    """Return the minimum synthetic device used by platform setup."""
    return SimpleNamespace(
        address=ADDRESS,
        category=category,
        datapoints=SimpleNamespace(has_id=Mock(return_value=False)),
        device_id=device_id,
        device_version="synthetic-device-version",
        hardware_version="synthetic-hardware-version",
        name="Synthetic lock",
        product_id=product_id,
        product_model="Synthetic lock model",
        protocol_version="4.0",
    )


def _assert_entity_device_reuses_registry_identity(
    context: SimpleNamespace,
    entity,
) -> None:
    """Assert an entity's emitted device identity reuses the legacy device."""
    device_info = entity.device_info
    assert device_info is not None
    assert device_info["identifiers"] == {(DOMAIN, ADDRESS)}

    reused = context.device_registry.async_get_or_create(
        config_entry_id=context.entry.entry_id,
        connections=device_info["connections"],
        identifiers=device_info["identifiers"],
    )

    assert reused.id == context.device_entry.id
    assert [
        entry.id
        for entry in dr.async_entries_for_config_entry(
            context.device_registry, context.entry.entry_id
        )
    ] == [context.device_entry.id]


def _register_runtime_entity(context: SimpleNamespace, entity):
    """Register an emitted entity using its stable integration identity."""
    return context.registry.async_get_or_create(
        entity.platform,
        DOMAIN,
        entity.unique_id,
        suggested_object_id=entity.unique_id,
        config_entry=context.entry,
        device_id=context.device_entry.id,
    )


def test_s1_repeated_platform_setup_reuses_migrated_registry_entries(
    tmp_path,
) -> None:
    """S1 setup reuses the legacy device and the migrated Motor State entity."""

    async def exercise() -> None:
        context = await _registry_context(tmp_path, "s1-platform-setup")
        old_entry = _create_old_motor_entry(context)
        integration._async_migrate_s1_motor_state_entity(
            context.hass, context.entry, context.device
        )

        device = _synthetic_runtime_device("jtmspro", "xqeob8h6", "synthetic-device")
        product = get_product_info_by_ids(device.category, device.product_id)
        assert product is not None
        context.hass.data.setdefault(DOMAIN, {})[context.entry.entry_id] = TuyaBLEData(
            title=context.entry.title,
            device=device,
            product=product,
            manager=Mock(),
            coordinator=SimpleNamespace(connected=False),
        )

        setup_batches = []
        for _ in range(2):
            entities = []
            await binary_sensor.async_setup_entry(
                context.hass, context.entry, entities.extend
            )
            setup_batches.append(entities)

        assert context.registry.async_get(old_entry.entity_id) is None
        assert [len(entities) for entities in setup_batches] == [1, 1]
        assert all(
            isinstance(entities[0], binary_sensor.TuyaBLEBinarySensor)
            for entities in setup_batches
        )
        emitted_entities = [entities[0] for entities in setup_batches]
        assert [entity.unique_id for entity in emitted_entities] == [
            MOTOR_UNIQUE_ID,
            MOTOR_UNIQUE_ID,
        ]

        migrated_entity_id = context.registry.async_get_entity_id(
            Platform.BINARY_SENSOR, DOMAIN, MOTOR_UNIQUE_ID
        )
        assert migrated_entity_id is not None
        registered = [
            _register_runtime_entity(context, entity) for entity in emitted_entities
        ]
        assert [entry.entity_id for entry in registered] == [
            migrated_entity_id,
            migrated_entity_id,
        ]
        assert [
            (entry.domain, entry.unique_id)
            for entry in er.async_entries_for_config_entry(
                context.registry, context.entry.entry_id
            )
        ] == [(Platform.BINARY_SENSOR, MOTOR_UNIQUE_ID)]

        for entity in emitted_entities:
            _assert_entity_device_reuses_registry_identity(context, entity)

    asyncio.run(exercise())


def test_v1_repeated_platform_setup_reuses_manual_lock_registry_entry(
    tmp_path,
) -> None:
    """V1 setup reuses the migrated manual_lock identity without duplicates."""

    async def exercise() -> None:
        context = await _registry_context(tmp_path, "v1-platform-setup")
        device = _synthetic_runtime_device("ms", "7a4xvbtt", "synthetic-v1-device")
        product = get_product_info_by_ids(device.category, device.product_id)
        assert product is not None
        expected_unique_id = "synthetic-v1-device-manual_lock"
        legacy_entry = context.registry.async_get_or_create(
            Platform.BUTTON,
            DOMAIN,
            expected_unique_id,
            suggested_object_id="legacy_manual_lock",
            config_entry=context.entry,
            device_id=context.device_entry.id,
        )
        v1_device = SimpleNamespace(
            category="ms",
            product_id="7a4xvbtt",
            device_id="synthetic-v1-device",
            address=ADDRESS,
        )
        integration._async_migrate_v1_manual_lock_entity(
            context.hass, context.entry, v1_device
        )
        context.hass.data.setdefault(DOMAIN, {})[context.entry.entry_id] = TuyaBLEData(
            title=context.entry.title,
            device=device,
            product=product,
            manager=Mock(),
            coordinator=SimpleNamespace(connected=False),
        )

        setup_batches = []
        for _ in range(2):
            entities = []
            await lock.async_setup_entry(context.hass, context.entry, entities.extend)
            setup_batches.append(entities)

        assert context.registry.async_get(legacy_entry.entity_id) is None
        assert [len(entities) for entities in setup_batches] == [1, 1]
        assert all(
            isinstance(entities[0], lock.TuyaBLEV1Lock) for entities in setup_batches
        )
        emitted_entities = [entities[0] for entities in setup_batches]
        assert [entity.unique_id for entity in emitted_entities] == [
            expected_unique_id,
            expected_unique_id,
        ]
        assert all(
            entity.entity_description.key == "manual_lock"
            for entity in emitted_entities
        )

        registered = [
            _register_runtime_entity(context, entity) for entity in emitted_entities
        ]
        assert [entry.entity_id for entry in registered] == [
            context.registry.async_get_entity_id(
                Platform.LOCK, DOMAIN, expected_unique_id
            ),
            context.registry.async_get_entity_id(
                Platform.LOCK, DOMAIN, expected_unique_id
            ),
        ]
        assert [
            (entry.domain, entry.unique_id)
            for entry in er.async_entries_for_config_entry(
                context.registry, context.entry.entry_id
            )
        ] == [(Platform.LOCK, expected_unique_id)]

        for entity in emitted_entities:
            _assert_entity_device_reuses_registry_identity(context, entity)

    asyncio.run(exercise())


def test_v1_migration_preserves_customization_collision_and_idempotency(
    tmp_path,
) -> None:
    """V1 migration is collision-safe, drops button options, and is idempotent."""

    async def exercise() -> None:
        context = await _registry_context(tmp_path, "v1-primary")
        collision = context.registry.async_get_or_create(
            Platform.LOCK,
            "other_integration",
            "other-v1-unique-id",
            suggested_object_id="custom_v1_lock",
        )
        old_entry = _create_old_v1_button_entry(context)

        integration._async_migrate_v1_manual_lock_entity(
            context.hass, context.entry, _v1_device()
        )

        assert context.registry.async_get(old_entry.entity_id) is None
        assert context.registry.async_get(collision.entity_id) == collision
        new_entity_id = context.registry.async_get_entity_id(
            Platform.LOCK, DOMAIN, V1_UNIQUE_ID
        )
        assert new_entity_id == "lock.custom_v1_lock_2"
        new_entry = context.registry.async_get(new_entity_id)
        assert new_entry is not None
        assert new_entry.config_entry_id == context.entry.entry_id
        assert new_entry.device_id == context.device_entry.id
        assert new_entry.name == "Garage V1 lock"
        assert new_entry.icon == "mdi:lock-outline"
        assert new_entry.area_id == context.area.id
        assert new_entry.disabled_by is er.RegistryEntryDisabler.USER
        assert new_entry.hidden_by is er.RegistryEntryHider.USER
        assert new_entry.labels == {context.label.label_id}
        expected_aliases = ["V1 lock alias"]
        if hasattr(er, "COMPUTED_NAME"):
            expected_aliases.insert(0, er.COMPUTED_NAME)
        assert list(new_entry.aliases) == expected_aliases
        assert new_entry.categories == {
            "old_scope": "lock",
            "shared_scope": "old",
        }
        assert new_entry.device_class is None
        assert new_entry.original_device_class is None
        assert new_entry.options == {}
        assert new_entry.entity_category is None
        assert new_entry.translation_key == "lock"
        assert new_entry.original_icon == "mdi:lock"
        assert new_entry.supported_features == 0

        before = new_entry
        integration._async_migrate_v1_manual_lock_entity(
            context.hass, context.entry, _v1_device()
        )
        assert context.registry.async_get(new_entity_id) == before

    asyncio.run(exercise())


def test_v1_migration_merges_existing_lock_target(tmp_path) -> None:
    """Existing lock customizations and lock-only options take precedence."""

    async def exercise() -> None:
        context = await _registry_context(tmp_path, "v1-existing-target")
        old_entry = _create_old_v1_button_entry(context)
        target_label = lr.async_get(context.hass).async_create("Existing V1 target")
        target = context.registry.async_get_or_create(
            Platform.LOCK,
            DOMAIN,
            V1_UNIQUE_ID,
            suggested_object_id="existing_v1_lock",
            get_initial_options=lambda: {"lock": {"synthetic_target_option": True}},
            config_entry=context.entry,
            device_id=context.device_entry.id,
        )
        target = context.registry.async_update_entity(
            target.entity_id,
            aliases=["Target alias"],
            categories={"new_scope": "lock", "shared_scope": "target"},
            icon="mdi:lock-check",
            labels={target_label.label_id},
            name="Existing V1 target name",
        )

        integration._async_migrate_v1_manual_lock_entity(
            context.hass, context.entry, _v1_device()
        )

        assert context.registry.async_get(old_entry.entity_id) is None
        merged = context.registry.async_get(target.entity_id)
        assert merged is not None
        assert merged.name == "Existing V1 target name"
        assert merged.icon == "mdi:lock-check"
        assert merged.area_id == context.area.id
        assert merged.disabled_by is er.RegistryEntryDisabler.USER
        assert merged.hidden_by is er.RegistryEntryHider.USER
        assert merged.labels == {context.label.label_id, target_label.label_id}
        assert list(merged.aliases) == ["Target alias", "V1 lock alias"]
        assert merged.categories == {
            "old_scope": "lock",
            "new_scope": "lock",
            "shared_scope": "target",
        }
        assert merged.device_class is None
        assert merged.options == {"lock": {"synthetic_target_option": True}}
        assert "button" not in merged.options

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "target_options",
    (
        {
            "cloud.alexa": {"synthetic_exposure": False},
            "conversation": {"synthetic_exposure": True},
        },
        {
            "cloud.alexa": {"synthetic_exposure": False},
            "cloud.google_assistant": {"synthetic_exposure": True},
            "conversation": {"synthetic_exposure": True},
        },
        {
            "lock": {"synthetic_lock_option": "target"},
            "cloud.alexa": {"synthetic_exposure": False},
            "conversation": {"synthetic_exposure": True},
        },
        {
            "button": {"synthetic_source_option": "obsolete"},
            "cloud.alexa": {"synthetic_exposure": False},
            "conversation": {"synthetic_exposure": True},
        },
        {
            "lock": {"synthetic_lock_option": "target"},
            "button": {"synthetic_source_option": "obsolete"},
            "cloud.alexa": {"synthetic_exposure": False},
            "conversation": {"synthetic_exposure": True},
        },
        {
            "example.integration": {"synthetic_extension_option": "preserved"},
        },
    ),
)
def test_v1_migration_preserves_every_non_button_target_option_namespace(
    tmp_path,
    target_options: dict,
) -> None:
    """Cross-cutting and extensible target option namespaces survive migration."""

    async def exercise() -> None:
        context = await _registry_context(tmp_path, "v1-target-options")
        old_entry = _create_old_v1_button_entry(context)
        target = _create_v1_lock_target(context, target_options)
        expected_options = {
            namespace: values
            for namespace, values in target_options.items()
            if namespace != Platform.BUTTON
        }

        integration._async_migrate_v1_manual_lock_entity(
            context.hass, context.entry, _v1_device()
        )

        assert context.registry.async_get(old_entry.entity_id) is None
        migrated = context.registry.async_get(target.entity_id)
        assert migrated is not None
        assert migrated.options == expected_options
        assert (
            context.registry.async_get_entity_id(Platform.LOCK, DOMAIN, V1_UNIQUE_ID)
            == target.entity_id
        )

        before_repeat = migrated
        integration._async_migrate_v1_manual_lock_entity(
            context.hass, context.entry, _v1_device()
        )
        assert context.registry.async_get(target.entity_id) == before_repeat

    asyncio.run(exercise())


def test_v1_migration_never_copies_old_button_options_to_target(tmp_path) -> None:
    """The lock target remains authoritative for every option namespace."""

    async def exercise() -> None:
        context = await _registry_context(tmp_path, "v1-target-authoritative")
        old_entry = _create_old_v1_button_entry(context)
        context.registry.async_update_entity_options(
            old_entry.entity_id,
            "cloud.alexa",
            {"synthetic_exposure": "old-button"},
        )
        target_options = {
            "conversation": {"synthetic_exposure": "lock-target"},
            "example.integration": {"synthetic_extension_option": "target"},
        }
        target = _create_v1_lock_target(context, target_options)

        integration._async_migrate_v1_manual_lock_entity(
            context.hass, context.entry, _v1_device()
        )

        assert context.registry.async_get(old_entry.entity_id) is None
        migrated = context.registry.async_get(target.entity_id)
        assert migrated is not None
        assert migrated.options == target_options
        assert "cloud.alexa" not in migrated.options

    asyncio.run(exercise())


def test_v1_migration_restores_target_after_post_normalization_failure(
    tmp_path,
) -> None:
    """A failure after button-option removal restores the complete target."""

    async def exercise() -> None:
        context = await _registry_context(tmp_path, "v1-options-rollback")
        old_entry = _create_old_v1_button_entry(context)
        target_options = {
            "button": {"synthetic_source_option": "restore"},
            "cloud.alexa": {"synthetic_exposure": False},
            "conversation": {"synthetic_exposure": True},
        }
        target = _create_v1_lock_target(context, target_options)
        target = context.registry.async_update_entity(
            target.entity_id,
            aliases=["Synthetic target alias"],
            categories={"synthetic_scope": "target"},
            icon="mdi:lock-check",
            name="Synthetic target name",
        )
        original_update = context.registry.async_update_entity
        failure_injected = False

        def fail_once(entity_id, **kwargs):
            nonlocal failure_injected
            if not failure_injected:
                failure_injected = True
                raise RuntimeError("synthetic post-normalization failure")
            return original_update(entity_id, **kwargs)

        with (
            patch.object(
                context.registry, "async_update_entity", side_effect=fail_once
            ),
            pytest.raises(ConfigEntryError, match="Unable to safely migrate"),
        ):
            integration._async_migrate_v1_manual_lock_entity(
                context.hass, context.entry, _v1_device()
            )

        assert failure_injected
        assert context.registry.async_get(old_entry.entity_id) is not None
        restored = context.registry.async_get(target.entity_id)
        assert restored is not None
        assert restored.options == target_options
        assert restored.aliases == target.aliases
        assert restored.categories == target.categories
        assert restored.icon == target.icon
        assert restored.name == target.name
        assert restored.config_entry_id == target.config_entry_id
        assert restored.device_id == target.device_id
        assert _registry_entry_subentry_id(restored) == _registry_entry_subentry_id(
            target
        )

    asyncio.run(exercise())


@pytest.mark.parametrize(
    ("domain", "platform"),
    (
        (Platform.SENSOR, DOMAIN),
        (Platform.LOCK, "synthetic_foreign_integration"),
    ),
)
def test_v1_migration_rejects_foreign_stable_identity_target(
    tmp_path,
    domain: Platform,
    platform: str,
) -> None:
    """A non-lock or non-Tuya-BLE target cannot share the stable identity."""

    async def exercise() -> None:
        context = await _registry_context(tmp_path, "v1-foreign-identity-target")
        old_entry = _create_old_v1_button_entry(context)
        foreign_target = context.registry.async_get_or_create(
            domain,
            platform,
            V1_UNIQUE_ID,
            suggested_object_id="synthetic_foreign_target",
            config_entry=context.entry,
            device_id=context.device_entry.id,
        )

        with pytest.raises(ConfigEntryError, match="target.*ambiguous"):
            integration._async_migrate_v1_manual_lock_entity(
                context.hass, context.entry, _v1_device()
            )

        assert context.registry.async_get(old_entry.entity_id) == old_entry
        assert context.registry.async_get(foreign_target.entity_id) == foreign_target

    asyncio.run(exercise())


@pytest.mark.parametrize(
    ("category", "product_id"),
    (("jtmspro", "xqeob8h6"), ("ms", "other-product")),
)
def test_v1_migration_is_scoped_to_exact_product(
    tmp_path, category: str, product_id: str
) -> None:
    """No other lock or product can enter the V1 registry migration."""

    async def exercise() -> None:
        context = await _registry_context(tmp_path, f"v1-{category}-{product_id}")
        old_entry = _create_old_v1_button_entry(context)
        other_device = SimpleNamespace(
            category=category,
            product_id=product_id,
            device_id="synthetic-v1-device",
            address=ADDRESS,
        )

        integration._async_migrate_v1_manual_lock_entity(
            context.hass, context.entry, other_device
        )

        assert context.registry.async_get(old_entry.entity_id) == old_entry
        assert (
            context.registry.async_get_entity_id(Platform.LOCK, DOMAIN, V1_UNIQUE_ID)
            is None
        )

    asyncio.run(exercise())


def test_v1_migration_rejects_ambiguous_and_foreign_buttons(tmp_path) -> None:
    """Suffix collisions and globally foreign button ownership fail closed."""

    async def exercise() -> None:
        ambiguous = await _registry_context(tmp_path, "v1-ambiguous")
        first = _create_old_v1_button_entry(ambiguous)
        second = _create_old_v1_button_entry(
            ambiguous, unique_id="other-v1-device-manual_lock"
        )
        with pytest.raises(ConfigEntryError, match="ambiguous"):
            integration._async_migrate_v1_manual_lock_entity(
                ambiguous.hass, ambiguous.entry, _v1_device()
            )
        assert ambiguous.registry.async_get(first.entity_id) == first
        assert ambiguous.registry.async_get(second.entity_id) == second

        foreign = await _registry_context(tmp_path, "v1-foreign")
        other_entry = _new_config_entry("v1-foreign-owner")
        foreign.hass.config_entries._entries[other_entry.entry_id] = other_entry
        foreign_old = _create_old_v1_button_entry(
            foreign,
            config_entry=other_entry,
            device_id=None,
        )
        with pytest.raises(ConfigEntryError, match="ambiguous"):
            integration._async_migrate_v1_manual_lock_entity(
                foreign.hass, foreign.entry, _v1_device()
            )
        assert foreign.registry.async_get(foreign_old.entity_id) == foreign_old

    asyncio.run(exercise())


def test_v1_migration_rejects_device_and_target_ownership_conflicts(
    tmp_path,
) -> None:
    """The V1 lock target must share the current owner and device association."""

    async def exercise() -> None:
        context = await _registry_context(tmp_path, "v1-device-conflict")
        old_entry = _create_old_v1_button_entry(context)
        other_device = context.device_registry.async_get_or_create(
            config_entry_id=context.entry.entry_id,
            identifiers={(DOMAIN, "AA:BB:CC:DD:EE:FF")},
        )
        target = context.registry.async_get_or_create(
            Platform.LOCK,
            DOMAIN,
            V1_UNIQUE_ID,
            suggested_object_id="wrong_device_v1_lock",
            config_entry=context.entry,
            device_id=other_device.id,
        )

        with pytest.raises(ConfigEntryError, match="different device"):
            integration._async_migrate_v1_manual_lock_entity(
                context.hass, context.entry, _v1_device()
            )
        assert context.registry.async_get(old_entry.entity_id) == old_entry
        assert context.registry.async_get(target.entity_id) == target

        foreign_target = await _registry_context(tmp_path, "v1-foreign-target")
        foreign_old = _create_old_v1_button_entry(foreign_target)
        other_entry = _new_config_entry("v1-target-owner")
        foreign_target.hass.config_entries._entries[other_entry.entry_id] = other_entry
        target = foreign_target.registry.async_get_or_create(
            Platform.LOCK,
            DOMAIN,
            V1_UNIQUE_ID,
            suggested_object_id="foreign_target_v1_lock",
            config_entry=other_entry,
        )

        with pytest.raises(ConfigEntryError, match="not owned"):
            integration._async_migrate_v1_manual_lock_entity(
                foreign_target.hass, foreign_target.entry, _v1_device()
            )
        assert foreign_target.registry.async_get(foreign_old.entity_id) == foreign_old
        assert foreign_target.registry.async_get(target.entity_id) == target

    asyncio.run(exercise())


@pytest.mark.parametrize(
    ("device_class", "options", "message"),
    (
        (
            SwitchDeviceClass.SWITCH,
            {"lock": {"synthetic_target_option": True}},
            "invalid device class",
        ),
    ),
)
def test_v1_migration_rejects_non_lock_target_state(
    tmp_path,
    device_class: SwitchDeviceClass | None,
    options: dict,
    message: str,
) -> None:
    """A partial lock target cannot retain state from another platform."""

    async def exercise() -> None:
        context = await _registry_context(tmp_path, f"v1-{message.replace(' ', '-')}")
        old_entry = _create_old_v1_button_entry(context)
        target = context.registry.async_get_or_create(
            Platform.LOCK,
            DOMAIN,
            V1_UNIQUE_ID,
            suggested_object_id="invalid_target_v1_lock",
            get_initial_options=lambda: options,
            config_entry=context.entry,
            device_id=context.device_entry.id,
        )
        if device_class is not None:
            target = context.registry.async_update_entity(
                target.entity_id, device_class=device_class
            )

        with pytest.raises(ConfigEntryError, match=message):
            integration._async_migrate_v1_manual_lock_entity(
                context.hass, context.entry, _v1_device()
            )
        assert context.registry.async_get(old_entry.entity_id) == old_entry
        assert context.registry.async_get(target.entity_id) == target

    asyncio.run(exercise())


def test_v1_migration_rejects_conflicting_valid_subentries(tmp_path) -> None:
    """Different valid V1 config subentries cannot be reconciled implicitly."""
    if "subentries_data" not in inspect.signature(ConfigEntry).parameters:
        pytest.skip("This Home Assistant version has no config subentries")

    async def exercise() -> None:
        subentries = (
            {
                "data": {},
                "subentry_id": "v1-subentry-old",
                "subentry_type": "device",
                "title": "Old V1 association",
                "unique_id": "v1-old-association",
            },
            {
                "data": {},
                "subentry_id": "v1-subentry-target",
                "subentry_type": "device",
                "title": "Target V1 association",
                "unique_id": "v1-target-association",
            },
        )
        context = await _registry_context(
            tmp_path,
            "v1-subentry-conflict",
            subentries_data=subentries,
            device_subentry_id="v1-subentry-old",
        )
        old_entry = _create_old_v1_button_entry(
            context,
            device_id=None,
            config_subentry_id="v1-subentry-old",
        )
        target = context.registry.async_get_or_create(
            Platform.LOCK,
            DOMAIN,
            V1_UNIQUE_ID,
            suggested_object_id="subentry_target_v1_lock",
            config_entry=context.entry,
            config_subentry_id="v1-subentry-target",
        )

        with pytest.raises(ConfigEntryError, match="different config subentries"):
            integration._async_migrate_v1_manual_lock_entity(
                context.hass, context.entry, _v1_device()
            )
        assert context.registry.async_get(old_entry.entity_id) == old_entry
        assert context.registry.async_get(target.entity_id) == target

    asyncio.run(exercise())


def test_v1_migration_rolls_back_new_target_when_update_fails(tmp_path) -> None:
    """A newly created V1 lock target is removed after an incomplete update."""

    async def exercise() -> None:
        context = await _registry_context(tmp_path, "v1-rollback")
        old_entry = _create_old_v1_button_entry(context)

        with (
            patch.object(
                context.registry,
                "async_update_entity",
                side_effect=RuntimeError("synthetic V1 update failure"),
            ),
            pytest.raises(ConfigEntryError, match="Unable to safely migrate"),
        ):
            integration._async_migrate_v1_manual_lock_entity(
                context.hass, context.entry, _v1_device()
            )

        assert context.registry.async_get(old_entry.entity_id) == old_entry
        assert (
            context.registry.async_get_entity_id(Platform.LOCK, DOMAIN, V1_UNIQUE_ID)
            is None
        )

    asyncio.run(exercise())


def test_v1_setup_stops_before_coordinator_and_forwarding_on_registry_conflict(
    tmp_path,
) -> None:
    """V1 registry ambiguity blocks setup before platform exposure."""

    async def exercise() -> None:
        context = await _registry_context(tmp_path, "v1-setup-order")
        other_entry = _new_config_entry("v1-setup-foreign-owner")
        context.hass.config_entries._entries[other_entry.entry_id] = other_entry
        old_entry = _create_old_v1_button_entry(
            context,
            config_entry=other_entry,
            device_id=None,
        )
        fake_device = SimpleNamespace(
            initialize=AsyncMock(),
            category="ms",
            product_id="7a4xvbtt",
            device_id="synthetic-v1-device",
            address=ADDRESS,
        )
        forward = AsyncMock()

        with (
            patch.object(
                integration.bluetooth,
                "async_ble_device_from_address",
                return_value=object(),
            ),
            patch.object(integration, "TuyaBLEDevice", return_value=fake_device),
            patch.object(integration, "get_device_product_info", return_value=object()),
            patch.object(integration, "TuyaBLECoordinator") as coordinator,
            patch.object(
                context.hass.config_entries,
                "async_forward_entry_setups",
                new=forward,
            ),
            pytest.raises(ConfigEntryError, match="ambiguous"),
        ):
            await integration.async_setup_entry(context.hass, context.entry)

        assert context.registry.async_get(old_entry.entity_id) == old_entry
        coordinator.assert_not_called()
        forward.assert_not_awaited()

    asyncio.run(exercise())


def test_migration_preserves_customization_collision_and_idempotency(tmp_path) -> None:
    """Creation is collision-safe, drops switch options, and is idempotent."""

    async def exercise() -> None:
        context = await _registry_context(tmp_path)
        collision = context.registry.async_get_or_create(
            Platform.BINARY_SENSOR,
            "other_integration",
            "other-unique-id",
            suggested_object_id="custom_motor",
        )
        old_entry = _create_old_motor_entry(context)

        integration._async_migrate_s1_motor_state_entity(
            context.hass, context.entry, context.device
        )

        assert context.registry.async_get(old_entry.entity_id) is None
        assert context.registry.async_get(collision.entity_id) == collision
        new_entity_id = context.registry.async_get_entity_id(
            Platform.BINARY_SENSOR, DOMAIN, MOTOR_UNIQUE_ID
        )
        assert new_entity_id == "binary_sensor.custom_motor_2"
        new_entry = context.registry.async_get(new_entity_id)
        assert new_entry is not None
        assert new_entry.config_entry_id == context.entry.entry_id
        assert new_entry.device_id == context.device_entry.id
        assert new_entry.name == "Garage motor"
        assert new_entry.icon == "mdi:cog"
        assert new_entry.area_id == context.area.id
        assert new_entry.disabled_by is er.RegistryEntryDisabler.USER
        assert new_entry.hidden_by is er.RegistryEntryHider.USER
        assert new_entry.labels == {context.label.label_id}
        expected_aliases = ["Motor alias"]
        if hasattr(er, "COMPUTED_NAME"):
            expected_aliases.insert(0, er.COMPUTED_NAME)
        assert list(new_entry.aliases) == expected_aliases
        assert new_entry.categories == {
            "old_scope": "lock",
            "shared_scope": "old",
        }
        assert new_entry.device_class is None
        assert new_entry.original_device_class is None
        assert new_entry.options == {}
        assert new_entry.entity_category is EntityCategory.DIAGNOSTIC
        assert new_entry.translation_key == "lock_motor_state"
        assert new_entry.original_icon == "mdi:engine"

        before = new_entry
        integration._async_migrate_s1_motor_state_entity(
            context.hass, context.entry, context.device
        )
        assert context.registry.async_get(new_entity_id) == before

    asyncio.run(exercise())


def test_migration_merges_existing_target_without_overwriting_target_data(
    tmp_path,
) -> None:
    """Existing target customizations and binary-sensor options take precedence."""

    async def exercise() -> None:
        context = await _registry_context(tmp_path, "existing-target")
        old_entry = _create_old_motor_entry(context)
        target_label = lr.async_get(context.hass).async_create("Existing target")
        target = context.registry.async_get_or_create(
            Platform.BINARY_SENSOR,
            DOMAIN,
            MOTOR_UNIQUE_ID,
            suggested_object_id="existing_motor",
            get_initial_options=lambda: {
                "binary_sensor": {"synthetic_target_option": True}
            },
            config_entry=context.entry,
            device_id=context.device_entry.id,
        )
        target = context.registry.async_update_entity(
            target.entity_id,
            aliases=["Target alias"],
            categories={"new_scope": "lock", "shared_scope": "target"},
            device_class=BinarySensorDeviceClass.RUNNING,
            icon="mdi:engine-outline",
            labels={target_label.label_id},
            name="Existing target name",
        )

        integration._async_migrate_s1_motor_state_entity(
            context.hass, context.entry, context.device
        )

        assert context.registry.async_get(old_entry.entity_id) is None
        merged = context.registry.async_get(target.entity_id)
        assert merged is not None
        assert merged.name == "Existing target name"
        assert merged.icon == "mdi:engine-outline"
        assert merged.area_id == context.area.id
        assert merged.disabled_by is er.RegistryEntryDisabler.USER
        assert merged.hidden_by is er.RegistryEntryHider.USER
        assert merged.labels == {context.label.label_id, target_label.label_id}
        assert list(merged.aliases) == ["Target alias", "Motor alias"]
        assert merged.categories == {
            "old_scope": "lock",
            "new_scope": "lock",
            "shared_scope": "target",
        }
        assert merged.device_class is BinarySensorDeviceClass.RUNNING
        assert merged.options == {"binary_sensor": {"synthetic_target_option": True}}
        assert "switch" not in merged.options

    asyncio.run(exercise())


@pytest.mark.parametrize(
    ("category", "product_id"),
    (("ms", "7a4xvbtt"), ("jtmspro", "other-product")),
)
def test_migration_is_scoped_to_exact_s1_product(
    tmp_path, category: str, product_id: str
) -> None:
    """Other locks and products cannot enter the S1 registry migration."""

    async def exercise() -> None:
        context = await _registry_context(tmp_path, f"{category}-{product_id}")
        old_entry = _create_old_motor_entry(context)
        other_device = SimpleNamespace(
            category=category,
            product_id=product_id,
            device_id="synthetic-device",
            address=ADDRESS,
        )

        integration._async_migrate_s1_motor_state_entity(
            context.hass, context.entry, other_device
        )

        assert context.registry.async_get(old_entry.entity_id) == old_entry
        assert (
            context.registry.async_get_entity_id(
                Platform.BINARY_SENSOR, DOMAIN, MOTOR_UNIQUE_ID
            )
            is None
        )

    asyncio.run(exercise())


def test_migration_rejects_ambiguous_and_foreign_switches(tmp_path) -> None:
    """Suffix collisions and globally foreign ownership both fail closed."""

    async def exercise() -> None:
        ambiguous = await _registry_context(tmp_path, "ambiguous")
        first = _create_old_motor_entry(ambiguous)
        second = _create_old_motor_entry(
            ambiguous, unique_id="other-device-lock_motor_state"
        )
        with pytest.raises(ConfigEntryError, match="ambiguous"):
            integration._async_migrate_s1_motor_state_entity(
                ambiguous.hass, ambiguous.entry, ambiguous.device
            )
        assert ambiguous.registry.async_get(first.entity_id) == first
        assert ambiguous.registry.async_get(second.entity_id) == second

        foreign = await _registry_context(tmp_path, "foreign")
        other_entry = _new_config_entry("foreign-owner")
        foreign.hass.config_entries._entries[other_entry.entry_id] = other_entry
        foreign_old = _create_old_motor_entry(
            foreign,
            config_entry=other_entry,
            device_id=None,
        )
        with pytest.raises(ConfigEntryError, match="ambiguous"):
            integration._async_migrate_s1_motor_state_entity(
                foreign.hass, foreign.entry, foreign.device
            )
        assert foreign.registry.async_get(foreign_old.entity_id) == foreign_old

    asyncio.run(exercise())


def test_migration_rejects_device_and_target_ownership_conflicts(tmp_path) -> None:
    """A target must share the exact current owner and device association."""

    async def exercise() -> None:
        context = await _registry_context(tmp_path, "device-conflict")
        old_entry = _create_old_motor_entry(context)
        other_device = context.device_registry.async_get_or_create(
            config_entry_id=context.entry.entry_id,
            identifiers={(DOMAIN, "AA:BB:CC:DD:EE:FF")},
        )
        target = context.registry.async_get_or_create(
            Platform.BINARY_SENSOR,
            DOMAIN,
            MOTOR_UNIQUE_ID,
            suggested_object_id="wrong_device_motor",
            config_entry=context.entry,
            device_id=other_device.id,
        )

        with pytest.raises(ConfigEntryError, match="different device"):
            integration._async_migrate_s1_motor_state_entity(
                context.hass, context.entry, context.device
            )

        assert context.registry.async_get(old_entry.entity_id) == old_entry
        assert context.registry.async_get(target.entity_id) == target

        foreign_target = await _registry_context(tmp_path, "foreign-target")
        foreign_old = _create_old_motor_entry(foreign_target)
        other_entry = _new_config_entry("target-owner")
        foreign_target.hass.config_entries._entries[other_entry.entry_id] = other_entry
        target = foreign_target.registry.async_get_or_create(
            Platform.BINARY_SENSOR,
            DOMAIN,
            MOTOR_UNIQUE_ID,
            suggested_object_id="foreign_target_motor",
            config_entry=other_entry,
        )

        with pytest.raises(ConfigEntryError, match="not owned"):
            integration._async_migrate_s1_motor_state_entity(
                foreign_target.hass, foreign_target.entry, foreign_target.device
            )
        assert foreign_target.registry.async_get(foreign_old.entity_id) == foreign_old
        assert foreign_target.registry.async_get(target.entity_id) == target

    asyncio.run(exercise())


@pytest.mark.parametrize(
    ("device_class", "options", "message"),
    (
        (
            SwitchDeviceClass.SWITCH,
            {"binary_sensor": {"synthetic_target_option": True}},
            "invalid device class",
        ),
        (
            None,
            {"switch": {"synthetic_target_option": True}},
            "invalid entity options",
        ),
    ),
)
def test_migration_rejects_switch_only_target_state(
    tmp_path,
    device_class: SwitchDeviceClass | None,
    options: dict,
    message: str,
) -> None:
    """A partial target cannot retain switch-only class or option state."""

    async def exercise() -> None:
        context = await _registry_context(tmp_path, message.replace(" ", "-"))
        old_entry = _create_old_motor_entry(context)
        target = context.registry.async_get_or_create(
            Platform.BINARY_SENSOR,
            DOMAIN,
            MOTOR_UNIQUE_ID,
            suggested_object_id="invalid_target_motor",
            get_initial_options=lambda: options,
            config_entry=context.entry,
            device_id=context.device_entry.id,
        )
        if device_class is not None:
            target = context.registry.async_update_entity(
                target.entity_id, device_class=device_class
            )

        with pytest.raises(ConfigEntryError, match=message):
            integration._async_migrate_s1_motor_state_entity(
                context.hass, context.entry, context.device
            )

        assert context.registry.async_get(old_entry.entity_id) == old_entry
        assert context.registry.async_get(target.entity_id) == target

    asyncio.run(exercise())


def test_migration_rejects_conflicting_valid_subentries(tmp_path) -> None:
    """Two valid but different config subentries cannot be reconciled implicitly."""
    if "subentries_data" not in inspect.signature(ConfigEntry).parameters:
        pytest.skip("This Home Assistant version has no config subentries")

    async def exercise() -> None:
        subentries = (
            {
                "data": {},
                "subentry_id": "subentry-old",
                "subentry_type": "device",
                "title": "Old association",
                "unique_id": "old-association",
            },
            {
                "data": {},
                "subentry_id": "subentry-target",
                "subentry_type": "device",
                "title": "Target association",
                "unique_id": "target-association",
            },
        )
        context = await _registry_context(
            tmp_path,
            "subentry-conflict",
            subentries_data=subentries,
            device_subentry_id="subentry-old",
        )
        old_entry = _create_old_motor_entry(
            context,
            device_id=None,
            config_subentry_id="subentry-old",
        )
        target = context.registry.async_get_or_create(
            Platform.BINARY_SENSOR,
            DOMAIN,
            MOTOR_UNIQUE_ID,
            suggested_object_id="subentry_target_motor",
            config_entry=context.entry,
            config_subentry_id="subentry-target",
        )

        with pytest.raises(ConfigEntryError, match="different config subentries"):
            integration._async_migrate_s1_motor_state_entity(
                context.hass, context.entry, context.device
            )

        assert context.registry.async_get(old_entry.entity_id) == old_entry
        assert context.registry.async_get(target.entity_id) == target

    asyncio.run(exercise())


def test_migration_rolls_back_new_target_when_update_fails(tmp_path) -> None:
    """A newly created target is removed if it cannot be fully updated."""

    async def exercise() -> None:
        context = await _registry_context(tmp_path, "rollback")
        old_entry = _create_old_motor_entry(context)

        with (
            patch.object(
                context.registry,
                "async_update_entity",
                side_effect=RuntimeError("synthetic update failure"),
            ),
            pytest.raises(ConfigEntryError, match="Unable to safely migrate"),
        ):
            integration._async_migrate_s1_motor_state_entity(
                context.hass, context.entry, context.device
            )

        assert context.registry.async_get(old_entry.entity_id) == old_entry
        assert (
            context.registry.async_get_entity_id(
                Platform.BINARY_SENSOR, DOMAIN, MOTOR_UNIQUE_ID
            )
            is None
        )

    asyncio.run(exercise())


def test_setup_stops_before_coordinator_and_forwarding_on_registry_conflict(
    tmp_path,
) -> None:
    """Registry ambiguity blocks setup before coordinator or platform exposure."""

    async def exercise() -> None:
        context = await _registry_context(tmp_path, "setup-order")
        other_entry = _new_config_entry("setup-foreign-owner")
        context.hass.config_entries._entries[other_entry.entry_id] = other_entry
        old_entry = _create_old_motor_entry(
            context,
            config_entry=other_entry,
            device_id=None,
        )
        fake_device = SimpleNamespace(
            initialize=AsyncMock(),
            category="jtmspro",
            product_id="xqeob8h6",
            device_id="synthetic-device",
            address=ADDRESS,
        )
        forward = AsyncMock()

        with (
            patch.object(
                integration.bluetooth,
                "async_ble_device_from_address",
                return_value=object(),
            ),
            patch.object(integration, "TuyaBLEDevice", return_value=fake_device),
            patch.object(integration, "get_device_product_info", return_value=object()),
            patch.object(integration, "TuyaBLECoordinator") as coordinator,
            patch.object(
                context.hass.config_entries,
                "async_forward_entry_setups",
                new=forward,
            ),
            pytest.raises(ConfigEntryError, match="ambiguous"),
        ):
            await integration.async_setup_entry(context.hass, context.entry)

        assert context.registry.async_get(old_entry.entity_id) == old_entry
        coordinator.assert_not_called()
        forward.assert_not_awaited()

    asyncio.run(exercise())
