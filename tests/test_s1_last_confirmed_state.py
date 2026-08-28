"""Regression contracts for S1 last-confirmed state after a safe disconnect."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from bleak.backends.device import BLEDevice
from homeassistant.components.number import NumberEntity
from homeassistant.components.select import SelectEntity
from homeassistant.components.sensor import RestoreSensor, SensorEntity
from homeassistant.components.switch import SwitchEntity
from homeassistant.core import HomeAssistant, State
from homeassistant.helpers.entity_component import EntityComponent
from homeassistant.helpers.restore_state import RestoreEntity, StoredState
from homeassistant.helpers.restore_state import async_get as async_get_restore

from custom_components.tuya_ble import binary_sensor, number, select, sensor, switch
from custom_components.tuya_ble.const import DOMAIN, ConnectionMode
from custom_components.tuya_ble.devices import (
    TuyaBLECoordinator,
    TuyaBLEEntity,
    TuyaBLEProductInfo,
)
from custom_components.tuya_ble.last_confirmed import (
    TuyaBLES1LastConfirmedEntity,
    _parse_restored_timestamp,
)
from custom_components.tuya_ble.number import (
    TuyaBLENumber,
    TuyaBLES1LastConfirmedNumber,
)
from custom_components.tuya_ble.select import (
    TuyaBLES1LastConfirmedSelect,
    TuyaBLESelect,
)
from custom_components.tuya_ble.sensor import (
    TuyaBLELastStatusUpdateSensor,
    TuyaBLES1LastConfirmedSensor,
    TuyaBLESensor,
)
from custom_components.tuya_ble.switch import (
    TuyaBLES1LastConfirmedSwitch,
    TuyaBLESwitch,
)
from custom_components.tuya_ble.tuya_ble import TuyaBLEDataPointType, TuyaBLEDevice
from custom_components.tuya_ble.tuya_ble import tuya_ble as tuya_ble_protocol
from custom_components.tuya_ble.tuya_ble.exceptions import (
    TuyaBLECommandUnconfirmedError,
    TuyaBLEControlSuspendedError,
)


class _SyntheticConnectedClient:
    """A synthetic, non-routable transport used only for session provenance."""

    def __init__(self) -> None:
        self.is_connected = True


def _make_s1_device() -> TuyaBLEDevice:
    """Construct the exact S1 product without any network or credential material."""
    device = TuyaBLEDevice(
        Mock(),
        BLEDevice(
            name="Synthetic S1",
            address="00:00:00:00:00:36",
            details={},
        ),
        connection_mode=ConnectionMode.ON_DEMAND.value,
    )
    device._device_info = SimpleNamespace(
        uuid="synthetic-issue-36-uuid",
        device_id="synthetic-issue-36-device",
        category="jtmspro",
        product_id="xqeob8h6",
        product_model="SYNTHETIC-S1",
    )
    return device


def _make_product_device(category: str, product_id: str) -> TuyaBLEDevice:
    """Construct one synthetic mapped product without BLE or persisted state."""
    device = _make_s1_device()
    device._device_info.category = category
    device._device_info.product_id = product_id
    return device


async def _factory_entities(
    hass: HomeAssistant, device: TuyaBLEDevice, suffix: str
) -> tuple[TuyaBLECoordinator, list[object]]:
    """Collect instances from the real platform factories for one synthetic device."""
    coordinator = TuyaBLECoordinator(hass, device)
    entry = SimpleNamespace(entry_id=f"synthetic-issue-36-{suffix}")
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = SimpleNamespace(
        coordinator=coordinator,
        device=device,
        product=TuyaBLEProductInfo(f"Synthetic {suffix}"),
    )
    entities: list[object] = []
    for factory in (
        binary_sensor.async_setup_entry,
        number.async_setup_entry,
        select.async_setup_entry,
        sensor.async_setup_entry,
        switch.async_setup_entry,
    ):
        await factory(hass, entry, entities.extend)
    return coordinator, entities


def _entity_for_mapping(entities: list[object], dp_id: int, entity_type: type):
    """Return one factory-created entity associated with an exact mapped DP."""
    return next(
        entity
        for entity in entities
        if isinstance(entity, entity_type)
        and getattr(getattr(entity, "_mapping", None), "dp_id", None) == dp_id
    )


def _non_scoped_state(entity: object) -> object:
    """Read the native platform state without relying on restore internals."""
    if isinstance(entity, TuyaBLESwitch):
        return entity.is_on
    if isinstance(entity, TuyaBLESelect):
        return entity.current_option
    if isinstance(entity, TuyaBLENumber):
        return entity.native_value
    assert isinstance(entity, TuyaBLESensor)
    entity._attr_native_value = "base-platform-state"
    return entity.native_value


def _mapping_for(mapping, dp_id: int):
    return next(item for item in mapping if item.dp_id == dp_id)


def _make_entities(hass: HomeAssistant):
    """Create the four public S1 entities attached to one coordinator."""
    device = _make_s1_device()
    coordinator = TuyaBLECoordinator(hass, device)
    product = TuyaBLEProductInfo("S1-TY-BLE-PRO")
    entities = {
        "auto_lock": TuyaBLES1LastConfirmedSwitch(
            hass,
            coordinator,
            device,
            product,
            _mapping_for(switch.get_mapping_by_device(device), 33),
        ),
        "authentication": TuyaBLES1LastConfirmedSelect(
            hass,
            coordinator,
            device,
            product,
            _mapping_for(select.get_mapping_by_device(device), 34),
        ),
        "auto_lock_delay": TuyaBLES1LastConfirmedNumber(
            hass,
            coordinator,
            device,
            product,
            _mapping_for(number.get_mapping_by_device(device), 36),
        ),
        "battery": TuyaBLES1LastConfirmedSensor(
            hass,
            coordinator,
            device,
            product,
            _mapping_for(sensor.get_mapping_by_device(device), 8),
        ),
        "last_status": TuyaBLELastStatusUpdateSensor(
            hass,
            coordinator,
            device,
            product,
            next(
                item
                for item in sensor.get_mapping_by_device(device)
                if item.description.key == "last_status_update"
            ),
        ),
    }
    listeners = []
    for entity in entities.values():
        entity.async_write_ha_state = Mock()
        listeners.append(
            coordinator.async_add_listener(entity._handle_coordinator_update)
        )
    return device, coordinator, entities, listeners


def _begin_authenticated_session(device: TuyaBLEDevice) -> _SyntheticConnectedClient:
    """Start one exact authenticated session without performing Bluetooth I/O."""
    client = _SyntheticConnectedClient()
    token = device._claim_connection_session(client)
    device._is_paired = True
    device._notifications_active = True
    device._physical_connection_active = True
    device._publish_connected_session(token)
    return client


def _report(
    device: TuyaBLEDevice,
    dp_id: int,
    dp_type: TuyaBLEDataPointType,
    value: bool | int,
) -> None:
    """Deliver an accepted report through the exact current session token."""
    token = device._connection_token
    assert token is not None
    device.datapoints._update_from_device(dp_id, 0, 0, dp_type, value, token)
    datapoint = device.datapoints[dp_id]
    assert datapoint is not None
    device._fire_callbacks([datapoint])


def _report_batch(
    device: TuyaBLEDevice,
    reports: list[tuple[int, TuyaBLEDataPointType, bool | int]],
) -> None:
    """Deliver one accepted callback batch through the exact current session."""
    token = device._connection_token
    assert token is not None
    datapoints = []
    for dp_id, dp_type, value in reports:
        device.datapoints._update_from_device(dp_id, 0, 0, dp_type, value, token)
        datapoint = device.datapoints[dp_id]
        assert datapoint is not None
        datapoints.append(datapoint)
    device._fire_callbacks(datapoints)


def _freeze_confirmation_time(
    monkeypatch: pytest.MonkeyPatch, clock: dict[str, datetime]
) -> None:
    """Freeze only the local confirmation clock used by the retained S1 model."""

    class _FrozenDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            value = clock["value"]
            return value if tz is None else value.astimezone(tz)

    monkeypatch.setattr(tuya_ble_protocol, "datetime", _FrozenDateTime)


async def _add_entities_to_real_ha_state_machine(
    hass: HomeAssistant, entities: dict[str, object]
) -> list[EntityComponent]:
    """Attach the reviewed entities to actual Home Assistant entity components."""
    components: list[EntityComponent] = []
    for domain, selected in (
        ("switch", [entities["auto_lock"]]),
        ("select", [entities["authentication"]]),
        ("number", [entities["auto_lock_delay"]]),
        ("sensor", [entities["battery"], entities["last_status"]]),
    ):
        for entity in selected:
            del entity.async_write_ha_state
        component = EntityComponent(logging.getLogger(__name__), domain, hass)
        await component.async_add_entities(selected)
        components.append(component)
    await hass.async_block_till_done()
    return components


def _state_timestamp(value: object) -> datetime:
    """Read Home Assistant's in-memory datetime attribute representation."""
    return value if isinstance(value, datetime) else datetime.fromisoformat(value)


def _intentional_disconnect(
    device: TuyaBLEDevice, client: _SyntheticConnectedClient
) -> None:
    """Invalidate the accepted session using the normal disconnect callback path."""
    token = device._connection_token
    assert token is not None
    device._expected_disconnect = True
    client.is_connected = False
    device._disconnected(client, token)


def _cleanup(coordinator: TuyaBLECoordinator, listeners: list) -> None:
    for remove_listener in listeners:
        remove_listener()
    coordinator.shutdown()


async def _restore_entity(
    hass: HomeAssistant,
    entity,
    state: str,
    attributes: dict[str, object],
) -> None:
    """Install one synthetic stored state through Home Assistant's restore API."""
    async_get_restore(hass).last_states[entity.entity_id] = StoredState(
        State(entity.entity_id, state, attributes),
        None,
        State(entity.entity_id, state).last_updated,
    )
    entity.hass = hass
    await entity.async_added_to_hass()


def test_generic_platform_mros_are_the_exact_non_restore_platform_bases() -> None:
    """Restore support is opt-in concrete behavior, never a generic platform trait."""
    for entity_class, platform_class, restore_class in (
        (TuyaBLESwitch, SwitchEntity, RestoreEntity),
        (TuyaBLESelect, SelectEntity, RestoreEntity),
        (TuyaBLENumber, NumberEntity, RestoreEntity),
        (TuyaBLESensor, SensorEntity, RestoreSensor),
    ):
        assert TuyaBLES1LastConfirmedEntity not in entity_class.__mro__
        assert restore_class not in entity_class.__mro__
        expected_mro = type(
            f"Expected{entity_class.__name__}",
            (TuyaBLEEntity, platform_class),
            {},
        ).__mro__[1:]
        assert entity_class.__mro__[1:] == expected_mro


async def test_factory_selects_restore_only_for_exact_s1_confirmed_entities(
    hass: HomeAssistant,
) -> None:
    """Real factory output limits restore behavior to the five reviewed S1 entities."""
    s1_coordinator, s1_entities = await _factory_entities(
        hass, _make_s1_device(), "s1-census"
    )
    s1_restore_entities = [
        entity for entity in s1_entities if isinstance(entity, RestoreEntity)
    ]
    s1_scoped = (
        _entity_for_mapping(s1_entities, 33, TuyaBLESwitch),
        _entity_for_mapping(s1_entities, 34, TuyaBLESelect),
        _entity_for_mapping(s1_entities, 36, TuyaBLENumber),
        _entity_for_mapping(s1_entities, 8, TuyaBLESensor),
    )
    status = next(
        entity
        for entity in s1_entities
        if isinstance(entity, TuyaBLELastStatusUpdateSensor)
    )

    assert all(
        type(entity) is not type_base
        for entity, type_base in zip(
            s1_scoped,
            (TuyaBLESwitch, TuyaBLESelect, TuyaBLENumber, TuyaBLESensor),
            strict=True,
        )
    )
    assert set(s1_restore_entities) == {*s1_scoped, status}
    assert isinstance(status, RestoreSensor)

    excluded_s1_dp_ids = {21, 40, 47}
    for entity in s1_entities:
        mapping = getattr(entity, "_mapping", None)
        if getattr(mapping, "dp_id", None) in excluded_s1_dp_ids:
            assert not isinstance(entity, RestoreEntity)
    assert not isinstance(
        next(
            entity
            for entity in s1_entities
            if type(entity).__name__ == "TuyaBLELastUnlockSensor"
        ),
        RestoreEntity,
    )
    assert not isinstance(
        _entity_for_mapping(s1_entities, -1, TuyaBLESensor), RestoreEntity
    )

    v1_coordinator, v1_entities = await _factory_entities(
        hass, _make_product_device("ms", "7a4xvbtt"), "v1-census"
    )
    for entity in v1_entities:
        mapping = getattr(entity, "_mapping", None)
        if getattr(mapping, "dp_id", None) in {8, 21, 33, 36, 47}:
            assert not isinstance(entity, RestoreEntity)

    foreign_s1_coordinator, foreign_s1_entities = await _factory_entities(
        hass, _make_product_device("jtmspro", "y2yaegze"), "foreign-s1-census"
    )
    for entity in foreign_s1_entities:
        mapping = getattr(entity, "_mapping", None)
        if getattr(mapping, "dp_id", None) in {8, 33}:
            assert not isinstance(entity, RestoreEntity)

    unrelated_coordinator, unrelated_entities = await _factory_entities(
        hass, _make_product_device("dcb", "z5ztlw3k"), "unrelated-census"
    )
    for entity_type in (TuyaBLESensor, TuyaBLESwitch, TuyaBLESelect, TuyaBLENumber):
        entity = next(
            entity for entity in unrelated_entities if type(entity) is entity_type
        )
        assert not isinstance(entity, RestoreEntity)

    s1_coordinator.shutdown()
    v1_coordinator.shutdown()
    foreign_s1_coordinator.shutdown()
    unrelated_coordinator.shutdown()


async def test_restore_lifecycle_lookup_and_setup_participation_are_scoped(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only the S1 restore subset consumes HA restore lifecycle work or callbacks."""
    device = _make_s1_device()
    coordinator, entities = await _factory_entities(hass, device, "restore-lifecycle")
    scoped = {
        _entity_for_mapping(entities, 33, TuyaBLESwitch),
        _entity_for_mapping(entities, 34, TuyaBLESelect),
        _entity_for_mapping(entities, 36, TuyaBLENumber),
        _entity_for_mapping(entities, 8, TuyaBLESensor),
        next(
            entity
            for entity in entities
            if isinstance(entity, TuyaBLELastStatusUpdateSensor)
        ),
    }
    setup_participants: list[object] = []
    lookups: list[object] = []
    reload_entry = AsyncMock()
    original_added = RestoreEntity.async_added_to_hass
    original_lookup = RestoreEntity.async_get_last_state

    async def tracked_added(entity) -> None:
        setup_participants.append(entity)
        await original_added(entity)

    async def tracked_lookup(entity):
        lookups.append(entity)
        return await original_lookup(entity)

    monkeypatch.setattr(RestoreEntity, "async_added_to_hass", tracked_added)
    monkeypatch.setattr(RestoreEntity, "async_get_last_state", tracked_lookup)
    monkeypatch.setattr(hass.config_entries, "async_reload", reload_entry)

    for entity in entities:
        entity.hass = hass
        entity.async_write_ha_state = Mock()
        await entity.async_added_to_hass()

    assert set(setup_participants) == scoped
    assert set(lookups) == scoped
    reload_entry.assert_not_awaited()
    assert len(device.last_confirmed_s1_state._callbacks) == 1

    status = next(
        entity for entity in scoped if isinstance(entity, TuyaBLELastStatusUpdateSensor)
    )
    for _ in range(3):
        await status.async_will_remove_from_hass()
        assert device.last_confirmed_s1_state._callbacks == []
        await status.async_added_to_hass()
        assert len(device.last_confirmed_s1_state._callbacks) == 1

    for entity in entities:
        await entity.async_will_remove_from_hass()
    assert device.last_confirmed_s1_state._callbacks == []
    coordinator.shutdown()


async def test_non_scoped_factory_entities_preserve_base_presentation_contract(
    hass: HomeAssistant,
) -> None:
    """Non-scoped S1, V1, and unrelated entities expose no restore provenance."""
    coordinators: list[TuyaBLECoordinator] = []
    all_entities: list[object] = []
    for category, product_id, suffix in (
        ("jtmspro", "xqeob8h6", "s1-base-presentation"),
        ("ms", "7a4xvbtt", "v1-base-presentation"),
        ("dcb", "z5ztlw3k", "unrelated-base-presentation"),
    ):
        coordinator, entities = await _factory_entities(
            hass, _make_product_device(category, product_id), suffix
        )
        coordinators.append(coordinator)
        all_entities.extend(entities)

    scoped_s1_dp_ids = {8, 33, 34, 36}
    checked = 0
    for entity in all_entities:
        mapping = getattr(entity, "_mapping", None)
        if (
            isinstance(entity, TuyaBLELastStatusUpdateSensor)
            or getattr(mapping, "dp_id", None) in scoped_s1_dp_ids
            and entity.device.category == "jtmspro"
            and entity.device.product_id == "xqeob8h6"
        ):
            continue
        if not isinstance(
            entity, (TuyaBLESensor, TuyaBLESwitch, TuyaBLESelect, TuyaBLENumber)
        ):
            continue
        checked += 1
        before = (
            _non_scoped_state(entity),
            entity.available,
            entity.extra_state_attributes,
            entity.unique_id,
            entity.entity_description.entity_category,
            entity.translation_key,
        )
        entity.hass = hass
        entity.async_write_ha_state = Mock()
        await entity.async_added_to_hass()
        after = (
            _non_scoped_state(entity),
            entity.available,
            entity.extra_state_attributes,
            entity.unique_id,
            entity.entity_description.entity_category,
            entity.translation_key,
        )
        assert type(entity) in {
            TuyaBLESensor,
            TuyaBLESwitch,
            TuyaBLESelect,
            TuyaBLENumber,
        }
        assert not isinstance(entity, RestoreEntity)
        assert before == after
        assert entity.extra_state_attributes is None
        assert not {
            "last_confirmed_at",
            "data_fresh",
            "value_source",
        }.intersection(entity.extra_state_attributes or {})
        await entity.async_will_remove_from_hass()

    assert checked >= 10
    for coordinator in coordinators:
        coordinator.shutdown()


async def test_s1_auto_lock_keeps_both_confirmed_boolean_states_after_disconnect(
    hass: HomeAssistant,
) -> None:
    """A confirmed S1 Auto-Lock value remains a normal toggle after disconnect."""
    observed: list[bool | None] = []
    for confirmed in (True, False):
        device, coordinator, entities, listeners = _make_entities(hass)
        client = _begin_authenticated_session(device)
        _report(device, 33, TuyaBLEDataPointType.DT_BOOL, confirmed)
        assert entities["auto_lock"].is_on is confirmed

        _intentional_disconnect(device, client)
        observed.append(entities["auto_lock"].is_on)
        _cleanup(coordinator, listeners)

    assert observed == [True, False]


async def test_s1_authentication_mode_keeps_confirmed_option_after_disconnect(
    hass: HomeAssistant,
) -> None:
    """A confirmed S1 Authentication Mode stays visible after disconnect."""
    device, coordinator, entities, listeners = _make_entities(hass)
    client = _begin_authenticated_session(device)
    _report(device, 34, TuyaBLEDataPointType.DT_ENUM, 1)
    assert entities["authentication"].current_option == "finger_card"

    _intentional_disconnect(device, client)
    _cleanup(coordinator, listeners)

    assert entities["authentication"].current_option == "finger_card"


async def test_s1_auto_lock_delay_keeps_confirmed_number_after_disconnect(
    hass: HomeAssistant,
) -> None:
    """A confirmed S1 Auto-Lock Delay remains usable as stale readback."""
    device, coordinator, entities, listeners = _make_entities(hass)
    client = _begin_authenticated_session(device)
    _report(device, 36, TuyaBLEDataPointType.DT_VALUE, 45)
    assert entities["auto_lock_delay"].native_value == 45.0

    _intentional_disconnect(device, client)
    _cleanup(coordinator, listeners)

    assert entities["auto_lock_delay"].native_value == 45.0


async def test_s1_battery_keeps_confirmed_percentage_available_after_disconnect(
    hass: HomeAssistant,
) -> None:
    """A valid confirmed S1 Battery percentage does not become unavailable."""
    device, coordinator, entities, listeners = _make_entities(hass)
    client = _begin_authenticated_session(device)
    _report(device, 8, TuyaBLEDataPointType.DT_VALUE, 73)
    assert entities["battery"].native_value == 73
    assert entities["battery"].available is True

    _intentional_disconnect(device, client)
    _cleanup(coordinator, listeners)

    assert entities["battery"].native_value == 73
    assert entities["battery"].available is True


async def test_s1_restart_restores_complete_stale_last_confirmed_contract(
    hass: HomeAssistant,
) -> None:
    """A restarted S1 restores validated HA entity state as stale data."""
    device, coordinator, entities, listeners = _make_entities(hass)
    client = _begin_authenticated_session(device)
    _report(device, 33, TuyaBLEDataPointType.DT_BOOL, True)
    _report(device, 34, TuyaBLEDataPointType.DT_ENUM, 1)
    _report(device, 36, TuyaBLEDataPointType.DT_VALUE, 45)
    _report(device, 8, TuyaBLEDataPointType.DT_VALUE, 73)
    _intentional_disconnect(device, client)
    previous_states = {
        "auto_lock": ("on", entities["auto_lock"].extra_state_attributes),
        "authentication": (
            "finger_card",
            entities["authentication"].extra_state_attributes,
        ),
        "auto_lock_delay": (
            "45.0",
            entities["auto_lock_delay"].extra_state_attributes,
        ),
        "battery": ("73.0", entities["battery"].extra_state_attributes),
        "last_status": (
            entities["last_status"].native_value.isoformat(),
            {},
        ),
    }
    _cleanup(coordinator, listeners)

    restarted_device, restarted_coordinator, restarted, restarted_listeners = (
        _make_entities(hass)
    )
    del restarted_device
    restore_data = async_get_restore(hass)
    for key in (
        "last_status",
        "auto_lock",
        "authentication",
        "auto_lock_delay",
        "battery",
    ):
        entity = restarted[key]
        state, attributes = previous_states[key]
        restore_data.last_states[entity.entity_id] = StoredState(
            State(entity.entity_id, state, attributes),
            None,
            State(entity.entity_id, state).last_updated,
        )
        entity.hass = hass
        await entity.async_added_to_hass()
        if key == "last_status":
            entity.async_write_ha_state.reset_mock()
    _cleanup(restarted_coordinator, restarted_listeners)
    assert restarted["auto_lock"].is_on is True
    assert restarted["authentication"].current_option == "finger_card"
    assert restarted["auto_lock_delay"].native_value == 45.0
    assert restarted["battery"].native_value == 73
    assert restarted["last_status"].native_value == max(
        entity.extra_state_attributes["last_confirmed_at"]
        for key, entity in restarted.items()
        if key != "last_status"
    )
    assert restarted["last_status"].async_write_ha_state.call_count == 4
    for key, entity in restarted.items():
        if key == "last_status":
            continue
        assert entity.extra_state_attributes["data_fresh"] is False
        assert entity.extra_state_attributes["value_source"] == "restored"


async def test_s1_freshness_attributes_distinguish_current_and_retained_data(
    hass: HomeAssistant,
) -> None:
    """Public metadata distinguishes an exact-session report from retained state."""
    device, coordinator, entities, listeners = _make_entities(hass)
    client = _begin_authenticated_session(device)
    _report(device, 33, TuyaBLEDataPointType.DT_BOOL, True)
    current = entities["auto_lock"].extra_state_attributes
    assert current["data_fresh"] is True
    assert current["value_source"] == "current_session"
    confirmed_at = current["last_confirmed_at"]

    _intentional_disconnect(device, client)
    _cleanup(coordinator, listeners)

    retained = entities["auto_lock"].extra_state_attributes
    assert retained == {
        "data_fresh": False,
        "value_source": "retained",
        "last_confirmed_at": confirmed_at,
    }


async def test_s1_exposes_one_last_status_update_timestamp_entity(
    hass: HomeAssistant,
) -> None:
    """The exact S1 product provides a read-only aggregate status timestamp."""
    del hass
    mappings = sensor.get_mapping_by_device(_make_s1_device())
    status_mappings = [
        item for item in mappings if item.description.key == "last_status_update"
    ]

    assert len(status_mappings) == 1


async def test_s1_rejects_invalid_reports_without_overwriting_confirmation(
    hass: HomeAssistant,
) -> None:
    """Only independently valid scoped reports can replace retained S1 values."""
    device, coordinator, entities, listeners = _make_entities(hass)
    client = _begin_authenticated_session(device)
    _report(device, 8, TuyaBLEDataPointType.DT_VALUE, 73)
    _report(device, 34, TuyaBLEDataPointType.DT_ENUM, 1)
    _report(device, 36, TuyaBLEDataPointType.DT_VALUE, 45)

    _report(device, 8, TuyaBLEDataPointType.DT_VALUE, 101)
    _report(device, 34, TuyaBLEDataPointType.DT_ENUM, 2)
    _report(device, 36, TuyaBLEDataPointType.DT_VALUE, 0)

    assert entities["battery"].native_value == 73
    assert entities["authentication"].current_option == "finger_card"
    assert entities["auto_lock_delay"].native_value == 45.0
    _intentional_disconnect(device, client)
    _cleanup(coordinator, listeners)


async def test_s1_old_session_report_cannot_replace_retained_state(
    hass: HomeAssistant,
) -> None:
    """A retired exact session cannot promote a stale callback as confirmation."""
    device, coordinator, _entities, listeners = _make_entities(hass)
    old_client = _begin_authenticated_session(device)
    old_token = device._connection_token
    assert old_token is not None
    _report(device, 33, TuyaBLEDataPointType.DT_BOOL, True)
    _intentional_disconnect(device, old_client)

    replacement_client = _begin_authenticated_session(device)
    replacement_token = device._connection_token
    assert replacement_token is not None
    device.datapoints._update_from_device(
        33,
        0,
        0,
        TuyaBLEDataPointType.DT_BOOL,
        False,
        old_token,
    )
    datapoint = device.datapoints[33]
    assert datapoint is not None
    device._fire_callbacks([datapoint])

    retained = device.last_confirmed_s1_state.get(33)
    assert retained is not None
    assert retained.value is True
    assert retained.data_fresh is False
    _report(device, 33, TuyaBLEDataPointType.DT_BOOL, False)
    assert device.last_confirmed_s1_state.get(33).data_fresh is True
    assert device.last_confirmed_s1_state.get(33).value is False

    _intentional_disconnect(device, replacement_client)
    _cleanup(coordinator, listeners)


async def test_s1_local_write_never_promotes_last_confirmed_state(
    hass: HomeAssistant,
) -> None:
    """A local requested value stays unconfirmed until a report arrives."""
    device, coordinator, entities, listeners = _make_entities(hass)
    _begin_authenticated_session(device)
    datapoint = device.datapoints.get_or_create(
        33,
        TuyaBLEDataPointType.DT_BOOL,
        False,
    )
    datapoint._set_local_value(True)
    device._fire_callbacks([datapoint])

    assert device.last_confirmed_s1_state.get(33) is None
    assert entities["auto_lock"].is_on is None
    _cleanup(coordinator, listeners)


async def test_s1_retention_excludes_alarm_door_and_motor_without_ble_work(
    hass: HomeAssistant,
) -> None:
    """Excluded reports and retained-state publication perform no transport work."""
    device, coordinator, _entities, listeners = _make_entities(hass)
    device._send_datapoints = Mock()
    client = _begin_authenticated_session(device)
    for dp_id, dp_type, value in (
        (21, TuyaBLEDataPointType.DT_ENUM, 1),
        (40, TuyaBLEDataPointType.DT_ENUM, 2),
        (47, TuyaBLEDataPointType.DT_BOOL, True),
    ):
        _report(device, dp_id, dp_type, value)

    assert device.last_confirmed_s1_state.latest_confirmed_at is None
    device._send_datapoints.assert_not_called()
    _intentional_disconnect(device, client)
    device._send_datapoints.assert_not_called()
    _cleanup(coordinator, listeners)


def test_v1_mappings_remain_outside_s1_last_confirmed_scope() -> None:
    """The exact V1 product has no status entity or retained-state opt-in."""
    device = _make_s1_device()
    device._device_info.category = "ms"
    device._device_info.product_id = "7a4xvbtt"

    assert device.last_confirmed_s1_state.enabled is False
    assert all(
        item.description.key != "last_status_update"
        for item in sensor.get_mapping_by_device(device)
    )
    assert not switch.get_mapping_by_device(device)[0].last_confirmed
    assert not number.get_mapping_by_device(device)[0].last_confirmed


async def test_s1_restored_state_stays_restored_across_reportless_reconnects(
    hass: HomeAssistant,
) -> None:
    """A stored value cannot become fresh merely because a session is established."""
    device, coordinator, entities, listeners = _make_entities(hass)
    await _restore_entity(
        hass,
        entities["auto_lock"],
        "on",
        {"last_confirmed_at": "2026-01-02T03:04:05+00:00"},
    )
    restored = device.last_confirmed_s1_state.get(33)
    assert restored is not None
    assert restored.value_source == "restored"
    assert restored.data_fresh is False

    first_client = _begin_authenticated_session(device)
    assert entities["auto_lock"].is_on is True
    assert entities["auto_lock"].extra_state_attributes["value_source"] == "restored"
    _intentional_disconnect(device, first_client)

    second_client = _begin_authenticated_session(device)
    reportless = device.last_confirmed_s1_state.get(33)
    assert reportless is not None
    assert reportless.value_source == "restored"
    assert reportless.data_fresh is False

    device._schedule_reconnect_locked = Mock()
    second_client.is_connected = False
    token = device._connection_token
    assert token is not None
    device._disconnected(second_client, token)
    after_unexpected_disconnect = device.last_confirmed_s1_state.get(33)
    assert after_unexpected_disconnect is not None
    assert after_unexpected_disconnect.value_source == "restored"
    assert after_unexpected_disconnect.data_fresh is False
    _cleanup(coordinator, listeners)


async def test_s1_restore_cannot_overwrite_current_session_confirmation(
    hass: HomeAssistant,
) -> None:
    """A late HA restore record cannot replace a newer accepted device report."""
    device, coordinator, entities, listeners = _make_entities(hass)
    _begin_authenticated_session(device)
    _report(device, 33, TuyaBLEDataPointType.DT_BOOL, False)
    current = device.last_confirmed_s1_state.get(33)
    assert current is not None

    await _restore_entity(
        hass,
        entities["auto_lock"],
        "on",
        {"last_confirmed_at": "2026-01-02T03:04:05+00:00"},
    )

    retained = device.last_confirmed_s1_state.get(33)
    assert retained == current
    assert entities["auto_lock"].is_on is False
    assert (
        entities["auto_lock"].extra_state_attributes["value_source"]
        == "current_session"
    )
    _cleanup(coordinator, listeners)


@pytest.mark.parametrize(
    ("entity_key", "state"),
    [
        ("auto_lock", "unknown"),
        ("authentication", "unsupported_option"),
        ("auto_lock_delay", "0"),
        ("battery", "101"),
    ],
)
async def test_s1_invalid_restore_is_discarded_independently(
    hass: HomeAssistant, entity_key: str, state: str
) -> None:
    """One malformed stored entity never blocks or manufactures another value."""
    device, coordinator, entities, listeners = _make_entities(hass)
    entity = entities[entity_key]
    await _restore_entity(
        hass,
        entity,
        state,
        {"last_confirmed_at": "2026-01-02T03:04:05+00:00"},
    )
    assert device.last_confirmed_s1_state.get(entity._mapping.dp_id) is None
    _cleanup(coordinator, listeners)


async def test_s1_all_entities_publish_truthful_confirmation_metadata(
    hass: HomeAssistant,
) -> None:
    """Every scoped entity publishes its own aware timestamp and provenance."""
    device, coordinator, entities, listeners = _make_entities(hass)
    client = _begin_authenticated_session(device)
    for dp_id, dp_type, value in (
        (33, TuyaBLEDataPointType.DT_BOOL, True),
        (34, TuyaBLEDataPointType.DT_ENUM, 1),
        (36, TuyaBLEDataPointType.DT_VALUE, 45),
        (8, TuyaBLEDataPointType.DT_VALUE, 50),
    ):
        _report(device, dp_id, dp_type, value)
    for key in ("auto_lock", "authentication", "auto_lock_delay", "battery"):
        attributes = entities[key].extra_state_attributes
        assert attributes["data_fresh"] is True
        assert attributes["value_source"] == "current_session"
        assert attributes["last_confirmed_at"].tzinfo is not None
        assert attributes["last_confirmed_at"].utcoffset() is not None

    _intentional_disconnect(device, client)
    for key in ("auto_lock", "authentication", "auto_lock_delay", "battery"):
        attributes = entities[key].extra_state_attributes
        assert attributes["data_fresh"] is False
        assert attributes["value_source"] == "retained"
    _cleanup(coordinator, listeners)


async def test_s1_unexpected_disconnect_retains_all_confirmed_values(
    hass: HomeAssistant,
) -> None:
    """An unexpected loss has the same stale retained presentation as idle close."""
    device, coordinator, entities, listeners = _make_entities(hass)
    client = _begin_authenticated_session(device)
    for dp_id, dp_type, value in (
        (33, TuyaBLEDataPointType.DT_BOOL, True),
        (34, TuyaBLEDataPointType.DT_ENUM, 0),
        (36, TuyaBLEDataPointType.DT_VALUE, 45),
        (8, TuyaBLEDataPointType.DT_VALUE, 50),
    ):
        _report(device, dp_id, dp_type, value)
    device._schedule_reconnect_locked = Mock()
    client.is_connected = False
    token = device._connection_token
    assert token is not None
    device._disconnected(client, token)

    for dp_id in (33, 34, 36, 8):
        value = device.last_confirmed_s1_state.get(dp_id)
        assert value is not None
        assert value.data_fresh is False
        assert value.value_source == "retained"
    assert entities["auto_lock"].is_on is True
    assert entities["authentication"].current_option == "single_unlock"
    assert entities["auto_lock_delay"].native_value == 45.0
    assert entities["battery"].native_value == 50
    _cleanup(coordinator, listeners)


async def test_s1_ble_control_off_keeps_values_visible_and_blocks_all_writes(
    hass: HomeAssistant,
) -> None:
    """Presentation is retained while the independent write boundary fails closed."""
    device, coordinator, entities, listeners = _make_entities(hass)
    _begin_authenticated_session(device)
    for dp_id, dp_type, value in (
        (33, TuyaBLEDataPointType.DT_BOOL, True),
        (34, TuyaBLEDataPointType.DT_ENUM, 1),
        (36, TuyaBLEDataPointType.DT_VALUE, 45),
        (8, TuyaBLEDataPointType.DT_VALUE, 50),
    ):
        _report(device, dp_id, dp_type, value)
    device._ble_control_enabled = False
    device._send_datapoints = AsyncMock()

    assert all(
        entity.available for key, entity in entities.items() if key != "last_status"
    )
    with pytest.raises(TuyaBLEControlSuspendedError):
        entities["auto_lock"].turn_off()
    with pytest.raises(TuyaBLEControlSuspendedError):
        entities["authentication"].select_option("single_unlock")
    with pytest.raises(TuyaBLEControlSuspendedError):
        entities["auto_lock_delay"].set_native_value(46)
    device._send_datapoints.assert_not_awaited()
    _cleanup(coordinator, listeners)


@pytest.mark.parametrize("value", [0, 1, 50, 99, 100])
async def test_s1_battery_retains_every_boundary_percentage(
    hass: HomeAssistant, value: int
) -> None:
    """All valid integral battery boundaries are safe confirmed values."""
    device, coordinator, entities, listeners = _make_entities(hass)
    _begin_authenticated_session(device)
    _report(device, 8, TuyaBLEDataPointType.DT_VALUE, value)
    retained = device.last_confirmed_s1_state.get(8)
    assert retained is not None
    assert retained.value == value
    assert isinstance(entities["battery"].native_value, int)
    _cleanup(coordinator, listeners)


@pytest.mark.parametrize("invalid", [True, -1, 101])
async def test_s1_invalid_battery_reports_never_replace_a_confirmation(
    hass: HomeAssistant, invalid: bool | int
) -> None:
    """Boolean and out-of-range battery data are rejected independently."""
    device, coordinator, entities, listeners = _make_entities(hass)
    _begin_authenticated_session(device)
    _report(device, 8, TuyaBLEDataPointType.DT_VALUE, 50)
    _report(device, 8, TuyaBLEDataPointType.DT_VALUE, invalid)
    assert entities["battery"].native_value == 50
    _cleanup(coordinator, listeners)


@pytest.mark.parametrize("delay", [1, 45, 1800])
async def test_s1_auto_lock_delay_retains_only_valid_range_boundaries(
    hass: HomeAssistant, delay: int
) -> None:
    """The S1 minimum, nominal, and maximum delay reports remain distinct."""
    device, coordinator, entities, listeners = _make_entities(hass)
    _begin_authenticated_session(device)
    _report(device, 36, TuyaBLEDataPointType.DT_VALUE, delay)
    assert entities["auto_lock_delay"].native_value == float(delay)
    _cleanup(coordinator, listeners)


@pytest.mark.parametrize("option", [(0, "single_unlock"), (1, "finger_card")])
async def test_s1_authentication_mode_retains_both_valid_options(
    hass: HomeAssistant, option: tuple[int, str]
) -> None:
    """Both exact S1 authentication options require a device confirmation."""
    device, coordinator, entities, listeners = _make_entities(hass)
    _begin_authenticated_session(device)
    _report(device, 34, TuyaBLEDataPointType.DT_ENUM, option[0])
    assert entities["authentication"].current_option == option[1]
    _cleanup(coordinator, listeners)


async def test_s1_failed_confirmed_write_does_not_promote_requested_value(
    hass: HomeAssistant,
) -> None:
    """A failed or ambiguous command acknowledgement is not device confirmation."""
    device, coordinator, entities, listeners = _make_entities(hass)
    _begin_authenticated_session(device)
    _report(device, 33, TuyaBLEDataPointType.DT_BOOL, True)
    datapoint = device.datapoints[33]
    assert datapoint is not None
    device._send_datapoints_once = AsyncMock(
        side_effect=TuyaBLECommandUnconfirmedError()
    )

    with pytest.raises(TuyaBLECommandUnconfirmedError):
        await datapoint.set_value_once(False)

    retained = device.last_confirmed_s1_state.get(33)
    assert retained is not None
    assert retained.value is True
    assert entities["auto_lock"].is_on is True
    _cleanup(coordinator, listeners)


async def test_s1_cached_and_wrong_type_data_cannot_become_confirmation(
    hass: HomeAssistant,
) -> None:
    """Startup cache and parser-incompatible data have no retained authority."""
    device, coordinator, entities, listeners = _make_entities(hass)
    cached = device.datapoints.get_or_create(34, TuyaBLEDataPointType.DT_ENUM, 1)
    device._fire_callbacks([cached])
    assert device.last_confirmed_s1_state.get(34) is None
    device._ensure_connected = AsyncMock()
    device.set_ble_device_and_advertisement_data(
        BLEDevice(
            name="Synthetic S1 advertisement",
            address="00:00:00:00:00:36",
            details={},
        ),
        Mock(),
    )
    assert device.last_confirmed_s1_state.get(34) is None
    device._ensure_connected.assert_not_awaited()

    _begin_authenticated_session(device)
    _report(device, 34, TuyaBLEDataPointType.DT_VALUE, 1)
    assert device.last_confirmed_s1_state.get(34) is None
    assert entities["authentication"].current_option is None
    _cleanup(coordinator, listeners)


async def test_s1_last_status_never_moves_backward_and_listener_cycles_cleanup(
    hass: HomeAssistant,
) -> None:
    """The aggregate timestamp is monotonic and setup cycles leave no callbacks."""
    device, coordinator, entities, listeners = _make_entities(hass)
    _begin_authenticated_session(device)
    _report(device, 8, TuyaBLEDataPointType.DT_VALUE, 50)
    first = device.last_confirmed_s1_state.latest_confirmed_at
    assert first is not None
    _report(device, 33, TuyaBLEDataPointType.DT_BOOL, True)
    assert device.last_confirmed_s1_state.latest_confirmed_at >= first

    unique_ids = set()
    for _ in range(3):
        status = entities["last_status"]
        unique_ids.add(status.unique_id)
        await status.async_added_to_hass()
        assert len(device.last_confirmed_s1_state._callbacks) == 1
        await status.async_will_remove_from_hass()
        assert device.last_confirmed_s1_state._callbacks == []
    assert len(unique_ids) == 1
    _cleanup(coordinator, listeners)


async def test_s1_timestamp_precision_contract_uses_real_ha_state_machine(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Public HA state and every scoped attribute use one exact UTC second."""
    fixed = datetime(2026, 8, 28, 12, 34, 56, 543896, tzinfo=timezone.utc)
    _freeze_confirmation_time(monkeypatch, {"value": fixed})
    device, coordinator, entities, listeners = _make_entities(hass)
    await _add_entities_to_real_ha_state_machine(hass, entities)
    _begin_authenticated_session(device)
    _report_batch(
        device,
        [
            (33, TuyaBLEDataPointType.DT_BOOL, True),
            (34, TuyaBLEDataPointType.DT_ENUM, 1),
            (36, TuyaBLEDataPointType.DT_VALUE, 45),
            (8, TuyaBLEDataPointType.DT_VALUE, 73),
        ],
    )
    await hass.async_block_till_done()

    scoped = [
        _state_timestamp(
            hass.states.get(entities[key].entity_id).attributes["last_confirmed_at"]
        )
        for key in ("auto_lock", "authentication", "auto_lock_delay", "battery")
    ]
    status = hass.states.get(entities["last_status"].entity_id)
    assert status is not None
    public_timestamp = datetime.fromisoformat(status.state)
    expected = fixed.replace(microsecond=0)

    assert max(scoped) - public_timestamp == timedelta(0), (
        "S1 scoped confirmation attributes and Home Assistant's public timestamp "
        "sensor state must compare exactly"
    )
    assert scoped == [expected] * 4
    assert entities["last_status"].native_value == expected
    assert public_timestamp == expected
    _cleanup(coordinator, listeners)


async def test_s1_confirmation_batch_uses_one_normalized_utc_second(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One accepted callback batch gives all valid scoped reports one timestamp."""
    fixed = datetime(2026, 8, 28, 12, 34, 56, 543896, tzinfo=timezone.utc)
    _freeze_confirmation_time(monkeypatch, {"value": fixed})
    device, coordinator, _entities, listeners = _make_entities(hass)
    _begin_authenticated_session(device)

    _report_batch(
        device,
        [
            (33, TuyaBLEDataPointType.DT_BOOL, True),
            (34, TuyaBLEDataPointType.DT_ENUM, 1),
            (36, TuyaBLEDataPointType.DT_VALUE, 45),
            (8, TuyaBLEDataPointType.DT_VALUE, 73),
        ],
    )

    expected = fixed.replace(microsecond=0)
    assert {
        device.last_confirmed_s1_state.get(dp_id).confirmed_at
        for dp_id in (8, 33, 34, 36)
    } == {expected}
    assert device.last_confirmed_s1_state.latest_confirmed_at == expected
    _cleanup(coordinator, listeners)


async def test_s1_restore_normalizes_legacy_precision_and_rejects_bad_timestamps(
    hass: HomeAssistant,
) -> None:
    """Restoration accepts aware legacy values, but retains only UTC seconds."""
    device, coordinator, entities, listeners = _make_entities(hass)
    legacy = "2026-08-28T14:34:56.543896+02:00"
    expected = datetime(2026, 8, 28, 12, 34, 56, tzinfo=timezone.utc)
    for key, state in (
        ("auto_lock", "on"),
        ("authentication", "finger_card"),
        ("auto_lock_delay", "45.0"),
        ("battery", "73.0"),
    ):
        await _restore_entity(hass, entities[key], state, {"last_confirmed_at": legacy})
    await _restore_entity(hass, entities["last_status"], legacy, {})

    assert {
        device.last_confirmed_s1_state.get(dp_id).confirmed_at
        for dp_id in (8, 33, 34, 36)
    } == {expected}
    assert entities["last_status"].native_value == expected
    naive = datetime(2026, 8, 28, 12, 34, 56)  # noqa: DTZ001 - deliberate input
    assert device.last_confirmed_s1_state.restore(33, True, naive) is False
    assert _parse_restored_timestamp("invalid") is None
    assert _parse_restored_timestamp(naive) is None
    _cleanup(coordinator, listeners)


async def test_s1_same_second_value_changes_publish_without_moving_time_backward(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Value changes within a second publish, while a backward clock stays monotonic."""
    first = datetime(2026, 8, 28, 12, 34, 56, 543896, tzinfo=timezone.utc)
    clock = {"value": first}
    _freeze_confirmation_time(monkeypatch, clock)
    device, coordinator, entities, listeners = _make_entities(hass)
    _begin_authenticated_session(device)
    _report(device, 8, TuyaBLEDataPointType.DT_VALUE, 73)
    confirmed = device.last_confirmed_s1_state.get(8)
    assert confirmed is not None
    expected = first.replace(microsecond=0)
    assert confirmed.confirmed_at == expected

    entities["battery"].async_write_ha_state.reset_mock()
    entities["last_status"].async_write_ha_state.reset_mock()
    clock["value"] = first.replace(microsecond=999999)
    _report(device, 8, TuyaBLEDataPointType.DT_VALUE, 74)
    updated = device.last_confirmed_s1_state.get(8)
    assert updated is not None
    assert updated.value == 74
    assert updated.data_fresh is True
    assert updated.value_source == "current_session"
    assert updated.confirmed_at == expected
    entities["battery"].async_write_ha_state.assert_called()
    entities["last_status"].async_write_ha_state.assert_called()

    clock["value"] = first - timedelta(seconds=1)
    _report(device, 8, TuyaBLEDataPointType.DT_VALUE, 75)
    monotonic = device.last_confirmed_s1_state.get(8)
    assert monotonic is not None
    assert monotonic.value == 75
    assert monotonic.confirmed_at == expected
    _cleanup(coordinator, listeners)


async def test_s1_backward_clock_keeps_one_timestamp_for_a_mixed_batch(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A prior DP clamps the one canonical timestamp for every valid batch DP."""
    first = datetime(2026, 8, 28, 12, 34, 56, 543896, tzinfo=timezone.utc)
    clock = {"value": first}
    _freeze_confirmation_time(monkeypatch, clock)
    device, coordinator, _entities, listeners = _make_entities(hass)
    _begin_authenticated_session(device)
    _report(device, 8, TuyaBLEDataPointType.DT_VALUE, 73)

    clock["value"] = first - timedelta(seconds=1)
    _report_batch(
        device,
        [
            (8, TuyaBLEDataPointType.DT_VALUE, 74),
            (33, TuyaBLEDataPointType.DT_BOOL, True),
        ],
    )

    expected = first.replace(microsecond=0)
    assert {
        device.last_confirmed_s1_state.get(dp_id).confirmed_at for dp_id in (8, 33)
    } == {expected}
    assert device.last_confirmed_s1_state.get(8).value == 74
    assert device.last_confirmed_s1_state.get(33).value is True
    _cleanup(coordinator, listeners)


async def test_s1_timestamp_normalization_never_uses_ble_transport(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Timestamp presentation is local and never creates a transport side effect."""
    fixed = datetime(2026, 8, 28, 12, 34, 56, 543896, tzinfo=timezone.utc)
    _freeze_confirmation_time(monkeypatch, {"value": fixed})
    device, coordinator, _entities, listeners = _make_entities(hass)
    device._ensure_connected = AsyncMock()
    device._send_datapoints = AsyncMock()
    device._send_datapoints_once = AsyncMock()
    device._send_datapoints_no_replay = AsyncMock()
    _begin_authenticated_session(device)

    _report(device, 8, TuyaBLEDataPointType.DT_VALUE, 73)

    device._ensure_connected.assert_not_awaited()
    device._send_datapoints.assert_not_awaited()
    device._send_datapoints_once.assert_not_awaited()
    device._send_datapoints_no_replay.assert_not_awaited()
    _cleanup(coordinator, listeners)
