"""Contract tests for the S1 On-Demand connection hold time."""

from __future__ import annotations

import asyncio
import math
from unittest.mock import AsyncMock, Mock, patch

import pytest
from bleak.backends.device import BLEDevice
from homeassistant.components import number as number_platform
from homeassistant.components import select as select_platform
from homeassistant.components import switch as switch_platform
from homeassistant.components.number.const import ATTR_VALUE
from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import ATTR_ENTITY_ID, Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers import entity_registry as er

from custom_components import tuya_ble as integration
from custom_components.tuya_ble.config_flow import TuyaBLEOptionsFlow
from custom_components.tuya_ble.const import (
    CONF_BLE_CONTROL_ENABLED,
    CONF_CONNECTION_MODE,
    CONF_ON_DEMAND_CONNECTION_HOLD_TIME,
    DEFAULT_ON_DEMAND_CONNECTION_HOLD_TIME,
    DOMAIN,
    MAX_ON_DEMAND_CONNECTION_HOLD_TIME,
    MIN_ON_DEMAND_CONNECTION_HOLD_TIME,
    ConnectionMode,
    PendingReleaseReason,
    normalize_on_demand_connection_hold_time,
)
from custom_components.tuya_ble.devices import (
    TuyaBLECoordinator,
    TuyaBLEData,
    TuyaBLEProductInfo,
)
from custom_components.tuya_ble.number import (
    TuyaBLEOnDemandConnectionHoldTimeNumber,
)
from custom_components.tuya_ble.number import (
    async_setup_entry as async_setup_numbers,
)
from custom_components.tuya_ble.select import (
    TuyaBLEConnectionModeSelect,
    async_setup_entry as async_setup_selects,
)
from custom_components.tuya_ble.switch import (
    TuyaBLEControlSwitch,
    async_setup_entry as async_setup_switches,
)
from custom_components.tuya_ble.tuya_ble.const import TuyaBLECode
from custom_components.tuya_ble.tuya_ble.exceptions import TuyaBLEPolicyTransitionError
from custom_components.tuya_ble.tuya_ble.manager import TuyaBLEDeviceCredentials
from custom_components.tuya_ble.tuya_ble.security import TuyaBLESecurityMaterial
from custom_components.tuya_ble.tuya_ble.tuya_ble import (
    ConnectionSessionToken,
    TuyaBLEDevice,
)

SYNTHETIC_ADDRESS = "00:00:00:00:00:29"
SYNTHETIC_DEVICE_ID = "synthetic-hold-time-device"
S1_PRODUCT = ("jtmspro", "xqeob8h6")
V1_PRODUCT = ("ms", "7a4xvbtt")
GENERIC_PRODUCT = ("jtmspro", "synthetic-other-product")


class _SyntheticClient:
    """Minimal visibly synthetic connected client."""

    def __init__(self, disconnect_error: Exception | None = None) -> None:
        self.is_connected = True
        self.stop_notify = AsyncMock()
        self.start_notify = AsyncMock()
        self.write_gatt_char = AsyncMock()

        async def disconnect() -> None:
            if disconnect_error is not None:
                raise disconnect_error
            self.is_connected = False

        self.disconnect = AsyncMock(side_effect=disconnect)


def _make_device(
    *,
    product: tuple[str, str] = S1_PRODUCT,
    mode: ConnectionMode = ConnectionMode.ON_DEMAND,
    enabled: bool = True,
    hold_time: object = DEFAULT_ON_DEMAND_CONNECTION_HOLD_TIME,
    persist_options=None,
) -> TuyaBLEDevice:
    device = TuyaBLEDevice(
        Mock(),
        BLEDevice(
            name="Synthetic hold-time device",
            address=SYNTHETIC_ADDRESS,
            details={},
        ),
        connection_mode=mode.value,
        ble_control_enabled=enabled,
        on_demand_connection_hold_time=hold_time,
        persist_options=persist_options,
    )
    device._device_info = TuyaBLEDeviceCredentials(
        uuid="synthetic-hold-time-uuid",
        local_key="synthetic-hold-time-key",
        device_id=SYNTHETIC_DEVICE_ID,
        category=product[0],
        product_id=product[1],
        device_name="Synthetic hold-time device",
        product_model="SYNTHETIC-HOLD",
        product_name="Synthetic hold-time device",
        functions=[],
        status_range=[],
    )
    return device


def _make_data(hass: HomeAssistant, device: TuyaBLEDevice) -> TuyaBLEData:
    return TuyaBLEData(
        title="Synthetic hold-time device",
        device=device,
        product=TuyaBLEProductInfo("Synthetic hold-time device"),
        manager=Mock(),
        coordinator=TuyaBLECoordinator(hass, device),
    )


async def _setup_hold_time_number_platform(
    hass: HomeAssistant,
    *,
    enabled: bool = True,
    hold_time: int = DEFAULT_ON_DEMAND_CONNECTION_HOLD_TIME,
    product: tuple[str, str] = S1_PRODUCT,
) -> tuple[object, TuyaBLEDevice, TuyaBLEOnDemandConnectionHoldTimeNumber | None]:
    """Set up the real HA number platform around one synthetic S1 device."""
    from pytest_homeassistant_custom_component.common import MockConfigEntry

    entry = MockConfigEntry(
        domain=DOMAIN,
        data={"address": SYNTHETIC_ADDRESS},
        options={
            CONF_CONNECTION_MODE: ConnectionMode.ON_DEMAND.value,
            CONF_BLE_CONTROL_ENABLED: enabled,
            CONF_ON_DEMAND_CONNECTION_HOLD_TIME: hold_time,
        },
    )
    entry.add_to_hass(hass)
    device = _make_device(enabled=enabled, hold_time=hold_time, product=product)

    async def persist_options(updates: dict[str, object]) -> None:
        options = dict(entry.options)
        options.update(updates)
        hass.config_entries.async_update_entry(entry, options=options)

    device._persist_options = persist_options
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = _make_data(hass, device)
    await number_platform.async_setup(hass, {})
    component = hass.data[number_platform.DATA_COMPONENT]

    def add_entities(entities: list[object]) -> None:
        hass.async_create_task(component.async_add_entities(entities))

    await async_setup_numbers(hass, entry, add_entities)
    await hass.async_block_till_done()
    entity = next(
        (
            entity
            for entity in component.entities
            if isinstance(entity, TuyaBLEOnDemandConnectionHoldTimeNumber)
        ),
        None,
    )
    return entry, device, entity


def _install_ready_session(
    device: TuyaBLEDevice,
    client: _SyntheticClient | None = None,
) -> tuple[ConnectionSessionToken, _SyntheticClient]:
    client = client or _SyntheticClient()
    token = device._claim_connection_session(client)
    device._is_paired = True
    device._physical_connection_active = True
    device._notifications_active = True
    device._connected_notified_token = token
    return token, client


def _schema_keys(result: dict) -> set[str]:
    return {str(marker.schema) for marker in result["data_schema"].schema}


def _live_policy_entities(
    hass: HomeAssistant,
    entry_id: str,
    platform: Platform,
    entity_type: type[object],
) -> list[object]:
    """Return live entities from one real forwarded entity platform."""
    component = hass.data.get(platform.value)
    entity_platform = getattr(component, "_platforms", {}).get(entry_id)
    if entity_platform is None:
        return []
    return [
        entity
        for entity in entity_platform.entities.values()
        if isinstance(entity, entity_type)
    ]


@pytest.mark.parametrize("value", (15, 100, 105))
def test_hold_time_accepts_documented_integer_values(value: int) -> None:
    assert normalize_on_demand_connection_hold_time(value) == value


@pytest.mark.parametrize(
    "value",
    (
        None,
        True,
        14,
        106,
        15.5,
        float("nan"),
        float("inf"),
        "15",
        object(),
    ),
)
def test_invalid_persisted_hold_time_falls_back_without_crashing(value: object) -> None:
    assert (
        normalize_on_demand_connection_hold_time(value)
        == DEFAULT_ON_DEMAND_CONNECTION_HOLD_TIME
    )


def test_hold_time_constants_lock_the_user_contract() -> None:
    assert MIN_ON_DEMAND_CONNECTION_HOLD_TIME == 15
    assert MAX_ON_DEMAND_CONNECTION_HOLD_TIME == 105
    assert DEFAULT_ON_DEMAND_CONNECTION_HOLD_TIME == 15


@pytest.mark.parametrize("hold_time", (15, 100, 105))
def test_device_restores_explicit_hold_time_without_persisting(hold_time: int) -> None:
    persist = AsyncMock()
    device = _make_device(hold_time=hold_time, persist_options=persist)

    assert device.on_demand_connection_hold_time == hold_time
    persist.assert_not_awaited()


def test_missing_and_invalid_device_options_use_default() -> None:
    assert _make_device(hold_time=None).on_demand_connection_hold_time == 15
    assert _make_device(hold_time=14).on_demand_connection_hold_time == 15
    assert _make_device(hold_time=106).on_demand_connection_hold_time == 15
    assert _make_device(hold_time=15.5).on_demand_connection_hold_time == 15


async def test_number_entity_exists_for_exact_s1_only(
    hass: HomeAssistant,
) -> None:
    from pytest_homeassistant_custom_component.common import MockConfigEntry

    for product, expected in ((S1_PRODUCT, 1), (V1_PRODUCT, 0), (GENERIC_PRODUCT, 0)):
        entry = MockConfigEntry(domain=DOMAIN, data={"address": SYNTHETIC_ADDRESS})
        device = _make_device(product=product)
        hass.data.setdefault(DOMAIN, {})[entry.entry_id] = _make_data(hass, device)
        added: list[object] = []

        await async_setup_numbers(hass, entry, added.extend)

        assert (
            sum(
                isinstance(entity, TuyaBLEOnDemandConnectionHoldTimeNumber)
                for entity in added
            )
            == expected
        )
        hass.data[DOMAIN].pop(entry.entry_id)


async def test_number_entity_is_local_available_and_has_stable_identity(
    hass: HomeAssistant,
) -> None:
    device = _make_device(enabled=False)
    first = TuyaBLEOnDemandConnectionHoldTimeNumber(
        hass,
        TuyaBLECoordinator(hass, device),
        device,
        TuyaBLEProductInfo("Synthetic hold-time device"),
    )
    second = TuyaBLEOnDemandConnectionHoldTimeNumber(
        hass,
        TuyaBLECoordinator(hass, device),
        device,
        TuyaBLEProductInfo("Synthetic hold-time device"),
    )

    assert first.available is True
    assert first.native_value == 15
    assert first.unique_id == second.unique_id
    assert first.unique_id.endswith("-on_demand_connection_hold_time")
    assert first.entity_description.entity_category is EntityCategory.CONFIG
    assert first.entity_description.native_min_value == 15
    assert first.entity_description.native_max_value == 105
    assert first.entity_description.native_step == 1
    assert first.entity_description.native_unit_of_measurement == "s"


@pytest.mark.parametrize("enabled", (True, False), ids=("ble-on", "ble-off"))
async def test_number_service_publishes_persisted_hold_time_without_ble(
    hass: HomeAssistant,
    enabled: bool,
) -> None:
    """The real HA service publishes a local S1 policy update immediately."""
    entry, device, entity = await _setup_hold_time_number_platform(
        hass, enabled=enabled
    )
    assert entity is not None
    device._ensure_connected = AsyncMock()
    device._send_datapoints = AsyncMock()

    assert entity.should_poll is False
    assert float(hass.states.get(entity.entity_id).state) == 15
    component = hass.data[number_platform.DATA_COMPONENT]
    assert (
        sum(
            isinstance(candidate, TuyaBLEOnDemandConnectionHoldTimeNumber)
            for candidate in component.entities
        )
        == 1
    )

    await hass.services.async_call(
        "number",
        "set_value",
        {ATTR_ENTITY_ID: entity.entity_id, ATTR_VALUE: 16},
        blocking=True,
    )
    await hass.async_block_till_done()

    assert entry.options[CONF_ON_DEMAND_CONNECTION_HOLD_TIME] == 16
    assert device.on_demand_connection_hold_time == 16
    assert float(hass.states.get(entity.entity_id).state) == 16
    assert device._idle_disconnect_task is None
    device._ensure_connected.assert_not_awaited()
    device._send_datapoints.assert_not_awaited()


async def test_number_service_repeated_values_keep_persisted_and_published_state_equal(
    hass: HomeAssistant,
) -> None:
    """Every local service update keeps the UI and ConfigEntry in agreement."""
    entry, device, entity = await _setup_hold_time_number_platform(hass)
    assert entity is not None
    device._ensure_connected = AsyncMock()
    device._send_datapoints = AsyncMock()

    for value in (100, 105, 15):
        await hass.services.async_call(
            "number",
            "set_value",
            {ATTR_ENTITY_ID: entity.entity_id, ATTR_VALUE: value},
            blocking=True,
        )
        await hass.async_block_till_done()

        assert entry.options[CONF_ON_DEMAND_CONNECTION_HOLD_TIME] == value
        assert device.on_demand_connection_hold_time == value
        assert float(hass.states.get(entity.entity_id).state) == value

    assert device._idle_disconnect_task is None
    device._ensure_connected.assert_not_awaited()
    device._send_datapoints.assert_not_awaited()


async def test_number_service_persistence_failure_keeps_existing_published_state(
    hass: HomeAssistant,
) -> None:
    """A failed policy write cannot publish an unpersisted hold time."""
    entry, device, entity = await _setup_hold_time_number_platform(hass)
    assert entity is not None
    device._persist_options = AsyncMock(side_effect=RuntimeError("synthetic failure"))
    device._ensure_connected = AsyncMock()
    device._send_datapoints = AsyncMock()

    with pytest.raises(TuyaBLEPolicyTransitionError):
        await hass.services.async_call(
            "number",
            "set_value",
            {ATTR_ENTITY_ID: entity.entity_id, ATTR_VALUE: 16},
            blocking=True,
        )
    await hass.async_block_till_done()

    assert entry.options[CONF_ON_DEMAND_CONNECTION_HOLD_TIME] == 15
    assert device.on_demand_connection_hold_time == 15
    assert float(hass.states.get(entity.entity_id).state) == 15
    assert device._idle_disconnect_task is None
    device._ensure_connected.assert_not_awaited()
    device._send_datapoints.assert_not_awaited()


async def test_number_platform_reconstruction_publishes_persisted_hold_time(
    hass: HomeAssistant,
) -> None:
    """A reconstructed platform publishes the ConfigEntry's local value."""
    entry, device, entity = await _setup_hold_time_number_platform(hass, hold_time=100)
    assert entity is not None

    assert entry.options[CONF_ON_DEMAND_CONNECTION_HOLD_TIME] == 100
    assert device.on_demand_connection_hold_time == 100
    assert float(hass.states.get(entity.entity_id).state) == 100
    assert device._idle_disconnect_task is None


async def test_number_platform_does_not_register_hold_time_for_non_s1_products(
    hass: HomeAssistant,
) -> None:
    """Only S1 receives the local hold-time NumberEntity."""
    for product in (V1_PRODUCT, GENERIC_PRODUCT):
        entry, _, _ = await _setup_hold_time_number_platform(hass, product=product)
        component = hass.data[number_platform.DATA_COMPONENT]
        assert not any(
            isinstance(entity, TuyaBLEOnDemandConnectionHoldTimeNumber)
            for entity in component.entities
        )
        hass.data[DOMAIN].pop(entry.entry_id)


async def test_options_update_listener_publishes_reloaded_s1_hold_time(
    hass: HomeAssistant,
) -> None:
    """The production listener keeps the reloaded NumberEntity state current."""
    from pytest_homeassistant_custom_component.common import MockConfigEntry

    entry = MockConfigEntry(
        domain=DOMAIN,
        title="Synthetic listener S1",
        data={"address": SYNTHETIC_ADDRESS},
        options={
            CONF_CONNECTION_MODE: ConnectionMode.ON_DEMAND.value,
            CONF_BLE_CONTROL_ENABLED: True,
            CONF_ON_DEMAND_CONNECTION_HOLD_TIME: 15,
        },
    )
    entry.add_to_hass(hass)
    manager = Mock()
    manager.get_device_credentials = AsyncMock(
        return_value=TuyaBLEDeviceCredentials(
            uuid="synthetic-listener-uuid",
            local_key="synthetic-listener-key",
            device_id="synthetic-listener-device",
            category=S1_PRODUCT[0],
            product_id=S1_PRODUCT[1],
            device_name="Synthetic listener S1",
            product_model="SYNTHETIC-LISTENER",
            product_name="Synthetic listener S1",
            functions=[],
            status_range=[],
        )
    )
    await number_platform.async_setup(hass, {})
    await select_platform.async_setup(hass, {})
    await switch_platform.async_setup(hass, {})
    components = {
        Platform.NUMBER: hass.data[number_platform.DATA_COMPONENT],
        Platform.SELECT: hass.data[select_platform.DATA_COMPONENT],
        Platform.SWITCH: hass.data[switch_platform.DATA_COMPONENT],
    }

    def add_entities(platform: Platform, entities: list[object]) -> None:
        hass.async_create_task(components[platform].async_add_entities(entities))

    async def forward_entry_setups(
        config_entry: object, platforms: list[Platform]
    ) -> None:
        assert config_entry is entry
        assert platforms == [Platform.NUMBER, Platform.SELECT, Platform.SWITCH]
        await async_setup_numbers(
            hass,
            entry,
            lambda entities: add_entities(Platform.NUMBER, entities),
        )
        await async_setup_selects(
            hass,
            entry,
            lambda entities: add_entities(Platform.SELECT, entities),
        )
        await async_setup_switches(
            hass,
            entry,
            lambda entities: add_entities(Platform.SWITCH, entities),
        )

    async def forward_entry_unload(config_entry: object, platform: Platform) -> bool:
        """Remove the real entities created by this synthetic entry."""
        assert config_entry is entry
        component = components[platform]
        for entity in tuple(component.entities):
            await component.async_remove_entity(entity.entity_id)
        return True

    entry.supports_unload = True
    entry.supports_remove_device = False
    entry_integration = Mock(domain=DOMAIN)
    entry_integration.async_get_component = AsyncMock(return_value=integration)
    entry_integration.async_get_platform = AsyncMock()

    async def reload_entry(entry_id: str) -> None:
        """Exercise the integration's supported ConfigEntry reconstruction."""
        assert entry_id == entry.entry_id
        await entry.setup_lock.acquire()
        try:
            assert await entry.async_unload(hass, integration=entry_integration) is True
            await entry.async_setup(hass, integration=entry_integration)
        finally:
            entry.setup_lock.release()

    with (
        patch.object(
            integration,
            "PLATFORMS",
            [Platform.NUMBER, Platform.SELECT, Platform.SWITCH],
        ),
        patch.object(integration, "HASSTuyaBLEDeviceManager", return_value=manager),
        patch.object(
            integration.bluetooth, "async_ble_device_from_address", return_value=None
        ),
        patch.object(
            integration.bluetooth, "async_register_callback", return_value=Mock()
        ),
        patch.object(
            hass.config_entries,
            "async_forward_entry_setups",
            new=forward_entry_setups,
        ),
        patch.object(
            hass.config_entries,
            "async_forward_entry_unload",
            new=forward_entry_unload,
        ),
        patch.object(
            hass.config_entries,
            "async_reload",
            new=AsyncMock(side_effect=reload_entry),
        ) as reload,
    ):
        assert await integration.async_setup_entry(hass, entry) is True
        await hass.async_block_till_done()
        number_entity = next(
            entity
            for entity in components[Platform.NUMBER].entities
            if isinstance(entity, TuyaBLEOnDemandConnectionHoldTimeNumber)
        )
        select_entity = next(
            entity
            for entity in components[Platform.SELECT].entities
            if entity.entity_description.key == CONF_CONNECTION_MODE
        )
        switch_entity = next(
            entity
            for entity in components[Platform.SWITCH].entities
            if entity.entity_description.key == CONF_BLE_CONTROL_ENABLED
        )
        device = hass.data[DOMAIN][entry.entry_id].device
        device._ensure_connected = AsyncMock()
        device._send_datapoints = AsyncMock()

        hass.config_entries.async_update_entry(
            entry,
            options={
                **entry.options,
                CONF_CONNECTION_MODE: ConnectionMode.ALWAYS_CONNECTED.value,
                CONF_BLE_CONTROL_ENABLED: False,
                CONF_ON_DEMAND_CONNECTION_HOLD_TIME: 100,
            },
        )
        await hass.async_block_till_done()

        assert entry.title == "Synthetic listener S1"
        assert entry.options[CONF_ON_DEMAND_CONNECTION_HOLD_TIME] == 100
        assert (
            entry.options[CONF_CONNECTION_MODE] == ConnectionMode.ALWAYS_CONNECTED.value
        )
        assert entry.options[CONF_BLE_CONTROL_ENABLED] is False
        assert device.on_demand_connection_hold_time == 100
        assert device.connection_mode is ConnectionMode.ALWAYS_CONNECTED
        assert device.ble_control_enabled is False
        assert hass.states.get(select_entity.entity_id).state == "always_connected"
        assert hass.states.get(switch_entity.entity_id).state == "off"
        assert float(hass.states.get(number_entity.entity_id).state) == 100
        reload.assert_not_awaited()

        for hold_time in (105, 15):
            hass.config_entries.async_update_entry(
                entry,
                options={
                    **entry.options,
                    CONF_ON_DEMAND_CONNECTION_HOLD_TIME: hold_time,
                },
            )
            await hass.async_block_till_done()
            assert entry.options[CONF_ON_DEMAND_CONNECTION_HOLD_TIME] == hold_time
            assert device.on_demand_connection_hold_time == hold_time
            assert float(hass.states.get(number_entity.entity_id).state) == hold_time
            assert (
                sum(
                    isinstance(entity, TuyaBLEOnDemandConnectionHoldTimeNumber)
                    for entity in components[Platform.NUMBER].entities
                )
                == 1
            )
        reload.assert_not_awaited()
        device._ensure_connected.assert_not_awaited()
        device._send_datapoints.assert_not_awaited()

        flow = TuyaBLEOptionsFlow(entry)
        flow.hass = hass
        result = await flow.async_step_connection_settings(
            {
                CONF_CONNECTION_MODE: ConnectionMode.ON_DEMAND.value,
                CONF_BLE_CONTROL_ENABLED: True,
                CONF_ON_DEMAND_CONNECTION_HOLD_TIME: 105,
            }
        )
        assert result["type"] == "create_entry"
        hass.config_entries.async_update_entry(entry, options=result["data"])
        await hass.async_block_till_done()

        assert device.connection_mode is ConnectionMode.ON_DEMAND
        assert device.ble_control_enabled is True
        assert device.on_demand_connection_hold_time == 105
        assert hass.states.get(select_entity.entity_id).state == "on_demand"
        assert hass.states.get(switch_entity.entity_id).state == "on"
        assert float(hass.states.get(number_entity.entity_id).state) == 105
        reload.assert_not_awaited()
        device._ensure_connected.assert_not_awaited()
        device._send_datapoints.assert_not_awaited()

        # The normal production setup lifecycle marks an entry loaded before a
        # title change invokes Home Assistant's reload path.
        entry._async_set_state(hass, ConfigEntryState.LOADED, None)
        hass.config_entries.async_update_entry(
            entry,
            title="Synthetic listener S1 renamed",
            options={
                **entry.options,
                CONF_ON_DEMAND_CONNECTION_HOLD_TIME: 100,
            },
        )
        await hass.async_block_till_done()

        assert entry.state is ConfigEntryState.LOADED
        reload.assert_awaited_once_with(entry.entry_id)
        device = hass.data[DOMAIN][entry.entry_id].device
        number_entity = next(
            candidate
            for candidate in components[Platform.NUMBER].entities
            if isinstance(candidate, TuyaBLEOnDemandConnectionHoldTimeNumber)
        )
        assert device.on_demand_connection_hold_time == 100
        assert float(hass.states.get(number_entity.entity_id).state) == 100
        assert (
            sum(
                isinstance(candidate, TuyaBLEOnDemandConnectionHoldTimeNumber)
                for candidate in components[Platform.NUMBER].entities
            )
            == 1
        )
        assert len(entry.update_listeners) == 1
        device._ensure_connected = AsyncMock()
        device._send_datapoints = AsyncMock()
        device._ensure_connected.assert_not_awaited()
        device._send_datapoints.assert_not_awaited()

        # Exercise a separate explicit unload and reconstruction after an
        # ordinary listener update. The forwarding stubs only replace Home
        # Assistant platform loading; entity setup and removal remain real.
        hass.config_entries.async_update_entry(
            entry,
            options={
                **entry.options,
                CONF_ON_DEMAND_CONNECTION_HOLD_TIME: 105,
            },
        )
        await hass.async_block_till_done()
        assert device.on_demand_connection_hold_time == 105
        assert float(hass.states.get(number_entity.entity_id).state) == 105
        reload.assert_awaited_once_with(entry.entry_id)

        old_number_entity = number_entity
        old_number_entity.async_write_ha_state = Mock()
        old_coordinator = hass.data[DOMAIN][entry.entry_id].coordinator

        await entry.setup_lock.acquire()
        try:
            assert await entry.async_unload(hass, integration=entry_integration) is True
        finally:
            entry.setup_lock.release()
        await hass.async_block_till_done()

        assert entry.state is ConfigEntryState.NOT_LOADED
        assert entry.entry_id not in hass.data[DOMAIN]
        assert not entry.update_listeners
        assert not any(
            isinstance(candidate, TuyaBLEOnDemandConnectionHoldTimeNumber)
            for candidate in components[Platform.NUMBER].entities
        )
        assert hass.states.get(old_number_entity.entity_id).state == "unavailable"

        # A ConfigEntry update after unload cannot notify the discarded entity.
        old_number_entity.async_write_ha_state.reset_mock()
        hass.config_entries.async_update_entry(
            entry,
            options={
                **entry.options,
                CONF_ON_DEMAND_CONNECTION_HOLD_TIME: 105,
            },
        )
        await hass.async_block_till_done()
        old_number_entity.async_write_ha_state.assert_not_called()
        assert old_coordinator._unsub_device_callbacks == []

        await entry.setup_lock.acquire()
        try:
            await entry.async_setup(hass, integration=entry_integration)
        finally:
            entry.setup_lock.release()
        await hass.async_block_till_done()

        assert entry.state is ConfigEntryState.LOADED
        reconstructed_device = hass.data[DOMAIN][entry.entry_id].device
        reconstructed_number_entity = next(
            candidate
            for candidate in components[Platform.NUMBER].entities
            if isinstance(candidate, TuyaBLEOnDemandConnectionHoldTimeNumber)
        )
        assert reconstructed_number_entity is not old_number_entity
        assert reconstructed_device.on_demand_connection_hold_time == 105
        assert (
            float(hass.states.get(reconstructed_number_entity.entity_id).state) == 105
        )
        assert (
            sum(
                isinstance(candidate, TuyaBLEOnDemandConnectionHoldTimeNumber)
                for candidate in components[Platform.NUMBER].entities
            )
            == 1
        )
        assert len(entry.update_listeners) == 1
        reload.assert_awaited_once_with(entry.entry_id)

        # Application failure must not publish a requested value, notify policy
        # entities, or take the title-triggered reload path.
        reconstructed_device._ensure_connected = AsyncMock()
        reconstructed_device._send_datapoints = AsyncMock()
        listener_tasks: list[asyncio.Task[object]] = []
        create_task_internal = hass.async_create_task_internal

        def track_listener_task(
            coro: object,
            name: str | None = None,
            eager_start: bool = False,
        ) -> asyncio.Task[object]:
            task = create_task_internal(coro, name=name, eager_start=eager_start)
            listener_tasks.append(task)
            return task

        with (
            patch.object(
                reconstructed_device,
                "async_apply_persisted_options",
                new=AsyncMock(side_effect=RuntimeError("synthetic apply failure")),
            ),
            patch.object(
                hass.data[DOMAIN][entry.entry_id].coordinator,
                "async_update_listeners",
            ) as notify_policy_entities,
            patch.object(
                hass,
                "async_create_task_internal",
                new=track_listener_task,
            ),
        ):
            hass.config_entries.async_update_entry(
                entry,
                title="Synthetic listener S1 failed policy",
                options={
                    **entry.options,
                    CONF_ON_DEMAND_CONNECTION_HOLD_TIME: 100,
                },
            )
            assert len(listener_tasks) == 1
            with pytest.raises(RuntimeError, match="synthetic apply failure"):
                await listener_tasks[0]
        await hass.async_block_till_done()

        assert entry.options[CONF_ON_DEMAND_CONNECTION_HOLD_TIME] == 100
        assert reconstructed_device.on_demand_connection_hold_time == 105
        assert (
            float(hass.states.get(reconstructed_number_entity.entity_id).state) == 105
        )
        notify_policy_entities.assert_not_called()
        reload.assert_awaited_once_with(entry.entry_id)
        reconstructed_device._ensure_connected.assert_not_awaited()
        reconstructed_device._send_datapoints.assert_not_awaited()


async def test_real_config_entry_policy_entities_reconstruct_without_duplicates(
    hass: HomeAssistant,
    enable_custom_integrations: None,
) -> None:
    """Exercise three real S1 policy entities through HA unload/setup cycles."""
    from pytest_homeassistant_custom_component.common import MockConfigEntry

    entry = MockConfigEntry(
        domain=DOMAIN,
        title="Synthetic lifecycle S1",
        data={"address": SYNTHETIC_ADDRESS},
        options={
            CONF_CONNECTION_MODE: ConnectionMode.ON_DEMAND.value,
            CONF_BLE_CONTROL_ENABLED: True,
            CONF_ON_DEMAND_CONNECTION_HOLD_TIME: 15,
        },
    )
    entry.add_to_hass(hass)
    entry.supports_unload = True
    entry.supports_remove_device = False
    object.__setattr__(
        entry,
        "_integration_for_domain",
        Mock(
            domain=DOMAIN,
            async_get_component=AsyncMock(return_value=integration),
            async_get_platform=AsyncMock(),
        ),
    )
    hass.config.components.add(DOMAIN)
    manager = Mock()
    manager.get_device_credentials = AsyncMock(
        return_value=TuyaBLEDeviceCredentials(
            uuid="synthetic-lifecycle-uuid",
            local_key="synthetic-lifecycle-key",
            device_id="synthetic-lifecycle-device",
            category=S1_PRODUCT[0],
            product_id=S1_PRODUCT[1],
            device_name="Synthetic lifecycle S1",
            product_model="SYNTHETIC-LIFECYCLE",
            product_name="Synthetic lifecycle S1",
            functions=[],
            status_range=[],
        )
    )
    registry = er.async_get(hass)
    entity_types = (
        (Platform.NUMBER, TuyaBLEOnDemandConnectionHoldTimeNumber),
        (Platform.SELECT, TuyaBLEConnectionModeSelect),
        (Platform.SWITCH, TuyaBLEControlSwitch),
    )

    def assert_loaded(hold_time: int) -> tuple[
        TuyaBLEOnDemandConnectionHoldTimeNumber,
        TuyaBLEConnectionModeSelect,
        TuyaBLEControlSwitch,
    ]:
        assert entry.state is ConfigEntryState.LOADED
        data = hass.data[DOMAIN][entry.entry_id]
        assert data.device.on_demand_connection_hold_time == hold_time
        live_entities = [
            _live_policy_entities(hass, entry.entry_id, platform, entity_type)
            for platform, entity_type in entity_types
        ]
        assert [len(entities) for entities in live_entities] == [1, 1, 1]
        number_entity, select_entity, switch_entity = (
            entities[0] for entities in live_entities
        )
        assert float(hass.states.get(number_entity.entity_id).state) == hold_time
        assert hass.states.get(select_entity.entity_id).state == "on_demand"
        assert hass.states.get(switch_entity.entity_id).state == "on"
        policy_rows = [
            row
            for row in er.async_entries_for_config_entry(registry, entry.entry_id)
            if row.platform == DOMAIN
            and row.unique_id
            in {
                number_entity.unique_id,
                select_entity.unique_id,
                switch_entity.unique_id,
            }
        ]
        assert len(policy_rows) == 3
        assert len({row.unique_id for row in policy_rows}) == 3
        assert len(entry.update_listeners) == 1
        assert len(data.coordinator._unsub_device_callbacks) == 4
        return number_entity, select_entity, switch_entity

    with (
        patch.object(integration, "HASSTuyaBLEDeviceManager", return_value=manager),
        patch.object(
            integration.bluetooth, "async_ble_device_from_address", return_value=None
        ),
        patch.object(
            integration.bluetooth, "async_register_callback", return_value=Mock()
        ),
    ):
        assert await hass.config_entries.async_setup(entry.entry_id) is True
        await hass.async_block_till_done()
        number_entity, _, _ = assert_loaded(15)
        data = hass.data[DOMAIN][entry.entry_id]
        data.device._ensure_connected = AsyncMock()
        data.device._send_datapoints = AsyncMock()

        await hass.services.async_call(
            number_platform.DOMAIN,
            number_platform.SERVICE_SET_VALUE,
            {ATTR_ENTITY_ID: number_entity.entity_id, ATTR_VALUE: 100},
            blocking=True,
        )
        await hass.async_block_till_done()
        data.device._ensure_connected.assert_not_awaited()
        data.device._send_datapoints.assert_not_awaited()
        assert_loaded(100)

        original_reload = hass.config_entries.async_reload
        with patch.object(
            hass.config_entries,
            "async_reload",
            wraps=original_reload,
        ) as reload:
            hass.config_entries.async_update_entry(
                entry,
                title="Synthetic lifecycle S1 renamed",
                options={
                    **entry.options,
                    CONF_ON_DEMAND_CONNECTION_HOLD_TIME: 105,
                },
            )
            await hass.async_block_till_done()
            reload.assert_awaited_once_with(entry.entry_id)
        initial_number, _, _ = assert_loaded(105)

        for cycle in range(3):
            old_data = hass.data[DOMAIN][entry.entry_id]
            old_number = _live_policy_entities(
                hass,
                entry.entry_id,
                Platform.NUMBER,
                TuyaBLEOnDemandConnectionHoldTimeNumber,
            )[0]
            assert await hass.config_entries.async_unload(entry.entry_id) is True
            await hass.async_block_till_done()

            assert entry.state is ConfigEntryState.NOT_LOADED
            assert entry.entry_id not in hass.data[DOMAIN]
            assert not entry.update_listeners
            assert all(
                not _live_policy_entities(hass, entry.entry_id, platform, entity_type)
                for platform, entity_type in entity_types
            )
            assert old_data.coordinator._unsub_device_callbacks == []
            assert old_data.coordinator._unsub_disconnect is None
            assert old_data.device._connected_callbacks == []
            assert old_data.device._callbacks == []
            assert old_data.device._session_invalidated_callbacks == []
            assert old_data.device._disconnected_callbacks == []
            assert old_data.device._reconnect_task is None
            assert old_data.device._scheduled_reconnect_delay is None
            assert old_data.device._pending_reconnect_delay is None
            assert old_data.device._active_reconnect_task is None
            assert old_data.device._idle_disconnect_task is None
            assert old_data.device._disconnect_retry_task is None
            assert old_data.device._startup_task is None
            assert not old_data.device._response_tasks
            assert not old_data.device._response_drain_tasks
            assert not old_data.device._response_cleanup_tasks
            assert hass.states.get(old_number.entity_id).state == "unavailable"

            assert await hass.config_entries.async_setup(entry.entry_id) is True
            await hass.async_block_till_done()
            reconstructed_number, _, _ = assert_loaded(105)
            assert reconstructed_number is not old_number
            if cycle == 0:
                assert reconstructed_number is not initial_number
            reconstructed_data = hass.data[DOMAIN][entry.entry_id]
            reconstructed_data.device._ensure_connected = AsyncMock()
            reconstructed_data.device._send_datapoints = AsyncMock()
            reconstructed_data.device._ensure_connected.assert_not_awaited()
            reconstructed_data.device._send_datapoints.assert_not_awaited()


async def test_number_entity_persists_and_reschedules_current_session(
    hass: HomeAssistant,
) -> None:
    persist = AsyncMock()
    device = _make_device(persist_options=persist)
    token, _ = _install_ready_session(device)
    device._record_confirmed_activity(token)
    original_owner = device._idle_disconnect_task
    entity = TuyaBLEOnDemandConnectionHoldTimeNumber(
        hass,
        TuyaBLECoordinator(hass, device),
        device,
        TuyaBLEProductInfo("Synthetic hold-time device"),
    )
    entity.async_write_ha_state = Mock()

    await entity.async_set_native_value(100)

    assert device.on_demand_connection_hold_time == 100
    persist.assert_awaited_once_with({CONF_ON_DEMAND_CONNECTION_HOLD_TIME: 100})
    entity.async_write_ha_state.assert_called_once()
    assert device._idle_disconnect_task is not original_owner
    if device._idle_disconnect_task is not None:
        device._idle_disconnect_task.cancel()
        await asyncio.sleep(0)


@pytest.mark.parametrize("value", (14, 106, 15.5, math.nan, math.inf))
async def test_number_entity_rejects_invalid_user_input(
    hass: HomeAssistant,
    value: float,
) -> None:
    device = _make_device(persist_options=AsyncMock())
    entity = TuyaBLEOnDemandConnectionHoldTimeNumber(
        hass,
        TuyaBLECoordinator(hass, device),
        device,
        TuyaBLEProductInfo("Synthetic hold-time device"),
    )

    with pytest.raises(ValueError):
        await entity.async_set_native_value(value)

    device._persist_options.assert_not_awaited()


async def test_repeated_number_setup_has_one_stable_local_entity_per_setup(
    hass: HomeAssistant,
) -> None:
    from pytest_homeassistant_custom_component.common import MockConfigEntry

    entry = MockConfigEntry(domain=DOMAIN, data={"address": SYNTHETIC_ADDRESS})
    device = _make_device()
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = _make_data(hass, device)
    identities: list[str] = []
    for _ in range(2):
        added: list[object] = []
        await async_setup_numbers(hass, entry, added.extend)
        local = [
            entity
            for entity in added
            if isinstance(entity, TuyaBLEOnDemandConnectionHoldTimeNumber)
        ]
        assert len(local) == 1
        identities.append(local[0].unique_id)

    assert identities[0] == identities[1]


async def test_options_flow_shows_hold_time_for_s1_only(
    hass: HomeAssistant,
) -> None:
    from pytest_homeassistant_custom_component.common import MockConfigEntry

    for product, expected in (
        (S1_PRODUCT, True),
        (V1_PRODUCT, False),
        (GENERIC_PRODUCT, False),
    ):
        entry = MockConfigEntry(
            domain=DOMAIN,
            data={"address": SYNTHETIC_ADDRESS},
            options={},
        )
        entry.add_to_hass(hass)
        hass.data.setdefault(DOMAIN, {})[entry.entry_id] = _make_data(
            hass, _make_device(product=product)
        )
        flow = TuyaBLEOptionsFlow(entry)
        flow.hass = hass

        result = await flow.async_step_connection_settings()

        assert (CONF_ON_DEMAND_CONNECTION_HOLD_TIME in _schema_keys(result)) is expected
        hass.data[DOMAIN].pop(entry.entry_id)


async def test_options_flow_preserves_credentials_and_persists_s1_hold_time(
    hass: HomeAssistant,
) -> None:
    from pytest_homeassistant_custom_component.common import MockConfigEntry

    entry = MockConfigEntry(
        domain=DOMAIN,
        data={"address": SYNTHETIC_ADDRESS},
        options={"access_id": "synthetic-access-id"},
    )
    entry.add_to_hass(hass)
    device = _make_device(persist_options=AsyncMock())
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = _make_data(hass, device)
    flow = TuyaBLEOptionsFlow(entry)
    flow.hass = hass

    result = await flow.async_step_connection_settings(
        {
            CONF_CONNECTION_MODE: ConnectionMode.ON_DEMAND.value,
            CONF_BLE_CONTROL_ENABLED: True,
            CONF_ON_DEMAND_CONNECTION_HOLD_TIME: 100,
        }
    )

    assert result["type"] == "create_entry"
    assert result["data"]["access_id"] == "synthetic-access-id"
    assert result["data"][CONF_ON_DEMAND_CONNECTION_HOLD_TIME] == 100
    assert device.on_demand_connection_hold_time == 100


@pytest.mark.parametrize(
    ("code", "data"),
    (
        (TuyaBLECode.FUN_SENDER_DEVICE_INFO, bytes(46)),
        (TuyaBLECode.FUN_SENDER_PAIR, b"\x00"),
        (TuyaBLECode.FUN_SENDER_DEVICE_STATUS, b"\x00"),
        (TuyaBLECode.FUN_SENDER_DPS, b"\x00"),
    ),
    ids=("device-info", "pair", "device-status", "command-ack"),
)
async def test_correlated_success_response_records_current_session_activity(
    code: TuyaBLECode,
    data: bytes,
) -> None:
    device = _make_device()
    token, _ = _install_ready_session(device)
    device._security_material = Mock(spec=TuyaBLESecurityMaterial)
    device._security_material.session_key.return_value = b"synthetic-session-key"
    response_key = (token, 7)
    future = asyncio.get_running_loop().create_future()
    device._input_expected_responses[response_key] = future
    device._input_expected_response_codes[response_key] = code

    with patch.object(device, "_record_confirmed_activity") as record:
        device._handle_command_or_response(
            8,
            7,
            code,
            data,
            session_token=token,
        )

    assert future.result() == 0
    record.assert_called_once_with(token)


@pytest.mark.parametrize(
    "code",
    (
        TuyaBLECode.FUN_RECEIVE_DP,
        TuyaBLECode.FUN_RECEIVE_SIGN_DP,
        TuyaBLECode.FUN_RECEIVE_TIME_DP,
        TuyaBLECode.FUN_RECEIVE_SIGN_TIME_DP,
    ),
)
def test_accepted_current_session_report_records_activity(code: TuyaBLECode) -> None:
    device = _make_device()
    token, _ = _install_ready_session(device)
    device._parse_datapoints_v3 = Mock()
    device._parse_timestamp = Mock(return_value=(1.0, 0))
    payloads = {
        TuyaBLECode.FUN_RECEIVE_DP: b"",
        TuyaBLECode.FUN_RECEIVE_SIGN_DP: b"\x00\x01\x00",
        TuyaBLECode.FUN_RECEIVE_TIME_DP: b"",
        TuyaBLECode.FUN_RECEIVE_SIGN_TIME_DP: b"\x00\x01\x00",
    }

    with (
        patch.object(device, "_record_confirmed_activity") as record,
        patch.object(device, "_schedule_response"),
    ):
        device._handle_command_or_response(
            8,
            0,
            code,
            payloads[code],
            session_token=token,
        )

    record.assert_called_once_with(token)


async def test_old_session_and_rejected_activity_never_move_deadline() -> None:
    device = _make_device()
    old_token, old_client = _install_ready_session(device)
    device._record_confirmed_activity(old_token)
    initial = device.last_confirmed_activity_monotonic
    old_client.is_connected = False
    device._mark_connection_lost(old_token)
    await asyncio.sleep(0)
    replacement, _ = _install_ready_session(device)

    with patch(
        "custom_components.tuya_ble.tuya_ble.tuya_ble.time.monotonic",
        return_value=(initial or 0) + 50,
    ):
        device._record_confirmed_activity(old_token)

    assert device.confirmed_activity_session is not old_token
    assert device.confirmed_activity_session is not replacement
    assert device.last_confirmed_activity_monotonic is None


async def test_unconfirmed_write_return_and_timeout_do_not_record_activity() -> None:
    device = _make_device()
    token, _ = _install_ready_session(device)
    device._build_packets = Mock(return_value=[b"synthetic-write"])
    device._int_send_packet_while_connected = AsyncMock()

    with patch.object(device, "_record_confirmed_activity") as record:
        assert (
            await device._send_packet_while_connected(
                TuyaBLECode.FUN_SENDER_DPS,
                b"synthetic",
                0,
                False,
                session_token=token,
            )
            is True
        )

    record.assert_not_called()


@pytest.mark.parametrize("hold_time", (15, 100, 105))
async def test_exact_monotonic_hold_deadline_releases_without_keepalive(
    hold_time: int,
) -> None:
    device = _make_device(hold_time=hold_time)
    token, _ = _install_ready_session(device)
    device._execute_disconnect = AsyncMock()
    device._request_status_while_connected = AsyncMock()
    clock = [100.0]
    sleeps: list[float] = []

    async def advance(delay: float) -> None:
        sleeps.append(delay)
        clock[0] += delay

    with (
        patch(
            "custom_components.tuya_ble.tuya_ble.tuya_ble.time.monotonic",
            side_effect=lambda: clock[0],
        ),
        patch(
            "custom_components.tuya_ble.tuya_ble.tuya_ble.asyncio.sleep",
            side_effect=advance,
        ),
    ):
        device._record_confirmed_activity(token)
        device._cancel_idle_disconnect_locked()
        await device._idle_disconnect_after_deadline(token)

    assert sleeps[0] == hold_time
    device._execute_disconnect.assert_awaited_once()
    device._request_status_while_connected.assert_not_awaited()


async def test_later_confirmed_activity_replaces_one_hold_owner() -> None:
    device = _make_device()
    token, _ = _install_ready_session(device)
    real_sleep = asyncio.sleep
    sleep_started = asyncio.Event()
    release_sleep = asyncio.Event()
    clock = [100.0]

    async def blocked_sleep(_: float) -> None:
        sleep_started.set()
        await release_sleep.wait()

    with (
        patch(
            "custom_components.tuya_ble.tuya_ble.tuya_ble.time.monotonic",
            side_effect=lambda: clock[0],
        ),
        patch(
            "custom_components.tuya_ble.tuya_ble.tuya_ble.asyncio.sleep",
            side_effect=blocked_sleep,
        ),
    ):
        device._record_confirmed_activity(token)
        first = device._idle_disconnect_task
        await sleep_started.wait()
        clock[0] = 110.0
        sleep_started.clear()
        device._record_confirmed_activity(token)
        second = device._idle_disconnect_task

        assert first is not None
        assert second is not None
        assert second is not first
        await real_sleep(0)
        assert first.done()
        second.cancel()
        release_sleep.set()
        await asyncio.gather(second, return_exceptions=True)


@pytest.mark.parametrize("protected", ("lease", "response-drain"))
async def test_deadline_waits_for_protected_work_to_drain(protected: str) -> None:
    device = _make_device()
    token, _ = _install_ready_session(device)
    real_sleep = asyncio.sleep
    device._execute_disconnect = AsyncMock()
    device._last_confirmed_activity_monotonic = 100.0
    device._confirmed_activity_session = token
    if protected == "lease":
        device._active_lease_count = 1
        device._lease_zero_event.clear()
        drain_event = device._lease_zero_event
    else:
        device._active_response_drain_count = 1
        device._response_drain_zero_event.clear()
        drain_event = device._response_drain_zero_event

    async def no_sleep(_: float) -> None:
        return

    with (
        patch(
            "custom_components.tuya_ble.tuya_ble.tuya_ble.time.monotonic",
            return_value=115.0,
        ),
        patch(
            "custom_components.tuya_ble.tuya_ble.tuya_ble.asyncio.sleep",
            side_effect=no_sleep,
        ),
    ):
        owner = asyncio.create_task(device._idle_disconnect_after_deadline(token))
        await real_sleep(0)
        await real_sleep(0)
        assert not owner.done()
        device._execute_disconnect.assert_not_awaited()
        if protected == "lease":
            device._active_lease_count = 0
        else:
            device._active_response_drain_count = 0
        drain_event.set()
        await owner

    device._execute_disconnect.assert_awaited_once()


async def test_stale_timer_cannot_release_replacement_session() -> None:
    device = _make_device()
    old_token, old_client = _install_ready_session(device)
    old_client.is_connected = False
    device._mark_connection_lost(old_token)
    replacement, replacement_client = _install_ready_session(device)
    device._execute_disconnect = AsyncMock()

    await device._idle_disconnect_after_deadline(old_token)

    assert device._connection_token is replacement
    assert replacement_client.is_connected is True
    device._execute_disconnect.assert_not_awaited()


async def test_hold_change_during_always_connected_has_no_transport_effect() -> None:
    persist = AsyncMock()
    device = _make_device(
        mode=ConnectionMode.ALWAYS_CONNECTED,
        persist_options=persist,
    )
    _install_ready_session(device)
    device._execute_disconnect = AsyncMock()
    device._schedule_reconnect_locked = Mock()

    await device.async_update_connection_policy(on_demand_connection_hold_time=100)

    assert device.on_demand_connection_hold_time == 100
    assert device._idle_disconnect_task is None
    device._execute_disconnect.assert_not_awaited()
    device._schedule_reconnect_locked.assert_not_called()


async def test_mode_transitions_cancel_and_rebuild_hold_from_latest_activity() -> None:
    device = _make_device()
    token, _ = _install_ready_session(device)
    device._record_confirmed_activity(token)
    first = device._idle_disconnect_task

    await device.async_update_connection_policy(
        connection_mode=ConnectionMode.ALWAYS_CONNECTED.value
    )

    assert first is not None
    await asyncio.sleep(0)
    assert first.cancelled()
    assert device._idle_disconnect_task is None

    await device.async_update_connection_policy(
        connection_mode=ConnectionMode.ON_DEMAND.value
    )

    assert device._idle_disconnect_task is not None
    device._idle_disconnect_task.cancel()
    await asyncio.sleep(0)


async def test_ble_control_off_cancels_hold_without_command_write() -> None:
    device = _make_device()
    token, _ = _install_ready_session(device)
    device._record_confirmed_activity(token)
    owner = device._idle_disconnect_task
    device._send_datapoints = AsyncMock()

    await device.async_update_connection_policy(ble_control_enabled=False)

    assert owner is not None
    await asyncio.sleep(0)
    assert owner.cancelled()
    assert device._idle_disconnect_task is None
    device._send_datapoints.assert_not_awaited()


async def test_stop_cancels_hold_and_leaves_zero_owner() -> None:
    device = _make_device()
    token, _ = _install_ready_session(device)
    device._record_confirmed_activity(token)

    await device.stop()

    assert device._idle_disconnect_task is None


async def test_intentional_release_has_no_reconnect_or_failure_pressure() -> None:
    device = _make_device()
    token, client = _install_ready_session(device)
    device._unexpected_reconnect_failures = 2
    device._schedule_reconnect_locked = Mock()
    device._last_confirmed_activity_monotonic = 0.0
    device._confirmed_activity_session = token

    with (
        patch(
            "custom_components.tuya_ble.tuya_ble.tuya_ble.time.monotonic",
            return_value=15.0,
        ),
        patch(
            "custom_components.tuya_ble.tuya_ble.tuya_ble.asyncio.sleep",
            new=AsyncMock(),
        ),
    ):
        await device._idle_disconnect_after_deadline(token)

    assert client.disconnect.await_count == 1
    assert device._unexpected_reconnect_failures == 2
    device._schedule_reconnect_locked.assert_not_called()


async def test_failed_physical_release_retains_mandatory_owner() -> None:
    device = _make_device()
    token, client = _install_ready_session(
        device,
        _SyntheticClient(disconnect_error=RuntimeError("synthetic disconnect")),
    )
    device._last_confirmed_activity_monotonic = 0.0
    device._confirmed_activity_session = token

    with (
        patch(
            "custom_components.tuya_ble.tuya_ble.tuya_ble.time.monotonic",
            return_value=15.0,
        ),
        patch(
            "custom_components.tuya_ble.tuya_ble.tuya_ble.asyncio.sleep",
            new=AsyncMock(),
        ),
    ):
        await device._idle_disconnect_after_deadline(token)

    assert client.is_connected is True
    assert device._pending_release is not None
    assert device._pending_release.reason in {
        PendingReleaseReason.ON_DEMAND_IDLE,
        PendingReleaseReason.SETUP_FAILURE,
    }
    assert device._disconnect_retry_task is not None
    device._disconnect_retry_task.cancel()
    await asyncio.sleep(0)


def test_v1_never_uses_s1_hold_option() -> None:
    device = _make_device(product=V1_PRODUCT, hold_time=105)

    assert device.supports_on_demand_connection_hold_time is False
    assert device.on_demand_connection_hold_time == 15
