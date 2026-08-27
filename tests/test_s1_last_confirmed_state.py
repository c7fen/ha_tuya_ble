"""Regression contracts for S1 last-confirmed state after a safe disconnect."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

from bleak.backends.device import BLEDevice
from homeassistant.core import HomeAssistant

from custom_components.tuya_ble import number, select, sensor, switch
from custom_components.tuya_ble.const import ConnectionMode
from custom_components.tuya_ble.devices import TuyaBLECoordinator, TuyaBLEProductInfo
from custom_components.tuya_ble.number import TuyaBLENumber
from custom_components.tuya_ble.select import TuyaBLESelect
from custom_components.tuya_ble.sensor import TuyaBLESensor
from custom_components.tuya_ble.switch import TuyaBLESwitch
from custom_components.tuya_ble.tuya_ble import TuyaBLEDataPointType, TuyaBLEDevice


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


def _mapping_for(mapping, dp_id: int):
    return next(item for item in mapping if item.dp_id == dp_id)


def _make_entities(hass: HomeAssistant):
    """Create the four public S1 entities attached to one coordinator."""
    device = _make_s1_device()
    coordinator = TuyaBLECoordinator(hass, device)
    product = TuyaBLEProductInfo("S1-TY-BLE-PRO")
    entities = {
        "auto_lock": TuyaBLESwitch(
            hass,
            coordinator,
            device,
            product,
            _mapping_for(switch.get_mapping_by_device(device), 33),
        ),
        "authentication": TuyaBLESelect(
            hass,
            coordinator,
            device,
            product,
            _mapping_for(select.get_mapping_by_device(device), 34),
        ),
        "auto_lock_delay": TuyaBLENumber(
            hass,
            coordinator,
            device,
            product,
            _mapping_for(number.get_mapping_by_device(device), 36),
        ),
        "battery": TuyaBLESensor(
            hass,
            coordinator,
            device,
            product,
            _mapping_for(sensor.get_mapping_by_device(device), 8),
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
    """A restarted S1 retains all confirmed values as stale public state."""
    device, coordinator, entities, listeners = _make_entities(hass)
    client = _begin_authenticated_session(device)
    _report(device, 33, TuyaBLEDataPointType.DT_BOOL, True)
    _report(device, 34, TuyaBLEDataPointType.DT_ENUM, 1)
    _report(device, 36, TuyaBLEDataPointType.DT_VALUE, 45)
    _report(device, 8, TuyaBLEDataPointType.DT_VALUE, 73)
    _intentional_disconnect(device, client)
    _cleanup(coordinator, listeners)

    restarted_device, restarted_coordinator, restarted, restarted_listeners = (
        _make_entities(hass)
    )
    del restarted_device
    _cleanup(restarted_coordinator, restarted_listeners)
    assert restarted["auto_lock"].is_on is True
    assert restarted["authentication"].current_option == "finger_card"
    assert restarted["auto_lock_delay"].native_value == 45.0
    assert restarted["battery"].native_value == 73
    for entity in restarted.values():
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
