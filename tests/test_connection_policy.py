"""Tests for per-device BLE connection policy and control entities."""

from __future__ import annotations

import asyncio
import traceback
from unittest.mock import MagicMock
from unittest.mock import AsyncMock, Mock, patch

import pytest
from bleak.backends.device import BLEDevice
from bleak_retry_connector import BleakError
from homeassistant.components.binary_sensor import BinarySensorDeviceClass
from homeassistant.components.vacuum import VacuumActivity
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ServiceValidationError
from homeassistant.helpers.entity import EntityCategory

from custom_components.tuya_ble.binary_sensor import (
    TuyaBLEConnectionSensor,
    async_setup_entry as async_setup_binary_sensors,
)
from custom_components import tuya_ble as integration
from custom_components.tuya_ble.config_flow import TuyaBLEOptionsFlow
from custom_components.tuya_ble.const import (
    CONF_BLE_CONTROL_ENABLED,
    CONF_CONNECTION_MODE,
    ConnectionMode,
    ConnectionPolicyState,
    DOMAIN,
    EffectiveConnectionPolicy,
)
from custom_components.tuya_ble.devices import (
    TuyaBLECoordinator,
    TuyaBLEData,
    TuyaBLEProductInfo,
)
from custom_components.tuya_ble.lock import TuyaBLES1Lock, TuyaBLEV1Lock
from custom_components.tuya_ble.select import TuyaBLEConnectionModeSelect
from custom_components.tuya_ble.switch import TuyaBLEControlSwitch
from custom_components.tuya_ble.tuya_ble import TuyaBLEDataPointType, TuyaBLEDevice
from custom_components.tuya_ble.tuya_ble.const import TuyaBLECode
from custom_components.tuya_ble.tuya_ble.tuya_ble import _lease_context_depth
from custom_components.tuya_ble.tuya_ble.exceptions import (
    TuyaBLEConnectionUnavailableError,
    TuyaBLEControlSuspendedError,
)
from custom_components.tuya_ble.tuya_ble.manager import TuyaBLEDeviceCredentials
from custom_components.tuya_ble.vacuum import (
    TuyaBLEVacuumEntity,
    TuyaBLEVacuumMapping,
)


SYNTHETIC_ADDRESS = "00:00:00:00:00:21"
SYNTHETIC_DEVICE_ID = "synthetic-policy-device"


class _SyntheticConnectedClient:
    """Minimal connected client whose disconnect behavior is configurable."""

    def __init__(
        self,
        *,
        stop_notify_error: Exception | None = None,
        disconnect_error: Exception | None = None,
    ) -> None:
        self.is_connected = True
        self.stop_notify = AsyncMock(side_effect=stop_notify_error)

        async def disconnect() -> None:
            if disconnect_error is not None:
                raise disconnect_error
            self.is_connected = False

        self.disconnect = AsyncMock(side_effect=disconnect)


def _make_device(
    *,
    mode: ConnectionMode = ConnectionMode.ALWAYS_CONNECTED,
    enabled: bool = True,
    persist_options=None,
) -> TuyaBLEDevice:
    device = TuyaBLEDevice(
        Mock(),
        BLEDevice(
            name="Synthetic policy device",
            address=SYNTHETIC_ADDRESS,
            details={},
        ),
        connection_mode=mode.value,
        ble_control_enabled=enabled,
        persist_options=persist_options,
    )
    device._device_info = TuyaBLEDeviceCredentials(
        uuid="synthetic-policy-uuid",
        local_key="synthetic-policy-key",
        device_id=SYNTHETIC_DEVICE_ID,
        category="jtmspro",
        product_id="xqeob8h6",
        device_name="Synthetic policy device",
        product_model="SYNTHETIC",
        product_name="Synthetic policy device",
        functions=[],
        status_range=[],
    )
    return device


def _make_data(hass: HomeAssistant, device: TuyaBLEDevice) -> TuyaBLEData:
    coordinator = TuyaBLECoordinator(hass, device)
    return TuyaBLEData(
        title="Synthetic policy device",
        device=device,
        product=TuyaBLEProductInfo("S1-TY-BLE-PRO"),
        manager=Mock(),
        coordinator=coordinator,
    )


def test_defaults_and_effective_policy() -> None:
    device = TuyaBLEDevice(
        Mock(),
        None,
        address=SYNTHETIC_ADDRESS,
    )

    assert device.connection_mode is ConnectionMode.ALWAYS_CONNECTED
    assert device.ble_control_enabled is True
    assert device.effective_policy is EffectiveConnectionPolicy.ALWAYS_CONNECTED
    assert device.policy_state is ConnectionPolicyState.ALWAYS_CONNECTED_CONNECTING
    assert device.is_connection_active is False


async def test_deferred_initialize_loads_without_advertisement() -> None:
    manager = Mock()
    manager.get_device_credentials = AsyncMock(
        return_value=TuyaBLEDeviceCredentials(
            uuid="synthetic-policy-uuid",
            local_key="synthetic-policy-key",
            device_id=SYNTHETIC_DEVICE_ID,
            category="jtmspro",
            product_id="xqeob8h6",
            device_name="Synthetic policy device",
            product_model="SYNTHETIC",
            product_name="Synthetic policy device",
            functions=[],
            status_range=[],
        )
    )
    device = TuyaBLEDevice(
        manager,
        None,
        address=SYNTHETIC_ADDRESS,
        connection_mode=ConnectionMode.ON_DEMAND.value,
    )

    await device.initialize()

    assert device.category == "jtmspro"
    assert device.product_id == "xqeob8h6"
    manager.get_device_credentials.assert_awaited_once_with(SYNTHETIC_ADDRESS, False)


@pytest.mark.parametrize(
    "options",
    [
        {CONF_BLE_CONTROL_ENABLED: False},
        {CONF_CONNECTION_MODE: ConnectionMode.ON_DEMAND.value},
    ],
    ids=("suspended", "on-demand"),
)
async def test_config_entry_setup_without_advertisement_stays_loaded(
    hass: HomeAssistant,
    options: dict[str, object],
) -> None:
    from pytest_homeassistant_custom_component.common import MockConfigEntry

    credentials = TuyaBLEDeviceCredentials(
        uuid="synthetic-setup-uuid",
        local_key="synthetic-setup-key",
        device_id="synthetic-setup-device",
        category="jtmspro",
        product_id="xqeob8h6",
        device_name="Synthetic setup device",
        product_model="SYNTHETIC",
        product_name="Synthetic setup device",
        functions=[],
        status_range=[],
    )
    manager = MagicMock()
    manager.get_device_credentials = AsyncMock(return_value=credentials)
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="Synthetic setup device",
        data={"address": SYNTHETIC_ADDRESS},
        options=options,
    )
    entry.add_to_hass(hass)
    forwarded = AsyncMock()
    hass.config_entries.async_forward_entry_setups = forwarded

    with (
        patch.object(integration, "HASSTuyaBLEDeviceManager", return_value=manager),
        patch.object(
            integration.bluetooth, "async_ble_device_from_address", return_value=None
        ),
        patch.object(integration, "get_device", new=AsyncMock()) as cloud_lookup,
        patch.object(
            integration.bluetooth, "async_register_callback", return_value=Mock()
        ),
    ):
        assert await integration.async_setup_entry(hass, entry) is True

    cloud_lookup.assert_not_awaited()
    forwarded.assert_awaited_once()
    assert entry.entry_id in hass.data[DOMAIN]
    assert hass.data[DOMAIN][entry.entry_id].device.ble_control_enabled is (
        options.get(CONF_BLE_CONTROL_ENABLED, True)
    )


async def test_overlapping_leases_do_not_disconnect_early() -> None:
    device = _make_device(mode=ConnectionMode.ON_DEMAND)
    device._ensure_connected = AsyncMock()
    device._execute_disconnect = AsyncMock()

    with patch(
        "custom_components.tuya_ble.tuya_ble.tuya_ble.DEFAULT_ON_DEMAND_IDLE_DISCONNECT_SECONDS",
        0.01,
    ):
        first = device.connection_lease("first")
        second = device.connection_lease("second")
        await first.__aenter__()
        await second.__aenter__()
        await first.__aexit__(None, None, None)
        await asyncio.sleep(0.02)
        device._execute_disconnect.assert_not_awaited()
        assert device.active_lease_count == 1
        await second.__aexit__(None, None, None)
        await asyncio.sleep(0.02)

    device._execute_disconnect.assert_awaited_once()
    assert device.active_lease_count == 0
    await device.stop()


async def test_new_lease_cancels_idle_disconnect() -> None:
    device = _make_device(mode=ConnectionMode.ON_DEMAND)
    device._ensure_connected = AsyncMock()
    device._execute_disconnect = AsyncMock()

    with patch(
        "custom_components.tuya_ble.tuya_ble.tuya_ble.DEFAULT_ON_DEMAND_IDLE_DISCONNECT_SECONDS",
        0.05,
    ):
        async with device.connection_lease("first"):
            pass
        async with device.connection_lease("second"):
            await asyncio.sleep(0.06)
        await asyncio.sleep(0)

    device._execute_disconnect.assert_not_awaited()
    await device.stop()


async def test_idle_disconnect_failure_stays_pending_for_retry() -> None:
    """A live client remains owned and retryable after an idle release failure."""
    device = _make_device(mode=ConnectionMode.ON_DEMAND)
    client = _SyntheticConnectedClient(disconnect_error=RuntimeError("synthetic"))
    device._client = client
    device._is_paired = True
    device._physical_connection_active = True
    lease = device.connection_lease("idle operation", defer_connection=True)

    with patch(
        "custom_components.tuya_ble.tuya_ble.tuya_ble.DEFAULT_ON_DEMAND_IDLE_DISCONNECT_SECONDS",
        0.01,
    ):
        await lease.__aenter__()
        await lease.__aexit__(None, None, None)
        await asyncio.sleep(0.02)

    assert device._client is client
    assert device._pending_disconnect_target is ConnectionPolicyState.ON_DEMAND_IDLE
    assert device._disconnect_retry_task is not None
    device._disconnect_retry_task.cancel()
    await asyncio.sleep(0)


async def test_lease_cancellation_and_exception_release_count() -> None:
    device = _make_device(mode=ConnectionMode.ON_DEMAND)
    device._ensure_connected = AsyncMock()

    with pytest.raises(RuntimeError):
        async with device.connection_lease("exception"):
            raise RuntimeError("synthetic failure")
    assert device.active_lease_count == 0

    async def cancel_inside() -> None:
        async with device.connection_lease("cancel"):
            raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await cancel_inside()
    assert device.active_lease_count == 0
    await device.stop()


async def test_suspension_persists_before_disconnect_and_blocks_new_leases() -> None:
    events: list[str] = []

    async def persist(updates: dict[str, object]) -> None:
        assert updates == {CONF_BLE_CONTROL_ENABLED: False}
        events.append("persist")

    device = _make_device(persist_options=persist)

    async def disconnect(*, terminal: bool = False) -> None:
        del terminal
        events.append("disconnect")

    device._execute_disconnect = disconnect
    await device.async_update_connection_policy(ble_control_enabled=False)

    assert events == ["persist", "disconnect"]
    assert device.effective_policy is EffectiveConnectionPolicy.SUSPENDED
    with pytest.raises(TuyaBLEControlSuspendedError):
        async with device.connection_lease("blocked"):
            pass
    assert device.active_lease_count == 0


async def test_suspension_waits_for_existing_lease() -> None:
    device = _make_device()
    device._ensure_connected = AsyncMock()
    device._execute_disconnect = AsyncMock()
    lease = device.connection_lease("long operation", defer_connection=True)
    await lease.__aenter__()

    suspension = asyncio.create_task(
        device.async_update_connection_policy(ble_control_enabled=False)
    )
    await asyncio.sleep(0)
    device._execute_disconnect.assert_not_awaited()
    await lease.__aexit__(None, None, None)
    await suspension

    device._execute_disconnect.assert_awaited_once()
    assert device.active_lease_count == 0


async def test_suspension_timeout_defers_disconnect_until_final_lease_release() -> None:
    device = _make_device()
    device._is_paired = True
    device._physical_connection_active = True
    disconnect = AsyncMock(wraps=device._execute_disconnect)
    device._execute_disconnect = disconnect
    lease = device.connection_lease("timeout operation", defer_connection=True)
    await lease.__aenter__()

    with (
        patch(
            "custom_components.tuya_ble.tuya_ble.tuya_ble.CONNECTION_POLICY_TRANSITION_TIMEOUT_SECONDS",
            0.01,
        ),
        pytest.raises(ServiceValidationError),
    ):
        await device.async_update_connection_policy(ble_control_enabled=False)

    assert disconnect.await_count == 0
    assert device._pending_disconnect_target is ConnectionPolicyState.SUSPENDED
    await lease.__aexit__(None, None, None)

    assert disconnect.await_count == 1
    assert device._pending_disconnect_target is None
    assert device.policy_state is ConnectionPolicyState.SUSPENDED
    assert device.is_authenticated is False
    assert device.active_lease_count == 0


@pytest.mark.parametrize(
    "mode",
    (ConnectionMode.ALWAYS_CONNECTED, ConnectionMode.ON_DEMAND),
)
async def test_reenable_supersedes_timed_out_pending_suspension(
    mode: ConnectionMode,
) -> None:
    """A newer enabled policy must win when the final lease drains."""
    device = _make_device(mode=mode)
    device._is_paired = True
    device._physical_connection_active = True
    disconnect = AsyncMock(wraps=device._execute_disconnect)
    device._execute_disconnect = disconnect
    lease = device.connection_lease("timeout operation", defer_connection=True)
    await lease.__aenter__()

    with (
        patch(
            "custom_components.tuya_ble.tuya_ble.tuya_ble.CONNECTION_POLICY_TRANSITION_TIMEOUT_SECONDS",
            0.01,
        ),
        pytest.raises(ServiceValidationError),
    ):
        await device.async_update_connection_policy(ble_control_enabled=False)

    assert device._pending_disconnect_target is ConnectionPolicyState.SUSPENDED
    await device.async_update_connection_policy(ble_control_enabled=True)
    await lease.__aexit__(None, None, None)
    await asyncio.sleep(0)

    assert device.ble_control_enabled is True
    assert device.effective_policy is not EffectiveConnectionPolicy.SUSPENDED
    assert device.policy_state is not ConnectionPolicyState.SUSPENDED
    assert device._pending_disconnect_target is None
    assert disconnect.await_count <= 1
    await device.stop()


@pytest.mark.parametrize(
    "mode",
    (ConnectionMode.ALWAYS_CONNECTED, ConnectionMode.ON_DEMAND),
)
async def test_reenable_reconciles_suspension_during_physical_disconnect(
    mode: ConnectionMode,
) -> None:
    """A completed old disconnect must reconcile to the latest enabled policy."""
    device = _make_device(mode=mode)
    disconnect_started = asyncio.Event()
    allow_disconnect = asyncio.Event()
    client = _SyntheticConnectedClient()

    async def disconnect() -> None:
        disconnect_started.set()
        await allow_disconnect.wait()
        client.is_connected = False

    client.disconnect.side_effect = disconnect
    device._client = client
    device._is_paired = True
    device._physical_connection_active = True
    device._schedule_reconnect_locked = Mock()
    lease = device.connection_lease("timeout operation", defer_connection=True)
    await lease.__aenter__()

    with (
        patch(
            "custom_components.tuya_ble.tuya_ble.tuya_ble.CONNECTION_POLICY_TRANSITION_TIMEOUT_SECONDS",
            0.01,
        ),
        pytest.raises(ServiceValidationError),
    ):
        await device.async_update_connection_policy(ble_control_enabled=False)

    release_lease = asyncio.create_task(lease.__aexit__(None, None, None))
    await disconnect_started.wait()
    await device.async_update_connection_policy(ble_control_enabled=True)
    allow_disconnect.set()
    await release_lease

    assert device.effective_policy is not EffectiveConnectionPolicy.SUSPENDED
    assert device.policy_state is not ConnectionPolicyState.SUSPENDED
    assert device._pending_disconnect_target is None
    if mode is ConnectionMode.ALWAYS_CONNECTED:
        device._schedule_reconnect_locked.assert_called_once_with(0)
    else:
        assert device._idle_disconnect_task is None


async def test_stop_notify_failure_still_releases_gatt_truthfully() -> None:
    """A notification cleanup failure must not suppress the real disconnect."""
    device = _make_device()
    client = _SyntheticConnectedClient(stop_notify_error=RuntimeError("synthetic"))
    device._client = client
    device._is_paired = True
    device._physical_connection_active = True
    state_changes: list[bool] = []
    device.register_connection_state_callback(state_changes.append)

    await device._execute_disconnect()

    client.stop_notify.assert_awaited_once()
    client.disconnect.assert_awaited_once()
    assert device._client is None
    assert device.is_gatt_connected is False
    assert device.is_authenticated is False
    assert state_changes == [False]


@pytest.mark.parametrize(
    "stop_notify_error",
    (None, RuntimeError("synthetic")),
    ids=("disconnect-only", "both-operations"),
)
async def test_disconnect_failure_retains_truthful_retryable_connection(
    stop_notify_error: Exception | None,
) -> None:
    """A client that remains connected must stay owned until a retry succeeds."""
    device = _make_device()
    client = _SyntheticConnectedClient(
        stop_notify_error=stop_notify_error,
        disconnect_error=RuntimeError("synthetic"),
    )
    device._client = client
    device._is_paired = True
    device._physical_connection_active = True
    state_changes: list[bool] = []
    device.register_connection_state_callback(state_changes.append)

    with pytest.raises(BleakError):
        await device._execute_disconnect()

    client.disconnect.assert_awaited_once()
    assert device._client is client
    assert device.is_gatt_connected is True
    assert device.is_authenticated is True
    assert state_changes == []


async def test_pending_disconnect_retries_after_a_live_client_failure() -> None:
    """A failed policy release stays pending until one later real disconnect."""
    device = _make_device()
    client = _SyntheticConnectedClient(disconnect_error=RuntimeError("synthetic"))
    device._client = client
    device._is_paired = True
    device._physical_connection_active = True

    with pytest.raises(ServiceValidationError):
        await device.async_update_connection_policy(ble_control_enabled=False)

    assert device._pending_disconnect_target is ConnectionPolicyState.SUSPENDED
    assert device._disconnect_retry_task is not None
    assert device._client is client

    async def release_client() -> None:
        client.is_connected = False

    client.disconnect.side_effect = release_client
    await device._complete_pending_disconnect()

    assert device._pending_disconnect_target is None
    assert device.is_gatt_connected is False
    assert client.disconnect.await_count == 2
    await device.stop()


async def test_stale_disconnect_callback_cannot_mutate_replacement_client() -> None:
    """A late callback from a replaced client must be observational only."""
    device = _make_device()
    old_client = _SyntheticConnectedClient()
    new_client = _SyntheticConnectedClient()
    device._client = new_client
    device._is_paired = True
    device._physical_connection_active = True
    device._state_data_fresh = True
    device._schedule_reconnect = Mock()
    state_changes: list[bool] = []
    device.register_connection_state_callback(state_changes.append)

    device._disconnected(old_client)

    assert device._client is new_client
    assert device.is_gatt_connected is True
    assert device.is_authenticated is True
    assert device.state_data_fresh is True
    assert state_changes == []
    device._schedule_reconnect.assert_not_called()


async def test_operation_response_drains_before_suspension_disconnect() -> None:
    """A response started by an operation owns a drain lifetime of its own."""
    device = _make_device()
    client = _SyntheticConnectedClient()
    device._client = client
    device._is_paired = True
    device._physical_connection_active = True
    response_started = asyncio.Event()
    allow_response = asyncio.Event()
    disconnect_started = asyncio.Event()

    async def write_response(*_: object) -> bool:
        response_started.set()
        await allow_response.wait()
        return True

    async def disconnect(*, terminal: bool = False) -> None:
        del terminal
        disconnect_started.set()

    device._send_packet_while_connected = write_response
    device._execute_disconnect = disconnect
    async with device.connection_lease("operation", defer_connection=True):
        device._schedule_response(TuyaBLECode.FUN_RECEIVE_DP, b"", 1)
        await response_started.wait()

    suspension = asyncio.create_task(
        device.async_update_connection_policy(ble_control_enabled=False)
    )
    try:
        await asyncio.sleep(0)
        assert disconnect_started.is_set() is False
    finally:
        allow_response.set()
        await asyncio.gather(suspension, return_exceptions=True)
        await asyncio.gather(*device._response_tasks, return_exceptions=True)


async def test_config_entry_unload_timeout_defers_terminal_disconnect(
    hass: HomeAssistant,
) -> None:
    from pytest_homeassistant_custom_component.common import MockConfigEntry

    entry = MockConfigEntry(domain=DOMAIN, title="Synthetic unload")
    entry.add_to_hass(hass)
    device = _make_device()
    device._is_paired = True
    device._physical_connection_active = True
    disconnect = AsyncMock(wraps=device._execute_disconnect)
    device._execute_disconnect = disconnect
    data = _make_data(hass, device)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = data
    lease = device.connection_lease("unload operation", defer_connection=True)
    await lease.__aenter__()

    with (
        patch.object(
            hass.config_entries,
            "async_unload_platforms",
            new=AsyncMock(return_value=True),
        ),
        patch(
            "custom_components.tuya_ble.tuya_ble.tuya_ble.CONNECTION_POLICY_TRANSITION_TIMEOUT_SECONDS",
            0.01,
        ),
    ):
        assert await integration.async_unload_entry(hass, entry) is False

    assert disconnect.await_count == 0
    assert device._pending_disconnect_target is ConnectionPolicyState.STOPPED
    assert hass.data[DOMAIN][entry.entry_id] is data
    await lease.__aexit__(None, None, None)
    if data.coordinator._unsub_disconnect is not None:
        data.coordinator._unsub_disconnect()

    assert disconnect.await_count == 1
    assert device._pending_disconnect_target is None
    assert device.policy_state is ConnectionPolicyState.STOPPED
    assert device.is_authenticated is False

    with patch.object(
        hass.config_entries,
        "async_unload_platforms",
        new=AsyncMock(return_value=True),
    ):
        assert await integration.async_unload_entry(hass, entry) is True

    assert entry.entry_id not in hass.data[DOMAIN]


async def test_unload_retains_runtime_when_terminal_disconnect_is_unverified(
    hass: HomeAssistant,
) -> None:
    """Home Assistant must not unload away the only owner of a live client."""
    from pytest_homeassistant_custom_component.common import MockConfigEntry

    entry = MockConfigEntry(domain=DOMAIN, title="Synthetic unload failure")
    entry.add_to_hass(hass)
    device = _make_device()
    client = _SyntheticConnectedClient(disconnect_error=RuntimeError("synthetic"))
    device._client = client
    device._is_paired = True
    device._physical_connection_active = True
    data = _make_data(hass, device)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = data

    with patch.object(
        hass.config_entries,
        "async_unload_platforms",
        new=AsyncMock(return_value=True),
    ):
        assert await integration.async_unload_entry(hass, entry) is False

    assert hass.data[DOMAIN][entry.entry_id] is data
    assert device._client is client
    assert device._pending_disconnect_target is ConnectionPolicyState.STOPPED
    assert device._disconnect_retry_task is not None
    device._disconnect_retry_task.cancel()
    await asyncio.sleep(0)


async def test_suspension_does_not_interrupt_nested_existing_operation() -> None:
    persisted = asyncio.Event()

    async def persist(_: dict[str, object]) -> None:
        persisted.set()

    device = _make_device(persist_options=persist)
    device._send_datapoints = AsyncMock()
    device._execute_disconnect = AsyncMock()
    datapoint = device.datapoints.get_or_create(46, TuyaBLEDataPointType.DT_BOOL, False)

    async with device.connection_lease("active operation", defer_connection=True):
        suspension = asyncio.create_task(
            device.async_update_connection_policy(ble_control_enabled=False)
        )
        await persisted.wait()
        await datapoint.set_value(True)
        await asyncio.sleep(0)
        assert device._send_datapoints.await_count == 1
    await suspension

    assert device.active_lease_count == 0
    device._execute_disconnect.assert_awaited_once()


async def test_cancelled_lease_acquisition_releases_count() -> None:
    connection_started = asyncio.Event()
    release_connection = asyncio.Event()

    device = _make_device()

    async def wait_for_connection() -> None:
        connection_started.set()
        await release_connection.wait()

    device._ensure_connected = wait_for_connection
    lease_task = asyncio.create_task(device.connection_lease("cancelled").__aenter__())
    await connection_started.wait()
    lease_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await lease_task

    assert device.active_lease_count == 0
    release_connection.set()


async def test_persistence_failure_does_not_disconnect() -> None:
    async def persist(_: dict[str, object]) -> None:
        raise RuntimeError("synthetic persistence failure")

    device = _make_device(persist_options=persist)
    device._execute_disconnect = AsyncMock()

    with pytest.raises(ServiceValidationError) as raised:
        await device.async_update_connection_policy(ble_control_enabled=False)

    assert device.ble_control_enabled is True
    device._execute_disconnect.assert_not_awaited()
    rendered = "".join(
        traceback.format_exception(
            type(raised.value), raised.value, raised.value.__traceback__
        )
    )
    assert "synthetic persistence failure" not in rendered


async def test_repeated_suspension_application_is_idempotent() -> None:
    device = _make_device()
    device._execute_disconnect = AsyncMock()

    await asyncio.gather(
        device.async_update_connection_policy(ble_control_enabled=False),
        device.async_apply_persisted_options({CONF_BLE_CONTROL_ENABLED: False}),
    )

    device._execute_disconnect.assert_awaited_once()
    assert device.policy_state is ConnectionPolicyState.SUSPENDED


async def test_generic_resend_is_single_flight_and_cancelled_by_mode_change() -> None:
    device = _make_device()
    device._resend_packets = AsyncMock(side_effect=asyncio.sleep(60))

    device._schedule_resend([b"synthetic-fragment-1"])
    first_task = device._resend_task
    device._schedule_resend([b"synthetic-fragment-2"])
    assert device._resend_task is first_task

    await asyncio.sleep(0)
    await device.async_update_connection_policy(
        connection_mode=ConnectionMode.ON_DEMAND.value
    )
    await asyncio.sleep(0)

    assert first_task is not None
    assert first_task.done()
    device._resend_packets.assert_awaited_once_with([b"synthetic-fragment-1"])


async def test_reconnect_is_single_flight_and_stop_cancels_task() -> None:
    device = _make_device()
    reconnect_started = asyncio.Event()
    release_reconnect = asyncio.Event()

    async def wait_for_reconnect() -> None:
        reconnect_started.set()
        await release_reconnect.wait()

    device._reconnect = wait_for_reconnect
    device._schedule_reconnect()
    first_task = device._reconnect_task
    await reconnect_started.wait()
    device._schedule_reconnect()

    assert first_task is device._reconnect_task
    await device.stop()
    await asyncio.sleep(0)
    release_reconnect.set()
    assert first_task is not None
    assert first_task.done()
    assert device._reconnect_task is None


async def test_stop_cancels_startup_status_task() -> None:
    device = _make_device()
    startup_started = asyncio.Event()
    release_startup = asyncio.Event()

    async def wait_for_startup() -> None:
        startup_started.set()
        await release_startup.wait()

    device.update = wait_for_startup
    startup_task = asyncio.create_task(device.startup_update())
    device._startup_task = startup_task
    await startup_started.wait()
    await device.stop()
    with pytest.raises(asyncio.CancelledError):
        await startup_task
    release_startup.set()
    assert device._startup_task is None


async def test_late_advertisement_completes_deferred_connection() -> None:
    device = _make_device()
    device._ble_device = None
    device._ble_target_event.clear()
    device._local_key = b"synthetic-local-key"
    device._is_paired = True
    device._send_packet_while_connected = AsyncMock(return_value=True)
    client = Mock(is_connected=True)
    client.services.get_characteristic.return_value = None
    client.start_notify = AsyncMock()
    target = BLEDevice(
        name="Synthetic late target",
        address="00:00:00:00:00:22",
        details={},
    )

    with patch(
        "custom_components.tuya_ble.tuya_ble.tuya_ble.establish_connection",
        new=AsyncMock(return_value=client),
    ) as establish_connection:
        connection_task = asyncio.create_task(
            device.connection_lease("late advertisement").__aenter__()
        )
        await asyncio.sleep(0)
        device.set_ble_device_and_advertisement_data(target, Mock())
        lease = await asyncio.wait_for(connection_task, 1)
        await lease.__aexit__(None, None, None)

    establish_connection.assert_awaited_once()
    assert device.address == target.address


async def test_policy_lock_is_available_during_disconnect_wait() -> None:
    device = _make_device()
    disconnect_started = asyncio.Event()
    release_disconnect = asyncio.Event()

    async def wait_for_disconnect(*, terminal: bool = False) -> None:
        del terminal
        disconnect_started.set()
        await release_disconnect.wait()

    device._execute_disconnect = wait_for_disconnect
    suspension = asyncio.create_task(
        device.async_update_connection_policy(ble_control_enabled=False)
    )
    await disconnect_started.wait()

    async def acquire_policy_lock() -> None:
        async with device._policy_lock:
            return

    await asyncio.wait_for(acquire_policy_lock(), 1)
    release_disconnect.set()
    await suspension


async def test_stop_cancels_pending_protocol_response_task() -> None:
    device = _make_device()
    response_started = asyncio.Event()
    release_response = asyncio.Event()

    async def wait_for_response(*_: object) -> None:
        response_started.set()
        await release_response.wait()

    device._send_response = wait_for_response
    device._schedule_response(TuyaBLECode.FUN_RECEIVE_DP, b"", 1)
    await response_started.wait()
    await device.stop()
    await asyncio.sleep(0)

    assert not device._response_tasks
    release_response.set()


async def test_stop_releases_response_drain_when_task_never_starts() -> None:
    """Terminal cancellation before task startup cannot strand a live client."""
    device = _make_device()
    client = _SyntheticConnectedClient()
    device._client = client
    device._is_paired = True
    device._physical_connection_active = True

    device._schedule_response(TuyaBLECode.FUN_RECEIVE_DP, b"", 1)
    await device.stop()
    await asyncio.sleep(0)

    assert device._active_response_drain_count == 0
    assert device._pending_disconnect_target is None
    assert device.is_gatt_connected is False


async def test_response_task_does_not_inherit_lease_context() -> None:
    device = _make_device()
    observed: list[int] = []
    response_started = asyncio.Event()

    async def record_response(_: TuyaBLECode, __: bytes, ___: int) -> None:
        observed.append(_lease_context_depth(device))
        response_started.set()

    device._send_response = record_response
    async with device.connection_lease("operation", defer_connection=True):
        device._schedule_response(TuyaBLECode.FUN_RECEIVE_DP, b"", 1)
        await response_started.wait()

    assert observed == [0]
    observed.clear()
    response_started.clear()
    device._schedule_response(TuyaBLECode.FUN_RECEIVE_DP, b"", 1)
    await response_started.wait()
    assert observed == [0]


@pytest.mark.parametrize("stopped", (False, True), ids=("suspended", "stopped"))
async def test_lease_context_is_device_scoped_and_cannot_bypass_other_device(
    stopped: bool,
) -> None:
    device_a = _make_device()
    device_b = _make_device(enabled=stopped)
    device_b._ensure_connected = AsyncMock()
    device_b._send_datapoints = AsyncMock()
    if stopped:
        device_b._terminal_stopped = True
        device_b._policy_state = ConnectionPolicyState.STOPPED
    datapoint = device_b.datapoints.get_or_create(
        46, TuyaBLEDataPointType.DT_BOOL, False
    )

    async with device_a.connection_lease("device A", defer_connection=True):
        assert _lease_context_depth(device_a) == 1
        assert _lease_context_depth(device_b) == 0
        expected_error = (
            TuyaBLEConnectionUnavailableError
            if stopped
            else TuyaBLEControlSuspendedError
        )
        with pytest.raises(expected_error):
            await datapoint.set_value(True)

    assert _lease_context_depth(device_a) == 0
    assert _lease_context_depth(device_b) == 0
    device_b._ensure_connected.assert_not_awaited()
    device_b._send_datapoints.assert_not_awaited()
    assert datapoint.value is False


async def test_mode_change_while_suspended_does_not_connect() -> None:
    device = _make_device(enabled=False)
    device._ensure_connected = AsyncMock()

    await device.async_update_connection_policy(
        connection_mode=ConnectionMode.ON_DEMAND.value
    )
    assert device.connection_mode is ConnectionMode.ON_DEMAND
    assert device.effective_policy is EffectiveConnectionPolicy.SUSPENDED

    await device.async_update_connection_policy(ble_control_enabled=True)
    assert device.effective_policy is EffectiveConnectionPolicy.ON_DEMAND
    device._ensure_connected.assert_not_awaited()


async def test_policy_entities_are_available_while_disconnected(
    hass: HomeAssistant,
) -> None:
    device = _make_device(enabled=False)
    data = _make_data(hass, device)
    mode = TuyaBLEConnectionModeSelect(hass, data.coordinator, device, data.product)
    control = TuyaBLEControlSwitch(hass, data.coordinator, device, data.product)
    connection = TuyaBLEConnectionSensor(hass, data.coordinator, device, data.product)

    assert mode.available is True
    assert control.available is True
    assert control.is_on is False
    assert connection.available is True
    assert connection.is_on is False
    assert mode.entity_category is EntityCategory.CONFIG
    assert control.entity_category is EntityCategory.CONFIG
    assert connection.entity_category is EntityCategory.DIAGNOSTIC
    assert connection.device_class is BinarySensorDeviceClass.CONNECTIVITY


async def test_target_connection_entity_is_added_only_for_s1_and_v1(
    hass: HomeAssistant,
) -> None:
    from pytest_homeassistant_custom_component.common import MockConfigEntry

    entry = MockConfigEntry(domain=DOMAIN, title="Synthetic policy")
    entry.add_to_hass(hass)
    device = _make_device()
    data = _make_data(hass, device)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = data
    added: list[object] = []

    await async_setup_binary_sensors(hass, entry, added.extend)

    assert any(isinstance(entity, TuyaBLEConnectionSensor) for entity in added)
    assert len(added) == 2
    assert isinstance(added[0], TuyaBLEConnectionSensor)
    assert isinstance(added[1], object)


async def test_s1_lock_lease_wraps_both_unlock_writes(
    hass: HomeAssistant,
) -> None:
    device = _make_device()
    device._send_datapoints = AsyncMock()
    device._ensure_connected = AsyncMock()
    coordinator = TuyaBLECoordinator(hass, device)
    store = Mock()
    store.templates_for.return_value = (
        b"synthetic-dp70",
        b"synthetic-dp71-template-000",
    )
    entity = TuyaBLES1Lock(
        hass,
        coordinator,
        device,
        TuyaBLEProductInfo("S1-TY-BLE-PRO"),
        store,
    )
    entity.async_write_ha_state = Mock()
    with patch("custom_components.tuya_ble.lock.asyncio.sleep", AsyncMock()):
        await entity.async_unlock()
    assert device.active_lease_count == 0
    assert device._send_datapoints.await_count == 2
    assert entity.is_unlocking is False


async def test_suspended_lock_commands_perform_zero_writes(
    hass: HomeAssistant,
) -> None:
    device = _make_device(enabled=False)
    device._send_datapoints = AsyncMock()
    device._send_datapoints_once = AsyncMock()
    coordinator = TuyaBLECoordinator(hass, device)
    v1_entity = TuyaBLEV1Lock(
        hass,
        coordinator,
        device,
        TuyaBLEProductInfo("V1 Smart Lock"),
    )
    v1_entity.async_write_ha_state = Mock()

    with pytest.raises(ServiceValidationError):
        await v1_entity.async_lock()
    with pytest.raises(ServiceValidationError):
        await v1_entity.async_unlock()

    assert device._send_datapoints.await_count == 0
    assert device._send_datapoints_once.await_count == 0


async def test_suspended_vacuum_command_performs_zero_writes(
    hass: HomeAssistant,
) -> None:
    device = _make_device(enabled=False)
    device._send_datapoints = AsyncMock()
    coordinator = TuyaBLECoordinator(hass, device)
    entity = TuyaBLEVacuumEntity(
        hass,
        coordinator,
        device,
        TuyaBLEProductInfo("Synthetic vacuum"),
        TuyaBLEVacuumMapping(
            dp_start_bool=1,
            status_map={"idle": VacuumActivity.IDLE},
        ),
    )

    with pytest.raises(TuyaBLEControlSuspendedError):
        await entity.async_start()

    assert device._send_datapoints.await_count == 0


async def test_options_flow_connection_settings_preserve_credentials(
    hass: HomeAssistant,
) -> None:
    from pytest_homeassistant_custom_component.common import MockConfigEntry

    entry = MockConfigEntry(
        domain=DOMAIN,
        title="Synthetic policy",
        data={"address": SYNTHETIC_ADDRESS},
        options={
            "access_id": "synthetic-access-id",
            "access_secret": "synthetic-access-secret",
            "username": "synthetic-user",
            "password": "synthetic-password",
        },
    )
    entry.add_to_hass(hass)
    device = _make_device()
    device._persist_options = AsyncMock()
    data = _make_data(hass, device)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = data

    flow = TuyaBLEOptionsFlow(entry)
    flow.hass = hass
    result = await flow.async_step_connection_settings(
        {
            CONF_CONNECTION_MODE: ConnectionMode.ON_DEMAND.value,
            CONF_BLE_CONTROL_ENABLED: False,
        }
    )

    assert result["type"] == "create_entry"
    assert result["data"]["access_id"] == "synthetic-access-id"
    assert result["data"][CONF_CONNECTION_MODE] == ConnectionMode.ON_DEMAND.value
    assert result["data"][CONF_BLE_CONTROL_ENABLED] is False
    device._persist_options.assert_awaited_once_with(
        {
            CONF_CONNECTION_MODE: ConnectionMode.ON_DEMAND.value,
            CONF_BLE_CONTROL_ENABLED: False,
        }
    )
