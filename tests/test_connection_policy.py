"""Tests for per-device BLE connection policy and control entities."""

from __future__ import annotations

import asyncio
import traceback
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest
from bleak.backends.device import BLEDevice
from bleak_retry_connector import BleakError
from homeassistant.components.binary_sensor import BinarySensorDeviceClass
from homeassistant.components.vacuum import VacuumActivity
from homeassistant.config_entries import ConfigEntry, ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ServiceValidationError
from homeassistant.helpers.entity import EntityCategory

from custom_components import tuya_ble as integration
from custom_components.tuya_ble.binary_sensor import (
    TuyaBLEConnectionSensor,
)
from custom_components.tuya_ble.binary_sensor import (
    async_setup_entry as async_setup_binary_sensors,
)
from custom_components.tuya_ble.config_flow import TuyaBLEOptionsFlow
from custom_components.tuya_ble.const import (
    CONF_BLE_CONTROL_ENABLED,
    CONF_CONNECTION_MODE,
    DOMAIN,
    ConnectionMode,
    ConnectionPolicyState,
    EffectiveConnectionPolicy,
    PendingRelease,
    PendingReleaseReason,
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
from custom_components.tuya_ble.tuya_ble.const import (
    CHARACTERISTIC_NOTIFY_FD50,
    TuyaBLECode,
)
from custom_components.tuya_ble.tuya_ble.exceptions import (
    TuyaBLEConnectionUnavailableError,
    TuyaBLEControlSuspendedError,
)
from custom_components.tuya_ble.tuya_ble.manager import TuyaBLEDeviceCredentials
from custom_components.tuya_ble.tuya_ble.tuya_ble import _lease_context_depth
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
        self.start_notify = AsyncMock()
        self.write_gatt_char = AsyncMock()

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
    device._notifications_active = True
    lease = device.connection_lease("idle operation", defer_connection=True)

    with patch(
        "custom_components.tuya_ble.tuya_ble.tuya_ble.DEFAULT_ON_DEMAND_IDLE_DISCONNECT_SECONDS",
        0.01,
    ):
        await lease.__aenter__()
        await lease.__aexit__(None, None, None)
        await asyncio.sleep(0.02)

    assert device._client is client
    assert device._pending_release is not None
    assert device._pending_release.reason is PendingReleaseReason.SETUP_FAILURE
    assert device._disconnect_retry_task is not None
    device._disconnect_retry_task.cancel()
    await asyncio.sleep(0)


async def test_mode_change_supersedes_inflight_idle_disconnect() -> None:
    """An old idle release cannot leave Always connected idle and disconnected."""
    device = _make_device(mode=ConnectionMode.ON_DEMAND)
    client = _SyntheticConnectedClient()
    disconnect_started = asyncio.Event()
    allow_disconnect = asyncio.Event()

    async def disconnect() -> None:
        disconnect_started.set()
        await allow_disconnect.wait()
        client.is_connected = False

    client.disconnect.side_effect = disconnect
    device._client = client
    device._is_paired = True
    device._physical_connection_active = True
    device._notifications_active = True
    device._schedule_reconnect_locked = Mock()

    with patch(
        "custom_components.tuya_ble.tuya_ble.tuya_ble.DEFAULT_ON_DEMAND_IDLE_DISCONNECT_SECONDS",
        0,
    ):
        idle_disconnect = asyncio.create_task(device._idle_disconnect_after_delay())
        await disconnect_started.wait()
        await device.async_update_connection_policy(
            connection_mode=ConnectionMode.ALWAYS_CONNECTED.value
        )
        allow_disconnect.set()
        await idle_disconnect

    assert device.connection_mode is ConnectionMode.ALWAYS_CONNECTED
    assert device.policy_state is not ConnectionPolicyState.ON_DEMAND_IDLE
    assert device.is_gatt_connected is False
    device._schedule_reconnect_locked.assert_called_once_with(0)


async def test_mode_change_cancels_pending_idle_disconnect_retry() -> None:
    """Always connected supersedes a failed On-demand idle release retry."""
    device = _make_device(mode=ConnectionMode.ON_DEMAND)
    client = _SyntheticConnectedClient(disconnect_error=RuntimeError("synthetic"))
    device._client = client
    device._is_paired = True
    device._physical_connection_active = True
    device._notifications_active = True
    device._pending_release = PendingRelease(
        PendingReleaseReason.ON_DEMAND_IDLE,
        device._policy_revision,
    )
    device._schedule_disconnect_retry_locked()

    await device.async_update_connection_policy(
        connection_mode=ConnectionMode.ALWAYS_CONNECTED.value
    )

    assert device.connection_mode is ConnectionMode.ALWAYS_CONNECTED
    assert device._pending_release is None
    assert device._disconnect_retry_task is None
    assert device.policy_state is ConnectionPolicyState.ALWAYS_CONNECTED_ACTIVE


def _prepare_new_client(client: _SyntheticConnectedClient) -> None:
    """Provide the minimum GATT surface required by connection setup."""
    client.services = Mock()
    client.services.get_characteristic.return_value = None
    client.start_notify = AsyncMock()


async def _seed_failed_setup_release(
    device: TuyaBLEDevice,
    client: _SyntheticConnectedClient,
) -> asyncio.Task:
    """Create a real failed-setup release with one retry owner."""
    _prepare_new_client(client)
    await device._cleanup_new_client(client, terminal=False)
    assert device._pending_release is not None
    assert device._pending_release.reason is PendingReleaseReason.SETUP_FAILURE
    assert device._disconnect_retry_task is not None
    return device._disconnect_retry_task


async def _apply_mode_change(
    device: TuyaBLEDevice,
    mode: ConnectionMode,
    persisted: bool,
) -> None:
    """Apply one visible policy change through either supported path."""
    if persisted:
        await device.async_apply_persisted_options(
            {
                CONF_CONNECTION_MODE: mode.value,
                CONF_BLE_CONTROL_ENABLED: True,
            }
        )
        return
    await device.async_update_connection_policy(connection_mode=mode.value)


@pytest.mark.parametrize("persisted", (False, True), ids=("direct", "persisted"))
@pytest.mark.parametrize(
    ("initial_mode", "new_mode"),
    (
        (ConnectionMode.ALWAYS_CONNECTED, ConnectionMode.ON_DEMAND),
        (ConnectionMode.ON_DEMAND, ConnectionMode.ALWAYS_CONNECTED),
    ),
    ids=("always-to-on-demand", "on-demand-to-always"),
)
async def test_setup_release_survives_visible_mode_changes(
    persisted: bool,
    initial_mode: ConnectionMode,
    new_mode: ConnectionMode,
) -> None:
    """Desired policy changes cannot discard mandatory setup cleanup."""
    device = _make_device(mode=initial_mode)
    client = _SyntheticConnectedClient(disconnect_error=RuntimeError("synthetic"))
    device._send_datapoints = AsyncMock()
    device._schedule_reconnect_locked = Mock()

    with patch("custom_components.tuya_ble.tuya_ble.tuya_ble.BLEAK_BACKOFF_TIME", 0.01):
        retry_owner = await _seed_failed_setup_release(device, client)
        await _apply_mode_change(device, new_mode, persisted)

        assert device._pending_release is not None
        assert device._pending_release.reason is PendingReleaseReason.SETUP_FAILURE
        assert device._client is client
        assert device._disconnect_retry_task is retry_owner
        assert device._reconnect_task is None
        assert device.policy_state is ConnectionPolicyState.DISCONNECT_FAILED
        assert device.is_gatt_connected is True
        assert device.is_connection_active is False
        with pytest.raises(TuyaBLEConnectionUnavailableError):
            device.ensure_control_available()
        device._send_datapoints.assert_not_awaited()

        async def release_client() -> None:
            client.is_connected = False

        client.disconnect.side_effect = release_client
        await asyncio.wait_for(retry_owner, 0.2)

    assert device._client is None
    assert device._pending_release is None
    assert device._disconnect_retry_task is None
    assert device.is_authenticated is False
    assert device.connection_mode is new_mode
    if new_mode is ConnectionMode.ALWAYS_CONNECTED:
        assert device.policy_state is ConnectionPolicyState.ALWAYS_CONNECTED_CONNECTING
        device._schedule_reconnect_locked.assert_called_once_with(0)
    else:
        assert device.policy_state is ConnectionPolicyState.ON_DEMAND_IDLE
        device._schedule_reconnect_locked.assert_not_called()
    device._send_datapoints.assert_not_awaited()


async def test_setup_release_survives_ble_control_off_on_sequence() -> None:
    """Re-enabling BLE control cannot cancel failed-setup cleanup."""
    device = _make_device()
    client = _SyntheticConnectedClient()
    release_attempts = 0
    second_failure = asyncio.Event()
    allow_release = asyncio.Event()

    async def disconnect() -> None:
        nonlocal release_attempts
        release_attempts += 1
        if release_attempts == 1:
            raise RuntimeError("synthetic")
        if release_attempts == 2:
            second_failure.set()
            raise RuntimeError("synthetic")
        await allow_release.wait()
        client.is_connected = False

    client.disconnect.side_effect = disconnect
    device._send_datapoints = AsyncMock()
    device._schedule_reconnect_locked = Mock()

    with patch("custom_components.tuya_ble.tuya_ble.tuya_ble.BLEAK_BACKOFF_TIME", 0.01):
        retry_owner = await _seed_failed_setup_release(device, client)
        await device.async_update_connection_policy(ble_control_enabled=False)
        await asyncio.wait_for(second_failure.wait(), 0.2)
        await device.async_update_connection_policy(ble_control_enabled=True)

        assert device._pending_release is not None
        assert device._pending_release.reason is PendingReleaseReason.SETUP_FAILURE
        assert device._client is client
        assert device._disconnect_retry_task is retry_owner
        assert device._reconnect_task is None
        with pytest.raises(TuyaBLEConnectionUnavailableError):
            device.ensure_control_available()

        allow_release.set()
        await asyncio.wait_for(retry_owner, 0.2)

    assert release_attempts == 3
    assert device._client is None
    assert device._pending_release is None
    assert device._disconnect_retry_task is None
    assert device.ble_control_enabled is True
    assert device.policy_state is ConnectionPolicyState.ALWAYS_CONNECTED_CONNECTING
    device._schedule_reconnect_locked.assert_called_once_with(0)
    device._send_datapoints.assert_not_awaited()


async def test_setup_release_reconciles_to_disabled_ble_control() -> None:
    """Verified mandatory cleanup reconciles to persistent suspension."""
    device = _make_device()
    client = _SyntheticConnectedClient(disconnect_error=RuntimeError("synthetic"))
    device._send_datapoints = AsyncMock()
    device._schedule_reconnect_locked = Mock()

    with patch("custom_components.tuya_ble.tuya_ble.tuya_ble.BLEAK_BACKOFF_TIME", 0.01):
        retry_owner = await _seed_failed_setup_release(device, client)
        await device.async_update_connection_policy(ble_control_enabled=False)

        assert device._pending_release is not None
        assert device._pending_release.reason is PendingReleaseReason.SETUP_FAILURE
        assert device._disconnect_retry_task is retry_owner

        async def release_client() -> None:
            client.is_connected = False

        client.disconnect.side_effect = release_client
        await asyncio.wait_for(retry_owner, 0.2)

    assert device._pending_release is None
    assert device._disconnect_retry_task is None
    assert device._client is None
    assert device.ble_control_enabled is False
    assert device.policy_state is ConnectionPolicyState.SUSPENDED
    assert device.effective_policy is EffectiveConnectionPolicy.SUSPENDED
    device._schedule_reconnect_locked.assert_not_called()
    device._send_datapoints.assert_not_awaited()


async def test_setup_release_survives_policy_change_during_physical_retry() -> None:
    """An in-progress retry remains authoritative through a policy change."""
    device = _make_device()
    client = _SyntheticConnectedClient()
    retry_started = asyncio.Event()
    allow_release = asyncio.Event()
    release_attempts = 0

    async def disconnect() -> None:
        nonlocal release_attempts
        release_attempts += 1
        if release_attempts == 1:
            raise RuntimeError("synthetic")
        retry_started.set()
        await allow_release.wait()
        client.is_connected = False

    client.disconnect.side_effect = disconnect
    device._send_datapoints = AsyncMock()
    device._schedule_reconnect_locked = Mock()

    with patch("custom_components.tuya_ble.tuya_ble.tuya_ble.BLEAK_BACKOFF_TIME", 0.01):
        retry_owner = await _seed_failed_setup_release(device, client)
        await asyncio.wait_for(retry_started.wait(), 0.2)
        assert device._disconnect_in_progress is True

        await device.async_update_connection_policy(
            connection_mode=ConnectionMode.ON_DEMAND.value
        )

        assert device._pending_release is not None
        assert device._pending_release.reason is PendingReleaseReason.SETUP_FAILURE
        assert device._client is client
        assert device._disconnect_retry_task is retry_owner
        assert device._reconnect_task is None
        with pytest.raises(TuyaBLEConnectionUnavailableError):
            device.ensure_control_available()

        allow_release.set()
        await asyncio.wait_for(retry_owner, 0.2)

    assert device._client is None
    assert device._pending_release is None
    assert device._disconnect_retry_task is None
    assert device.connection_mode is ConnectionMode.ON_DEMAND
    assert device.policy_state is ConnectionPolicyState.ON_DEMAND_IDLE
    device._schedule_reconnect_locked.assert_not_called()
    device._send_datapoints.assert_not_awaited()


async def test_terminal_stop_retains_live_client_returned_by_connection() -> None:
    """A terminal in-flight connection remains owned when release fails."""
    device = _make_device()
    client = _SyntheticConnectedClient(disconnect_error=RuntimeError("synthetic"))
    _prepare_new_client(client)
    connection_started = asyncio.Event()
    release_connection = asyncio.Event()

    async def establish(*_: object, **__: object) -> _SyntheticConnectedClient:
        connection_started.set()
        await release_connection.wait()
        return client

    with patch(
        "custom_components.tuya_ble.tuya_ble.tuya_ble.establish_connection",
        new=establish,
    ):
        connection = asyncio.create_task(device._ensure_connected())
        await connection_started.wait()
        stop = asyncio.create_task(device.stop())
        await asyncio.sleep(0)
        assert device._terminal_stopped is True
        release_connection.set()
        with pytest.raises(TuyaBLEConnectionUnavailableError):
            await connection
        await stop

    assert device._client is client
    assert device.is_gatt_connected is True
    assert device._pending_release is not None
    assert device._pending_release.reason is PendingReleaseReason.STOP
    assert device._disconnect_retry_task is not None
    device._disconnect_retry_task.cancel()
    await asyncio.sleep(0)


async def test_terminal_stop_retains_in_progress_setup_release_owner() -> None:
    """Terminal supersession cannot cancel the active physical-release owner."""
    device = _make_device()
    client = _SyntheticConnectedClient()
    retry_started = asyncio.Event()
    allow_release = asyncio.Event()
    release_attempts = 0

    async def disconnect() -> None:
        nonlocal release_attempts
        release_attempts += 1
        if release_attempts == 1:
            raise RuntimeError("synthetic")
        retry_started.set()
        await allow_release.wait()
        client.is_connected = False

    client.disconnect.side_effect = disconnect

    with patch("custom_components.tuya_ble.tuya_ble.tuya_ble.BLEAK_BACKOFF_TIME", 0.01):
        retry_owner = await _seed_failed_setup_release(device, client)
        await asyncio.wait_for(retry_started.wait(), 0.2)
        stop = asyncio.create_task(device.stop())
        await asyncio.sleep(0)
        pending = device._pending_release
        retained_owner = device._disconnect_retry_task
        allow_release.set()
        await asyncio.gather(stop, retry_owner, return_exceptions=True)

    assert pending is not None
    assert pending.reason is PendingReleaseReason.STOP
    assert retained_owner is retry_owner
    assert release_attempts == 2
    assert device._client is None
    assert device._pending_release is None
    assert device._disconnect_retry_task is None
    assert device.policy_state is ConnectionPolicyState.STOPPED


@pytest.mark.parametrize(
    "failure",
    ("start_notify", "device_info", "pairing"),
)
async def test_setup_failure_retains_live_client_until_release_is_verified(
    failure: str,
) -> None:
    """Setup failures must not discard a connected client whose release fails."""
    device = _make_device()
    client = _SyntheticConnectedClient(disconnect_error=RuntimeError("synthetic"))
    _prepare_new_client(client)
    if failure == "start_notify":
        client.start_notify.side_effect = RuntimeError("synthetic")
    else:
        device._send_packet_while_connected = AsyncMock(
            side_effect=RuntimeError("synthetic")
        )

    with patch(
        "custom_components.tuya_ble.tuya_ble.tuya_ble.establish_connection",
        new=AsyncMock(return_value=client),
    ):
        with pytest.raises(BleakError):
            await device._ensure_connected()

    assert device._client is client
    assert device.is_gatt_connected is True
    assert device._pending_release is not None
    assert device._pending_release.reason is PendingReleaseReason.SETUP_FAILURE
    assert device._disconnect_retry_task is not None
    device._disconnect_retry_task.cancel()
    await asyncio.sleep(0)


async def test_start_notify_failure_reports_release_only_after_success() -> None:
    """A setup failure reports disconnected only when cleanup releases GATT."""
    device = _make_device()
    client = _SyntheticConnectedClient()
    _prepare_new_client(client)
    client.start_notify.side_effect = RuntimeError("synthetic")
    state_changes: list[bool] = []
    device.register_connection_state_callback(state_changes.append)

    with patch(
        "custom_components.tuya_ble.tuya_ble.tuya_ble.establish_connection",
        new=AsyncMock(return_value=client),
    ):
        with pytest.raises(BleakError):
            await device._ensure_connected()

    assert device._client is None
    assert device.is_gatt_connected is False
    assert state_changes == [False]
    client.disconnect.assert_awaited_once()


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
    device._notifications_active = True
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
    assert device._pending_release is not None
    assert device._pending_release.reason is PendingReleaseReason.SUSPEND
    await lease.__aexit__(None, None, None)

    assert disconnect.await_count == 1
    assert device._pending_release is None
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
    device._notifications_active = True
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

    assert device._pending_release is not None
    assert device._pending_release.reason is PendingReleaseReason.SUSPEND
    await device.async_update_connection_policy(ble_control_enabled=True)
    await lease.__aexit__(None, None, None)
    await asyncio.sleep(0)

    assert device.ble_control_enabled is True
    assert device.effective_policy is not EffectiveConnectionPolicy.SUSPENDED
    assert device.policy_state is not ConnectionPolicyState.SUSPENDED
    assert device._pending_release is None
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
    device._notifications_active = True
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
    assert device._pending_release is None
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
    device._notifications_active = True
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
    device._notifications_active = True
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
    device._notifications_active = True

    with pytest.raises(ServiceValidationError):
        await device.async_update_connection_policy(ble_control_enabled=False)

    assert device._pending_release is not None
    assert device._pending_release.reason is PendingReleaseReason.SETUP_FAILURE
    assert device._disconnect_retry_task is not None
    assert device._client is client

    async def release_client() -> None:
        client.is_connected = False

    client.disconnect.side_effect = release_client
    await device._complete_pending_release()

    assert device._pending_release is None
    assert device.is_gatt_connected is False
    assert client.disconnect.await_count == 2
    await device.stop()


@pytest.mark.parametrize("persisted", (False, True), ids=("direct", "persisted"))
@pytest.mark.parametrize(
    "mode",
    (ConnectionMode.ALWAYS_CONNECTED, ConnectionMode.ON_DEMAND),
    ids=("always-connected", "on-demand"),
)
async def test_failed_suspension_release_remains_mandatory_after_reenable(
    persisted: bool,
    mode: ConnectionMode,
) -> None:
    """A connected session without notifications cannot become command-ready."""
    device = _make_device(mode=mode)
    client = _SyntheticConnectedClient(disconnect_error=RuntimeError("synthetic"))
    device._client = client
    device._is_paired = True
    device._physical_connection_active = True
    device._notifications_active = True
    device._send_datapoints = AsyncMock()
    device._schedule_reconnect_locked = Mock()

    with (
        patch("custom_components.tuya_ble.tuya_ble.tuya_ble.BLEAK_BACKOFF_TIME", 60),
        pytest.raises(ServiceValidationError),
    ):
        await device.async_update_connection_policy(ble_control_enabled=False)

    retry_owner = device._disconnect_retry_task
    assert retry_owner is not None
    assert client.stop_notify.await_count == 1

    if persisted:
        await device.async_apply_persisted_options(
            {
                CONF_CONNECTION_MODE: mode.value,
                CONF_BLE_CONTROL_ENABLED: True,
            }
        )
    else:
        await device.async_update_connection_policy(ble_control_enabled=True)

    if device._idle_disconnect_task is not None:
        device._idle_disconnect_task.cancel()
        await asyncio.sleep(0)

    assert device._pending_release is not None
    assert device._pending_release.reason is PendingReleaseReason.SETUP_FAILURE
    assert device._disconnect_retry_task is retry_owner
    assert device._client is client
    assert device._reconnect_task is None
    assert device._notifications_active is False
    assert device.is_gatt_connected is True
    assert device.is_connection_active is False
    with pytest.raises(TuyaBLEConnectionUnavailableError):
        device.ensure_control_available()
    device._send_datapoints.assert_not_awaited()

    async def release_client() -> None:
        client.is_connected = False

    client.disconnect.side_effect = release_client
    retry_owner.cancel()
    await asyncio.sleep(0)
    device._disconnect_retry_task = None
    await device._complete_pending_release()

    assert device._pending_release is None
    assert device._client is None
    assert device.ble_control_enabled is True
    if mode is ConnectionMode.ALWAYS_CONNECTED:
        device._schedule_reconnect_locked.assert_called_once_with(0)
    else:
        device._schedule_reconnect_locked.assert_not_called()


@pytest.mark.parametrize("persisted", (False, True), ids=("direct", "persisted"))
async def test_failed_idle_release_remains_mandatory_after_always_connected(
    persisted: bool,
) -> None:
    """Always connected cannot supersede an unusable On-demand GATT session."""
    device = _make_device(mode=ConnectionMode.ON_DEMAND)
    client = _SyntheticConnectedClient(disconnect_error=RuntimeError("synthetic"))
    device._client = client
    device._is_paired = True
    device._physical_connection_active = True
    device._notifications_active = True
    device._send_datapoints = AsyncMock()
    device._schedule_reconnect_locked = Mock()
    device._pending_release = PendingRelease(
        PendingReleaseReason.ON_DEMAND_IDLE,
        device._policy_revision,
    )

    with patch("custom_components.tuya_ble.tuya_ble.tuya_ble.BLEAK_BACKOFF_TIME", 60):
        await device._complete_pending_release()
        retry_owner = device._disconnect_retry_task
        assert retry_owner is not None

        if persisted:
            await device.async_apply_persisted_options(
                {
                    CONF_CONNECTION_MODE: ConnectionMode.ALWAYS_CONNECTED.value,
                    CONF_BLE_CONTROL_ENABLED: True,
                }
            )
        else:
            await device.async_update_connection_policy(
                connection_mode=ConnectionMode.ALWAYS_CONNECTED.value
            )

    assert device._pending_release is not None
    assert device._pending_release.reason is PendingReleaseReason.SETUP_FAILURE
    assert device._disconnect_retry_task is retry_owner
    assert device._client is client
    assert device._reconnect_task is None
    assert device.is_connection_active is False
    with pytest.raises(TuyaBLEConnectionUnavailableError):
        device.ensure_control_available()
    device._send_datapoints.assert_not_awaited()

    async def release_client() -> None:
        client.is_connected = False

    client.disconnect.side_effect = release_client
    retry_owner.cancel()
    await asyncio.sleep(0)
    device._disconnect_retry_task = None
    await device._complete_pending_release()

    assert device._pending_release is None
    assert device._client is None
    device._schedule_reconnect_locked.assert_called_once_with(0)


async def test_policy_change_while_failed_release_retry_is_in_progress() -> None:
    """A blocked retry remains the only owner until verified physical release."""
    device = _make_device(mode=ConnectionMode.ON_DEMAND)
    client = _SyntheticConnectedClient()
    retry_started = asyncio.Event()
    allow_release = asyncio.Event()
    release_attempts = 0

    async def disconnect() -> None:
        nonlocal release_attempts
        release_attempts += 1
        if release_attempts == 1:
            raise RuntimeError("synthetic")
        retry_started.set()
        await allow_release.wait()
        client.is_connected = False

    client.disconnect.side_effect = disconnect
    device._client = client
    device._is_paired = True
    device._physical_connection_active = True
    device._notifications_active = True
    device._schedule_reconnect_locked = Mock()
    device._pending_release = PendingRelease(
        PendingReleaseReason.ON_DEMAND_IDLE,
        device._policy_revision,
    )

    with patch("custom_components.tuya_ble.tuya_ble.tuya_ble.BLEAK_BACKOFF_TIME", 0.01):
        await device._complete_pending_release()
        retry_owner = device._disconnect_retry_task
        assert retry_owner is not None
        await asyncio.wait_for(retry_started.wait(), 0.2)

        await device.async_update_connection_policy(
            connection_mode=ConnectionMode.ALWAYS_CONNECTED.value
        )

        assert device._disconnect_in_progress is True
        assert device._disconnect_retry_task is retry_owner
        assert device._pending_release is not None
        assert device._pending_release.reason is PendingReleaseReason.SETUP_FAILURE
        assert device._reconnect_task is None
        device._schedule_reconnect_locked.assert_not_called()

        allow_release.set()
        await asyncio.wait_for(retry_owner, 0.2)

    assert release_attempts == 2
    assert device._client is None
    assert device._pending_release is None
    assert device._disconnect_retry_task is None
    device._schedule_reconnect_locked.assert_called_once_with(0)


async def test_failed_release_repair_rejects_all_command_paths(
    hass: HomeAssistant,
) -> None:
    """S1, V1, and generic writes fail before traffic on an unusable session."""
    device = _make_device()
    client = _SyntheticConnectedClient(disconnect_error=RuntimeError("synthetic"))
    device._client = client
    device._is_paired = True
    device._physical_connection_active = True
    device._notifications_active = True
    device._protocol_version = 3
    device._send_datapoints = AsyncMock()
    device._send_datapoints_once = AsyncMock()
    device._schedule_reconnect_locked = Mock()

    with (
        patch("custom_components.tuya_ble.tuya_ble.tuya_ble.BLEAK_BACKOFF_TIME", 60),
        pytest.raises(ServiceValidationError),
    ):
        await device.async_update_connection_policy(ble_control_enabled=False)
    await device.async_update_connection_policy(ble_control_enabled=True)

    retry_owner = device._disconnect_retry_task
    assert retry_owner is not None
    coordinator = TuyaBLECoordinator(hass, device)
    template_store = Mock()
    template_store.templates_for.return_value = (
        b"synthetic-dp70",
        b"synthetic-dp71-template-000",
    )
    s1 = TuyaBLES1Lock(
        hass,
        coordinator,
        device,
        TuyaBLEProductInfo("S1-TY-BLE-PRO"),
        template_store,
    )
    v1 = TuyaBLEV1Lock(
        hass,
        coordinator,
        device,
        TuyaBLEProductInfo("V1 Smart Lock"),
    )
    s1.async_write_ha_state = Mock()
    v1.async_write_ha_state = Mock()
    generic = device.datapoints.get_or_create(1, TuyaBLEDataPointType.DT_BOOL, False)
    connection = TuyaBLEConnectionSensor(
        hass,
        coordinator,
        device,
        TuyaBLEProductInfo("Synthetic connection"),
    )

    for command in (
        s1.async_lock,
        s1.async_unlock,
        v1.async_lock,
        v1.async_unlock,
    ):
        with pytest.raises(ServiceValidationError):
            await command()
    with pytest.raises(TuyaBLEConnectionUnavailableError):
        await generic.set_value(True)

    device._send_datapoints.assert_not_awaited()
    device._send_datapoints_once.assert_not_awaited()
    device._schedule_reconnect_locked.assert_not_called()
    assert device._client is client
    assert device.is_connection_active is False
    assert connection.is_on is True
    assert device._pending_release is not None
    assert device._pending_release.reason is PendingReleaseReason.SETUP_FAILURE

    retry_owner.cancel()
    await asyncio.sleep(0)
    device._disconnect_retry_task = None


async def test_stale_disconnect_callback_cannot_mutate_replacement_client() -> None:
    """A late callback from a replaced client must be observational only."""
    device = _make_device()
    old_client = _SyntheticConnectedClient()
    new_client = _SyntheticConnectedClient()
    device._client = new_client
    device._is_paired = True
    device._physical_connection_active = True
    device._notifications_active = True
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
    device._notifications_active = True
    response_started = asyncio.Event()
    allow_response = asyncio.Event()
    disconnect_started = asyncio.Event()

    async def write_response(*_: object, **__: object) -> bool:
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


async def test_config_entry_unload_timeout_restores_operational_runtime(
    hass: HomeAssistant,
) -> None:
    """A quiesce timeout restores policy without terminalizing the runtime."""
    from pytest_homeassistant_custom_component.common import MockConfigEntry

    entry = MockConfigEntry(domain=DOMAIN, title="Synthetic unload")
    entry.add_to_hass(hass)
    device = _make_device()
    device._is_paired = True
    device._physical_connection_active = True
    device._notifications_active = True
    disconnect = AsyncMock(wraps=device._execute_disconnect)
    device._execute_disconnect = disconnect
    device._schedule_reconnect_locked = Mock()
    data = _make_data(hass, device)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = data
    lease = device.connection_lease("unload operation", defer_connection=True)
    await lease.__aenter__()

    with (
        patch.object(
            integration,
            "_async_unload_platforms_transactional",
            new=AsyncMock(return_value=integration._PlatformUnloadOutcome.UNLOADED),
        ) as unload_platforms,
        patch(
            "custom_components.tuya_ble.tuya_ble.tuya_ble.CONNECTION_POLICY_TRANSITION_TIMEOUT_SECONDS",
            0.01,
        ),
    ):
        assert await integration.async_unload_entry(hass, entry) is False

    assert disconnect.await_count == 0
    unload_platforms.assert_not_awaited()
    assert device._pending_release is None
    assert device._terminal_stopped is False
    assert device.effective_policy is EffectiveConnectionPolicy.ALWAYS_CONNECTED
    assert hass.data[DOMAIN][entry.entry_id] is data
    await lease.__aexit__(None, None, None)
    if data.coordinator._unsub_disconnect is not None:
        data.coordinator._unsub_disconnect()

    assert disconnect.await_count == 0
    assert device._pending_release is None
    assert device.policy_state is ConnectionPolicyState.ALWAYS_CONNECTED_CONNECTING
    device.ensure_control_available()

    with patch.object(
        integration,
        "_async_unload_platforms_transactional",
        new=AsyncMock(return_value=integration._PlatformUnloadOutcome.UNLOADED),
    ):
        assert await integration.async_unload_entry(hass, entry) is True

    assert entry.entry_id not in hass.data[DOMAIN]
    assert device._terminal_stopped is True
    assert device.policy_state is ConnectionPolicyState.STOPPED
    if data.coordinator._unsub_disconnect is not None:
        data.coordinator._unsub_disconnect()


async def test_unload_release_failure_restores_operational_runtime(
    hass: HomeAssistant,
) -> None:
    """Failed GATT release restores the loaded entry without a terminal runtime."""
    from pytest_homeassistant_custom_component.common import MockConfigEntry

    entry = MockConfigEntry(domain=DOMAIN, title="Synthetic unload failure")
    entry.add_to_hass(hass)
    device = _make_device()
    client = _SyntheticConnectedClient(disconnect_error=RuntimeError("synthetic"))
    device._client = client
    device._is_paired = True
    device._physical_connection_active = True
    device._notifications_active = True
    data = _make_data(hass, device)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = data
    unload_platforms = AsyncMock(
        return_value=integration._PlatformUnloadOutcome.UNLOADED
    )

    with patch.object(
        integration,
        "_async_unload_platforms_transactional",
        new=unload_platforms,
    ):
        assert await integration.async_unload_entry(hass, entry) is False

    unload_platforms.assert_not_awaited()
    assert hass.data[DOMAIN][entry.entry_id] is data
    assert device._client is client
    assert device._pending_release is None
    assert device._disconnect_retry_task is None
    assert device._terminal_stopped is False
    assert device.policy_state is ConnectionPolicyState.ALWAYS_CONNECTED_ACTIVE
    assert device.effective_policy is EffectiveConnectionPolicy.ALWAYS_CONNECTED
    device.ensure_control_available()


async def test_fd50_unload_notification_restore_failure_retains_repair_owner(
    hass: HomeAssistant,
) -> None:
    """A failed FD50 notification rollback remains unusable and repair-owned."""
    from pytest_homeassistant_custom_component.common import MockConfigEntry

    entry = MockConfigEntry(domain=DOMAIN, title="Synthetic FD50 unload failure")
    entry.add_to_hass(hass)
    device = _make_device()
    assert device._device_info is not None
    device._device_info.product_id = "jntxv3q4"
    device._characteristic_notify = CHARACTERISTIC_NOTIFY_FD50
    client = _SyntheticConnectedClient(disconnect_error=RuntimeError("synthetic"))
    client.start_notify.side_effect = RuntimeError("synthetic")
    device._client = client
    device._is_paired = True
    device._physical_connection_active = True
    device._notifications_active = True
    data = _make_data(hass, device)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = data

    with patch.object(
        integration,
        "_async_unload_platforms_transactional",
        new=AsyncMock(return_value=integration._PlatformUnloadOutcome.UNLOADED),
    ) as unload_platforms:
        assert await integration.async_unload_entry(hass, entry) is False

    unload_platforms.assert_not_awaited()
    client.stop_notify.assert_awaited_once()
    client.start_notify.assert_awaited_once_with(
        CHARACTERISTIC_NOTIFY_FD50,
        device._notification_handler,
        bluez={"use_start_notify": True},
    )
    assert device._client is client
    assert device.is_gatt_connected is True
    assert device._pending_release is not None
    assert device._pending_release.reason is PendingReleaseReason.SETUP_FAILURE
    assert device._disconnect_retry_task is not None
    assert device._reconnect_task is None
    assert device.policy_state is ConnectionPolicyState.DISCONNECT_FAILED
    with pytest.raises(TuyaBLEConnectionUnavailableError):
        device.ensure_control_available()
    device._disconnect_retry_task.cancel()
    await asyncio.sleep(0)


async def test_terminal_stop_cannot_be_overwritten_by_notification_rollback() -> None:
    """A notification rollback completing after stop cannot supersede STOP."""
    device = _make_device()
    assert device._device_info is not None
    device._device_info.product_id = "jntxv3q4"
    device._characteristic_notify = CHARACTERISTIC_NOTIFY_FD50
    client = _SyntheticConnectedClient(disconnect_error=RuntimeError("synthetic"))
    notification_restore_started = asyncio.Event()
    allow_notification_failure = asyncio.Event()

    async def restore_notifications(*_: object, **__: object) -> None:
        notification_restore_started.set()
        await allow_notification_failure.wait()
        raise RuntimeError("synthetic")

    client.start_notify.side_effect = restore_notifications
    device._client = client
    device._is_paired = True
    device._physical_connection_active = True
    device._notifications_active = True
    device._unload_quiescing = True
    device._pending_release = PendingRelease(
        PendingReleaseReason.UNLOAD,
        device._policy_revision,
    )

    rollback = asyncio.create_task(device.async_cancel_unload())
    await asyncio.wait_for(notification_restore_started.wait(), 0.2)
    stop = asyncio.create_task(device.stop())
    await asyncio.sleep(0)
    allow_notification_failure.set()
    await asyncio.gather(rollback, stop)

    assert device._terminal_stopped is True
    assert device._unload_quiescing is False
    assert device._client is client
    assert device.is_gatt_connected is True
    assert device._pending_release is not None
    assert device._pending_release.reason is PendingReleaseReason.STOP
    assert device._pending_release.terminal is True
    assert device._disconnect_retry_task is not None
    assert device._reconnect_task is None
    assert device.policy_state is ConnectionPolicyState.STOPPED
    with pytest.raises(TuyaBLEConnectionUnavailableError):
        device.ensure_control_available()
    device._disconnect_retry_task.cancel()
    await asyncio.sleep(0)


async def test_unload_waits_for_in_progress_on_demand_release_ownership() -> None:
    """Unload rollback cannot erase an in-flight On-demand release failure."""
    device = _make_device(mode=ConnectionMode.ON_DEMAND)
    client = _SyntheticConnectedClient()
    disconnect_started = asyncio.Event()
    allow_failure = asyncio.Event()

    async def disconnect() -> None:
        disconnect_started.set()
        await allow_failure.wait()
        raise RuntimeError("synthetic")

    client.disconnect.side_effect = disconnect
    device._client = client
    device._is_paired = True
    device._physical_connection_active = True
    device._notifications_active = True

    with patch(
        "custom_components.tuya_ble.tuya_ble.tuya_ble.DEFAULT_ON_DEMAND_IDLE_DISCONNECT_SECONDS",
        0,
    ):
        async with device._policy_lock:
            device._schedule_idle_disconnect_locked()
        idle_owner = device._idle_disconnect_task
        assert idle_owner is not None
        await asyncio.wait_for(disconnect_started.wait(), 0.2)
        preparation = asyncio.create_task(device.async_prepare_unload())
        await asyncio.sleep(0)
        allow_failure.set()
        assert await preparation is False
        await idle_owner

    assert device._terminal_stopped is False
    assert device._unload_quiescing is False
    assert device._client is client
    assert device.is_gatt_connected is True
    assert device._pending_release is not None
    assert device._pending_release.reason is PendingReleaseReason.ON_DEMAND_IDLE
    assert device._disconnect_retry_task is not None
    assert device._idle_disconnect_task is None
    device._disconnect_retry_task.cancel()
    await asyncio.sleep(0)


async def test_unload_release_failure_restores_disabled_policy_repair(
    hass: HomeAssistant,
) -> None:
    """Rollback retains suspension repair when disabled-policy release still fails."""
    from pytest_homeassistant_custom_component.common import MockConfigEntry

    entry = MockConfigEntry(domain=DOMAIN, title="Synthetic disabled unload failure")
    entry.add_to_hass(hass)
    device = _make_device(enabled=False)
    client = _SyntheticConnectedClient(disconnect_error=RuntimeError("synthetic"))
    device._client = client
    device._is_paired = True
    device._physical_connection_active = True
    device._notifications_active = True
    data = _make_data(hass, device)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = data
    unload_platforms = AsyncMock(
        return_value=integration._PlatformUnloadOutcome.UNLOADED
    )

    with patch.object(
        integration,
        "_async_unload_platforms_transactional",
        new=unload_platforms,
    ):
        assert await integration.async_unload_entry(hass, entry) is False

    unload_platforms.assert_not_awaited()
    assert hass.data[DOMAIN][entry.entry_id] is data
    assert device._terminal_stopped is False
    assert device.effective_policy is EffectiveConnectionPolicy.SUSPENDED
    assert device._pending_release is not None
    assert device._pending_release.reason is PendingReleaseReason.SETUP_FAILURE
    assert device._disconnect_retry_task is not None
    assert device._client is client
    device._disconnect_retry_task.cancel()
    await asyncio.sleep(0)


async def test_unload_keeps_platforms_loaded_when_physical_release_fails(
    hass: HomeAssistant,
) -> None:
    """Platform teardown cannot start before physical release is verified."""
    from pytest_homeassistant_custom_component.common import MockConfigEntry

    entry = MockConfigEntry(domain=DOMAIN, title="Synthetic unload ordering")
    entry.add_to_hass(hass)
    device = _make_device()
    client = _SyntheticConnectedClient(disconnect_error=RuntimeError("synthetic"))
    device._client = client
    device._is_paired = True
    device._physical_connection_active = True
    device._notifications_active = True
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = _make_data(hass, device)
    unload_platforms = AsyncMock(
        return_value=integration._PlatformUnloadOutcome.UNLOADED
    )

    with patch.object(
        integration,
        "_async_unload_platforms_transactional",
        new=unload_platforms,
    ):
        assert await integration.async_unload_entry(hass, entry) is False

    unload_platforms.assert_not_awaited()
    assert entry.entry_id in hass.data[DOMAIN]
    assert device._pending_release is None
    assert device._disconnect_retry_task is None
    assert device._terminal_stopped is False


async def test_platform_unload_failure_restores_nonterminal_runtime(
    hass: HomeAssistant,
) -> None:
    """A failed platform unload must restore a usable loaded config entry."""
    from pytest_homeassistant_custom_component.common import MockConfigEntry

    entry = MockConfigEntry(domain=DOMAIN, title="Synthetic unload rollback")
    entry.add_to_hass(hass)
    device = _make_device()
    client = _SyntheticConnectedClient()
    device._client = client
    device._is_paired = True
    device._physical_connection_active = True
    device._notifications_active = True
    device._schedule_reconnect_locked = Mock()
    data = _make_data(hass, device)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = data

    with patch.object(
        integration,
        "_async_unload_platforms_transactional",
        new=AsyncMock(return_value=integration._PlatformUnloadOutcome.RESTORED),
    ):
        assert await integration.async_unload_entry(hass, entry) is False

    assert hass.data[DOMAIN][entry.entry_id] is data
    assert device._terminal_stopped is False
    assert device.policy_state is ConnectionPolicyState.ALWAYS_CONNECTED_CONNECTING
    assert device.effective_policy is EffectiveConnectionPolicy.ALWAYS_CONNECTED
    assert device._pending_release is None
    assert device._disconnect_retry_task is None
    assert device._reconnect_task is None
    device._schedule_reconnect_locked.assert_called_once_with(0)
    device.ensure_control_available()

    with patch.object(
        integration,
        "_async_unload_platforms_transactional",
        new=AsyncMock(return_value=integration._PlatformUnloadOutcome.UNLOADED),
    ):
        assert await integration.async_unload_entry(hass, entry) is True

    assert entry.entry_id not in hass.data[DOMAIN]
    assert device._terminal_stopped is True
    if data.coordinator._unsub_disconnect is not None:
        data.coordinator._unsub_disconnect()


async def test_partial_platform_unload_restores_only_verified_unloads(
    hass: HomeAssistant,
) -> None:
    """Platform rollback restores the exact unloaded set without duplicates."""
    from pytest_homeassistant_custom_component.common import MockConfigEntry

    entry = MockConfigEntry(domain=DOMAIN, title="Synthetic platform transaction")
    entry.add_to_hass(hass)
    loaded_platforms = set(integration.PLATFORMS)
    failed_platform = integration.PLATFORMS[2]
    restored_platforms: list[object] = []

    async def unload_platform(_: object, platform: object) -> bool:
        if platform is failed_platform:
            return False
        assert platform in loaded_platforms
        loaded_platforms.remove(platform)
        return True

    async def restore_platform(_: object, __: object, platform: object) -> bool:
        if platform in loaded_platforms:
            return True
        assert platform not in loaded_platforms
        loaded_platforms.add(platform)
        restored_platforms.append(platform)
        return True

    with (
        patch.object(
            hass.config_entries,
            "async_forward_entry_unload",
            new=AsyncMock(side_effect=unload_platform),
        ),
        patch.object(
            integration,
            "_async_restore_platform_after_unload_failure",
            new=AsyncMock(side_effect=restore_platform),
        ),
    ):
        assert (
            await integration._async_unload_platforms_transactional(hass, entry)
            is integration._PlatformUnloadOutcome.RESTORED
        )

    assert loaded_platforms == set(integration.PLATFORMS)
    assert set(restored_platforms) == set(integration.PLATFORMS) - {failed_platform}
    assert len(restored_platforms) == len(set(restored_platforms))


async def test_platform_rollback_retries_one_failed_setup_without_duplicates(
    hass: HomeAssistant,
) -> None:
    """A transient rollback setup failure cannot leave a partially loaded entry."""
    from pytest_homeassistant_custom_component.common import MockConfigEntry

    entry = MockConfigEntry(domain=DOMAIN, title="Synthetic rollback retry")
    entry.add_to_hass(hass)
    loaded_platforms = set(integration.PLATFORMS)
    unload_failure = integration.PLATFORMS[-1]
    setup_failure = integration.PLATFORMS[2]
    setup_attempts: dict[object, int] = {}

    async def unload_platform(_: object, platform: object) -> bool:
        if platform is unload_failure:
            return False
        loaded_platforms.remove(platform)
        return True

    async def restore_platform(_: object, __: object, platform: object) -> bool:
        if platform in loaded_platforms:
            return True
        setup_attempts[platform] = setup_attempts.get(platform, 0) + 1
        if platform is setup_failure and setup_attempts[platform] == 1:
            raise RuntimeError("synthetic")
        assert platform not in loaded_platforms
        loaded_platforms.add(platform)
        return True

    with (
        patch.object(
            hass.config_entries,
            "async_forward_entry_unload",
            new=AsyncMock(side_effect=unload_platform),
        ),
        patch.object(
            integration,
            "_async_restore_platform_after_unload_failure",
            new=AsyncMock(side_effect=restore_platform),
        ),
    ):
        assert (
            await integration._async_unload_platforms_transactional(hass, entry)
            is integration._PlatformUnloadOutcome.RESTORED
        )

    assert loaded_platforms == set(integration.PLATFORMS)
    assert setup_attempts[setup_failure] == 2
    assert all(
        attempts == 1
        for platform, attempts in setup_attempts.items()
        if platform is not setup_failure
    )


async def test_permanent_platform_rollback_failure_is_bounded(
    hass: HomeAssistant,
) -> None:
    """A platform that never restores cannot retain unload forever."""
    from pytest_homeassistant_custom_component.common import MockConfigEntry

    entry = MockConfigEntry(domain=DOMAIN, title="Synthetic permanent rollback")
    entry.add_to_hass(hass)

    with (
        patch.object(
            hass.config_entries,
            "async_forward_entry_unload",
            new=AsyncMock(return_value=False),
        ),
        patch.object(
            integration,
            "_async_restore_platform_after_unload_failure",
            new=AsyncMock(return_value=False),
        ) as restore_platform,
        patch.object(integration, "PLATFORM_ROLLBACK_BACKOFF_SECONDS", 0),
    ):
        result = await asyncio.wait_for(
            integration._async_unload_platforms_transactional(hass, entry),
            0.2,
        )

    assert result is integration._PlatformUnloadOutcome.RESTORATION_FAILED
    assert restore_platform.await_count == (
        len(integration.PLATFORMS) * integration.PLATFORM_ROLLBACK_MAX_ATTEMPTS
    )


async def test_initial_platform_unload_failure_is_bounded_and_cancels_children(
    hass: HomeAssistant,
) -> None:
    """A platform that hangs before rollback cannot outlive the platform bound."""
    from pytest_homeassistant_custom_component.common import MockConfigEntry

    entry = MockConfigEntry(domain=DOMAIN, title="Synthetic initial unload timeout")
    entry.add_to_hass(hass)
    unload_started = 0
    unload_cancelled = 0
    all_started = asyncio.Event()

    async def never_unload(*_: object) -> bool:
        nonlocal unload_started, unload_cancelled
        unload_started += 1
        if unload_started == len(integration.PLATFORMS):
            all_started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            unload_cancelled += 1
            raise

    with (
        patch.object(
            hass.config_entries,
            "async_forward_entry_unload",
            new=AsyncMock(side_effect=never_unload),
        ),
        patch.object(integration, "PLATFORM_ROLLBACK_TIMEOUT_SECONDS", 0.05),
    ):
        transaction = asyncio.create_task(
            integration._async_unload_platforms_transactional(hass, entry)
        )
        await asyncio.wait_for(all_started.wait(), 0.2)
        assert await asyncio.wait_for(transaction, 0.2) is (
            integration._PlatformUnloadOutcome.RESTORATION_FAILED
        )

    assert unload_started == len(integration.PLATFORMS)
    assert unload_cancelled == len(integration.PLATFORMS)
    assert transaction.done()


async def test_stalled_notification_rollback_cannot_extend_unload_cancellation(
    hass: HomeAssistant,
) -> None:
    """The outer entry deadline cancels stalled notification restoration."""
    from pytest_homeassistant_custom_component.common import MockConfigEntry

    entry = MockConfigEntry(domain=DOMAIN, title="Synthetic notification timeout")
    entry.add_to_hass(hass)
    device = _make_device()
    client = _SyntheticConnectedClient(disconnect_error=RuntimeError("synthetic"))
    notification_restore_started = asyncio.Event()
    notification_restore_cancelled = asyncio.Event()

    async def never_restore(*_: object, **__: object) -> None:
        notification_restore_started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            notification_restore_cancelled.set()
            raise

    client.start_notify.side_effect = never_restore
    device._client = client
    device._is_paired = True
    device._physical_connection_active = True
    device._notifications_active = True
    data = _make_data(hass, device)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = data

    with patch.object(integration, "ENTRY_UNLOAD_TRANSACTION_TIMEOUT_SECONDS", 0.05):
        unload = asyncio.create_task(integration.async_unload_entry(hass, entry))
        await asyncio.wait_for(notification_restore_started.wait(), 0.2)
        unload.cancel()
        assert await asyncio.wait_for(unload, 0.2) is False

    assert notification_restore_cancelled.is_set()
    assert device._unload_quiescing is False
    assert device.is_connection_active is False
    assert device._pending_release is not None
    assert device._pending_release.reason is PendingReleaseReason.SETUP_FAILURE
    assert device._disconnect_retry_task is not None
    assert device._reconnect_task is None
    assert hass.data[DOMAIN][entry.entry_id] is data
    device._disconnect_retry_task.cancel()
    await asyncio.sleep(0)


def _prepare_loaded_entry_for_unload(
    hass: HomeAssistant,
    title: str,
) -> tuple[ConfigEntry, TuyaBLEDevice, TuyaBLEData]:
    """Create one loaded config entry with an owned synthetic runtime."""
    from pytest_homeassistant_custom_component.common import MockConfigEntry

    entry = MockConfigEntry(domain=DOMAIN, title=title)
    entry.add_to_hass(hass)
    object.__setattr__(entry, "state", ConfigEntryState.LOADED)
    object.__setattr__(entry, "supports_unload", True)
    object.__setattr__(entry, "supports_remove_device", False)
    object.__setattr__(
        entry,
        "_integration_for_domain",
        Mock(
            domain=DOMAIN,
            async_get_component=AsyncMock(return_value=integration),
        ),
    )
    device = _make_device()
    device._schedule_reconnect_locked = Mock()
    data = _make_data(hass, device)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = data
    return entry, device, data


async def test_permanent_platform_rollback_leaves_failed_unload_recoverable(
    hass: HomeAssistant,
) -> None:
    """Exhausted restoration returns promptly and preserves the runtime owner."""
    entry, device, data = _prepare_loaded_entry_for_unload(
        hass, "Synthetic bounded failed unload"
    )

    with (
        patch.object(
            hass.config_entries,
            "async_forward_entry_unload",
            new=AsyncMock(return_value=False),
        ),
        patch.object(
            integration,
            "_async_restore_platform_after_unload_failure",
            new=AsyncMock(return_value=False),
        ) as restore_platform,
        patch.object(integration, "PLATFORM_ROLLBACK_BACKOFF_SECONDS", 0),
        patch.object(integration, "PLATFORM_ROLLBACK_TIMEOUT_SECONDS", 0.2),
    ):
        assert (
            await asyncio.wait_for(hass.config_entries.async_unload(entry.entry_id), 1)
            is False
        )

    await hass.async_block_till_done()
    assert entry.state is ConfigEntryState.FAILED_UNLOAD
    assert hass.data[DOMAIN][entry.entry_id] is data
    assert device._terminal_stopped is False
    assert device._unload_quiescing is False
    assert device._pending_release is None
    device.ensure_control_available()
    assert restore_platform.await_count == (
        len(integration.PLATFORMS) * integration.PLATFORM_ROLLBACK_MAX_ATTEMPTS
    )
    if data.coordinator._unsub_disconnect is not None:
        data.coordinator._unsub_disconnect()


async def test_cancellation_during_platform_rollback_ends_at_timeout(
    hass: HomeAssistant,
) -> None:
    """Deferred cancellation cannot outlive the bounded restoration window."""
    entry, device, data = _prepare_loaded_entry_for_unload(
        hass, "Synthetic cancelled bounded unload"
    )
    restore_started = asyncio.Event()
    restore_cancelled = asyncio.Event()

    async def never_restore(*_: object) -> bool:
        restore_started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            restore_cancelled.set()
            raise

    with (
        patch.object(
            hass.config_entries,
            "async_forward_entry_unload",
            new=AsyncMock(return_value=False),
        ),
        patch.object(
            integration,
            "_async_restore_platform_after_unload_failure",
            new=AsyncMock(side_effect=never_restore),
        ),
        patch.object(integration, "PLATFORM_ROLLBACK_TIMEOUT_SECONDS", 0.05),
    ):
        unload = asyncio.create_task(hass.config_entries.async_unload(entry.entry_id))
        await asyncio.wait_for(restore_started.wait(), 0.5)
        unload.cancel()
        result = (await asyncio.wait_for(asyncio.gather(unload), 0.5))[0]

    await hass.async_block_till_done()
    assert result is False
    assert restore_cancelled.is_set()
    assert entry.state is ConfigEntryState.FAILED_UNLOAD
    assert hass.data[DOMAIN][entry.entry_id] is data
    assert device._terminal_stopped is False
    assert device._unload_quiescing is False
    assert device._pending_release is None
    if data.coordinator._unsub_disconnect is not None:
        data.coordinator._unsub_disconnect()


async def test_later_unload_recovers_after_restart_state_recovery(
    hass: HomeAssistant,
) -> None:
    """A later clean unload succeeds after restart restores loaded HA state."""
    entry, device, data = _prepare_loaded_entry_for_unload(
        hass, "Synthetic later unload recovery"
    )

    with (
        patch.object(
            hass.config_entries,
            "async_forward_entry_unload",
            new=AsyncMock(return_value=False),
        ),
        patch.object(
            integration,
            "_async_restore_platform_after_unload_failure",
            new=AsyncMock(return_value=False),
        ),
        patch.object(integration, "PLATFORM_ROLLBACK_BACKOFF_SECONDS", 0),
    ):
        assert await hass.config_entries.async_unload(entry.entry_id) is False

    await hass.async_block_till_done()
    assert entry.state is ConfigEntryState.FAILED_UNLOAD
    assert hass.data[DOMAIN][entry.entry_id] is data

    # FAILED_UNLOAD is deliberately non-recoverable in HA 2025.1; a restart
    # reconstructs platform state and the retained runtime before a later retry.
    recovered_components: dict[str, Mock] = {}
    recovered_platform_data: dict[str, Mock] = {}
    for platform in (integration.Platform.SELECT, integration.Platform.SWITCH):
        platform_data = Mock(_platforms={entry.entry_id: Mock(_setup_complete=False)})

        async def unload_stale(
            _: object,
            unload_entry: object,
            *,
            component_data: Mock = platform_data,
        ) -> bool:
            assert unload_entry is entry
            component_data._platforms.pop(entry.entry_id)
            return True

        async def setup_recovered(
            _: object,
            setup_entry: object,
            *,
            component_data: Mock = platform_data,
        ) -> bool:
            assert setup_entry is entry
            assert entry.entry_id not in component_data._platforms
            component_data._platforms[entry.entry_id] = Mock(_setup_complete=True)
            return True

        recovered_platform_data[platform.value] = platform_data
        recovered_components[platform.value] = Mock(
            async_unload_entry=AsyncMock(side_effect=unload_stale),
            async_setup_entry=AsyncMock(side_effect=setup_recovered),
        )

    def loaded_platform_integration(_: object, domain: str) -> Mock:
        return Mock(
            async_get_component=AsyncMock(return_value=recovered_components[domain])
        )

    with (
        patch.dict(hass.data, recovered_platform_data),
        patch.object(
            integration.loader,
            "async_get_loaded_integration",
            side_effect=loaded_platform_integration,
        ),
    ):
        for platform in (integration.Platform.SELECT, integration.Platform.SWITCH):
            assert await integration._async_restore_platform_after_unload_failure(
                hass, entry, platform
            )

    for platform in (integration.Platform.SELECT, integration.Platform.SWITCH):
        platform_data = recovered_platform_data[platform.value]
        component = recovered_components[platform.value]
        assert list(platform_data._platforms) == [entry.entry_id]
        assert platform_data._platforms[entry.entry_id]._setup_complete is True
        component.async_unload_entry.assert_awaited_once_with(hass, entry)
        component.async_setup_entry.assert_awaited_once_with(hass, entry)

    entry._async_set_state(hass, ConfigEntryState.LOADED, None)
    with patch.object(
        hass.config_entries,
        "async_forward_entry_unload",
        new=AsyncMock(return_value=True),
    ):
        assert await hass.config_entries.async_unload(entry.entry_id) is True

    assert entry.state is ConfigEntryState.NOT_LOADED
    assert entry.entry_id not in hass.data[DOMAIN]
    assert device._terminal_stopped is True
    if data.coordinator._unsub_disconnect is not None:
        data.coordinator._unsub_disconnect()


async def test_platform_rollback_setup_works_while_entry_is_unloading(
    hass: HomeAssistant,
) -> None:
    """Rollback bypasses forwarded-setup state rejection without duplication."""
    from pytest_homeassistant_custom_component.common import MockConfigEntry

    entry = MockConfigEntry(domain=DOMAIN, title="Synthetic unloading rollback")
    entry.add_to_hass(hass)
    object.__setattr__(
        entry,
        "state",
        getattr(
            ConfigEntryState,
            "UNLOAD_IN_PROGRESS",
            ConfigEntryState.SETUP_IN_PROGRESS,
        ),
    )
    platform = integration.PLATFORMS[0]
    entity_component = Mock(_platforms={})

    async def setup_entry(_: object, setup_entry: object) -> bool:
        assert setup_entry is entry
        assert entry.entry_id not in entity_component._platforms
        entity_component._platforms[entry.entry_id] = Mock(_setup_complete=True)
        return True

    component = Mock(async_setup_entry=AsyncMock(side_effect=setup_entry))
    platform_integration = Mock(async_get_component=AsyncMock(return_value=component))

    with (
        patch.dict(hass.data, {platform.value: entity_component}),
        patch.object(
            integration.loader,
            "async_get_loaded_integration",
            return_value=platform_integration,
        ),
        patch.object(
            hass.config_entries,
            "async_forward_entry_setups",
            new=AsyncMock(),
        ) as forwarded_setup,
    ):
        assert (
            await integration._async_restore_platform_after_unload_failure(
                hass, entry, platform
            )
            is True
        )

    component.async_setup_entry.assert_awaited_once_with(hass, entry)
    forwarded_setup.assert_not_awaited()
    assert list(entity_component._platforms) == [entry.entry_id]


async def test_platform_rollback_cleans_partial_setup_before_retry(
    hass: HomeAssistant,
) -> None:
    """Entity-component membership cannot certify an incomplete platform setup."""
    from pytest_homeassistant_custom_component.common import MockConfigEntry

    entry = MockConfigEntry(domain=DOMAIN, title="Synthetic partial rollback")
    entry.add_to_hass(hass)
    platform = integration.Platform.SELECT
    entity_component = Mock(_platforms={})
    setup_attempts = 0

    async def setup_entry(_: object, setup_entry: object) -> bool:
        nonlocal setup_attempts
        assert setup_entry is entry
        setup_attempts += 1
        marker = Mock(_setup_complete=setup_attempts > 1)
        entity_component._platforms[entry.entry_id] = marker
        if setup_attempts == 1:
            raise RuntimeError("synthetic")
        return True

    async def unload_entry(_: object, unload_entry: object) -> bool:
        assert unload_entry is entry
        entity_component._platforms.pop(entry.entry_id)
        return True

    component = Mock(
        async_setup_entry=AsyncMock(side_effect=setup_entry),
        async_unload_entry=AsyncMock(side_effect=unload_entry),
    )
    platform_integration = Mock(async_get_component=AsyncMock(return_value=component))

    with (
        patch.dict(hass.data, {platform.value: entity_component}),
        patch.object(
            integration.loader,
            "async_get_loaded_integration",
            return_value=platform_integration,
        ),
    ):
        assert (
            await integration._async_restore_platform_after_unload_failure(
                hass, entry, platform
            )
            is False
        )
        assert entry.entry_id not in entity_component._platforms
        assert (
            await integration._async_restore_platform_after_unload_failure(
                hass, entry, platform
            )
            is True
        )

    assert setup_attempts == 2
    assert entity_component._platforms[entry.entry_id]._setup_complete is True
    component.async_unload_entry.assert_awaited_once_with(hass, entry)


async def test_cancelled_home_assistant_unload_finishes_runtime_rollback(
    hass: HomeAssistant,
) -> None:
    """Cancellation waits for a consistent rollback and leaves unload recoverable."""
    from pytest_homeassistant_custom_component.common import MockConfigEntry

    entry = MockConfigEntry(domain=DOMAIN, title="Synthetic cancelled unload")
    entry.add_to_hass(hass)
    object.__setattr__(entry, "state", ConfigEntryState.LOADED)
    object.__setattr__(entry, "supports_unload", True)
    object.__setattr__(entry, "supports_remove_device", False)
    object.__setattr__(
        entry,
        "_integration_for_domain",
        Mock(
            domain=DOMAIN,
            async_get_component=AsyncMock(return_value=integration),
        ),
    )
    device = _make_device()
    device._schedule_reconnect_locked = Mock()
    data = _make_data(hass, device)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = data
    rollback_started = asyncio.Event()
    allow_rollback = asyncio.Event()
    transaction_calls = 0
    restored_platforms = {
        platform.value: Mock(_platforms={entry.entry_id: Mock(_setup_complete=True)})
        for platform in integration.PLATFORMS
    }

    async def platform_transaction(*_: object) -> integration._PlatformUnloadOutcome:
        nonlocal transaction_calls
        transaction_calls += 1
        if transaction_calls == 1:
            rollback_started.set()
            await allow_rollback.wait()
            return integration._PlatformUnloadOutcome.RESTORED
        return integration._PlatformUnloadOutcome.UNLOADED

    with (
        patch.dict(hass.data, restored_platforms),
        patch.object(
            integration,
            "_async_unload_platforms_transactional",
            new=AsyncMock(side_effect=platform_transaction),
        ),
    ):
        unload = asyncio.create_task(hass.config_entries.async_unload(entry.entry_id))
        await asyncio.wait_for(rollback_started.wait(), 2)
        unload.cancel()
        await asyncio.sleep(0)
        cancellation_deferred = not unload.done()
        allow_rollback.set()
        unload_result = (await asyncio.gather(unload, return_exceptions=True))[0]
        if isinstance(unload_result, asyncio.CancelledError):
            object.__setattr__(entry, "state", ConfigEntryState.LOADED)
            await device.async_cancel_unload()

        assert cancellation_deferred is True
        assert unload_result is False

        await hass.async_block_till_done()
        assert entry.state is ConfigEntryState.LOADED
        assert entry.entry_id in hass.data[DOMAIN]
        assert device._terminal_stopped is False
        assert device._unload_quiescing is False
        assert device._pending_release is None
        device.ensure_control_available()

        assert await hass.config_entries.async_unload(entry.entry_id) is True

    assert transaction_calls == 2
    assert entry.entry_id not in hass.data[DOMAIN]
    assert device._terminal_stopped is True
    assert entry.state is ConfigEntryState.NOT_LOADED
    if data.coordinator._unsub_disconnect is not None:
        data.coordinator._unsub_disconnect()


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


async def test_transport_has_no_deferred_packet_replay_state() -> None:
    """Encrypted packet fragments are never retained for a later session."""
    device = _make_device()

    assert not hasattr(device, "_deferred_resend_packets")
    assert not hasattr(device, "_resend_task")


@pytest.mark.parametrize(
    "mode",
    (ConnectionMode.ALWAYS_CONNECTED, ConnectionMode.ON_DEMAND),
    ids=("always-connected", "on-demand"),
)
async def test_connected_write_failure_retains_client_for_mandatory_release(
    mode: ConnectionMode,
) -> None:
    """A write error is not a disconnect while the exact client stays connected."""
    device = _make_device(mode=mode)
    client = _SyntheticConnectedClient()
    client.write_gatt_char.side_effect = BleakError("synthetic write failure")
    device._client = client
    device._is_paired = True
    device._physical_connection_active = True
    device._notifications_active = True
    device._state_data_fresh = True
    device._schedule_reconnect = Mock()
    device._schedule_reconnect_locked = Mock()
    state_changes: list[bool] = []
    device.register_connection_state_callback(state_changes.append)

    async with device.connection_lease(
        "synthetic write failure", defer_connection=True
    ):
        with pytest.raises(BleakError, match="synthetic write failure"):
            await device._send_packets_locked([b"synthetic-fragment"])

        assert client.is_connected is True
        assert device._client is client
        assert device.is_gatt_connected is True
        assert device.is_authenticated is True
        assert device.is_connection_active is False
        assert device.state_data_fresh is False
        assert state_changes == []
        assert device._pending_release is not None
        assert device._pending_release.reason is PendingReleaseReason.SESSION_FAILURE
        assert device._reconnect_task is None

    assert client.disconnect.await_count == 1
    assert client.is_connected is False


async def test_actual_write_loss_marks_the_current_client_disconnected_once() -> None:
    """A verified lost client is the only local write-error disconnect transition."""
    device = _make_device()
    client = _SyntheticConnectedClient()

    async def lose_connection(*_: object) -> None:
        client.is_connected = False
        raise BleakError("synthetic physical loss")

    client.write_gatt_char.side_effect = lose_connection
    device._client = client
    device._is_paired = True
    device._physical_connection_active = True
    device._notifications_active = True
    device._schedule_reconnect = Mock()
    device._schedule_reconnect_locked = Mock()
    state_changes: list[bool] = []
    device.register_connection_state_callback(state_changes.append)

    async with device.connection_lease(
        "synthetic physical loss", defer_connection=True
    ):
        with pytest.raises(BleakError, match="synthetic physical loss"):
            await device._send_packets_locked([b"synthetic-fragment"])

    assert device._client is None
    assert device.is_gatt_connected is False
    assert state_changes == [False]
    assert device._pending_release is None


async def test_no_replay_verified_loss_recovers_one_future_always_session() -> None:
    """A no-replay write failure still restores the future Always session."""
    device = _make_device()
    client = _SyntheticConnectedClient()

    async def lose_connection(*_: object) -> None:
        client.is_connected = False
        raise BleakError("synthetic no-replay physical loss")

    client.write_gatt_char.side_effect = lose_connection
    device._client = client
    device._is_paired = True
    device._physical_connection_active = True
    device._notifications_active = True
    device._state_data_fresh = True
    device._protocol_version = 3
    device._build_packets = Mock(return_value=[b"synthetic-no-replay-fragment"])
    device._schedule_reconnect_locked = Mock()
    state_changes: list[bool] = []
    device.register_connection_state_callback(state_changes.append)
    device.datapoints.get_or_create(42, TuyaBLEDataPointType.DT_BOOL, True)

    with pytest.raises(BleakError, match="synthetic no-replay physical loss"):
        await device._send_datapoints_no_replay([42])

    assert client.write_gatt_char.await_count == 1
    assert device._client is None
    assert device.is_gatt_connected is False
    assert device.policy_state is ConnectionPolicyState.ALWAYS_CONNECTED_CONNECTING
    assert device._pending_release is None
    assert state_changes == [False]
    device._schedule_reconnect_locked.assert_called_once_with(0)
    assert not hasattr(device, "_deferred_resend_packets")
    assert not hasattr(device, "_resend_task")

    device._disconnected(client)

    assert state_changes == [False]
    device._schedule_reconnect_locked.assert_called_once_with(0)


async def test_callback_before_no_replay_write_error_recovers_only_once() -> None:
    """Callback-first physical loss and later write failure share one recovery."""
    device = _make_device()
    client = _SyntheticConnectedClient()

    async def lose_connection_then_callback(*_: object) -> None:
        client.is_connected = False
        device._disconnected(client)
        raise BleakError("synthetic callback-first physical loss")

    client.write_gatt_char.side_effect = lose_connection_then_callback
    device._client = client
    device._is_paired = True
    device._physical_connection_active = True
    device._notifications_active = True
    device._protocol_version = 3
    device._build_packets = Mock(return_value=[b"synthetic-callback-first-fragment"])
    device._schedule_reconnect_locked = Mock()
    device._reconnect = AsyncMock()
    state_changes: list[bool] = []
    device.register_connection_state_callback(state_changes.append)
    device.datapoints.get_or_create(42, TuyaBLEDataPointType.DT_BOOL, True)

    with pytest.raises(BleakError, match="synthetic callback-first physical loss"):
        await device._send_datapoints_no_replay([42])

    assert client.write_gatt_char.await_count == 1
    assert device._client is None
    assert device.is_gatt_connected is False
    assert device.policy_state is ConnectionPolicyState.ALWAYS_CONNECTED_CONNECTING
    assert state_changes == [False]
    device._schedule_reconnect_locked.assert_called_once_with(0)
    assert not hasattr(device, "_deferred_resend_packets")
    assert not hasattr(device, "_resend_task")


async def test_verified_loss_enters_on_demand_idle_without_an_idle_timer() -> None:
    """A lost On-demand client is idle, not active or pending an idle release."""
    device = _make_device(mode=ConnectionMode.ON_DEMAND)
    client = _SyntheticConnectedClient()

    async def lose_connection(*_: object) -> None:
        client.is_connected = False
        raise BleakError("synthetic on-demand physical loss")

    client.write_gatt_char.side_effect = lose_connection
    device._client = client
    device._is_paired = True
    device._physical_connection_active = True
    device._notifications_active = True
    device._protocol_version = 3
    device._build_packets = Mock(return_value=[b"synthetic-on-demand-fragment"])
    device._schedule_reconnect_locked = Mock()
    device.datapoints.get_or_create(42, TuyaBLEDataPointType.DT_BOOL, True)

    try:
        with pytest.raises(BleakError, match="synthetic on-demand physical loss"):
            await device._send_datapoints_no_replay([42])

        assert device._client is None
        assert device.policy_state is ConnectionPolicyState.ON_DEMAND_IDLE
        assert device._idle_disconnect_task is None
        device._schedule_reconnect_locked.assert_not_called()
    finally:
        if device._idle_disconnect_task is not None:
            device._idle_disconnect_task.cancel()
            await asyncio.sleep(0)


@pytest.mark.parametrize(
    "variant",
    ("suspended", "stopped", "unload"),
)
async def test_verified_loss_respects_non_reconnecting_runtime_ownership(
    variant: str,
) -> None:
    """Verified loss never supersedes suspension, stop, or unload ownership."""
    device = _make_device(enabled=variant != "suspended")
    client = _SyntheticConnectedClient()
    client.is_connected = False
    device._client = client
    device._is_paired = True
    device._physical_connection_active = True
    device._notifications_active = True
    device._schedule_reconnect_locked = Mock()

    if variant == "stopped":
        device._terminal_stopped = True
        device._suspension_requested = True
        device._policy_state = ConnectionPolicyState.STOPPED
        expected_state = ConnectionPolicyState.STOPPED
    elif variant == "unload":
        device._unload_quiescing = True
        expected_state = ConnectionPolicyState.DISCONNECTING
    else:
        expected_state = ConnectionPolicyState.SUSPENDED

    await device._record_write_transport_failure(client)

    assert device._client is None
    assert device.is_gatt_connected is False
    assert device.policy_state is expected_state
    assert device._pending_release is None
    device._schedule_reconnect_locked.assert_not_called()


async def test_protocol_response_verified_loss_recovers_without_response_replay() -> (
    None
):
    """A failed response leaves no response state but restores future traffic."""
    device = _make_device()
    client = _SyntheticConnectedClient()

    async def lose_connection(*_: object) -> None:
        client.is_connected = False
        raise BleakError("synthetic response physical loss")

    client.write_gatt_char.side_effect = lose_connection
    device._client = client
    device._is_paired = True
    device._physical_connection_active = True
    device._notifications_active = True
    device._build_packets = Mock(return_value=[b"synthetic-response-fragment"])
    device._schedule_reconnect_locked = Mock()

    with pytest.raises(BleakError, match="synthetic response physical loss"):
        await device._send_response(TuyaBLECode.FUN_RECEIVE_DP, b"", 7)

    assert client.write_gatt_char.await_count == 1
    assert device._client is None
    assert device._input_expected_responses == {}
    assert device._input_expected_response_codes == {}
    assert device.policy_state is ConnectionPolicyState.ALWAYS_CONNECTED_CONNECTING
    device._schedule_reconnect_locked.assert_called_once_with(0)
    assert not hasattr(device, "_deferred_resend_packets")
    assert not hasattr(device, "_resend_task")


async def test_generic_verified_loss_recovers_without_packet_replay() -> None:
    """Generic write loss schedules one future session without replaying bytes."""
    device = _make_device()
    client = _SyntheticConnectedClient()

    async def lose_connection(*_: object) -> None:
        client.is_connected = False
        raise BleakError("synthetic generic physical loss")

    client.write_gatt_char.side_effect = lose_connection
    device._client = client
    device._is_paired = True
    device._physical_connection_active = True
    device._notifications_active = True
    device._reconnect = AsyncMock()

    async with device.connection_lease(
        "synthetic generic physical loss", defer_connection=True
    ):
        with pytest.raises(BleakError, match="synthetic generic physical loss"):
            await device._send_packets_locked([b"synthetic-generic-fragment"])

    await asyncio.sleep(0)

    assert client.write_gatt_char.await_count == 1
    assert device._reconnect.await_count == 1
    assert not hasattr(device, "_deferred_resend_packets")
    assert not hasattr(device, "_resend_task")


async def test_session_failure_hides_cached_s1_lock_state_until_new_data_arrives(
    hass: HomeAssistant,
) -> None:
    """A still-connected failed session cannot present cached DP47 as current."""
    device = _make_device()
    client = _SyntheticConnectedClient()
    client.write_gatt_char.side_effect = BleakError("synthetic write failure")
    device._client = client
    device._is_paired = True
    device._physical_connection_active = True
    device._notifications_active = True
    device._schedule_reconnect_locked = Mock()
    device.datapoints._update_from_device(
        47, 1.0, 0, TuyaBLEDataPointType.DT_BOOL, False
    )
    template_store = Mock()
    template_store.templates_for.return_value = None
    entity = TuyaBLES1Lock(
        hass,
        TuyaBLECoordinator(hass, device),
        device,
        TuyaBLEProductInfo("S1-TY-BLE-PRO"),
        template_store,
    )
    entity.async_write_ha_state = Mock()
    device._disconnected_callbacks.clear()

    assert entity.is_locked is True
    async with device.connection_lease(
        "synthetic stale-state check", defer_connection=True
    ):
        with pytest.raises(BleakError, match="synthetic write failure"):
            await device._send_packets_locked([b"synthetic-fragment"])

        assert device.is_gatt_connected is True
        assert device.state_data_fresh is False
        assert entity.is_locked is None


async def test_generic_write_failure_never_replays_after_a_replacement_session() -> (
    None
):
    """A new authenticated session is only available for future operations."""
    device = _make_device()
    client = _SyntheticConnectedClient()
    packets = [b"synthetic-fragment-one", b"synthetic-fragment-two"]
    client.write_gatt_char.side_effect = [None, BleakError("synthetic write failure")]
    device._client = client
    device._is_paired = True
    device._physical_connection_active = True
    device._notifications_active = True
    device._state_data_fresh = True
    device._schedule_reconnect_locked = Mock()

    async with device.connection_lease(
        "synthetic generic write failure", defer_connection=True
    ):
        with pytest.raises(BleakError, match="synthetic write failure"):
            await device._send_packets_locked(packets)

        assert client.write_gatt_char.await_count == 2
        assert device.state_data_fresh is False
        assert not hasattr(device, "_deferred_resend_packets")
        assert not hasattr(device, "_resend_task")
        assert device._reconnect_task is None

    assert client.is_connected is False

    replacement = _SyntheticConnectedClient()
    device._client = replacement
    device._is_paired = True
    device._physical_connection_active = True
    device._notifications_active = True

    await device._reconnect()

    replacement.write_gatt_char.assert_not_awaited()


async def test_protocol_response_write_failure_never_defers_old_request_bytes() -> None:
    """Responses remain bound to their inbound sequence and current session."""
    device = _make_device()
    client = _SyntheticConnectedClient()
    client.write_gatt_char.side_effect = BleakError("synthetic response failure")
    device._client = client
    device._is_paired = True
    device._physical_connection_active = True
    device._notifications_active = True
    device._build_packets = Mock(return_value=[b"synthetic-response-fragment"])
    device._schedule_reconnect_locked = Mock()

    with pytest.raises(BleakError, match="synthetic response failure"):
        await device._send_response(TuyaBLECode.FUN_RECEIVE_DP, b"", 7)

    client.write_gatt_char.assert_awaited_once()
    assert not hasattr(device, "_deferred_resend_packets")
    assert not hasattr(device, "_resend_task")
    assert device._pending_release is None
    assert client.disconnect.await_count == 1

    replacement = _SyntheticConnectedClient()
    device._client = replacement
    device._is_paired = True
    device._physical_connection_active = True
    device._notifications_active = True

    await device._reconnect()

    replacement.write_gatt_char.assert_not_awaited()


async def test_session_failure_release_survives_policy_change_and_unload() -> None:
    """Visible policy changes cannot supersede a connected write-failure repair."""
    device = _make_device()
    client = _SyntheticConnectedClient(disconnect_error=RuntimeError("synthetic"))
    device._client = client
    device._is_paired = True
    device._physical_connection_active = True
    device._notifications_active = True

    await device._record_write_transport_failure(client)
    await device.async_update_connection_policy(
        connection_mode=ConnectionMode.ON_DEMAND.value,
        ble_control_enabled=False,
    )

    assert device._client is client
    assert device._pending_release is not None
    assert device._pending_release.reason is PendingReleaseReason.SESSION_FAILURE
    assert device.policy_state is ConnectionPolicyState.DISCONNECT_FAILED
    assert await device.async_prepare_unload() is False
    assert device._pending_release is not None
    assert device._pending_release.reason is PendingReleaseReason.SESSION_FAILURE

    assert device._disconnect_retry_task is not None
    device._disconnect_retry_task.cancel()
    await asyncio.sleep(0)


async def test_stop_keeps_session_failure_client_under_terminal_release() -> None:
    """Shutdown replaces session repair with terminal ownership without forgetting GATT."""
    device = _make_device()
    client = _SyntheticConnectedClient(disconnect_error=RuntimeError("synthetic"))
    device._client = client
    device._is_paired = True
    device._physical_connection_active = True
    device._notifications_active = True

    await device._record_write_transport_failure(client)
    await device.stop()

    assert device._client is client
    assert device.is_gatt_connected is True
    assert device._pending_release is not None
    assert device._pending_release.reason is PendingReleaseReason.STOP
    assert device._pending_release.terminal is True
    assert device._reconnect_task is None

    assert device._disconnect_retry_task is not None
    device._disconnect_retry_task.cancel()
    await asyncio.sleep(0)


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
    device._notifications_active = True

    device._schedule_response(TuyaBLECode.FUN_RECEIVE_DP, b"", 1)
    await device.stop()
    await asyncio.sleep(0)

    assert device._active_response_drain_count == 0
    assert device._pending_release is None
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
    device._send_datapoints_no_replay = AsyncMock()
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
    assert device._send_datapoints_no_replay.await_count == 2
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
