"""Contract tests for the S1 On-Demand connection hold time."""

from __future__ import annotations

import asyncio
import math
from unittest.mock import AsyncMock, Mock, patch

from bleak.backends.device import BLEDevice
import pytest
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import EntityCategory

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
    async_setup_entry as async_setup_numbers,
)
from custom_components.tuya_ble.tuya_ble.const import TuyaBLECode
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

    await entity.async_set_native_value(100)

    assert device.on_demand_connection_hold_time == 100
    persist.assert_awaited_once_with({CONF_ON_DEMAND_CONNECTION_HOLD_TIME: 100})
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


def test_old_session_and_rejected_activity_never_move_deadline() -> None:
    device = _make_device()
    old_token, old_client = _install_ready_session(device)
    device._record_confirmed_activity(old_token)
    initial = device.last_confirmed_activity_monotonic
    old_client.is_connected = False
    device._mark_connection_lost(old_token)
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
        await asyncio.sleep(0)
        assert first.cancelled()
        second.cancel()
        release_sleep.set()
        await asyncio.gather(second, return_exceptions=True)


@pytest.mark.parametrize("protected", ("lease", "response-drain"))
async def test_deadline_waits_for_protected_work_to_drain(protected: str) -> None:
    device = _make_device()
    token, _ = _install_ready_session(device)
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
        await asyncio.sleep(0)
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
