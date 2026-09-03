"""Behavioral contracts for the S1 Refresh Status action."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from bleak.backends.device import BLEDevice
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import EntityCategory

from custom_components.tuya_ble import button
from custom_components.tuya_ble.const import (
    DOMAIN,
    ConnectionMode,
    ConnectionPolicyState,
)
from custom_components.tuya_ble.devices import (
    TuyaBLECoordinator,
    TuyaBLEData,
    TuyaBLEProductInfo,
)
from custom_components.tuya_ble.tuya_ble.const import TuyaBLECode
from custom_components.tuya_ble.tuya_ble.exceptions import (
    TuyaBLEControlSuspendedError,
    TuyaBLES1StatusRefreshBusyError,
    TuyaBLES1StatusRefreshFailedError,
)
from custom_components.tuya_ble.tuya_ble.tuya_ble import (
    ConnectionSessionToken,
    TuyaBLEDataPointType,
    TuyaBLEDevice,
)


class _SyntheticClient:
    """Connected synthetic transport owner."""

    is_connected = True


def _connected_s1(
    *,
    mode: ConnectionMode = ConnectionMode.ON_DEMAND,
    hold_time: int = 15,
    device_id: str = "synthetic-s1-refresh",
) -> tuple[TuyaBLEDevice, ConnectionSessionToken]:
    device = TuyaBLEDevice(
        Mock(),
        BLEDevice(name="Synthetic S1", address="00:00:00:00:00:64", details={}),
        connection_mode=mode.value,
        on_demand_connection_hold_time=hold_time,
    )
    device._device_info = SimpleNamespace(
        category="jtmspro",
        product_id="xqeob8h6",
        device_id=device_id,
        device_name="Synthetic S1",
        product_model="SYNTHETIC-S1",
        uuid="synthetic-r64-uuid",
        local_key="",
        sec_key="",
    )
    token = device._claim_connection_session(_SyntheticClient())
    device._is_paired = True
    device._notifications_active = True
    device._policy_state = (
        ConnectionPolicyState.ON_DEMAND_ACTIVE
        if mode is ConnectionMode.ON_DEMAND
        else ConnectionPolicyState.ALWAYS_CONNECTED_ACTIVE
    )
    device._ensure_connected = AsyncMock()
    device._schedule_idle_disconnect_locked = Mock()
    device._build_packets = Mock(return_value=[b"synthetic-status-request"])
    return device, token


def _dp(dp_id: int, dp_type: TuyaBLEDataPointType, raw: bytes) -> bytes:
    return bytes((dp_id, dp_type.value, len(raw))) + raw


def _install_response(
    device: TuyaBLEDevice,
    token: ConnectionSessionToken,
    *,
    ordering: str = "ack_before_batch",
    payload: bytes | None = None,
) -> AsyncMock:
    payload = payload or _dp(69, TuyaBLEDataPointType.DT_RAW, b"\x01\x02\x03")

    async def respond(
        session_token: ConnectionSessionToken,
        _: list[bytes],
        **__: object,
    ) -> None:
        assert session_token is token
        assert token.operation_lock.locked() is True
        response_key = next(iter(device._input_expected_responses))

        def ack() -> None:
            device._handle_command_or_response(
                1,
                response_key[1],
                TuyaBLECode.FUN_SENDER_DEVICE_STATUS,
                b"\x00",
                session_token=token,
            )

        def batch() -> None:
            device._parse_datapoints_v3(token, 1.0, 0, payload, 0)

        if ordering == "ack_before_batch":
            ack()
            batch()
        elif ordering == "batch_before_ack":
            batch()
            ack()
        elif ordering == "ack_only":
            ack()
        elif ordering == "batch_only":
            batch()
        else:
            raise AssertionError(ordering)

    transport = AsyncMock(side_effect=respond)
    device._send_packets_locked = transport
    return transport


def _assert_refresh_clean(device: TuyaBLEDevice) -> None:
    assert device._manual_status_refresh_active is False
    assert device._status_observers == []
    assert device._status_task_tokens == {}
    assert device._input_expected_responses == {}
    assert device.active_lease_count == 0


async def _start_acked_refresh(
    device: TuyaBLEDevice,
) -> tuple[asyncio.Task[None], AsyncMock]:
    acked = asyncio.Event()

    async def ack_without_batch(
        session_token: ConnectionSessionToken, _: list[bytes], **__: object
    ) -> None:
        response_key = next(iter(device._input_expected_responses))
        device._handle_command_or_response(
            1,
            response_key[1],
            TuyaBLECode.FUN_SENDER_DEVICE_STATUS,
            b"\x00",
            session_token=session_token,
        )
        acked.set()

    transport = AsyncMock(side_effect=ack_without_batch)
    device._send_packets_locked = transport
    refresh = asyncio.create_task(device.async_refresh_s1_status())
    await acked.wait()
    await asyncio.sleep(0)
    return refresh, transport


def test_parent_exposes_dedicated_s1_refresh_device_api() -> None:
    """Refresh Status needs one dedicated device-level operation."""
    assert hasattr(TuyaBLEDevice, "async_refresh_s1_status")


def test_parent_exposes_dedicated_s1_refresh_button() -> None:
    """The generic datapoint-writing button cannot represent a status read."""
    assert hasattr(button, "TuyaBLES1RefreshStatusButton")


def test_parent_exposes_refresh_status_translations() -> None:
    """The new entity needs explicit English and German presentation."""
    integration_root = Path(__file__).parents[1] / "custom_components" / "tuya_ble"
    expected = {
        "strings.json": "Refresh Status",
        "translations/en.json": "Refresh Status",
        "translations/de.json": "Status aktualisieren",
    }
    for relative_path, name in expected.items():
        catalog = json.loads((integration_root / relative_path).read_text())
        assert catalog["entity"]["button"]["refresh_status"]["name"] == name


async def test_exact_s1_exposes_one_diagnostic_refresh_button(
    hass: HomeAssistant,
) -> None:
    """Only the exact S1 receives the dedicated read-only action."""
    device, _ = _connected_s1()
    coordinator = TuyaBLECoordinator(hass, device)
    entry = SimpleNamespace(entry_id="synthetic-r64-entry")
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = TuyaBLEData(
        title="Synthetic S1",
        device=device,
        product=TuyaBLEProductInfo("S1-TY-BLE-PRO"),
        manager=Mock(),
        coordinator=coordinator,
    )
    entities = []

    await button.async_setup_entry(hass, entry, entities.extend)

    assert len(entities) == 1
    entity = entities[0]
    assert isinstance(entity, button.TuyaBLES1RefreshStatusButton)
    assert entity.entity_description.key == "refresh_status"
    assert entity.entity_description.icon == "mdi:refresh"
    assert entity.entity_description.entity_category is EntityCategory.DIAGNOSTIC
    assert entity.unique_id == "synthetic-s1-refresh-refresh_status"
    device.async_refresh_s1_status = AsyncMock()
    await entity.async_press()
    device.async_refresh_s1_status.assert_awaited_once_with()
    assert device.datapoints._datapoints == {}


@pytest.mark.parametrize(
    ("category", "product_id"),
    (("ms", "7a4xvbtt"), ("jtmspro", "akwn32dw")),
    ids=("v1", "other-jtmspro"),
)
async def test_unrelated_products_do_not_expose_refresh_button(
    hass: HomeAssistant, category: str, product_id: str
) -> None:
    """V1 and adjacent products retain their existing entity sets."""
    device, _ = _connected_s1()
    device._device_info.category = category
    device._device_info.product_id = product_id
    coordinator = TuyaBLECoordinator(hass, device)
    entry = SimpleNamespace(entry_id=f"synthetic-r64-{product_id}")
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = TuyaBLEData(
        title="Synthetic other lock",
        device=device,
        product=TuyaBLEProductInfo("Synthetic other lock"),
        manager=Mock(),
        coordinator=coordinator,
    )
    entities = []

    await button.async_setup_entry(hass, entry, entities.extend)

    assert all(
        not isinstance(entity, button.TuyaBLES1RefreshStatusButton)
        for entity in entities
    )


@pytest.mark.parametrize("ordering", ("ack_before_batch", "batch_before_ack"))
@pytest.mark.parametrize("hold_time", (15, 45))
async def test_refresh_requires_one_ack_and_exact_batch_and_retains_hold(
    ordering: str, hold_time: int
) -> None:
    """One press completes in either order and leaves normal hold scheduling."""
    device, token = _connected_s1(hold_time=hold_time)
    automatic_marker = object()
    device._status_attempted_token = automatic_marker
    transport = _install_response(device, token, ordering=ordering)

    await device.async_refresh_s1_status()

    assert transport.await_count == 1
    assert (
        device._build_packets.call_args.args[1] is TuyaBLECode.FUN_SENDER_DEVICE_STATUS
    )
    assert device.active_lease_count == 0
    assert token.operation_lock.locked() is False
    assert device._manual_status_refresh_active is False
    assert device._status_observers == []
    assert device._status_task_tokens == {}
    assert device.on_demand_connection_hold_time == hold_time
    device._schedule_idle_disconnect_locked.assert_called()
    assert device._status_attempted_token is automatic_marker


async def test_two_separate_presses_reuse_warm_session() -> None:
    """A completed later user action may issue one new request on the same session."""
    device, token = _connected_s1()
    transport = _install_response(device, token)

    await device.async_refresh_s1_status()
    await device.async_refresh_s1_status()

    assert transport.await_count == 2
    assert device._ensure_connected.await_count == 2
    assert device._connection_token is token
    assert device._connection_epoch == token.epoch


async def test_always_connected_refresh_reuses_session_without_policy_churn() -> None:
    """An explicit refresh leaves automatic ownership and connectivity unchanged."""
    device, token = _connected_s1(mode=ConnectionMode.ALWAYS_CONNECTED)
    automatic_marker = object()
    device._status_attempted_token = automatic_marker
    transport = _install_response(device, token)

    await device.async_refresh_s1_status()

    assert transport.await_count == 1
    assert device._connection_token is token
    assert device.policy_state is ConnectionPolicyState.ALWAYS_CONNECTED_ACTIVE
    assert device._status_attempted_token is automatic_marker
    device._schedule_idle_disconnect_locked.assert_not_called()
    _assert_refresh_clean(device)


async def test_overlapping_second_press_is_rejected_before_io() -> None:
    """An active owner rejects rather than queues another Device Status."""
    device, token = _connected_s1()
    entered = asyncio.Event()
    release = asyncio.Event()

    async def blocked_transport(
        session_token: ConnectionSessionToken, _: list[bytes], **__: object
    ) -> None:
        assert session_token is token
        entered.set()
        await release.wait()
        response_key = next(iter(device._input_expected_responses))
        device._handle_command_or_response(
            1,
            response_key[1],
            TuyaBLECode.FUN_SENDER_DEVICE_STATUS,
            b"\x00",
            session_token=token,
        )
        device._parse_datapoints_v3(
            token,
            1.0,
            0,
            _dp(69, TuyaBLEDataPointType.DT_RAW, b"\x01\x02\x03"),
            0,
        )

    device._send_packets_locked = AsyncMock(side_effect=blocked_transport)
    first = asyncio.create_task(device.async_refresh_s1_status())
    await entered.wait()

    with pytest.raises(TuyaBLES1StatusRefreshBusyError):
        await device.async_refresh_s1_status()

    assert device._send_packets_locked.await_count == 1
    assert device._ensure_connected.await_count == 1
    release.set()
    await first
    assert device._manual_status_refresh_active is False


@pytest.mark.parametrize("ordering", ("ack_only", "batch_only"))
async def test_incomplete_refresh_times_out_without_replay(
    monkeypatch: pytest.MonkeyPatch, ordering: str
) -> None:
    """Neither ACK nor batch alone can complete or trigger a second request."""
    device, token = _connected_s1()
    transport = _install_response(device, token, ordering=ordering)
    monkeypatch.setattr(
        "custom_components.tuya_ble.tuya_ble.tuya_ble.RESPONSE_WAIT_TIMEOUT", 0.01
    )

    with pytest.raises(TuyaBLES1StatusRefreshFailedError):
        await device.async_refresh_s1_status()

    assert transport.await_count == 1
    assert device._manual_status_refresh_active is False
    assert device._status_observers == []
    assert device._status_task_tokens == {}
    assert device.active_lease_count == 0
    assert token.operation_lock.locked() is False


@pytest.mark.parametrize("failure", ("transport", "ack"))
async def test_transport_and_ack_failures_are_bounded_without_replay(
    failure: str,
) -> None:
    """Transport rejection and negative ACK both return a clean fixed failure."""
    device, token = _connected_s1()

    if failure == "transport":
        device._send_packets_locked = AsyncMock(
            side_effect=OSError("synthetic transport failure")
        )
    else:

        async def reject_ack(
            session_token: ConnectionSessionToken, _: list[bytes], **__: object
        ) -> None:
            response_key = next(iter(device._input_expected_responses))
            device._handle_command_or_response(
                1,
                response_key[1],
                TuyaBLECode.FUN_SENDER_DEVICE_STATUS,
                b"\x01",
                session_token=session_token,
            )

        device._send_packets_locked = AsyncMock(side_effect=reject_ack)

    with pytest.raises(TuyaBLES1StatusRefreshFailedError):
        await device.async_refresh_s1_status()

    assert device._send_packets_locked.await_count == 1
    _assert_refresh_clean(device)
    assert token.operation_lock.locked() is False


async def test_partial_batch_promotes_only_present_retained_dps() -> None:
    """Conditional omissions preserve the previous value and timestamp."""
    device, token = _connected_s1()
    initial = b"".join(
        (
            _dp(8, TuyaBLEDataPointType.DT_VALUE, (40).to_bytes(4, "big")),
            _dp(33, TuyaBLEDataPointType.DT_BOOL, b"\x00"),
            _dp(34, TuyaBLEDataPointType.DT_ENUM, b"\x01"),
            _dp(36, TuyaBLEDataPointType.DT_VALUE, (30).to_bytes(4, "big")),
        )
    )
    device._parse_datapoints_v3(token, 1.0, 0, initial, 0)
    before_34 = device.last_confirmed_s1_state.get(34)
    before_36 = device.last_confirmed_s1_state.get(36)
    response = b"".join(
        (
            _dp(8, TuyaBLEDataPointType.DT_VALUE, (55).to_bytes(4, "big")),
            _dp(33, TuyaBLEDataPointType.DT_BOOL, b"\x01"),
        )
    )
    _install_response(device, token, payload=response)

    await device.async_refresh_s1_status()

    assert device.last_confirmed_s1_state.get(8).value == 55
    assert device.last_confirmed_s1_state.get(33).value is True
    assert device.last_confirmed_s1_state.get(34) == before_34
    assert device.last_confirmed_s1_state.get(36) == before_36


async def test_non_retained_batch_completes_without_advancing_status_time() -> None:
    """DP69 is a valid batch but never synthetic last-confirmed evidence."""
    device, token = _connected_s1()
    initial = b"".join(
        (
            _dp(8, TuyaBLEDataPointType.DT_VALUE, (40).to_bytes(4, "big")),
            _dp(33, TuyaBLEDataPointType.DT_BOOL, b"\x00"),
            _dp(34, TuyaBLEDataPointType.DT_ENUM, b"\x01"),
            _dp(36, TuyaBLEDataPointType.DT_VALUE, (30).to_bytes(4, "big")),
        )
    )
    device._parse_datapoints_v3(token, 1.0, 0, initial, 0)
    before = {
        dp_id: device.last_confirmed_s1_state.get(dp_id) for dp_id in (8, 33, 34, 36)
    }
    before_latest = device.last_confirmed_s1_state.latest_confirmed_at
    _install_response(device, token)

    await device.async_refresh_s1_status()

    assert {
        dp_id: device.last_confirmed_s1_state.get(dp_id) for dp_id in (8, 33, 34, 36)
    } == before
    assert device.last_confirmed_s1_state.latest_confirmed_at == before_latest
    assert device.last_confirmed_s1_state.get(69) is None


async def test_wrong_retained_type_is_not_promoted() -> None:
    """The existing promotion map rejects a mismatched retained DP type."""
    device, token = _connected_s1()
    device._parse_datapoints_v3(
        token,
        1.0,
        0,
        _dp(34, TuyaBLEDataPointType.DT_ENUM, b"\x01"),
        0,
    )
    before = device.last_confirmed_s1_state.get(34)
    _install_response(
        device,
        token,
        payload=b"".join(
            (
                _dp(34, TuyaBLEDataPointType.DT_BOOL, b"\x00"),
                _dp(8, TuyaBLEDataPointType.DT_VALUE, (60).to_bytes(4, "big")),
            )
        ),
    )

    await device.async_refresh_s1_status()

    assert device.last_confirmed_s1_state.get(34) == before
    assert device.last_confirmed_s1_state.get(8).value == 60


async def test_full_retained_batch_uses_existing_promotion_path() -> None:
    """All four evidenced values update with existing current-session semantics."""
    device, token = _connected_s1()
    payload = b"".join(
        (
            _dp(8, TuyaBLEDataPointType.DT_VALUE, (75).to_bytes(4, "big")),
            _dp(33, TuyaBLEDataPointType.DT_BOOL, b"\x01"),
            _dp(34, TuyaBLEDataPointType.DT_ENUM, b"\x00"),
            _dp(36, TuyaBLEDataPointType.DT_VALUE, (90).to_bytes(4, "big")),
        )
    )
    _install_response(device, token, payload=payload)

    await device.async_refresh_s1_status()

    expected = {8: 75, 33: True, 34: 0, 36: 90}
    confirmations = {
        dp_id: device.last_confirmed_s1_state.get(dp_id) for dp_id in expected
    }
    assert {dp_id: value.value for dp_id, value in confirmations.items()} == expected
    assert {value.value_source for value in confirmations.values()} == {
        "current_session"
    }
    assert {value.data_fresh for value in confirmations.values()} == {True}
    assert device.last_confirmed_s1_state.latest_confirmed_at == max(
        value.confirmed_at for value in confirmations.values()
    )


async def test_superseded_generation_fails_without_accepting_replacement() -> None:
    """A replacement observation cannot donate its batch to the old refresh."""
    device, token = _connected_s1()

    async def supersede(
        session_token: ConnectionSessionToken, _: list[bytes], **__: object
    ) -> None:
        response_key = next(iter(device._input_expected_responses))
        device._handle_command_or_response(
            1,
            response_key[1],
            TuyaBLECode.FUN_SENDER_DEVICE_STATUS,
            b"\x00",
            session_token=session_token,
        )
        device._start_status_observation(token, "explicit", 999)
        device._parse_datapoints_v3(
            token,
            1.0,
            0,
            _dp(8, TuyaBLEDataPointType.DT_VALUE, (70).to_bytes(4, "big")),
            0,
        )

    device._send_packets_locked = AsyncMock(side_effect=supersede)

    with pytest.raises(TuyaBLES1StatusRefreshFailedError):
        await device.async_refresh_s1_status()

    assert device._send_packets_locked.await_count == 1
    assert device._manual_status_refresh_active is False


async def test_old_session_batch_cannot_complete_or_promote(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A retired token cannot satisfy the waiter or update retained state."""
    device, token = _connected_s1()
    old_token = ConnectionSessionToken(_SyntheticClient(), token.epoch - 1)
    monkeypatch.setattr(
        "custom_components.tuya_ble.tuya_ble.tuya_ble.RESPONSE_WAIT_TIMEOUT", 0.01
    )

    async def stale_batch(
        session_token: ConnectionSessionToken, _: list[bytes], **__: object
    ) -> None:
        response_key = next(iter(device._input_expected_responses))
        device._handle_command_or_response(
            1,
            response_key[1],
            TuyaBLECode.FUN_SENDER_DEVICE_STATUS,
            b"\x00",
            session_token=session_token,
        )
        device._parse_datapoints_v3(
            old_token,
            1.0,
            0,
            _dp(8, TuyaBLEDataPointType.DT_VALUE, (80).to_bytes(4, "big")),
            0,
        )

    device._send_packets_locked = AsyncMock(side_effect=stale_batch)

    with pytest.raises(TuyaBLES1StatusRefreshFailedError):
        await device.async_refresh_s1_status()

    assert device.last_confirmed_s1_state.get(8) is None
    assert device._send_packets_locked.await_count == 1


async def test_session_invalidation_cancels_without_replay() -> None:
    """Retiring the exact session cancels and cleans its manual refresh task."""
    device, token = _connected_s1()
    acked = asyncio.Event()

    async def ack_then_wait(
        session_token: ConnectionSessionToken, _: list[bytes], **__: object
    ) -> None:
        response_key = next(iter(device._input_expected_responses))
        device._handle_command_or_response(
            1,
            response_key[1],
            TuyaBLECode.FUN_SENDER_DEVICE_STATUS,
            b"\x00",
            session_token=session_token,
        )
        acked.set()

    device._send_packets_locked = AsyncMock(side_effect=ack_then_wait)
    refresh = asyncio.create_task(device.async_refresh_s1_status())
    await acked.wait()
    await asyncio.sleep(0)

    device._invalidate_session_data(token)

    with pytest.raises(asyncio.CancelledError):
        await refresh
    assert device._send_packets_locked.await_count == 1
    assert device._manual_status_refresh_active is False
    assert device._status_observers == []
    assert device._status_task_tokens == {}
    assert device.active_lease_count == 0


@pytest.mark.parametrize("boundary", ("disconnect", "replacement"))
async def test_session_loss_boundaries_cancel_without_replay(boundary: str) -> None:
    """Disconnect and replacement retire the exact refresh session once."""
    device, token = _connected_s1()
    refresh, transport = await _start_acked_refresh(device)

    token.client.is_connected = False
    if boundary == "disconnect":
        device._mark_connection_lost(token, unexpected=True)
    else:
        device._claim_connection_session(_SyntheticClient())

    with pytest.raises(asyncio.CancelledError):
        await refresh
    assert transport.await_count == 1
    _assert_refresh_clean(device)


@pytest.mark.parametrize("boundary", ("mode", "suspension"))
async def test_policy_boundaries_cancel_active_refresh(boundary: str) -> None:
    """Mode changes and BLE suspension promptly release refresh ownership."""
    device, _ = _connected_s1()
    refresh, transport = await _start_acked_refresh(device)
    if boundary == "suspension":
        device._apply_connection_policy = AsyncMock()
        await device.async_update_connection_policy(ble_control_enabled=False)
    else:
        await device.async_update_connection_policy(
            connection_mode=ConnectionMode.ALWAYS_CONNECTED.value
        )

    with pytest.raises(asyncio.CancelledError):
        await refresh
    assert transport.await_count == 1
    _assert_refresh_clean(device)


@pytest.mark.parametrize("boundary", ("unload", "shutdown"))
async def test_terminal_lifecycle_boundaries_cancel_active_refresh(
    boundary: str,
) -> None:
    """Unload preparation and shutdown leave no manual refresh resources."""
    device, token = _connected_s1()
    refresh, transport = await _start_acked_refresh(device)

    async def complete_release() -> None:
        token.client.is_connected = False
        device._client = None
        device._connection_token = None

    device._complete_pending_release = AsyncMock(side_effect=complete_release)
    if boundary == "unload":
        assert await device.async_prepare_unload() is True
    else:
        await device.stop()

    with pytest.raises(asyncio.CancelledError):
        await refresh
    assert transport.await_count == 1
    _assert_refresh_clean(device)


async def test_existing_session_lock_serializes_a_concurrent_command() -> None:
    """A command waits through the refresh ACK-plus-batch boundary."""
    device, token = _connected_s1()
    acked = asyncio.Event()

    async def transport(
        session_token: ConnectionSessionToken, _: list[bytes], **__: object
    ) -> None:
        if device._send_packets_locked.await_count == 1:
            response_key = next(iter(device._input_expected_responses))
            device._handle_command_or_response(
                1,
                response_key[1],
                TuyaBLECode.FUN_SENDER_DEVICE_STATUS,
                b"\x00",
                session_token=session_token,
            )
            acked.set()

    device._send_packets_locked = AsyncMock(side_effect=transport)
    refresh = asyncio.create_task(device.async_refresh_s1_status())
    await acked.wait()
    command = asyncio.create_task(
        device._int_send_packet_while_connected(token, [b"synthetic-command"])
    )
    await asyncio.sleep(0)
    assert command.done() is False
    assert device._send_packets_locked.await_count == 1

    device._parse_datapoints_v3(
        token,
        1.0,
        0,
        _dp(69, TuyaBLEDataPointType.DT_RAW, b"\x01\x02\x03"),
        0,
    )
    await refresh
    await command

    assert device._send_packets_locked.await_count == 2
    assert device._build_packets.call_count == 1


async def test_cancellation_releases_all_manual_refresh_ownership() -> None:
    """Cancellation cannot leave a waiter, observer, lease, or owner behind."""
    device, token = _connected_s1()
    entered = asyncio.Event()

    async def never_returns(*_: object, **__: object) -> None:
        entered.set()
        await asyncio.Event().wait()

    device._send_packets_locked = AsyncMock(side_effect=never_returns)
    task = asyncio.create_task(device.async_refresh_s1_status())
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert device._send_packets_locked.await_count == 1
    assert device._manual_status_refresh_active is False
    assert device._status_observers == []
    assert device._status_task_tokens == {}
    assert device.active_lease_count == 0
    assert token.operation_lock.locked() is False


async def test_ble_control_off_rejects_before_connection_or_status_io() -> None:
    """The existing control guard runs before owner claim and connection work."""
    device, _ = _connected_s1()
    device._ble_control_enabled = False
    device._suspension_requested = True

    with pytest.raises(TuyaBLEControlSuspendedError):
        await device.async_refresh_s1_status()

    device._ensure_connected.assert_not_awaited()
    device._build_packets.assert_not_called()
    assert device._manual_status_refresh_active is False
