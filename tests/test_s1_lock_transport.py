"""Safety contracts for the S1-TY-BLE-PRO lock transport."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import os
import stat
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest
from bleak.backends.device import BLEDevice
from bleak_retry_connector import BleakError
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError

from custom_components.tuya_ble.const import (
    UNEXPECTED_RECONNECT_MIN_SECONDS,
    ConnectionMode,
    ConnectionPolicyState,
)
from custom_components.tuya_ble.devices import (
    TuyaBLECoordinator,
    TuyaBLEProductInfo,
)
from custom_components.tuya_ble.lock import (
    S1_DP71_MIN_LENGTH,
    S1_DP71_TIMESTAMP,
    S1_DP_LOCK,
    S1_DP_MOTOR_STATE,
    S1_DP_UNLOCK_CONFIRM,
    S1_DP_UNLOCK_REQUEST,
    S1_STORE_KEY,
    S1_STORE_VERSION,
    S1_UNLOCK_DELAY,
    S1_UNLOCK_ERROR_TRANSLATION_KEY,
    TuyaBLES1Lock,
    TuyaBLES1TemplateStore,
    _async_get_s1_template_store,
    _harden_s1_store_permissions,
)
from custom_components.tuya_ble.tuya_ble import (
    TuyaBLEDataPointType,
    TuyaBLEDevice,
)
from custom_components.tuya_ble.tuya_ble.manager import TuyaBLEDeviceCredentials
from custom_components.tuya_ble.tuya_ble.tuya_ble import ConnectionSessionToken

SYNTHETIC_DEVICE_ID = "synthetic-s1-device"
SYNTHETIC_OTHER_DEVICE_ID = "synthetic-other-device"
SYNTHETIC_DP70_SAMPLE_LENGTH = 16
SYNTHETIC_DP70 = hashlib.shake_256(b"tuya-ble-test-only:synthetic-s1-dp70").digest(
    SYNTHETIC_DP70_SAMPLE_LENGTH
)
SYNTHETIC_DP71 = hashlib.shake_256(b"tuya-ble-test-only:synthetic-s1-dp71").digest(
    S1_DP71_MIN_LENGTH
)
SYNTHETIC_TIMESTAMP = 1_700_000_123


def _encoded(raw_value: bytes) -> str:
    return base64.b64encode(raw_value).decode("ascii")


def _stored_pair() -> dict[str, str]:
    return {
        "dp70_b64": _encoded(SYNTHETIC_DP70),
        "dp71_b64": _encoded(SYNTHETIC_DP71),
    }


class _BackingStore:
    """Minimal storage double that retains delayed persistence snapshots."""

    def __init__(self, loaded: object = None, path: str = "") -> None:
        self.loaded = loaded
        self.path = path
        self.load_calls = 0
        self.delayed_saves: list[tuple[object, float]] = []

    async def async_load(self) -> object:
        self.load_calls += 1
        return self.loaded

    def async_delay_save(self, data_func, delay: float = 0) -> None:
        self.delayed_saves.append((data_func, delay))


class _ConnectedTransportClient:
    """Connected client double for ambiguous S1 write failures."""

    def __init__(self, write_side_effect: object) -> None:
        self.is_connected = True
        self.stop_notify = AsyncMock()
        self.write_gatt_char = AsyncMock(side_effect=write_side_effect)

        async def disconnect() -> None:
            self.is_connected = False

        self.disconnect = AsyncMock(side_effect=disconnect)


def _make_device(device_id: str = SYNTHETIC_DEVICE_ID) -> TuyaBLEDevice:
    ble_device = BLEDevice(
        name="Synthetic S1",
        address="00:00:00:00:00:01",
        details={},
        rssi=-50,
    )
    device = TuyaBLEDevice(Mock(), ble_device)
    device._device_info = TuyaBLEDeviceCredentials(
        uuid="synthetic-s1-uuid",
        local_key="synthetic-key-01",
        device_id=device_id,
        category="jtmspro",
        product_id="xqeob8h6",
        device_name="Synthetic S1",
        product_model="SYNTHETIC",
        product_name="Synthetic S1",
        functions=[],
        status_range=[],
    )
    device._send_datapoints = AsyncMock()
    device._send_datapoints_no_replay = AsyncMock()
    return device


def _install_synthetic_session(
    device: TuyaBLEDevice, client: _ConnectedTransportClient | Mock | None = None
) -> ConnectionSessionToken:
    """Install one exact synthetic S1 session for focused transport tests."""
    if client is None:
        client = Mock(is_connected=True)
    token = device._claim_connection_session(client)
    device._is_paired = True
    device._notifications_active = True
    device._connected_notified_token = token
    return token


def _make_entity(
    hass: HomeAssistant,
    stored_data: object,
) -> tuple[TuyaBLES1Lock, TuyaBLEDevice, _BackingStore]:
    device = _make_device()
    coordinator = TuyaBLECoordinator(hass, device)
    backing_store = _BackingStore(stored_data)
    template_store = TuyaBLES1TemplateStore(hass, backing_store, stored_data)
    entity = TuyaBLES1Lock(
        hass,
        coordinator,
        device,
        TuyaBLEProductInfo("S1-TY-BLE-PRO", lock=1),
        template_store,
    )
    entity.async_write_ha_state = Mock()

    async def ensure_synthetic_session() -> None:
        if device.current_session_epoch is None:
            _install_synthetic_session(device)

    device._ensure_connected = AsyncMock(side_effect=ensure_synthetic_session)
    return entity, device, backing_store


def _make_transport_entity(
    hass: HomeAssistant,
    write_side_effect: object,
) -> tuple[TuyaBLES1Lock, TuyaBLEDevice, _ConnectedTransportClient]:
    """Build a real S1 entity and transport path with synthetic GATT only."""
    entity, device, _ = _make_entity(hass, {SYNTHETIC_DEVICE_ID: _stored_pair()})
    device._disconnected_callbacks.clear()
    del device._send_datapoints
    del device._send_datapoints_no_replay
    client = _ConnectedTransportClient(write_side_effect)
    device._protocol_version = 3
    _install_synthetic_session(device, client)
    device._state_data_fresh = True
    device._build_packets = Mock(return_value=[b"synthetic-s1-gatt-fragment"])
    device._schedule_reconnect_locked = Mock()
    return entity, device, client


async def test_s1_store_uses_private_atomic_legacy_version_one_key(
    hass: HomeAssistant, tmp_path: Path
) -> None:
    """The b2 key remains readable through private atomic storage."""
    backing_store = _BackingStore(
        {SYNTHETIC_DEVICE_ID: _stored_pair()}, str(tmp_path / "missing-store")
    )
    with patch(
        "custom_components.tuya_ble.lock.storage.Store", return_value=backing_store
    ) as store_class:
        template_store = await TuyaBLES1TemplateStore.async_load(hass)

    store_class.assert_called_once_with(
        hass,
        S1_STORE_VERSION,
        S1_STORE_KEY,
        private=True,
        atomic_writes=True,
    )
    assert backing_store.load_calls == 1
    assert S1_STORE_VERSION == 1
    assert S1_STORE_KEY == "tuya_ble_jtmspro_lock_templates"
    assert template_store.templates_for(SYNTHETIC_DEVICE_ID) == (
        SYNTHETIC_DP70,
        SYNTHETIC_DP71,
    )


async def test_s1_store_hardens_existing_legacy_file_before_load(
    hass: HomeAssistant, tmp_path: Path
) -> None:
    """An existing non-private b2 Store becomes owner-only before loading."""
    store_path = tmp_path / S1_STORE_KEY
    store_path.write_text("synthetic legacy store", encoding="utf-8")
    store_path.chmod(0o644)
    backing_store = _BackingStore({}, str(store_path))

    with patch(
        "custom_components.tuya_ble.lock.storage.Store", return_value=backing_store
    ):
        await TuyaBLES1TemplateStore.async_load(hass)

    assert stat.S_IMODE(store_path.stat().st_mode) == 0o600
    assert backing_store.load_calls == 1


async def test_s1_store_rejects_non_regular_legacy_path_before_load(
    hass: HomeAssistant, tmp_path: Path
) -> None:
    """Unexpected Store paths fail closed before template data is loaded."""
    store_path = tmp_path / S1_STORE_KEY
    store_path.mkdir()
    backing_store = _BackingStore({}, str(store_path))

    with (
        patch(
            "custom_components.tuya_ble.lock.storage.Store",
            return_value=backing_store,
        ),
        pytest.raises(HomeAssistantError, match="not a regular file"),
    ):
        await TuyaBLES1TemplateStore.async_load(hass)

    assert backing_store.load_calls == 0


def test_s1_store_permission_hardening_rejects_symlink(tmp_path: Path) -> None:
    """Permission migration never follows a replacement path symlink."""
    target_path = tmp_path / "target"
    target_path.write_text("synthetic target", encoding="utf-8")
    target_path.chmod(0o644)
    store_path = tmp_path / S1_STORE_KEY
    store_path.symlink_to(target_path)

    with pytest.raises(HomeAssistantError, match="permissions are invalid"):
        _harden_s1_store_permissions(str(store_path))

    assert stat.S_IMODE(target_path.stat().st_mode) == 0o644


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO required")
def test_s1_store_permission_hardening_rejects_fifo(tmp_path: Path) -> None:
    """A special Store path is rejected without blocking setup."""
    store_path = tmp_path / S1_STORE_KEY
    os.mkfifo(store_path)

    with pytest.raises(HomeAssistantError, match="not a regular file"):
        _harden_s1_store_permissions(str(store_path))


async def test_s1_store_load_is_singleton_under_concurrent_setup(
    hass: HomeAssistant,
) -> None:
    """Concurrent config-entry setup cannot create diverging store instances."""
    load_started = asyncio.Event()
    allow_load = asyncio.Event()
    template_store = TuyaBLES1TemplateStore(hass, _BackingStore(), {})

    async def controlled_load(_: HomeAssistant) -> TuyaBLES1TemplateStore:
        load_started.set()
        await allow_load.wait()
        return template_store

    with patch.object(
        TuyaBLES1TemplateStore, "async_load", side_effect=controlled_load
    ) as load:
        first = asyncio.create_task(_async_get_s1_template_store(hass))
        await load_started.wait()
        second = asyncio.create_task(_async_get_s1_template_store(hass))
        allow_load.set()
        first_result, second_result = await asyncio.gather(first, second)

    assert first_result is template_store
    assert second_result is template_store
    load.assert_awaited_once_with(hass)


async def test_s1_entity_captures_existing_inbound_snapshot(
    hass: HomeAssistant,
) -> None:
    """A snapshot received just before platform setup remains captureable."""
    device = _make_device()
    token = _install_synthetic_session(device)
    device.datapoints._update_from_device(
        70, 1.0, 0, TuyaBLEDataPointType.DT_RAW, SYNTHETIC_DP70, token
    )
    device.datapoints._update_from_device(
        71, 1.0, 0, TuyaBLEDataPointType.DT_RAW, SYNTHETIC_DP71, token
    )
    backing_store = _BackingStore({})
    template_store = TuyaBLES1TemplateStore(hass, backing_store, {})

    TuyaBLES1Lock(
        hass,
        TuyaBLECoordinator(hass, device),
        device,
        TuyaBLEProductInfo("S1-TY-BLE-PRO", lock=1),
        template_store,
    )

    assert template_store.templates_for(SYNTHETIC_DEVICE_ID) == (
        SYNTHETIC_DP70,
        SYNTHETIC_DP71,
    )
    assert len(backing_store.delayed_saves) == 1


async def test_s1_lock_motor_state_requires_its_replacement_session_dp47(
    hass: HomeAssistant,
) -> None:
    """Replacement DP8 cannot make the lock reuse an old DP47 motor value."""
    entity, device, _ = _make_entity(hass, None)
    old_client = Mock(is_connected=True)
    old_token = _install_synthetic_session(device, old_client)
    device.datapoints._update_from_device(
        S1_DP_MOTOR_STATE,
        1.0,
        0,
        TuyaBLEDataPointType.DT_BOOL,
        True,
        old_token,
    )
    assert entity.is_locked is False

    old_client.is_connected = False
    replacement_token = _install_synthetic_session(device, Mock(is_connected=True))
    device.datapoints._update_from_device(
        8,
        2.0,
        0,
        TuyaBLEDataPointType.DT_VALUE,
        74,
        replacement_token,
    )
    assert entity.is_locked is None

    device.datapoints._update_from_device(
        S1_DP_MOTOR_STATE,
        3.0,
        0,
        TuyaBLEDataPointType.DT_BOOL,
        False,
        replacement_token,
    )
    assert entity.is_locked is True

    await entity.async_will_remove_from_hass()
    entity._coordinator.shutdown()


async def test_s1_lock_and_unlock_transport_contract(hass: HomeAssistant) -> None:
    """S1 uses DP46 and an ordered, delayed, timestamp-rebuilt DP70/71 pair."""
    entity, device, _ = _make_entity(hass, {SYNTHETIC_DEVICE_ID: _stored_pair()})
    events: list[tuple[str, object, object]] = []

    async def record_send(datapoint_ids: list[int]) -> None:
        datapoint_id = datapoint_ids[0]
        events.append(
            ("write", datapoint_id, bytes(device.datapoints[datapoint_id].value))
        )

    async def record_sleep(delay: float) -> None:
        events.append(("sleep", delay, None))

    def record_time() -> int:
        events.append(("time", None, None))
        return SYNTHETIC_TIMESTAMP

    device._send_datapoints_no_replay.side_effect = record_send
    await entity.async_lock()
    assert device._send_datapoints_no_replay.call_count == 1
    assert device.datapoints[46].value is True

    device._send_datapoints_no_replay.reset_mock()
    events.clear()
    with (
        patch("custom_components.tuya_ble.lock.asyncio.sleep", record_sleep),
        patch("custom_components.tuya_ble.lock.time.time", record_time),
    ):
        await entity.async_unlock()

    assert [event[:2] for event in events if event[0] != "time"] == [
        ("write", 70),
        ("sleep", S1_UNLOCK_DELAY),
        ("write", 71),
    ]
    first_write_index = next(
        index for index, event in enumerate(events) if event[:2] == ("write", 70)
    )
    assert events.index(("time", None, None)) < first_write_index
    writes = [event for event in events if event[0] == "write"]
    assert writes[0][2] == SYNTHETIC_DP70
    dp71_payload = writes[1][2]
    assert isinstance(dp71_payload, bytes)
    assert len(dp71_payload) == S1_DP71_MIN_LENGTH
    assert (
        dp71_payload[: S1_DP71_TIMESTAMP.start]
        == SYNTHETIC_DP71[: S1_DP71_TIMESTAMP.start]
    )
    assert dp71_payload[S1_DP71_TIMESTAMP] == SYNTHETIC_TIMESTAMP.to_bytes(4, "big")
    assert (
        dp71_payload[S1_DP71_TIMESTAMP.stop :]
        == SYNTHETIC_DP71[S1_DP71_TIMESTAMP.stop :]
    )
    assert entity.entity_description.key == "ble_unlock_lock"
    assert entity.entity_description.translation_key == "lock"
    assert entity.entity_description.icon == "mdi:lock"
    assert entity.unique_id == f"{SYNTHETIC_DEVICE_ID}-ble_unlock_lock"


async def test_s1_on_demand_unlock_selects_refreshed_templates_after_connection(
    hass: HomeAssistant,
) -> None:
    """On-demand S1 unlock selects a refreshed pair after connecting."""
    session_two_dp70 = hashlib.shake_256(
        b"tuya-ble-test-only:synthetic-session-two-dp70"
    ).digest(SYNTHETIC_DP70_SAMPLE_LENGTH)
    session_two_dp71 = hashlib.shake_256(
        b"tuya-ble-test-only:synthetic-session-two-dp71"
    ).digest(S1_DP71_MIN_LENGTH)
    entity, device, _ = _make_entity(hass, {SYNTHETIC_DEVICE_ID: _stored_pair()})
    device._connection_mode = ConnectionMode.ON_DEMAND
    device._protocol_version = 3
    del device._send_datapoints_no_replay
    device._execute_disconnect = AsyncMock()
    sent_payloads: list[bytes] = []
    ensure_count = 0

    async def establish_session_two() -> None:
        nonlocal ensure_count
        ensure_count += 1
        if ensure_count != 1:
            return
        token = _install_synthetic_session(device)
        device.datapoints._update_from_device(
            S1_DP_UNLOCK_REQUEST,
            1.0,
            0,
            TuyaBLEDataPointType.DT_RAW,
            session_two_dp70,
            token,
        )
        device.datapoints._update_from_device(
            S1_DP_UNLOCK_CONFIRM,
            2.0,
            0,
            TuyaBLEDataPointType.DT_RAW,
            session_two_dp71,
            token,
        )
        device._fire_callbacks(
            [
                device.datapoints[S1_DP_UNLOCK_REQUEST],
                device.datapoints[S1_DP_UNLOCK_CONFIRM],
            ]
        )

    async def record_packet(_, data: bytes, *__: object) -> bool:
        sent_payloads.append(data)
        return True

    device._ensure_connected = AsyncMock(side_effect=establish_session_two)
    device._send_packet_while_connected = AsyncMock(side_effect=record_packet)
    with (
        patch("custom_components.tuya_ble.lock.asyncio.sleep", AsyncMock()),
        patch(
            "custom_components.tuya_ble.lock.time.time",
            return_value=SYNTHETIC_TIMESTAMP,
        ),
    ):
        await entity.async_unlock()

    sent_session_two_pair = (
        session_two_dp70 in sent_payloads[0]
        and session_two_dp71[: S1_DP71_TIMESTAMP.start] in sent_payloads[1]
    )
    sent_persistent_pair = (
        SYNTHETIC_DP70 in sent_payloads[0]
        or SYNTHETIC_DP71[: S1_DP71_TIMESTAMP.start] in sent_payloads[1]
    )
    assert sent_session_two_pair
    assert not sent_persistent_pair


async def test_s1_on_demand_unlock_uses_persisted_pair_without_session_templates(
    hass: HomeAssistant,
) -> None:
    """On-demand S1 unlock retains a validated persisted-pair fallback."""
    entity, device, _ = _make_entity(hass, {SYNTHETIC_DEVICE_ID: _stored_pair()})
    device._connection_mode = ConnectionMode.ON_DEMAND
    device._execute_disconnect = AsyncMock()

    async def establish_session_without_templates() -> None:
        if device._connection_token is None:
            _install_synthetic_session(device)

    device._ensure_connected = AsyncMock(
        side_effect=establish_session_without_templates
    )

    await entity.async_unlock()

    assert device._send_datapoints_no_replay.await_args_list == [
        (([S1_DP_UNLOCK_REQUEST],), {}),
        (([S1_DP_UNLOCK_CONFIRM],), {}),
    ]
    assert device._ensure_connected.await_count == 1
    assert entity.is_unlocking is False
    if device._idle_disconnect_task is not None:
        device._idle_disconnect_task.cancel()
        await asyncio.sleep(0)


@pytest.mark.parametrize("partial_dp_id", (S1_DP_UNLOCK_REQUEST, S1_DP_UNLOCK_CONFIRM))
async def test_s1_on_demand_partial_refresh_uses_only_persisted_complete_pair(
    hass: HomeAssistant, partial_dp_id: int
) -> None:
    """A Session-2 half cannot mix with the persisted Session-1 pair."""
    partial_value = hashlib.shake_256(
        f"tuya-ble-test-only:partial-session-two-{partial_dp_id}".encode()
    ).digest(
        SYNTHETIC_DP70_SAMPLE_LENGTH
        if partial_dp_id == S1_DP_UNLOCK_REQUEST
        else S1_DP71_MIN_LENGTH
    )
    entity, device, backing_store = _make_entity(
        hass, {SYNTHETIC_DEVICE_ID: _stored_pair()}
    )
    device._connection_mode = ConnectionMode.ON_DEMAND
    device._execute_disconnect = AsyncMock()
    writes: list[tuple[int, bytes]] = []

    async def establish_partial_session() -> None:
        token = _install_synthetic_session(device)
        device.datapoints._update_from_device(
            partial_dp_id,
            1.0,
            0,
            TuyaBLEDataPointType.DT_RAW,
            partial_value,
            token,
        )
        device._fire_callbacks([device.datapoints[partial_dp_id]])

    async def record_send(datapoint_ids: list[int]) -> None:
        datapoint_id = datapoint_ids[0]
        writes.append((datapoint_id, bytes(device.datapoints[datapoint_id].value)))

    device._ensure_connected = AsyncMock(side_effect=establish_partial_session)
    device._send_datapoints_no_replay.side_effect = record_send
    with (
        patch("custom_components.tuya_ble.lock.asyncio.sleep", AsyncMock()),
        patch(
            "custom_components.tuya_ble.lock.time.time",
            return_value=SYNTHETIC_TIMESTAMP,
        ),
    ):
        await entity.async_unlock()

    assert writes[0] == (S1_DP_UNLOCK_REQUEST, SYNTHETIC_DP70)
    assert writes[1][0] == S1_DP_UNLOCK_CONFIRM
    assert (
        writes[1][1][: S1_DP71_TIMESTAMP.start]
        == SYNTHETIC_DP71[: S1_DP71_TIMESTAMP.start]
    )
    assert backing_store.delayed_saves == []
    if device._idle_disconnect_task is not None:
        device._idle_disconnect_task.cancel()
        await asyncio.sleep(0)


@pytest.mark.parametrize("partial_dp_id", (S1_DP_UNLOCK_REQUEST, S1_DP_UNLOCK_CONFIRM))
async def test_s1_on_demand_partial_pair_without_fallback_writes_nothing(
    hass: HomeAssistant, partial_dp_id: int
) -> None:
    """One current-session half without a persisted pair fails before DP70."""
    partial_value = hashlib.shake_256(
        f"tuya-ble-test-only:no-fallback-partial-{partial_dp_id}".encode()
    ).digest(
        SYNTHETIC_DP70_SAMPLE_LENGTH
        if partial_dp_id == S1_DP_UNLOCK_REQUEST
        else S1_DP71_MIN_LENGTH
    )
    entity, device, backing_store = _make_entity(hass, {})
    device._connection_mode = ConnectionMode.ON_DEMAND
    device._execute_disconnect = AsyncMock()

    async def establish_partial_session() -> None:
        token = _install_synthetic_session(device)
        device.datapoints._update_from_device(
            partial_dp_id,
            1.0,
            0,
            TuyaBLEDataPointType.DT_RAW,
            partial_value,
            token,
        )
        device._fire_callbacks([device.datapoints[partial_dp_id]])

    device._ensure_connected = AsyncMock(side_effect=establish_partial_session)

    with pytest.raises(ServiceValidationError):
        await entity.async_unlock()

    device._send_datapoints_no_replay.assert_not_awaited()
    assert backing_store.delayed_saves == []
    assert entity.is_unlocking is False
    if device._idle_disconnect_task is not None:
        device._idle_disconnect_task.cancel()
        await asyncio.sleep(0)


async def test_s1_on_demand_outer_lease_protects_connection_and_both_writes(
    hass: HomeAssistant,
) -> None:
    """Idle release begins only after the complete unlock operation drains."""
    entity, device, _ = _make_entity(hass, {SYNTHETIC_DEVICE_ID: _stored_pair()})
    device._connection_mode = ConnectionMode.ON_DEMAND
    device._schedule_idle_disconnect_locked = Mock()
    observed_counts: list[int] = []

    async def record_send(_: list[int]) -> None:
        observed_counts.append(device.active_lease_count)
        device._schedule_idle_disconnect_locked.assert_not_called()

    async def record_delay(delay: float) -> None:
        assert delay >= S1_UNLOCK_DELAY
        observed_counts.append(device.active_lease_count)
        device._schedule_idle_disconnect_locked.assert_not_called()

    device._send_datapoints_no_replay.side_effect = record_send
    with patch("custom_components.tuya_ble.lock.asyncio.sleep", record_delay):
        await entity.async_unlock()

    assert observed_counts == [1, 1, 1]
    assert device.active_lease_count == 0
    device._schedule_idle_disconnect_locked.assert_called_once_with()


async def test_s1_cancelled_unlock_releases_shared_operation_lock(
    hass: HomeAssistant,
) -> None:
    """Cancelling an unlock cannot block a later S1 lock operation."""
    entity, device, _ = _make_entity(hass, {SYNTHETIC_DEVICE_ID: _stored_pair()})
    writes: list[int] = []
    unlock_delay_started = asyncio.Event()

    async def record_send(datapoint_ids: list[int]) -> None:
        writes.extend(datapoint_ids)

    async def wait_until_cancelled(delay: float) -> None:
        assert delay == S1_UNLOCK_DELAY
        unlock_delay_started.set()
        await asyncio.Event().wait()

    device._send_datapoints_no_replay.side_effect = record_send
    with patch("custom_components.tuya_ble.lock.asyncio.sleep", wait_until_cancelled):
        unlock_task = asyncio.create_task(entity.async_unlock())
        await unlock_delay_started.wait()
        unlock_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await unlock_task
        await entity.async_lock()

    assert writes == [S1_DP_UNLOCK_REQUEST, S1_DP_LOCK]


async def test_s1_cancelled_lock_releases_shared_operation_lock(
    hass: HomeAssistant,
) -> None:
    """Cancelling an active Lock cannot block a later Unlock sequence."""
    entity, device, _ = _make_entity(hass, {SYNTHETIC_DEVICE_ID: _stored_pair()})
    lock_send_started = asyncio.Event()

    async def wait_until_cancelled(datapoint_ids: list[int]) -> None:
        assert datapoint_ids == [S1_DP_LOCK]
        lock_send_started.set()
        await asyncio.Event().wait()

    device._send_datapoints_no_replay.side_effect = wait_until_cancelled
    lock_task = asyncio.create_task(entity.async_lock())
    await lock_send_started.wait()
    lock_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await lock_task

    device._send_datapoints_no_replay.side_effect = None
    with patch("custom_components.tuya_ble.lock.asyncio.sleep", AsyncMock()):
        await entity.async_unlock()

    assert entity.is_locking is False
    assert entity.is_unlocking is False
    assert device._send_datapoints_no_replay.await_args_list[-2:] == [
        (([S1_DP_UNLOCK_REQUEST],), {}),
        (([S1_DP_UNLOCK_CONFIRM],), {}),
    ]


async def test_s1_cancelled_waiter_does_not_orphan_operation_lock(
    hass: HomeAssistant,
) -> None:
    """A cancelled waiting Lock leaves later operations able to acquire the lock."""
    entity, _, _ = _make_entity(hass, {SYNTHETIC_DEVICE_ID: _stored_pair()})
    delay_started = asyncio.Event()
    release_delay = asyncio.Event()
    real_sleep = asyncio.sleep

    async def controlled_delay(delay: float) -> None:
        assert delay == S1_UNLOCK_DELAY
        delay_started.set()
        await release_delay.wait()

    with patch("custom_components.tuya_ble.lock.asyncio.sleep", controlled_delay):
        unlock_task = asyncio.create_task(entity.async_unlock())
        await delay_started.wait()
        waiting_lock = asyncio.create_task(entity.async_lock())
        await real_sleep(0)
        waiting_lock.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiting_lock
        release_delay.set()
        await unlock_task

    await entity.async_lock()
    assert entity.is_locking is False


@pytest.mark.parametrize(
    "stored_data",
    [
        None,
        {},
        {SYNTHETIC_OTHER_DEVICE_ID: _stored_pair()},
        {SYNTHETIC_DEVICE_ID: {"dp70_b64": _encoded(SYNTHETIC_DP70)}},
        {SYNTHETIC_DEVICE_ID: {"dp71_b64": _encoded(SYNTHETIC_DP71)}},
        {
            SYNTHETIC_DEVICE_ID: {
                "dp70_b64": "not strict base64",
                "dp71_b64": _encoded(SYNTHETIC_DP71),
            }
        },
        {
            SYNTHETIC_DEVICE_ID: {
                "dp70_b64": f"{_encoded(SYNTHETIC_DP70)[:-3]}x==",
                "dp71_b64": _encoded(SYNTHETIC_DP71),
            }
        },
        {
            SYNTHETIC_DEVICE_ID: {
                "dp70_b64": _encoded(b""),
                "dp71_b64": _encoded(SYNTHETIC_DP71),
            }
        },
        {
            SYNTHETIC_DEVICE_ID: {
                "dp70_b64": _encoded(SYNTHETIC_DP70),
                "dp71_b64": _encoded(SYNTHETIC_DP71[:-1]),
            }
        },
        {
            SYNTHETIC_DEVICE_ID: {
                **_stored_pair(),
                "category": "synthetic-conflicting-category",
            }
        },
        {
            SYNTHETIC_DEVICE_ID: {
                **_stored_pair(),
                "product_id": "synthetic-conflicting-product",
            }
        },
    ],
)
async def test_s1_unlock_fails_closed_before_writing(
    hass: HomeAssistant, stored_data: object
) -> None:
    """Missing, cross-device, malformed, or incomplete templates write nothing."""
    entity, device, backing_store = _make_entity(hass, stored_data)

    with pytest.raises(ServiceValidationError) as raised:
        await entity.async_unlock()

    device._send_datapoints_no_replay.assert_not_awaited()
    assert raised.value.translation_domain == "tuya_ble"
    assert raised.value.translation_key == S1_UNLOCK_ERROR_TRANSLATION_KEY
    rendered = str(raised.value)
    assert SYNTHETIC_DEVICE_ID not in rendered
    assert SYNTHETIC_DP70.hex() not in rendered
    assert _encoded(SYNTHETIC_DP70) not in rendered
    assert entity.is_unlocking is False
    assert backing_store.delayed_saves == []


async def test_s1_unlock_accepts_variable_length_legacy_templates(
    hass: HomeAssistant,
) -> None:
    """Valid b2 templates retain variable lengths and the complete DP71 suffix."""
    extended_dp70 = hashlib.shake_256(
        b"tuya-ble-test-only:synthetic-variable-dp70"
    ).digest(23)
    extended_dp71 = hashlib.shake_256(
        b"tuya-ble-test-only:synthetic-variable-dp71"
    ).digest(S1_DP71_MIN_LENGTH + 8)
    stored_data = {
        SYNTHETIC_DEVICE_ID: {
            "dp70_b64": _encoded(extended_dp70),
            "dp71_b64": _encoded(extended_dp71),
        }
    }
    entity, device, _ = _make_entity(hass, stored_data)
    writes: list[tuple[int, bytes]] = []

    async def record_send(datapoint_ids: list[int]) -> None:
        datapoint_id = datapoint_ids[0]
        writes.append((datapoint_id, bytes(device.datapoints[datapoint_id].value)))

    device._send_datapoints_no_replay.side_effect = record_send
    with (
        patch("custom_components.tuya_ble.lock.asyncio.sleep", AsyncMock()),
        patch(
            "custom_components.tuya_ble.lock.time.time",
            return_value=SYNTHETIC_TIMESTAMP,
        ),
    ):
        await entity.async_unlock()

    assert writes[0] == (70, extended_dp70)
    assert writes[1][0] == 71
    rebuilt_dp71 = writes[1][1]
    assert len(rebuilt_dp71) == len(extended_dp71)
    assert (
        rebuilt_dp71[: S1_DP71_TIMESTAMP.start]
        == extended_dp71[: S1_DP71_TIMESTAMP.start]
    )
    assert (
        rebuilt_dp71[S1_DP71_TIMESTAMP.stop :]
        == extended_dp71[S1_DP71_TIMESTAMP.stop :]
    )


async def test_s1_unlock_rejects_non_raw_transport_slot_before_writing(
    hass: HomeAssistant,
) -> None:
    """A conflicting live datapoint type cannot reinterpret template bytes."""
    entity, device, _ = _make_entity(hass, {SYNTHETIC_DEVICE_ID: _stored_pair()})
    token = _install_synthetic_session(device)
    device.datapoints._update_from_device(
        71, 1.0, 0, TuyaBLEDataPointType.DT_STRING, "synthetic", token
    )

    with pytest.raises(ServiceValidationError):
        await entity.async_unlock()

    device._send_datapoints_no_replay.assert_not_awaited()


async def test_s1_unlock_sequences_are_serialized(hass: HomeAssistant) -> None:
    """Concurrent requests cannot interleave their DP70/DP71 writes."""
    entity, device, _ = _make_entity(hass, {SYNTHETIC_DEVICE_ID: _stored_pair()})
    writes: list[int] = []
    first_sleep_started = asyncio.Event()
    release_first_sleep = asyncio.Event()
    sleep_count = 0
    real_sleep = asyncio.sleep

    async def record_send(datapoint_ids: list[int]) -> None:
        writes.append(datapoint_ids[0])

    async def controlled_sleep(delay: float) -> None:
        nonlocal sleep_count
        assert delay == S1_UNLOCK_DELAY
        sleep_count += 1
        if sleep_count == 1:
            first_sleep_started.set()
            await release_first_sleep.wait()

    device._send_datapoints_no_replay.side_effect = record_send
    with patch("custom_components.tuya_ble.lock.asyncio.sleep", controlled_sleep):
        first = asyncio.create_task(entity.async_unlock())
        await first_sleep_started.wait()
        second = asyncio.create_task(entity.async_unlock())
        await real_sleep(0)
        assert writes == [70]
        release_first_sleep.set()
        await asyncio.gather(first, second)

    assert writes == [70, 71, 70, 71]
    assert sleep_count == 2
    assert entity.is_unlocking is False


async def test_s1_lock_waits_for_the_complete_unlock_sequence(
    hass: HomeAssistant,
) -> None:
    """A manual S1 lock cannot interrupt the protected unlock pair."""
    entity, device, _ = _make_entity(hass, {SYNTHETIC_DEVICE_ID: _stored_pair()})
    writes: list[int] = []
    unlock_delay_started = asyncio.Event()
    release_unlock_delay = asyncio.Event()
    real_sleep = asyncio.sleep

    async def record_send(datapoint_ids: list[int]) -> None:
        writes.extend(datapoint_ids)

    async def controlled_sleep(delay: float) -> None:
        assert delay == S1_UNLOCK_DELAY
        unlock_delay_started.set()
        await release_unlock_delay.wait()

    device._send_datapoints_no_replay.side_effect = record_send
    with patch("custom_components.tuya_ble.lock.asyncio.sleep", controlled_sleep):
        unlock_task = asyncio.create_task(entity.async_unlock())
        await unlock_delay_started.wait()
        lock_task = asyncio.create_task(entity.async_lock())
        await real_sleep(0)
        assert writes == [S1_DP_UNLOCK_REQUEST]
        assert entity.is_locking is False
        release_unlock_delay.set()
        await asyncio.gather(unlock_task, lock_task)

    assert writes == [S1_DP_UNLOCK_REQUEST, S1_DP_UNLOCK_CONFIRM, S1_DP_LOCK]


async def test_s1_operation_locks_are_independent_between_devices(
    hass: HomeAssistant,
) -> None:
    """An active sequence on one S1 does not block another S1 device."""
    first, _, _ = _make_entity(hass, {SYNTHETIC_DEVICE_ID: _stored_pair()})
    second_device_id = SYNTHETIC_OTHER_DEVICE_ID
    second_device = _make_device(second_device_id)
    second_store_data = {second_device_id: _stored_pair()}
    second_store = TuyaBLES1TemplateStore(
        hass, _BackingStore(second_store_data), second_store_data
    )
    second = TuyaBLES1Lock(
        hass,
        TuyaBLECoordinator(hass, second_device),
        second_device,
        TuyaBLEProductInfo("Synthetic second S1", lock=1),
        second_store,
    )
    second.async_write_ha_state = Mock()
    _install_synthetic_session(second_device)
    second_device._ensure_connected = AsyncMock()
    second_device._send_datapoints_no_replay = AsyncMock()
    first_delay_started = asyncio.Event()
    release_first = asyncio.Event()

    async def controlled_delay(delay: float) -> None:
        assert delay == S1_UNLOCK_DELAY
        if not first_delay_started.is_set():
            first_delay_started.set()
            await release_first.wait()

    with patch("custom_components.tuya_ble.lock.asyncio.sleep", controlled_delay):
        first_task = asyncio.create_task(first.async_unlock())
        await first_delay_started.wait()
        await second.async_lock()
        second_device._send_datapoints_no_replay.assert_awaited_once_with([S1_DP_LOCK])
        release_first.set()
        await first_task


async def test_s1_unlock_resets_transient_state_on_transport_error(
    hass: HomeAssistant,
) -> None:
    """Transport failure cannot leave the entity stuck in an unlocking state."""
    entity, device, _ = _make_entity(hass, {SYNTHETIC_DEVICE_ID: _stored_pair()})
    device._send_datapoints_no_replay.side_effect = RuntimeError(
        "synthetic transport failure"
    )

    with pytest.raises(RuntimeError, match="synthetic transport failure"):
        await entity.async_unlock()

    assert entity.is_unlocking is False


async def test_s1_unlock_resets_transient_state_on_cancellation(
    hass: HomeAssistant,
) -> None:
    """Cancellation during the validated delay clears transient state safely."""
    entity, device, _ = _make_entity(hass, {SYNTHETIC_DEVICE_ID: _stored_pair()})
    sleep_started = asyncio.Event()

    async def wait_until_cancelled(delay: float) -> None:
        assert delay == S1_UNLOCK_DELAY
        sleep_started.set()
        await asyncio.Event().wait()

    with patch("custom_components.tuya_ble.lock.asyncio.sleep", wait_until_cancelled):
        unlock_task = asyncio.create_task(entity.async_unlock())
        await sleep_started.wait()
        unlock_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await unlock_task

    assert device._send_datapoints_no_replay.await_count == 1
    assert entity.is_unlocking is False


@pytest.mark.parametrize(
    ("operation", "expected_attempts"),
    (("lock", 1), ("unlock_dp70", 1), ("unlock_dp71", 2)),
)
async def test_s1_ambiguous_write_never_defers_or_replays_a_command(
    hass: HomeAssistant,
    operation: str,
    expected_attempts: int,
) -> None:
    """S1 controls have one semantic attempt, even after a replacement session."""
    real_asyncio_sleep = asyncio.sleep

    async def yield_without_delay(_: float) -> None:
        await real_asyncio_sleep(0)

    write_side_effect: object
    if operation == "unlock_dp71":
        write_side_effect = [None, BleakError("synthetic ambiguous S1 failure")]
    else:
        write_side_effect = BleakError("synthetic ambiguous S1 failure")
    entity, device, client = _make_transport_entity(hass, write_side_effect)

    if operation == "lock":
        datapoint_id = S1_DP_LOCK
        datapoint_type = TuyaBLEDataPointType.DT_BOOL
        original_value: bytes | bool = False
    elif operation == "unlock_dp70":
        datapoint_id = S1_DP_UNLOCK_REQUEST
        datapoint_type = TuyaBLEDataPointType.DT_RAW
        original_value = b"synthetic-original-dp70"
    else:
        datapoint_id = S1_DP_UNLOCK_CONFIRM
        datapoint_type = TuyaBLEDataPointType.DT_RAW
        original_value = b"synthetic-original-dp71"
    device.datapoints.get_or_create(datapoint_id, datapoint_type, original_value)

    if operation == "lock":
        command = entity.async_lock
        sleep_patch = None
    else:
        command = entity.async_unlock
        sleep_patch = patch(
            "custom_components.tuya_ble.lock.asyncio.sleep",
            new=AsyncMock(side_effect=yield_without_delay),
        )
    timeout_patch = patch(
        "custom_components.tuya_ble.tuya_ble.tuya_ble.RESPONSE_WAIT_TIMEOUT", 0
    )

    if sleep_patch is None:
        with (
            timeout_patch,
            pytest.raises(BleakError, match="synthetic ambiguous S1 failure"),
        ):
            await command()
    else:
        with (
            sleep_patch,
            timeout_patch,
            pytest.raises(BleakError, match="synthetic ambiguous S1 failure"),
        ):
            await command()

    assert client.write_gatt_char.await_count == expected_attempts
    assert device.datapoints[datapoint_id].value == original_value
    assert getattr(device, "_deferred_resend_packets", None) is None
    assert getattr(device, "_resend_task", None) is None
    assert device.state_data_fresh is False
    assert entity.is_locking is False
    assert entity.is_unlocking is False

    replacement = _ConnectedTransportClient(None)
    replacement_token = _install_synthetic_session(device, replacement)
    device._status_attempted_token = replacement_token

    await device._reconnect()

    replacement.write_gatt_char.assert_not_awaited()


@pytest.mark.parametrize(
    ("operation", "expected_attempts"),
    (("lock", 1), ("unlock_dp70", 1), ("unlock_dp71", 2)),
)
async def test_s1_verified_loss_recovers_future_session_without_replay(
    hass: HomeAssistant,
    operation: str,
    expected_attempts: int,
) -> None:
    """S1 no-replay commands still recover the next Always-connected session."""
    real_asyncio_sleep = asyncio.sleep

    async def yield_without_delay(_: float) -> None:
        await real_asyncio_sleep(0)

    entity, device, client = _make_transport_entity(hass, None)

    write_attempts = 0

    async def lose_connection_on_final_attempt(*_: object) -> None:
        nonlocal write_attempts
        write_attempts += 1
        if write_attempts == expected_attempts:
            client.is_connected = False
            raise BleakError("synthetic S1 physical loss")

    client.write_gatt_char.side_effect = lose_connection_on_final_attempt

    if operation == "lock":
        command = entity.async_lock
        sleep_patch = None
    else:
        command = entity.async_unlock
        sleep_patch = patch(
            "custom_components.tuya_ble.lock.asyncio.sleep",
            new=AsyncMock(side_effect=yield_without_delay),
        )
    timeout_patch = patch(
        "custom_components.tuya_ble.tuya_ble.tuya_ble.RESPONSE_WAIT_TIMEOUT", 0
    )
    state_changes: list[bool] = []
    device.register_connection_state_callback(state_changes.append)

    if sleep_patch is None:
        with (
            timeout_patch,
            pytest.raises(BleakError, match="physical loss"),
        ):
            await command()
    else:
        with (
            sleep_patch,
            timeout_patch,
            pytest.raises(BleakError, match="physical loss"),
        ):
            await command()

    assert client.write_gatt_char.await_count == expected_attempts
    assert device._client is None
    assert device.is_gatt_connected is False
    assert device.policy_state is ConnectionPolicyState.ALWAYS_CONNECTED_CONNECTING
    assert device._pending_release is None
    assert entity.is_locking is False
    assert entity.is_unlocking is False
    assert state_changes == [False]
    device._schedule_reconnect_locked.assert_called_once_with(
        UNEXPECTED_RECONNECT_MIN_SECONDS
    )
    assert not hasattr(device, "_deferred_resend_packets")
    assert not hasattr(device, "_resend_task")

    token = device._connected_notified_token
    assert token is not None
    device._disconnected(client, token)

    assert state_changes == [False]
    device._schedule_reconnect_locked.assert_called_once_with(
        UNEXPECTED_RECONNECT_MIN_SECONDS
    )


async def test_s1_unlock_does_not_log_templates(
    hass: HomeAssistant, caplog: pytest.LogCaptureFixture
) -> None:
    """Neither successful transport nor validation errors log template material."""
    entity, _, _ = _make_entity(hass, {SYNTHETIC_DEVICE_ID: _stored_pair()})
    caplog.set_level(logging.DEBUG)
    with (
        patch("custom_components.tuya_ble.lock.asyncio.sleep", AsyncMock()),
        patch(
            "custom_components.tuya_ble.lock.time.time",
            return_value=SYNTHETIC_TIMESTAMP,
        ),
    ):
        await entity.async_unlock()

    invalid, _, _ = _make_entity(hass, {})
    with pytest.raises(ServiceValidationError):
        await invalid.async_unlock()

    rendered = caplog.text
    for raw_value in (SYNTHETIC_DP70, SYNTHETIC_DP71):
        assert raw_value.hex() not in rendered
        assert _encoded(raw_value) not in rendered
    assert SYNTHETIC_DEVICE_ID not in rendered
