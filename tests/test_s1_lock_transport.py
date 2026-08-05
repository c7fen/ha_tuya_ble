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
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError

from custom_components.tuya_ble.devices import (
    TuyaBLECoordinator,
    TuyaBLEProductInfo,
)
from custom_components.tuya_ble.lock import (
    S1_DP71_MIN_LENGTH,
    S1_DP71_TIMESTAMP,
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
    return device


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
    return entity, device, backing_store


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
    device.datapoints._update_from_device(
        70, 1.0, 0, TuyaBLEDataPointType.DT_RAW, SYNTHETIC_DP70
    )
    device.datapoints._update_from_device(
        71, 1.0, 0, TuyaBLEDataPointType.DT_RAW, SYNTHETIC_DP71
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

    device._send_datapoints.side_effect = record_send
    await entity.async_lock()
    assert device._send_datapoints.call_count == 1
    assert device.datapoints[46].value is True

    device._send_datapoints.reset_mock()
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

    device._send_datapoints.assert_not_awaited()
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

    device._send_datapoints.side_effect = record_send
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
    device.datapoints._update_from_device(
        71, 1.0, 0, TuyaBLEDataPointType.DT_STRING, "synthetic"
    )

    with pytest.raises(ServiceValidationError):
        await entity.async_unlock()

    device._send_datapoints.assert_not_awaited()


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

    device._send_datapoints.side_effect = record_send
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


async def test_s1_unlock_resets_transient_state_on_transport_error(
    hass: HomeAssistant,
) -> None:
    """Transport failure cannot leave the entity stuck in an unlocking state."""
    entity, device, _ = _make_entity(hass, {SYNTHETIC_DEVICE_ID: _stored_pair()})
    device._send_datapoints.side_effect = RuntimeError("synthetic transport failure")

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

    assert device._send_datapoints.await_count == 1
    assert entity.is_unlocking is False


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
