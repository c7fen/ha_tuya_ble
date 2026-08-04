"""The Tuya BLE integration."""
from __future__ import annotations

import asyncio
import base64
import inspect
import time
from dataclasses import dataclass
from typing import Callable

from homeassistant.components.lock import LockEntity, LockEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import storage
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .devices import (
    TuyaBLEData,
    TuyaBLEEntity,
    TuyaBLEPassiveCoordinator,
    TuyaBLEProductInfo,
)
from .tuya_ble import TuyaBLEDataPointType, TuyaBLEDevice

FALLBACK_DP70_B64 = "AAH//wAAAAAAAAAAAP//AA=="
FALLBACK_DP71_B64 = "AAH//zgzNjcxNDYyAWnRJAkAAA=="

DP71_TIME_OFFSET_SECONDS = 0

CACHE_KEY = "jtmspro_lock_templates"
STORE_KEY = "jtmspro_lock_templates_store"
STORE_VERSION = 1
STORE_FILENAME = f"{DOMAIN}_jtmspro_lock_templates"

TuyaBLELockIsAvailable = Callable[["TuyaBLELock", TuyaBLEProductInfo], bool] | None


@dataclass
class TuyaBLELockMapping:
    description: LockEntityDescription
    force_add: bool = True
    is_available: TuyaBLELockIsAvailable = None


@dataclass
class TuyaBLECategoryLockMapping:
    products: dict[str, list[TuyaBLELockMapping]] | None = None
    mapping: list[TuyaBLELockMapping] | None = None


mapping: dict[str, TuyaBLECategoryLockMapping] = {
    "jtmspro": TuyaBLECategoryLockMapping(
        products={
            "xqeob8h6": [
                TuyaBLELockMapping(
                    description=LockEntityDescription(
                        key="ble_unlock_lock",
                        translation_key="lock",
                        icon="mdi:lock",
                    ),
                    force_add=True,
                ),
            ],
        },
    ),
}


def get_mapping_by_device(device: TuyaBLEDevice) -> list[TuyaBLELockMapping]:
    category = mapping.get(device.category)
    if category is not None and category.products is not None:
        product_mapping = category.products.get(device.product_id)
        if product_mapping is not None:
            return product_mapping
        if category.mapping is not None:
            return category.mapping
    return []


class TuyaBLELock(TuyaBLEEntity, LockEntity):
    """Representation of a Tuya BLE Lock."""

    _attr_should_poll = False

    def __init__(
        self,
        hass: HomeAssistant,
        coordinator: TuyaBLEPassiveCoordinator,
        device: TuyaBLEDevice,
        product: TuyaBLEProductInfo,
        mapping: TuyaBLELockMapping,
    ) -> None:
        super().__init__(hass, coordinator, device, product, mapping.description)
        self._mapping = mapping
        self._attr_is_unlocking = False
        self._attr_is_locking = False

        domain_data = hass.data.setdefault(DOMAIN, {})
        self._cache: dict = domain_data.setdefault(CACHE_KEY, {})
        self._store: storage.Store = domain_data[STORE_KEY]
        self._device_cache: dict = self._cache.setdefault(self._device.device_id, {})

        self._save_task: asyncio.Task | None = None

        self._capture_live_templates()
        self._unsub_callback = self._device.register_callback(self._handle_device_update)

    async def async_will_remove_from_hass(self) -> None:
        if hasattr(self, "_unsub_callback") and self._unsub_callback:
            self._unsub_callback()
        if self._save_task and not self._save_task.done():
            self._save_task.cancel()

    def _schedule_persist_cache(self) -> None:
        if self._save_task and not self._save_task.done():
            self._save_task.cancel()
        self._save_task = self.hass.async_create_task(self._async_persist_cache())

    async def _async_persist_cache(self) -> None:
        await asyncio.sleep(0)
        await self._store.async_save(self._cache)

    def _cache_set_b64(self, key: str, raw_value: bytes) -> bool:
        new_b64 = base64.b64encode(raw_value).decode()
        old_b64 = self._device_cache.get(key)
        if old_b64 != new_b64:
            self._device_cache[key] = new_b64
            return True
        return False

    def _cache_get_bytes(self, key: str) -> bytes | None:
        value = self._device_cache.get(key)
        if isinstance(value, str) and value:
            try:
                return base64.b64decode(value)
            except Exception:
                return None
        return None

    def _handle_device_update(self, datapoints) -> None:
        self._capture_live_templates()

    def _capture_live_templates(self) -> None:
        changed = False

        dp70 = self._device.datapoints[70]
        if dp70 is not None and isinstance(dp70.value, (bytes, bytearray)):
            raw70 = bytes(dp70.value)
            if self._cache_set_b64("dp70_b64", raw70):
                changed = True

        dp71 = self._device.datapoints[71]
        if dp71 is not None and isinstance(dp71.value, (bytes, bytearray)):
            raw71 = bytes(dp71.value)
            if self._cache_set_b64("dp71_b64", raw71):
                changed = True

        if changed:
            self._schedule_persist_cache()

    def _fallback_dp70_bytes(self) -> bytes:
        return base64.b64decode(FALLBACK_DP70_B64)

    def _fallback_dp71_bytes(self) -> bytes:
        return base64.b64decode(FALLBACK_DP71_B64)

    def _get_dp70_bytes(self) -> bytes:
        cached = self._cache_get_bytes("dp70_b64")
        if cached is not None:
            return cached

        live = self._device.datapoints[70]
        if live is not None and isinstance(live.value, (bytes, bytearray)):
            raw = bytes(live.value)
            self._cache_set_b64("dp70_b64", raw)
            self._schedule_persist_cache()
            return raw

        return self._fallback_dp70_bytes()

    def _get_dp71_template_bytes(self) -> bytes:
        cached = self._cache_get_bytes("dp71_b64")
        if cached is not None:
            return cached

        live = self._device.datapoints[71]
        if live is not None and isinstance(live.value, (bytes, bytearray)):
            raw = bytes(live.value)
            self._cache_set_b64("dp71_b64", raw)
            self._schedule_persist_cache()
            return raw

        return self._fallback_dp71_bytes()

    def _build_dp71_payload(self) -> bytes:
        template = self._get_dp71_template_bytes()

        if len(template) >= 19:
            prefix = template[0:4]
            identifier = template[4:12]
            marker = template[12:13]
            suffix = template[17:]

            timestamp = int(time.time()) + DP71_TIME_OFFSET_SECONDS
            timestamp_bytes = timestamp.to_bytes(4, "big", signed=False)

            return prefix + identifier + marker + timestamp_bytes + suffix

        fallback = self._fallback_dp71_bytes()
        prefix = fallback[0:4]
        identifier = fallback[4:12]
        marker = fallback[12:13]
        suffix = fallback[17:]

        timestamp = int(time.time()) + DP71_TIME_OFFSET_SECONDS
        timestamp_bytes = timestamp.to_bytes(4, "big", signed=False)

        return prefix + identifier + marker + timestamp_bytes + suffix

    async def _send_raw_dp_bytes(self, dp_id: int, raw_value: bytes) -> None:
        datapoint = self._device.datapoints.get_or_create(
            dp_id,
            TuyaBLEDataPointType.DT_RAW,
            raw_value,
        )

        if not datapoint:
            return

        result = datapoint.set_value(raw_value)
        if inspect.isawaitable(result):
            await result

    async def _send_bool_dp(self, dp_id: int, value: bool) -> None:
        datapoint = self._device.datapoints.get_or_create(
            dp_id,
            TuyaBLEDataPointType.DT_BOOL,
            value,
        )

        if not datapoint:
            return

        result = datapoint.set_value(value)
        if inspect.isawaitable(result):
            await result

    async def _unlock_sequence(self) -> None:
        self._attr_is_unlocking = True
        self.async_write_ha_state()
        try:
            dp70_payload = self._get_dp70_bytes()
            await self._send_raw_dp_bytes(70, dp70_payload)

            await asyncio.sleep(0.8)

            dp71_payload = self._build_dp71_payload()
            await self._send_raw_dp_bytes(71, dp71_payload)
        finally:
            self._attr_is_unlocking = False
            self.async_write_ha_state()

    async def _lock_sequence(self) -> None:
        self._attr_is_locking = True
        self.async_write_ha_state()
        try:
            await self._send_bool_dp(46, True)
        finally:
            self._attr_is_locking = False
            self.async_write_ha_state()

    async def async_unlock(self, **kwargs) -> None:
        await self._unlock_sequence()

    async def async_lock(self, **kwargs) -> None:
        await self._lock_sequence()

    @property
    def is_locked(self) -> bool | None:
        datapoint = self._device.datapoints[47]
        if datapoint is not None and isinstance(datapoint.value, bool):
            return not bool(datapoint.value)
        return None

    @property
    def is_locking(self) -> bool | None:
        return self._attr_is_locking

    @property
    def is_unlocking(self) -> bool | None:
        return self._attr_is_unlocking

    @property
    def available(self) -> bool:
        if self._device is None:
            return False
        if self._mapping.is_available is not None:
            return self._mapping.is_available(self, self._product)
        return True


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the Tuya BLE lock entities."""
    domain_data = hass.data.setdefault(DOMAIN, {})

    if STORE_KEY not in domain_data:
        store = storage.Store(hass, STORE_VERSION, STORE_FILENAME)
        saved = await store.async_load()
        domain_data[STORE_KEY] = store
        domain_data[CACHE_KEY] = saved if isinstance(saved, dict) else {}

    data: TuyaBLEData = hass.data[DOMAIN][entry.entry_id]
    mappings = get_mapping_by_device(data.device)

    entities: list[TuyaBLELock] = []
    for mapping_item in mappings:
        if mapping_item.force_add:
            entities.append(
                TuyaBLELock(
                    hass,
                    data.coordinator,
                    data.device,
                    data.product,
                    mapping_item,
                )
            )

    async_add_entities(entities)
