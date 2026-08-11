"""Tuya BLE lock entities."""

from __future__ import annotations

import asyncio
import base64
import binascii
import os
import stat
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, NoReturn

from homeassistant.components.lock import (
    LockEntity,
    LockEntityDescription,
    LockEntityFeature,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers import storage
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN, DPCode
from .devices import (
    TuyaBLECoordinator,
    TuyaBLEData,
    TuyaBLEEntity,
    TuyaBLEProductInfo,
    get_device_product_info,
)
from .tuya_ble import TuyaBLEDataPoint, TuyaBLEDataPointType, TuyaBLEDevice

S1_CATEGORY = "jtmspro"
S1_PRODUCT_ID = "xqeob8h6"
S1_DP_LOCK = 46
S1_DP_MOTOR_STATE = 47
S1_DP_UNLOCK_REQUEST = 70
S1_DP_UNLOCK_CONFIRM = 71
S1_DP70_MIN_LENGTH = 1
S1_DP71_MIN_LENGTH = 19
S1_DP71_TIMESTAMP = slice(13, 17)
S1_UNLOCK_DELAY = 0.8

V1_CATEGORY = "ms"
V1_PRODUCT_ID = "7a4xvbtt"
V1_DP_ACCESS = 6
V1_DP_LOCK = 46
V1_DP_MOTOR_STATE = 47
V1_ACCESS_FIELD_COUNT = 2
V1_COMMAND_ERROR_TRANSLATION_KEY = "v1_command_unavailable"

S1_STORE_VERSION = 1
S1_STORE_KEY = f"{DOMAIN}_jtmspro_lock_templates"
S1_RUNTIME_STORE_KEY = "__s1_lock_template_store_v1"
S1_UNLOCK_ERROR_TRANSLATION_KEY = "s1_unlock_templates_unavailable"


def _harden_s1_store_permissions(path: str) -> None:
    """Restrict an existing regular S1 template Store file to its owner."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return
    except OSError as err:
        raise HomeAssistantError(
            "Secure S1 template storage permissions are invalid."
        ) from err

    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise HomeAssistantError(
                "Secure S1 template storage path is not a regular file."
            )
        if stat.S_IMODE(file_stat.st_mode) != 0o600:
            os.fchmod(descriptor, 0o600)
    except OSError as err:
        raise HomeAssistantError(
            "Secure S1 template storage permissions could not be applied."
        ) from err
    finally:
        os.close(descriptor)


def _strict_decode_template(value: object, minimum_length: int) -> bytes | None:
    """Decode one canonical, strictly validated base64 template."""
    if not isinstance(value, str) or not value:
        return None
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(decoded) < minimum_length:
        return None
    if base64.b64encode(decoded).decode("ascii") != value:
        return None
    return decoded


def _raise_s1_unlock_validation_error() -> NoReturn:
    """Raise the translated, payload-free S1 unlock validation error."""
    raise ServiceValidationError(
        "Secure unlock templates are unavailable or invalid.",
        translation_domain=DOMAIN,
        translation_key=S1_UNLOCK_ERROR_TRANSLATION_KEY,
    )


def _raise_v1_command_validation_error() -> NoReturn:
    """Raise the translated, payload-free V1 command validation error."""
    raise ServiceValidationError(
        "The V1 command datapoints are unavailable or invalid.",
        translation_domain=DOMAIN,
        translation_key=V1_COMMAND_ERROR_TRANSLATION_KEY,
    )


def _build_v1_access_value() -> bytes:
    """Build the observed two-field V1 access action without replaying a frame."""
    return bytes([int(True)] * V1_ACCESS_FIELD_COUNT)


@dataclass(slots=True, repr=False)
class _S1PendingTemplatePair:
    """Private template material received during one exact BLE session."""

    session_epoch: int
    dp70: bytes | None = None
    dp71: bytes | None = None

    @property
    def complete(self) -> bool:
        """Return whether both template halves belong to this pending pair."""
        return self.dp70 is not None and self.dp71 is not None


class TuyaBLES1TemplateStore:
    """Device-scoped version 1 store for S1 live unlock templates."""

    def __init__(
        self,
        hass: HomeAssistant,
        backing_store: storage.Store,
        data: object,
    ) -> None:
        self._hass = hass
        self._backing_store = backing_store
        self._data: dict[str, object] = data if isinstance(data, dict) else {}
        self._pending: dict[str, _S1PendingTemplatePair] = {}

    @classmethod
    async def async_load(cls, hass: HomeAssistant) -> TuyaBLES1TemplateStore:
        """Load the legacy-compatible device-scoped template store."""
        backing_store = storage.Store(
            hass,
            S1_STORE_VERSION,
            S1_STORE_KEY,
            private=True,
            atomic_writes=True,
        )
        await hass.async_add_executor_job(
            _harden_s1_store_permissions, backing_store.path
        )
        return cls(hass, backing_store, await backing_store.async_load())

    def templates_for(
        self, device_id: str, session_epoch: int | None = None
    ) -> tuple[bytes, bytes] | None:
        """Return a current-session pair, or the persisted complete fallback."""
        if not device_id:
            return None
        pending = self._pending.get(device_id)
        if (
            session_epoch is not None
            and pending is not None
            and pending.session_epoch == session_epoch
            and pending.complete
        ):
            assert pending.dp70 is not None
            assert pending.dp71 is not None
            return pending.dp70, pending.dp71

        device_data = self._data.get(device_id)
        if not isinstance(device_data, dict):
            return None
        expected_metadata = {
            "category": S1_CATEGORY,
            "product_id": S1_PRODUCT_ID,
            "format_version": S1_STORE_VERSION,
        }
        if any(
            key in device_data and device_data[key] != expected
            for key, expected in expected_metadata.items()
        ):
            return None

        dp70 = _strict_decode_template(device_data.get("dp70_b64"), S1_DP70_MIN_LENGTH)
        dp71 = _strict_decode_template(device_data.get("dp71_b64"), S1_DP71_MIN_LENGTH)
        if dp70 is None or dp71 is None:
            return None
        return dp70, dp71

    def discard_pending(self, device_id: str) -> None:
        """Forget incomplete or complete session-local material for one device."""
        self._pending.pop(device_id, None)

    def capture_inbound(
        self, device_id: str, datapoints: list[TuyaBLEDataPoint]
    ) -> bool:
        """Capture valid raw templates proven to come from this device."""
        if not device_id:
            return False

        expected_metadata = {
            "category": S1_CATEGORY,
            "product_id": S1_PRODUCT_ID,
            "format_version": S1_STORE_VERSION,
        }
        previous = self._data.get(device_id)
        if isinstance(previous, dict) and any(
            key in previous and previous[key] != expected
            for key, expected in expected_metadata.items()
        ):
            return False

        captured: dict[int, bytes] = {}
        captured_epoch: int | None = None
        for datapoint in datapoints:
            if (
                not datapoint.received_from_device
                or datapoint.received_session_epoch is None
                or datapoint.type is not TuyaBLEDataPointType.DT_RAW
                or not isinstance(datapoint.value, (bytes, bytearray))
            ):
                continue
            if captured_epoch is None:
                captured_epoch = datapoint.received_session_epoch
            elif captured_epoch != datapoint.received_session_epoch:
                return False
            raw_value = bytes(datapoint.value)
            if (
                datapoint.id == S1_DP_UNLOCK_REQUEST
                and len(raw_value) >= S1_DP70_MIN_LENGTH
            ):
                captured[S1_DP_UNLOCK_REQUEST] = raw_value
            elif (
                datapoint.id == S1_DP_UNLOCK_CONFIRM
                and len(raw_value) >= S1_DP71_MIN_LENGTH
            ):
                captured[S1_DP_UNLOCK_CONFIRM] = raw_value

        if not captured or captured_epoch is None:
            return False

        pending = self._pending.get(device_id)
        if (
            pending is None
            or pending.session_epoch != captured_epoch
            or pending.complete
        ):
            pending = _S1PendingTemplatePair(captured_epoch)
        if S1_DP_UNLOCK_REQUEST in captured:
            pending.dp70 = captured[S1_DP_UNLOCK_REQUEST]
        if S1_DP_UNLOCK_CONFIRM in captured:
            pending.dp71 = captured[S1_DP_UNLOCK_CONFIRM]
        self._pending[device_id] = pending

        if not pending.complete:
            return True
        assert pending.dp70 is not None
        assert pending.dp71 is not None

        device_data = dict(previous) if isinstance(previous, dict) else {}
        replacement = {
            **device_data,
            **expected_metadata,
            "dp70_b64": base64.b64encode(pending.dp70).decode("ascii"),
            "dp71_b64": base64.b64encode(pending.dp71).decode("ascii"),
        }
        if replacement == device_data:
            return True

        self._data[device_id] = replacement
        self._backing_store.async_delay_save(self._snapshot, 0)
        return True

    def _snapshot(self) -> dict[str, object]:
        """Return a shallow-isolated JSON-compatible storage snapshot."""
        return {
            device_id: (
                dict(device_data) if isinstance(device_data, dict) else device_data
            )
            for device_id, device_data in self._data.items()
        }


async def _async_get_s1_template_store(
    hass: HomeAssistant,
) -> TuyaBLES1TemplateStore:
    """Return the singleton S1 template store for this Home Assistant instance."""
    domain_data = hass.data.setdefault(DOMAIN, {})
    template_store = domain_data.get(S1_RUNTIME_STORE_KEY)
    if isinstance(template_store, TuyaBLES1TemplateStore):
        return template_store
    if isinstance(template_store, asyncio.Future):
        return await template_store

    load_task = hass.async_create_task(TuyaBLES1TemplateStore.async_load(hass))
    domain_data[S1_RUNTIME_STORE_KEY] = load_task
    try:
        template_store = await load_task
    except Exception:
        if domain_data.get(S1_RUNTIME_STORE_KEY) is load_task:
            domain_data.pop(S1_RUNTIME_STORE_KEY)
        raise
    domain_data[S1_RUNTIME_STORE_KEY] = template_store
    return template_store


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the Tuya BLE locks."""
    data: TuyaBLEData = hass.data[DOMAIN][entry.entry_id]
    product = get_device_product_info(data.device)
    if data.device.category == V1_CATEGORY and data.device.product_id == V1_PRODUCT_ID:
        async_add_entities(
            [
                TuyaBLEV1Lock(
                    hass,
                    data.coordinator,
                    data.device,
                    product or data.product,
                )
            ]
        )
    elif (
        data.device.category == S1_CATEGORY and data.device.product_id == S1_PRODUCT_ID
    ):
        template_store = await _async_get_s1_template_store(hass)
        async_add_entities(
            [
                TuyaBLES1Lock(
                    hass,
                    data.coordinator,
                    data.device,
                    product or data.product,
                    template_store,
                )
            ]
        )
    elif product and product.lock:
        async_add_entities([TuyaBLELock(hass, data.coordinator, data.device, product)])


class TuyaBLEV1Lock(TuyaBLEEntity, LockEntity):
    """Product-specific bidirectional V1 coupling control."""

    platform = Platform.LOCK
    _is_command_entity = True
    _attr_should_poll = False

    def __init__(
        self,
        hass: HomeAssistant,
        coordinator: TuyaBLECoordinator,
        device: TuyaBLEDevice,
        product: TuyaBLEProductInfo,
    ) -> None:
        super().__init__(
            hass,
            coordinator,
            device,
            product,
            LockEntityDescription(
                key="manual_lock",
                translation_key="lock",
                icon="mdi:lock",
            ),
        )
        self._attr_supported_features = LockEntityFeature(0)
        self._attr_is_locking = False
        self._attr_is_unlocking = False
        self._operation_lock = asyncio.Lock()

    @property
    def is_locked(self) -> bool | None:
        """Return the physical secure state reported by read-only DP47."""
        motor_state = self._device.datapoints[V1_DP_MOTOR_STATE]
        if (
            motor_state is None
            or not motor_state.received_in_current_session
            or motor_state.type is not TuyaBLEDataPointType.DT_BOOL
            or not isinstance(motor_state.value, bool)
        ):
            return None
        return not motor_state.value

    async def async_lock(self, **kwargs: Any) -> None:
        """Secure by issuing exactly one DP46 true command."""
        self._device.ensure_control_available()
        async with self._operation_lock:
            async with self._device.connection_lease("v1 lock"):
                if self._device.protocol_major_version != 3:
                    _raise_v1_command_validation_error()
                datapoint = self._device.datapoints[V1_DP_LOCK]
                if datapoint is not None and (
                    datapoint.type is not TuyaBLEDataPointType.DT_BOOL
                    or not isinstance(datapoint.value, bool)
                ):
                    _raise_v1_command_validation_error()
                manual_lock = self._device.datapoints.get_or_create(
                    V1_DP_LOCK, TuyaBLEDataPointType.DT_BOOL, True
                )

                self._attr_is_locking = True
                self.async_write_ha_state()
                try:
                    await manual_lock.set_value_once(True)
                finally:
                    self._attr_is_locking = False
                    self.async_write_ha_state()

    async def async_unlock(self, **kwargs: Any) -> None:
        """Enable access using one observed product-specific DP6 action."""
        self._device.ensure_control_available()
        async with self._operation_lock:
            async with self._device.connection_lease("v1 unlock"):
                if self._device.protocol_major_version != 3:
                    _raise_v1_command_validation_error()
                datapoint = self._device.datapoints[V1_DP_ACCESS]
                if datapoint is not None and (
                    datapoint.type is not TuyaBLEDataPointType.DT_RAW
                    or not isinstance(datapoint.value, bytes | bytearray)
                ):
                    _raise_v1_command_validation_error()
                access_value = _build_v1_access_value()
                access = self._device.datapoints.get_or_create(
                    V1_DP_ACCESS, TuyaBLEDataPointType.DT_RAW, access_value
                )

                self._attr_is_unlocking = True
                self.async_write_ha_state()
                try:
                    await access.set_value_once(access_value)
                finally:
                    self._attr_is_unlocking = False
                    self.async_write_ha_state()


class TuyaBLELock(TuyaBLEEntity, LockEntity):
    """Generic upstream Tuya BLE lock."""

    platform = Platform.LOCK
    _is_command_entity = True

    def __init__(
        self,
        hass: HomeAssistant,
        coordinator: TuyaBLECoordinator,
        device: TuyaBLEDevice,
        product: TuyaBLEProductInfo,
    ) -> None:
        super().__init__(
            hass,
            coordinator,
            device,
            product,
            LockEntityDescription(key="lock", name=product.name),
        )
        self._attr_supported_features = LockEntityFeature.OPEN

    @property
    def is_locked(self) -> bool | None:
        """Return true if lock is locked."""
        if not self._device.state_data_fresh:
            return None
        dpid = self.find_dpid(DPCode.LOCK_MOTOR_STATE)
        if dpid is None:
            dpid = DPCode.LOCK_MOTOR_STATE
        if motor_state := self._device.datapoints.get_or_create(
            dpid, TuyaBLEDataPointType.DT_BOOL, False
        ):
            return not motor_state.value
        return None

    async def async_lock(self, **kwargs: Any) -> None:
        """Lock the lock."""
        self._device.ensure_control_available()
        manual_lock_id = self.find_dpid(DPCode.MANUAL_LOCK)
        if manual_lock_id is not None:
            if manual_lock := self._device.datapoints.get_or_create(
                manual_lock_id, TuyaBLEDataPointType.DT_BOOL, True
            ):
                await manual_lock.set_value(True)
        elif self.find_dpid(DPCode.LOCK_MOTOR_STATE) is not None:
            if motor_state := self._device.datapoints.get_or_create(
                self.find_dpid(DPCode.LOCK_MOTOR_STATE),
                TuyaBLEDataPointType.DT_BOOL,
                False,
            ):
                await motor_state.set_value(False)
        elif self._device.product_id == "wgv4haro":
            # Guard Dog Security Smart Lock locks automatically, locking command is no-op
            # NOTE: Other momentary locks in category ms/jtmspro (like okkyfgfs, k53ok3u9,
            # sidhzylo, a6nttc41, stugc8dl, xicdxood, rlyxv7pe, oyqux5vv, hs21i377, kholoaew)
            # may also need updating in the future.
            return
        else:
            if manual_lock := self._device.datapoints.get_or_create(
                DPCode.MANUAL_LOCK, TuyaBLEDataPointType.DT_BOOL, True
            ):
                await manual_lock.set_value(True)

    async def async_unlock(self, **kwargs: Any) -> None:
        """Unlock the lock."""
        self._device.ensure_control_available()
        manual_lock_id = self.find_dpid(DPCode.MANUAL_LOCK)
        if manual_lock_id is not None:
            if manual_lock := self._device.datapoints.get_or_create(
                manual_lock_id, TuyaBLEDataPointType.DT_BOOL, False
            ):
                await manual_lock.set_value(False)
        elif self.find_dpid(DPCode.LOCK_MOTOR_STATE) is not None:
            if motor_state := self._device.datapoints.get_or_create(
                self.find_dpid(DPCode.LOCK_MOTOR_STATE),
                TuyaBLEDataPointType.DT_BOOL,
                True,
            ):
                await motor_state.set_value(True)
        elif self._device.product_id == "wgv4haro":
            # Guard Dog Security Smart Lock uses DP 6 for bluetooth unlock
            # NOTE: Other momentary locks (e.g. okkyfgfs, k53ok3u9, sidhzylo, a6nttc41 on DP 6;
            # or stugc8dl, xicdxood, rlyxv7pe, oyqux5vv, hs21i377, kholoaew on DP 71)
            # may also need updating in the future.
            if bluetooth_unlock := self._device.datapoints.get_or_create(
                6, TuyaBLEDataPointType.DT_BOOL, False
            ):
                await bluetooth_unlock.set_value(True)
        else:
            if manual_lock := self._device.datapoints.get_or_create(
                DPCode.MANUAL_LOCK, TuyaBLEDataPointType.DT_BOOL, False
            ):
                await manual_lock.set_value(False)

    async def async_open(self, **kwargs: Any) -> None:
        """Open the lock."""
        self._device.ensure_control_available()
        await self.async_unlock(**kwargs)


class TuyaBLES1Lock(TuyaBLEEntity, LockEntity):
    """S1 lock using device-specific, live-captured unlock templates."""

    platform = Platform.LOCK
    _is_command_entity = True
    _attr_should_poll = False

    def __init__(
        self,
        hass: HomeAssistant,
        coordinator: TuyaBLECoordinator,
        device: TuyaBLEDevice,
        product: TuyaBLEProductInfo,
        template_store: TuyaBLES1TemplateStore,
    ) -> None:
        super().__init__(
            hass,
            coordinator,
            device,
            product,
            LockEntityDescription(
                key="ble_unlock_lock",
                translation_key="lock",
                icon="mdi:lock",
            ),
        )
        self._attr_supported_features = LockEntityFeature(0)
        self._attr_is_locking = False
        self._attr_is_unlocking = False
        self._template_store = template_store
        self._operation_lock = asyncio.Lock()
        self._template_store.discard_pending(self._device.device_id)
        current_templates = [
            datapoint
            for dp_id in (S1_DP_UNLOCK_REQUEST, S1_DP_UNLOCK_CONFIRM)
            if (datapoint := device.datapoints[dp_id]) is not None
        ]
        self._capture_inbound_templates(current_templates)
        self._unsub_template_callback: Callable[[], None] | None = (
            device.register_callback(self._capture_inbound_templates)
        )
        self._unsub_template_session_callback: Callable[[], None] | None = (
            device.register_session_invalidated_callback(
                self._discard_pending_templates
            )
        )

    async def async_will_remove_from_hass(self) -> None:
        """Stop capturing templates when the entity is removed."""
        if self._unsub_template_callback is not None:
            self._unsub_template_callback()
            self._unsub_template_callback = None
        if self._unsub_template_session_callback is not None:
            self._unsub_template_session_callback()
            self._unsub_template_session_callback = None
        self._discard_pending_templates()
        await super().async_will_remove_from_hass()

    def _capture_inbound_templates(self, datapoints: list[TuyaBLEDataPoint]) -> None:
        self._template_store.capture_inbound(self._device.device_id, datapoints)

    def _discard_pending_templates(self) -> None:
        self._template_store.discard_pending(self._device.device_id)

    @property
    def is_locked(self) -> bool | None:
        """Return true if the S1 motor is in its locked state."""
        motor_state = self._device.datapoints[S1_DP_MOTOR_STATE]
        if (
            motor_state is not None
            and motor_state.received_in_current_session
            and isinstance(motor_state.value, bool)
        ):
            return not motor_state.value
        return None

    async def async_lock(self, **kwargs: Any) -> None:
        """Lock by issuing the S1's one-way manual-lock command."""
        self._device.ensure_control_available()
        async with self._operation_lock:
            self._attr_is_locking = True
            self.async_write_ha_state()
            try:
                async with self._device.connection_lease(
                    "s1 lock", defer_connection=True
                ):
                    manual_lock = self._device.datapoints.get_or_create(
                        S1_DP_LOCK, TuyaBLEDataPointType.DT_BOOL, True
                    )
                    await manual_lock.set_value_no_replay(True)
            finally:
                self._attr_is_locking = False
                self.async_write_ha_state()

    async def async_unlock(self, **kwargs: Any) -> None:
        """Unlock using one validated, serialized S1 DP70/DP71 sequence."""
        self._device.ensure_control_available()
        async with self._operation_lock:
            self._attr_is_unlocking = True
            self.async_write_ha_state()
            try:
                async with self._device.connection_lease("s1 unlock"):
                    session_epoch = self._device.current_session_epoch
                    if session_epoch is None:
                        _raise_s1_unlock_validation_error()
                    templates = self._template_store.templates_for(
                        self._device.device_id, session_epoch
                    )
                    if templates is None:
                        _raise_s1_unlock_validation_error()
                    for dp_id in (S1_DP_UNLOCK_REQUEST, S1_DP_UNLOCK_CONFIRM):
                        datapoint = self._device.datapoints[dp_id]
                        if (
                            datapoint is not None
                            and datapoint.type is not TuyaBLEDataPointType.DT_RAW
                        ):
                            _raise_s1_unlock_validation_error()
                    dp70_payload, dp71_template = templates
                    dp71_payload = bytearray(dp71_template)
                    timestamp = int(time.time()).to_bytes(4, "big", signed=False)
                    dp71_payload[S1_DP71_TIMESTAMP] = timestamp

                    dp70 = self._device.datapoints.get_or_create(
                        S1_DP_UNLOCK_REQUEST,
                        TuyaBLEDataPointType.DT_RAW,
                        dp70_payload,
                    )
                    await dp70.set_value_no_replay(dp70_payload)

                    await asyncio.sleep(S1_UNLOCK_DELAY)

                    dp71 = self._device.datapoints.get_or_create(
                        S1_DP_UNLOCK_CONFIRM,
                        TuyaBLEDataPointType.DT_RAW,
                        bytes(dp71_payload),
                    )
                    await dp71.set_value_no_replay(bytes(dp71_payload))
            finally:
                self._attr_is_unlocking = False
                self.async_write_ha_state()
