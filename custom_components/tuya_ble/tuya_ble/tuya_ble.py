from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from contextlib import AbstractAsyncContextManager
from contextvars import ContextVar, Token, copy_context
from datetime import datetime, timezone
import hashlib
import inspect
import logging
import re
import secrets
import time
from collections.abc import Callable, Hashable
from struct import pack, unpack
from dataclasses import dataclass
from typing import Any, Self

import json

from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData
from bleak.exc import BleakDBusError
from bleak_retry_connector import BLEAK_BACKOFF_TIME
from bleak_retry_connector import BLEAK_RETRY_EXCEPTIONS
from bleak_retry_connector import (
    BleakClientWithServiceCache,
    BleakError,
    BleakNotFoundError,
    establish_connection,
)
from Crypto.Cipher import AES

from .const import (
    CHARACTERISTIC_NOTIFY,
    CHARACTERISTIC_NOTIFY_FD50,
    CHARACTERISTIC_WRITE,
    GATT_MTU,
    MANUFACTURER_DATA_ID,
    RESPONSE_WAIT_TIMEOUT,
    SERVICE_CHARACTERISTICS,
    SERVICE_UUID_TEMP,
    SERVICE_UUIDS,
    TuyaBLECode,
    TuyaBLEDataPointType,
)

from ..const import (
    BLE_TARGET_WAIT_TIMEOUT_SECONDS,
    CONF_BLE_CONTROL_ENABLED,
    CONF_CONNECTION_MODE,
    CONNECTION_POLICY_TRANSITION_TIMEOUT_SECONDS,
    ConnectionMode,
    ConnectionPolicyState,
    EffectiveConnectionPolicy,
    DEFAULT_BLE_CONTROL_ENABLED,
    DEFAULT_CONNECTION_MODE,
    DEFAULT_ON_DEMAND_IDLE_DISCONNECT_SECONDS,
    DPType,
)

from .exceptions import (
    TuyaBLECommandUnconfirmedError,
    TuyaBLEDataCRCError,
    TuyaBLEDataFormatError,
    TuyaBLEDataLengthError,
    TuyaBLEDeviceError,
    TuyaBLEEnumValueError,
    TuyaBLEConnectionUnavailableError,
    TuyaBLEControlSuspendedError,
    TuyaBLEPolicyTransitionError,
    TuyaBLEError,
)
from .manager import AbstaractTuyaBLEDeviceManager, TuyaBLEDeviceCredentials
from .security import TuyaBLESecurityMaterial


_LOGGER = logging.getLogger(__name__)


_LOG_IDENTITY_ALPHABET = "ghjkmnpqrstuvwxyz"
_LOG_IDENTITY_LENGTH = 16
_TRANSPORT_ERROR_FALLBACK = "Tuya BLE transport error"
_ConnectionLeaseContext = dict[int, int]
_CONNECTION_LEASE_CONTEXT: ContextVar[_ConnectionLeaseContext] = ContextVar(
    "tuya_ble_connection_lease", default={}
)


def _lease_context_depth(device: object) -> int:
    """Return the current task's lease depth for one device object."""
    return _CONNECTION_LEASE_CONTEXT.get().get(id(device), 0)


def _enter_lease_context(device: object) -> Token[_ConnectionLeaseContext]:
    """Add one device-scoped lease to the current task context."""
    context = dict(_CONNECTION_LEASE_CONTEXT.get())
    device_key = id(device)
    context[device_key] = context.get(device_key, 0) + 1
    return _CONNECTION_LEASE_CONTEXT.set(context)


BLEAK_EXCEPTIONS = (*BLEAK_RETRY_EXCEPTIONS, OSError)


FD50_DEVICE_INFO_PRODUCT_IDS = frozenset({"jntxv3q4"})


# @dataclass
class TuyaBLEEntityDescription:
    # Added to info that we get from the cloud
    function: list[dict[str, dict]] | None = None
    status_range: list[dict[str, dict]] | None = None

    # Replace the values that we got from the cloud
    values_overrides: dict[str, dict] | None = None

    # Values if nothing was set from the cloud
    values_defaults: dict[str, dict] | None = None


class TuyaBLEDataPoint:
    def __init__(
        self,
        owner: TuyaBLEDataPoints,
        id: int,
        timestamp: float,
        flags: int,
        type: TuyaBLEDataPointType,
        value: bytes | bool | int | str,
        *,
        received_from_device: bool = False,
    ) -> None:
        self._owner = owner
        self._id = id
        self._timestamp = timestamp
        self._flags = flags
        self._type = type
        self._value = value
        self._changed_by_device = False
        self._received_from_device = received_from_device

    def __repr__(self) -> str:
        return (
            f"<TuyaBLEDataPoint id={self.id} timestamp={self.timestamp} "
            f"type={self.type} flags={self.flags} changed_by_device="
            f"{self.changed_by_device}>"
        )

    def _update_from_device(
        self,
        timestamp: float,
        flags: int,
        type: TuyaBLEDataPointType,
        value: bytes | bool | int | str,
    ) -> None:
        self._timestamp = timestamp
        self._flags = flags
        self._type = type
        self._changed_by_device = self._value != value
        self._value = value
        self._received_from_device = True

    def _get_value(self) -> bytes:
        match self._type:
            case TuyaBLEDataPointType.DT_RAW | TuyaBLEDataPointType.DT_BITMAP:
                return self._value
            case TuyaBLEDataPointType.DT_BOOL:
                return pack(">B", 1 if self._value else 0)
            case TuyaBLEDataPointType.DT_VALUE:
                return pack(">i", self._value)
            case TuyaBLEDataPointType.DT_ENUM:
                if self._value > 0xFFFF:
                    return pack(">I", self._value)
                if self._value > 0xFF:
                    return pack(">H", self._value)

                return pack(">B", self._value)
            case TuyaBLEDataPointType.DT_STRING:
                return self._value.encode()

    @property
    def id(self) -> int:
        return self._id

    @property
    def timestamp(self) -> float:
        return self._timestamp

    @property
    def flags(self) -> int:
        return self._flags

    @property
    def type(self) -> TuyaBLEDataPointType:
        return self._type

    @property
    def value(self) -> bytes | bool | int | str:
        return self._value

    @property
    def changed_by_device(self) -> bool:
        return self._changed_by_device

    @property
    def received_from_device(self) -> bool:
        """Return whether the current value came from an inbound device update."""
        return self._received_from_device

    def __str__(self) -> str:
        return repr(self)

    def _set_local_value(self, value: bytes | bool | int | str) -> None:
        """Normalize a value and mark it as locally originated."""
        match self._type:
            case TuyaBLEDataPointType.DT_RAW | TuyaBLEDataPointType.DT_BITMAP:
                self._value = bytes(value)
            case TuyaBLEDataPointType.DT_BOOL:
                self._value = bool(value)
            case TuyaBLEDataPointType.DT_VALUE:
                self._value = int(value)
            case TuyaBLEDataPointType.DT_ENUM:
                value = int(value)
                if value >= 0:
                    self._value = value
                else:
                    raise TuyaBLEEnumValueError()

            case TuyaBLEDataPointType.DT_STRING:
                self._value = str(value)

        self._changed_by_device = False
        self._received_from_device = False

    async def set_value(self, value: bytes | bool | int | str) -> None:
        self._owner._owner.ensure_control_available()
        self._set_local_value(value)
        await self._owner._update_from_user(self._id)

    async def set_value_once(self, value: bytes | bool | int | str) -> None:
        """Send one confirmed command without automatic packet replay."""
        self._owner._owner.ensure_control_available()
        previous_value = self._value
        previous_changed_by_device = self._changed_by_device
        previous_received_from_device = self._received_from_device
        self._set_local_value(value)
        try:
            await self._owner._update_from_user_once(self._id)
        except (Exception, asyncio.CancelledError):
            self._value = previous_value
            self._changed_by_device = previous_changed_by_device
            self._received_from_device = previous_received_from_device
            raise


class TuyaBLEDataPoints:
    """Models DPs"""

    def __init__(self, owner: TuyaBLEDevice) -> None:
        self._owner = owner
        self._datapoints: dict[int, TuyaBLEDataPoint] = {}
        self._update_started: int = 0
        self._updated_datapoints: list[int] = []
        self._last_data_received: datetime | None = None

    def __len__(self) -> int:
        return len(self._datapoints)

    def __getitem__(self, key: int) -> TuyaBLEDataPoint | None:
        return self._datapoints.get(key)

    def __dict__(self) -> dict:
        return self._datapoints

    @property
    def last_data_received(self) -> datetime | None:
        """Last data received"""
        return self._last_data_received

    def has_id(self, id: int, type: TuyaBLEDataPointType | None = None) -> bool:
        return (id in self._datapoints) and (
            (type is None) or (self._datapoints[id].type == type)
        )

    def get_or_create(
        self,
        id: int,
        type: TuyaBLEDataPointType,
        value: bytes | bool | int | str | None = None,
    ) -> TuyaBLEDataPoint:
        """Lazy loaded datapoint"""
        datapoint = self._datapoints.get(id)
        if datapoint:
            return datapoint
        datapoint = TuyaBLEDataPoint(self, id, time.time(), 0, type, value)
        self._datapoints[id] = datapoint
        return datapoint

    def begin_update(self) -> None:
        self._update_started += 1

    async def end_update(self) -> None:
        if self._update_started > 0:
            self._update_started -= 1
            if self._update_started == 0 and len(self._updated_datapoints) > 0:
                await self._owner._send_datapoints(self._updated_datapoints)
                self._updated_datapoints = []

    def _update_from_device(
        self,
        dp_id: int,
        timestamp: float,
        flags: int,
        type: TuyaBLEDataPointType,
        value: bytes | bool | int | str,
    ) -> None:
        self._last_data_received = datetime.now(timezone.utc)
        self._owner._mark_state_data_fresh()
        dp = self._datapoints.get(dp_id)
        if dp:
            dp._update_from_device(timestamp, flags, type, value)
        else:
            self._datapoints[dp_id] = TuyaBLEDataPoint(
                self,
                dp_id,
                timestamp,
                flags,
                type,
                value,
                received_from_device=True,
            )

    async def _update_from_user(self, dp_id: int) -> None:
        if self._update_started > 0:
            if dp_id in self._updated_datapoints:
                self._updated_datapoints.remove(dp_id)
            self._updated_datapoints.append(dp_id)
        else:
            await self._owner._send_datapoints([dp_id])

    async def _update_from_user_once(self, dp_id: int) -> None:
        """Send one datapoint through the confirmed at-most-once path."""
        await self._owner._send_datapoints_once([dp_id])


class TuyaBLEConnectionLease(AbstractAsyncContextManager):
    """Reference-counted permission to use one device connection."""

    def __init__(
        self,
        device: TuyaBLEDevice,
        reason: str,
        defer_connection: bool = False,
    ) -> None:
        self._device = device
        self._reason = reason
        self._defer_connection = defer_connection
        self._acquired = False
        self._context_token: Token[_ConnectionLeaseContext] | None = None

    async def __aenter__(self) -> Self:
        await self._device._acquire_connection_lease(
            self._reason, self._defer_connection
        )
        self._acquired = True
        self._context_token = _enter_lease_context(self._device)
        return self

    async def __aexit__(self, exc_type, exc_value, traceback) -> None:
        if self._acquired:
            self._acquired = False
            context_token = self._context_token
            self._context_token = None
            if context_token is not None:
                try:
                    _CONNECTION_LEASE_CONTEXT.reset(context_token)
                except ValueError:
                    pass
            try:
                await self._device._release_connection_lease()
            finally:
                self._context_token = None


global_connect_lock = asyncio.Lock()


@dataclass
class TuyaBLEDeviceFunction:
    """Models a code, DP and values"""

    code: str
    dp_id: int
    type: DPType
    values: str | dict | list | None

    def __setattr__(self, name: str, value: str | dict | list | None):
        if name == "values":
            # string values are JSON representations of the actual values
            if isinstance(value, str) and (v := json.loads(value)):
                value = v
        super().__setattr__(name, value)


class TuyaBLEDevice:
    """Abstract model of a device"""

    def __init__(
        self,
        device_manager: AbstaractTuyaBLEDeviceManager,
        ble_device: BLEDevice | None,
        advertisement_data: AdvertisementData | None = None,
        *,
        address: str | None = None,
        connection_mode: str = DEFAULT_CONNECTION_MODE,
        ble_control_enabled: bool = DEFAULT_BLE_CONTROL_ENABLED,
        persist_options: (
            Callable[[dict[str, Any]], Awaitable[None] | None] | None
        ) = None,
    ) -> None:
        """Init the TuyaBLE."""
        self._device_manager = device_manager
        self._device_info: TuyaBLEDeviceCredentials | None = None
        self._address = address or (ble_device.address if ble_device else "")
        self._ble_device = ble_device
        self._advertisement_data = advertisement_data
        self._ble_target_event = asyncio.Event()
        if ble_device is not None:
            self._ble_target_event.set()
        self._log_identity = "tuya-ble-session-" + "".join(
            secrets.choice(_LOG_IDENTITY_ALPHABET) for _ in range(_LOG_IDENTITY_LENGTH)
        )
        self._operation_lock = asyncio.Lock()
        self._connect_lock = asyncio.Lock()
        self._policy_lock = asyncio.Lock()
        self._policy_transition_lock = asyncio.Lock()
        self._lease_zero_event = asyncio.Event()
        self._lease_zero_event.set()
        self._active_lease_count = 0
        self._response_drain_zero_event = asyncio.Event()
        self._response_drain_zero_event.set()
        self._active_response_drain_count = 0
        self._pending_disconnect_target: ConnectionPolicyState | None = None
        self._pending_disconnect_revision: int | None = None
        self._policy_revision = 0
        self._disconnect_in_progress = False
        self._idle_disconnect_task: asyncio.Task | None = None
        self._disconnect_retry_task: asyncio.Task | None = None
        self._reconnect_task: asyncio.Task | None = None
        self._resend_task: asyncio.Task | None = None
        self._response_tasks: set[asyncio.Task] = set()
        self._response_drain_tasks: set[asyncio.Task] = set()
        self._response_cleanup_tasks: set[asyncio.Task] = set()
        self._startup_task: asyncio.Task | None = None
        self._persist_options = persist_options
        try:
            self._connection_mode = ConnectionMode(connection_mode)
        except (TypeError, ValueError):
            self._connection_mode = ConnectionMode.ALWAYS_CONNECTED
        self._ble_control_enabled = (
            ble_control_enabled
            if isinstance(ble_control_enabled, bool)
            else DEFAULT_BLE_CONTROL_ENABLED
        )
        self._suspension_requested = not self._ble_control_enabled
        self._terminal_stopped = False
        self._policy_state = (
            ConnectionPolicyState.SUSPENDED
            if not self._ble_control_enabled
            else (
                ConnectionPolicyState.ON_DEMAND_IDLE
                if self._connection_mode is ConnectionMode.ON_DEMAND
                else ConnectionPolicyState.ALWAYS_CONNECTED_CONNECTING
            )
        )
        self._state_data_fresh = False
        self._has_disconnected = False
        self._physical_connection_active = False
        self._connection_state_callbacks: list[Callable[[bool], None]] = []
        self._client: BleakClientWithServiceCache | None = None
        self._characteristic_notify = CHARACTERISTIC_NOTIFY
        self._characteristic_write = CHARACTERISTIC_WRITE
        self._expected_disconnect = False
        self._connected_callbacks: list[Callable[[], None]] = []
        self._callbacks: list[Callable[[list[TuyaBLEDataPoint]], None]] = []
        self._disconnected_callbacks: list[Callable[[], None]] = []
        self._current_seq_num = 1
        self._seq_num_lock = asyncio.Lock()

        self._is_bound = False
        self._flags = 0
        self._protocol_version = 2

        self._device_version: str = ""
        self._protocol_version_str: str = ""
        self._hardware_version: str = ""

        self._device_info: TuyaBLEDeviceCredentials | None = None

        self._auth_key: bytes | None = None
        self._local_key: bytes | None = None
        self._login_key: bytes | None = None
        self._session_key: bytes | None = None
        self._security_material: TuyaBLESecurityMaterial | None = None

        self._is_paired = False

        self._input_buffer: bytearray | None = None
        self._input_expected_packet_num = 0
        self._input_expected_length = 0
        self._input_expected_responses: dict[int, asyncio.Future[int] | None] = {}
        self._input_expected_response_codes: dict[int, TuyaBLECode] = {}
        # self._input_future: asyncio.Future[int] | None = None

        self._datapoints = TuyaBLEDataPoints(self)

        self._function = {}
        self._status_range = {}

    def set_ble_device_and_advertisement_data(
        self, ble_device: BLEDevice, advertisement_data: AdvertisementData
    ) -> None:
        """Set the ble device."""
        self._ble_device = ble_device
        self._advertisement_data = advertisement_data
        self._address = ble_device.address
        self._ble_target_event.set()

    @property
    def connection_mode(self) -> ConnectionMode:
        """Return the desired connection mode."""
        return self._connection_mode

    @property
    def ble_control_enabled(self) -> bool:
        """Return whether Home Assistant may control this device."""
        return self._ble_control_enabled

    @property
    def effective_policy(self) -> EffectiveConnectionPolicy:
        """Return the effective policy after applying suspension and stop."""
        if self._terminal_stopped:
            return EffectiveConnectionPolicy.STOPPED
        if not self._ble_control_enabled or self._suspension_requested:
            return EffectiveConnectionPolicy.SUSPENDED
        if self._connection_mode is ConnectionMode.ALWAYS_CONNECTED:
            return EffectiveConnectionPolicy.ALWAYS_CONNECTED
        return EffectiveConnectionPolicy.ON_DEMAND

    @property
    def policy_state(self) -> ConnectionPolicyState:
        """Return the current runtime state."""
        return self._policy_state

    @property
    def is_gatt_connected(self) -> bool:
        """Return whether a physical GATT client is connected."""
        return bool(self._client and self._client.is_connected)

    @property
    def is_authenticated(self) -> bool:
        """Return whether the current session completed pairing."""
        return self._is_paired

    @property
    def is_connection_active(self) -> bool:
        """Return whether an authenticated paired GATT session is active."""
        return self.is_gatt_connected and self._is_paired

    @property
    def active_lease_count(self) -> int:
        """Return the number of active connection leases."""
        return self._active_lease_count

    @property
    def state_data_fresh(self) -> bool:
        """Return whether current-session device data has been received."""
        return self._state_data_fresh

    def connection_lease(
        self, reason: str, *, defer_connection: bool = False
    ) -> TuyaBLEConnectionLease:
        """Return a lease protecting a complete BLE operation."""
        return TuyaBLEConnectionLease(self, reason, defer_connection)

    def ensure_control_available(self) -> None:
        """Reject work that cannot safely use the current policy."""
        lease_active = _lease_context_depth(self) > 0
        if self._terminal_stopped and not lease_active:
            raise TuyaBLEConnectionUnavailableError()
        if (
            not self._ble_control_enabled or self._suspension_requested
        ) and not lease_active:
            raise TuyaBLEControlSuspendedError()

    def register_connection_state_callback(
        self, callback: Callable[[bool], None]
    ) -> Callable[[], None]:
        """Register a callback for immediate paired-session state changes."""
        self._connection_state_callbacks.append(callback)

        def unregister_callback() -> None:
            if callback in self._connection_state_callbacks:
                self._connection_state_callbacks.remove(callback)

        return unregister_callback

    def _fire_connection_state_callbacks(self, connected: bool) -> None:
        for callback in tuple(self._connection_state_callbacks):
            callback(connected)

    def _mark_state_data_fresh(self) -> None:
        self._state_data_fresh = True

    async def _persist_policy_options(self, updates: dict[str, Any]) -> None:
        if self._persist_options is None:
            return
        try:
            result = self._persist_options(updates)
            if inspect.isawaitable(result):
                await result
        except Exception:
            _LOGGER.error("%s: Connection policy persistence failed", self.log_identity)
            raise TuyaBLEPolicyTransitionError() from None

    async def async_update_connection_policy(
        self,
        *,
        connection_mode: str | None = None,
        ble_control_enabled: bool | None = None,
    ) -> None:
        """Persist and apply one or both connection policy settings."""
        async with self._policy_transition_lock:
            if connection_mode is None:
                new_mode = self._connection_mode
            else:
                try:
                    new_mode = ConnectionMode(connection_mode)
                except (TypeError, ValueError):
                    raise TuyaBLEPolicyTransitionError() from None

            if ble_control_enabled is None:
                new_enabled = self._ble_control_enabled
            elif isinstance(ble_control_enabled, bool):
                new_enabled = ble_control_enabled
            else:
                raise TuyaBLEPolicyTransitionError()

            updates: dict[str, Any] = {}
            if new_mode is not self._connection_mode:
                updates[CONF_CONNECTION_MODE] = new_mode.value
            if new_enabled != self._ble_control_enabled:
                updates[CONF_BLE_CONTROL_ENABLED] = new_enabled
            if updates:
                await self._persist_policy_options(updates)

            re_enabled = new_enabled and not self._ble_control_enabled
            self._connection_mode = new_mode
            self._ble_control_enabled = new_enabled
            if re_enabled:
                async with self._policy_lock:
                    self._policy_revision += 1
                    if (
                        self._pending_disconnect_target
                        is ConnectionPolicyState.SUSPENDED
                    ):
                        self._pending_disconnect_target = None
                        self._pending_disconnect_revision = None
                        self._cancel_disconnect_retry_locked()
                    self._suspension_requested = False
                    self._cancel_idle_disconnect_locked()
            elif not new_enabled:
                self._suspension_requested = True
            await self._apply_connection_policy()

    async def async_apply_persisted_options(self, options: dict[str, Any]) -> None:
        """Apply stored policy options without writing them again."""
        async with self._policy_transition_lock:
            try:
                new_mode = ConnectionMode(
                    options.get(CONF_CONNECTION_MODE, DEFAULT_CONNECTION_MODE)
                )
            except (TypeError, ValueError):
                new_mode = ConnectionMode.ALWAYS_CONNECTED
            raw_enabled = options.get(
                CONF_BLE_CONTROL_ENABLED, DEFAULT_BLE_CONTROL_ENABLED
            )
            new_enabled = raw_enabled if isinstance(raw_enabled, bool) else True
            self._connection_mode = new_mode
            self._ble_control_enabled = new_enabled
            self._suspension_requested = not new_enabled
            await self._apply_connection_policy()

    async def _apply_connection_policy(self) -> None:
        if self._terminal_stopped:
            return
        if not self._ble_control_enabled:
            await self._suspend_runtime()
            return

        self._suspension_requested = False
        if self._connection_mode is ConnectionMode.ON_DEMAND:
            async with self._policy_lock:
                self._cancel_reconnect_locked()
                self._cancel_resend_locked()
                if self._active_lease_count:
                    self._policy_state = (
                        ConnectionPolicyState.ON_DEMAND_ACTIVE
                        if self.is_connection_active
                        else ConnectionPolicyState.ON_DEMAND_CONNECTING
                    )
                elif self.is_connection_active:
                    self._policy_state = ConnectionPolicyState.ON_DEMAND_ACTIVE
                    self._schedule_idle_disconnect_locked()
                else:
                    self._policy_state = ConnectionPolicyState.ON_DEMAND_IDLE
                    self._cancel_idle_disconnect_locked()
            return

        async with self._policy_lock:
            self._cancel_resend_locked()
            self._cancel_idle_disconnect_locked()
            if self.is_connection_active:
                self._policy_state = ConnectionPolicyState.ALWAYS_CONNECTED_ACTIVE
            else:
                self._policy_state = ConnectionPolicyState.ALWAYS_CONNECTED_CONNECTING
                self._schedule_reconnect_locked(0)

    async def _suspend_runtime(self) -> None:
        async with self._policy_lock:
            if self._terminal_stopped:
                return
            if (
                self._policy_state is ConnectionPolicyState.SUSPENDED
                and not self.is_gatt_connected
            ):
                return
            self._suspension_requested = True
            self._pending_disconnect_target = ConnectionPolicyState.SUSPENDED
            self._pending_disconnect_revision = self._policy_revision
            self._cancel_reconnect_locked()
            self._cancel_resend_locked()
            self._cancel_idle_disconnect_locked()
            if self.is_connection_active:
                self._policy_state = ConnectionPolicyState.DISCONNECTING

        try:
            await asyncio.wait_for(
                self._lease_zero_event.wait(),
                CONNECTION_POLICY_TRANSITION_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            raise TuyaBLEPolicyTransitionError() from None
        await self._complete_pending_disconnect(raise_on_error=True)

    async def _acquire_connection_lease(
        self, reason: str, defer_connection: bool
    ) -> None:
        del reason
        self.ensure_control_available()
        async with self._policy_lock:
            self.ensure_control_available()
            self._cancel_idle_disconnect_locked()
            self._active_lease_count += 1
            self._lease_zero_event.clear()
            self._expected_disconnect = False
            if self._connection_mode is ConnectionMode.ALWAYS_CONNECTED:
                self._policy_state = ConnectionPolicyState.ALWAYS_CONNECTED_CONNECTING
            else:
                self._policy_state = ConnectionPolicyState.ON_DEMAND_CONNECTING

        if defer_connection:
            return
        try:
            await self._ensure_connected()
        except asyncio.CancelledError:
            await self._release_connection_lease()
            raise
        except (TuyaBLEControlSuspendedError, TuyaBLEConnectionUnavailableError):
            await self._release_connection_lease()
            raise
        except Exception:
            await self._release_connection_lease()
            raise TuyaBLEConnectionUnavailableError() from None

        async with self._policy_lock:
            if self._connection_mode is ConnectionMode.ALWAYS_CONNECTED:
                self._policy_state = ConnectionPolicyState.ALWAYS_CONNECTED_ACTIVE
            else:
                self._policy_state = ConnectionPolicyState.ON_DEMAND_ACTIVE

    async def _release_connection_lease(self) -> None:
        async with self._policy_lock:
            if self._active_lease_count == 0:
                return
            self._active_lease_count -= 1
            if self._active_lease_count != 0:
                return
            self._lease_zero_event.set()
            pending_disconnect = self._pending_disconnect_target is not None
            if (
                self._connection_mode is ConnectionMode.ON_DEMAND
                and self._ble_control_enabled
                and not self._suspension_requested
                and not self._terminal_stopped
            ):
                self._policy_state = ConnectionPolicyState.ON_DEMAND_ACTIVE
                self._schedule_idle_disconnect_locked()
        if pending_disconnect:
            await self._complete_pending_disconnect()

    async def _complete_pending_disconnect(
        self, *, raise_on_error: bool = False
    ) -> None:
        """Complete one deferred disconnect after all protected work drains."""
        async with self._policy_lock:
            target = self._pending_disconnect_target
            revision = self._pending_disconnect_revision
            if (
                target is None
                or self._active_lease_count
                or self._active_response_drain_count
                or self._disconnect_in_progress
            ):
                return
            self._disconnect_in_progress = True
            self._policy_state = ConnectionPolicyState.DISCONNECTING

        disconnect_failed = False
        reconcile_policy = False
        complete_superseding_target = False
        try:
            await self._execute_disconnect(
                terminal=target is ConnectionPolicyState.STOPPED
            )
        except asyncio.CancelledError:
            disconnect_failed = True
            raise
        except Exception:
            disconnect_failed = True
            _LOGGER.error("%s: Deferred BLE disconnect failed", self.log_identity)
        finally:
            async with self._policy_lock:
                self._disconnect_in_progress = False
                if disconnect_failed:
                    self._schedule_disconnect_retry_locked()
                elif self._pending_disconnect_target is target:
                    self._pending_disconnect_target = None
                    self._pending_disconnect_revision = None
                    if (
                        target is ConnectionPolicyState.SUSPENDED
                        and revision != self._policy_revision
                    ):
                        self._suspension_requested = False
                        reconcile_policy = True
                    else:
                        self._suspension_requested = True
                        self._policy_state = target
                elif (
                    target is ConnectionPolicyState.SUSPENDED
                    and revision != self._policy_revision
                ):
                    self._suspension_requested = False
                    reconcile_policy = True
                else:
                    complete_superseding_target = True

        if reconcile_policy:
            await self._apply_connection_policy()
        elif complete_superseding_target:
            await self._complete_pending_disconnect()

        if disconnect_failed and raise_on_error:
            raise TuyaBLEPolicyTransitionError() from None

    def _cancel_idle_disconnect_locked(self) -> None:
        if self._idle_disconnect_task is not None:
            self._idle_disconnect_task.cancel()
            self._idle_disconnect_task = None

    def _cancel_reconnect_locked(self) -> None:
        if self._reconnect_task is not None:
            self._reconnect_task.cancel()
            self._reconnect_task = None

    def _cancel_resend_locked(self) -> None:
        if self._resend_task is not None:
            self._resend_task.cancel()
            self._resend_task = None

    def _schedule_disconnect_retry_locked(self) -> None:
        """Retry a pending physical release with one bounded-backoff task."""
        if self._disconnect_retry_task is not None:
            return
        self._disconnect_retry_task = self._create_policy_task(
            self._disconnect_retry_runner()
        )

    async def _disconnect_retry_runner(self) -> None:
        """Retry a failed policy disconnect without reconnecting or writing."""
        current_task = asyncio.current_task()
        try:
            while self._pending_disconnect_target is not None:
                await asyncio.sleep(BLEAK_BACKOFF_TIME)
                await self._complete_pending_disconnect()
        except asyncio.CancelledError:
            return
        finally:
            async with self._policy_lock:
                if self._disconnect_retry_task is current_task:
                    self._disconnect_retry_task = None

    def _cancel_disconnect_retry_locked(self) -> None:
        if self._disconnect_retry_task is not None:
            self._disconnect_retry_task.cancel()
            self._disconnect_retry_task = None

    @staticmethod
    def _create_policy_task(coroutine: Any) -> asyncio.Task:
        """Create background policy work without inheriting an operation lease."""
        context = copy_context()
        context.run(_CONNECTION_LEASE_CONTEXT.set, {})
        return context.run(asyncio.create_task, coroutine)

    def _schedule_idle_disconnect_locked(self) -> None:
        if self._idle_disconnect_task is not None:
            return
        self._idle_disconnect_task = self._create_policy_task(
            self._idle_disconnect_after_delay()
        )

    async def _idle_disconnect_after_delay(self) -> None:
        current_task = asyncio.current_task()
        try:
            await asyncio.sleep(DEFAULT_ON_DEMAND_IDLE_DISCONNECT_SECONDS)
            async with self._policy_lock:
                if (
                    self._active_lease_count
                    or self._connection_mode is not ConnectionMode.ON_DEMAND
                    or not self._ble_control_enabled
                    or self._suspension_requested
                    or self._terminal_stopped
                ):
                    return
                self._policy_state = ConnectionPolicyState.DISCONNECTING
            await self._execute_disconnect()
            async with self._policy_lock:
                if not self._terminal_stopped and self._ble_control_enabled:
                    self._policy_state = ConnectionPolicyState.ON_DEMAND_IDLE
        except asyncio.CancelledError:
            return
        except Exception:
            _LOGGER.error(
                "%s: On-demand idle disconnect failed",
                self.log_identity,
            )
        finally:
            if self._idle_disconnect_task is current_task:
                self._idle_disconnect_task = None

    def _schedule_reconnect_locked(self, delay: float) -> None:
        if self._reconnect_task is not None:
            return
        self._reconnect_task = self._create_policy_task(
            self._reconnect_after_delay(delay)
        )

    async def _reconnect_after_delay(self, delay: float) -> None:
        current_task = asyncio.current_task()
        try:
            if delay:
                await asyncio.sleep(delay)
            await self._reconnect()
        except asyncio.CancelledError:
            return
        finally:
            if self._reconnect_task is current_task:
                self._reconnect_task = None

    def _schedule_resend(self, packets: list[bytes]) -> None:
        if (
            self._connection_mode is not ConnectionMode.ALWAYS_CONNECTED
            or self._terminal_stopped
            or self._suspension_requested
            or self._resend_task is not None
        ):
            return
        self._resend_task = self._create_policy_task(self._resend_task_runner(packets))

    async def _resend_task_runner(self, packets: list[bytes]) -> None:
        current_task = asyncio.current_task()
        try:
            await self._resend_packets(packets)
        except asyncio.CancelledError:
            return
        except Exception:
            _LOGGER.debug("%s: Background resend failed", self.log_identity)
        finally:
            if self._resend_task is current_task:
                self._resend_task = None

    def _schedule_response(
        self, code: TuyaBLECode, data: bytes, response_to: int
    ) -> None:
        self._active_response_drain_count += 1
        self._response_drain_zero_event.clear()
        task = self._create_policy_task(
            self._response_task_runner(code, data, response_to)
        )
        self._response_tasks.add(task)
        self._response_drain_tasks.add(task)
        task.add_done_callback(self._response_tasks.discard)
        task.add_done_callback(self._response_task_done)

    def _response_task_done(self, task: asyncio.Task) -> None:
        """Release drain ownership when cancellation prevents task startup."""
        self._release_response_drain(task)

    def _release_response_drain(self, task: asyncio.Task | None) -> None:
        """Release exactly one response drain and resume pending policy work."""
        if task is None or task not in self._response_drain_tasks:
            return
        self._response_drain_tasks.remove(task)
        self._active_response_drain_count -= 1
        if self._active_response_drain_count == 0:
            self._response_drain_zero_event.set()
            cleanup_task = self._create_policy_task(self._complete_pending_disconnect())
            self._response_cleanup_tasks.add(cleanup_task)
            cleanup_task.add_done_callback(self._response_cleanup_tasks.discard)

    async def _response_task_runner(
        self,
        code: TuyaBLECode,
        data: bytes,
        response_to: int,
    ) -> None:
        try:
            await self._send_response(code, data, response_to)
        except asyncio.CancelledError:
            return
        except Exception:
            _LOGGER.debug("%s: Protocol response failed", self.log_identity)
        finally:
            self._release_response_drain(asyncio.current_task())

    async def initialize(self) -> None:
        _LOGGER.debug("%s: Initializing", self.log_identity)
        if await self._update_device_info():
            self._decode_advertisement_data()

    def _requires_fd50_device_info_handshake(self) -> bool:
        """Return whether this device needs the TuyaOS FD50 login framing."""
        return (
            self._characteristic_notify == CHARACTERISTIC_NOTIFY_FD50
            and self.product_id in FD50_DEVICE_INFO_PRODUCT_IDS
        )

    def _build_pairing_request(self) -> bytes:
        result = bytearray()

        result += self._device_info.uuid.encode()
        result += self._local_key
        result += self._device_info.device_id.encode()
        for _ in range(44 - len(result)):
            result += b"\x00"

        return result

    async def pair(self) -> None:
        """Pair with the device."""
        await self._send_packet(
            TuyaBLECode.FUN_SENDER_PAIR, self._build_pairing_request()
        )

    async def update(self) -> None:
        _LOGGER.debug("%s: Updating", self.log_identity)
        await self._send_packet(TuyaBLECode.FUN_SENDER_DEVICE_STATUS, bytes())

    async def startup_update(self) -> None:
        """Run the initial status path without failing config-entry setup."""
        try:
            await self.update()
        except Exception:
            if self.effective_policy is EffectiveConnectionPolicy.ALWAYS_CONNECTED:
                self._schedule_reconnect()
        finally:
            if self._startup_task is asyncio.current_task():
                self._startup_task = None

    async def _update_device_info(self) -> bool:
        if self._device_info is None:
            if self._device_manager:
                self._device_info = await self._device_manager.get_device_credentials(
                    self._address, False
                )
            if self._device_info:
                self._security_material = TuyaBLESecurityMaterial(
                    self._device_info.local_key,
                    self._device_info.sec_key,
                )
                self._local_key = self._security_material.pairing_login_key
                self._login_key = self._security_material.login_key

                self.append_functions(
                    self._device_info.functions, self._device_info.status_range
                )

        return self._device_info is not None

    def append_functions(self, function: list[dict], status_range: list[dict]) -> None:
        if function:
            for f in function:
                dpcode = f.get("code")
                if dpcode:
                    self.function[dpcode] = TuyaBLEDeviceFunction(**f)
            for f in status_range:
                dpcode = f.get("code")
                if dpcode:
                    self.status_range[dpcode] = TuyaBLEDeviceFunction(**f)

    def update_description(self, description: TuyaBLEEntityDescription | None) -> None:
        if not description:
            return
        self.append_functions(description.function, description.status_range)

        if description.values_overrides:
            for key in description.values_overrides:
                values = description.values_overrides.values
                if f := self.function.get(key):
                    f.values = values

                if f := self.status_range.get(key):
                    f.values = values

        if description.values_defaults:
            for key in description.values_defaults:
                values = description.values_defaults.values
                if f := self.function.get(key) and not f.values:
                    f.values = values

                if f := self.status_range.get(key) and not f.values:
                    f.values = values

    def _decode_advertisement_data(self) -> None:
        raw_product_id: bytes | None = None
        # raw_product_key: bytes | None = None
        raw_uuid: bytes | None = None
        if self._advertisement_data:
            if self._advertisement_data.service_data:
                service_data = None
                for service_uuid in SERVICE_UUIDS:
                    service_data = self._advertisement_data.service_data.get(
                        service_uuid
                    )
                    if service_data:
                        break
                if service_data and len(service_data) > 1:
                    match service_data[0]:
                        case 0:
                            raw_product_id = service_data[1:]
                        # case 1:
                        #    raw_product_key = service_data[1:]

            if self._advertisement_data.manufacturer_data:
                manufacturer_data = self._advertisement_data.manufacturer_data.get(
                    MANUFACTURER_DATA_ID
                )
                if manufacturer_data and len(manufacturer_data) > 6:
                    self._is_bound = (manufacturer_data[0] & 0x80) != 0
                    self._protocol_version = manufacturer_data[1]
                    raw_uuid = manufacturer_data[6:]
                    if raw_product_id:
                        key = hashlib.md5(raw_product_id).digest()
                        cipher = AES.new(key, AES.MODE_CBC, key)
                        raw_uuid = cipher.decrypt(raw_uuid)
                        self._uuid = raw_uuid.decode("utf-8")

    @property
    def address(self) -> str:
        """Return the address."""
        return self._address

    @property
    def log_identity(self) -> str:
        """Return this device object's process-local opaque log label."""
        return self._log_identity

    def _sanitized_transport_error(self, error: BaseException) -> BleakError:
        """Return a transport error without device identifiers or foreign context."""
        message = str(error) or _TRANSPORT_ERROR_FALLBACK
        address = self.address
        protected_values = {
            address,
            address.replace(":", ""),
            address.replace(":", "-"),
            address.replace(":", "_"),
            address.replace(":", "."),
        }
        if self._device_info is not None:
            protected_values.update(
                {
                    self._device_info.device_id,
                    self._device_info.uuid,
                    self._device_info.local_key,
                    self._device_info.sec_key,
                    self._device_info.device_name,
                }
            )
        for value in sorted(
            (value for value in protected_values if value), key=len, reverse=True
        ):
            message = re.sub(
                re.escape(value), "[redacted]", message, flags=re.IGNORECASE
            )
        message = re.sub(
            r"(?i)(?<![0-9a-f])[0-9a-f]{12,}(?![0-9a-f])",
            "[redacted]",
            message,
        )
        return BleakError(message)

    @property
    def name(self) -> str:
        """Get the name of the device."""
        if self._device_info:
            return self._device_info.device_name

        if self._ble_device:
            return self._ble_device.name or "Tuya BLE device"
        return "Tuya BLE device"

    @property
    def rssi(self) -> int | None:
        """Get the rssi of the device."""
        if self._advertisement_data:
            return self._advertisement_data.rssi
        return None

    @property
    def uuid(self) -> str:
        """UUID"""
        if self._device_info is not None:
            return self._device_info.uuid

        if self._uuid is not None:
            return self._uuid

        return ""

    @property
    def local_key(self) -> str:
        """Local key"""
        if self._device_info is not None:
            return self._device_info.local_key

        return ""

    @property
    def category(self) -> str:
        if self._device_info is not None:
            return self._device_info.category

        return ""

    @property
    def device_id(self) -> str:
        if self._device_info is not None:
            return self._device_info.device_id

        return ""

    @property
    def product_id(self) -> str:
        """Product ID"""
        if self._device_info is not None:
            return self._device_info.product_id

        return ""

    @property
    def product_model(self) -> str:
        """Produce model"""
        if self._device_info is not None:
            return self._device_info.product_model

        return ""

    @property
    def product_name(self) -> str:
        if self._device_info is not None:
            return self._device_info.product_name

        return ""

    @property
    def function(self) -> dict(str, dict):
        return self._function

    @property
    def status_range(self) -> dict(str, dict):
        return self._status_range

    @property
    def device_version(self) -> str:
        return self._device_version

    @property
    def hardware_version(self) -> str:
        return self._hardware_version

    @property
    def protocol_version(self) -> str:
        return self._protocol_version_str

    @property
    def protocol_major_version(self) -> int:
        """Return the negotiated Tuya BLE protocol major version."""
        return self._protocol_version

    @property
    def datapoints(self) -> TuyaBLEDataPoints:
        """Get datapoints exposed by device."""
        return self._datapoints

    @property
    def status(self) -> dict[str, Any]:
        """Get current datapoints values."""

        result = {}
        dps = self.datapoints._datapoints
        if dps:
            order = [self.status_range, self.function]
            for functions in order:
                for dpcode in functions:
                    f = functions[dpcode]
                    dpid = f.dp_id
                    v = dps.get(dpid)
                    if v:
                        result[dpcode] = v.value
        return result

    def datapoint_log_payload(self) -> dict[Hashable, dict[str, Any]]:
        """Create payload-safe datapoint metadata for diagnostic logging."""
        item: dict[Hashable, dict[str, Any]] = {}
        for key, value in self.datapoints.__dict__().items():
            if isinstance(value, TuyaBLEDataPoint):
                item[key] = {
                    "type": value.type.name,
                    "changed_by_device": value.changed_by_device,
                }
            else:
                item[key] = {"type": type(value).__name__}
        return item

    @property
    def last_data_received(self) -> datetime | None:
        """Last data received"""
        return self._datapoints.last_data_received

    def get_or_create_datapoint(
        self,
        id: int,
        type: TuyaBLEDataPointType,
        value: bytes | bool | int | str | None = None,
    ) -> TuyaBLEDataPoint:
        """Get datapoints exposed by device."""

    def _fire_connected_callbacks(self) -> None:
        """Fire the callbacks."""
        for callback in self._connected_callbacks:
            callback()

    def register_connected_callback(
        self, callback: Callable[[], None]
    ) -> Callable[[], None]:
        """Register a callback to be called when device disconnected."""

        def unregister_callback() -> None:
            self._connected_callbacks.remove(callback)

        self._connected_callbacks.append(callback)
        return unregister_callback

    def _fire_callbacks(self, datapoints: list[TuyaBLEDataPoint]) -> None:
        """Fire the callbacks."""
        for callback in self._callbacks:
            callback(datapoints)

    def register_callback(
        self,
        callback: Callable[[list[TuyaBLEDataPoint]], None],
    ) -> Callable[[], None]:
        """Register a callback to be called when the state changes."""

        def unregister_callback() -> None:
            self._callbacks.remove(callback)

        self._callbacks.append(callback)
        return unregister_callback

    def _fire_disconnected_callbacks(self) -> None:
        """Fire the callbacks."""
        for callback in self._disconnected_callbacks:
            callback()

    def register_disconnected_callback(
        self, callback: Callable[[], None]
    ) -> Callable[[], None]:
        """Register a callback to be called when device disconnected."""

        def unregister_callback() -> None:
            self._disconnected_callbacks.remove(callback)

        self._disconnected_callbacks.append(callback)
        return unregister_callback

    async def start(self) -> None:
        """Start the TuyaBLE."""
        _LOGGER.debug("%s: Starting...", self.log_identity)

    async def stop(self) -> None:
        """Stop the TuyaBLE."""
        _LOGGER.debug("%s: Stop", self.log_identity)
        async with self._policy_lock:
            if self._terminal_stopped:
                return
            self._terminal_stopped = True
            self._suspension_requested = True
            self._policy_state = ConnectionPolicyState.STOPPED
            self._pending_disconnect_target = ConnectionPolicyState.STOPPED
            self._pending_disconnect_revision = self._policy_revision
            self._cancel_reconnect_locked()
            self._cancel_resend_locked()
            self._cancel_idle_disconnect_locked()
            self._cancel_disconnect_retry_locked()
            for task in tuple(self._response_tasks):
                task.cancel()
                self._release_response_drain(task)
            self._response_tasks.clear()
            if self._startup_task is not None:
                self._startup_task.cancel()
                self._startup_task = None
        try:
            await asyncio.wait_for(
                self._lease_zero_event.wait(),
                CONNECTION_POLICY_TRANSITION_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            _LOGGER.error(
                "%s: Stop deferred while a BLE operation remained active",
                self.log_identity,
            )
            return
        await self._complete_pending_disconnect()

    def _mark_connection_lost(self) -> None:
        was_connected = self._physical_connection_active or self._is_paired
        self._physical_connection_active = False
        self._is_paired = False
        self._state_data_fresh = False
        if was_connected:
            self._has_disconnected = True
        self._clean_input()
        if was_connected:
            self._fire_disconnected_callbacks()
            self._fire_connection_state_callbacks(False)

    def _disconnected(self, client: BleakClientWithServiceCache) -> None:
        """Disconnected callback."""
        if client is not self._client:
            _LOGGER.debug(
                "%s: Ignoring stale disconnected client callback", self.log_identity
            )
            return
        was_paired = self._is_paired
        self._client = None
        self._mark_connection_lost()
        if self._expected_disconnect:
            _LOGGER.debug(
                "%s: Disconnected from device; RSSI: %s",
                self.log_identity,
                self.rssi,
            )
            return
        _LOGGER.warning(
            "%s: Device unexpectedly disconnected; RSSI: %s",
            self.log_identity,
            self.rssi,
        )
        if was_paired:
            _LOGGER.debug(
                "%s: Scheduling reconnect; RSSI: %s",
                self.log_identity,
                self.rssi,
            )
            self._schedule_reconnect()

    def _disconnect(self) -> None:
        """Disconnect from device."""
        asyncio.create_task(self._execute_timed_disconnect())

    async def _execute_timed_disconnect(self) -> None:
        """Execute timed disconnection."""
        _LOGGER.debug(
            "%s: Disconnecting",
            self.log_identity,
        )
        await self._execute_disconnect()

    async def _execute_disconnect(self, *, terminal: bool = False) -> None:
        """Execute disconnection."""
        async with self._connect_lock:
            client = self._client
            self._expected_disconnect = True
            if terminal:
                self._terminal_stopped = True
            stop_notify_error: BleakError | None = None
            disconnect_error: BleakError | None = None
            if client and client.is_connected:
                try:
                    await client.stop_notify(self._characteristic_notify)
                except Exception as ex:  # noqa: BLE001
                    stop_notify_error = self._sanitized_transport_error(ex)
                try:
                    await client.disconnect()
                except Exception as ex:  # noqa: BLE001
                    disconnect_error = self._sanitized_transport_error(ex)
            released = (
                client is None or not client.is_connected or self._client is not client
            )
            if not released:
                if disconnect_error is not None:
                    raise disconnect_error from None
                if stop_notify_error is not None:
                    raise stop_notify_error from None
                raise BleakError(_TRANSPORT_ERROR_FALLBACK)
            if self._client is client:
                self._client = None
            self._mark_connection_lost()
        self._clean_input()
        async with self._seq_num_lock:
            self._current_seq_num = 1
        self._session_key = None
        self._auth_key = None
        if stop_notify_error is not None:
            _LOGGER.warning("%s: BLE notification cleanup failed", self.log_identity)
        if disconnect_error is not None:
            _LOGGER.warning(
                "%s: BLE disconnect reported an error after release", self.log_identity
            )

    async def _ensure_connected(self) -> None:
        """Ensure connection to device is established."""
        global global_connect_lock
        self.ensure_control_available()
        if self._expected_disconnect and self._active_lease_count == 0:
            raise TuyaBLEConnectionUnavailableError()
        if self._connect_lock.locked():
            _LOGGER.debug(
                "%s: Connection already in progress,"
                " waiting for it to complete; RSSI: %s",
                self.log_identity,
                self.rssi,
            )
        if self._client and self._client.is_connected and self._is_paired:
            return
        if self._ble_device is None:
            try:
                await asyncio.wait_for(
                    self._ble_target_event.wait(),
                    BLE_TARGET_WAIT_TIMEOUT_SECONDS,
                )
            except asyncio.TimeoutError as err:
                raise BleakNotFoundError() from err
        if self._ble_device is None:
            raise BleakNotFoundError()
        async with self._connect_lock:
            # Check again while holding the lock
            await asyncio.sleep(0.01)
            if self._client and self._client.is_connected and self._is_paired:
                return
            if self._terminal_stopped:
                raise TuyaBLEConnectionUnavailableError()
            try:
                async with global_connect_lock:
                    _LOGGER.debug(
                        "%s: Connecting; RSSI: %s",
                        self.log_identity,
                        self.rssi,
                    )
                    client = await establish_connection(
                        BleakClientWithServiceCache,
                        self._ble_device,
                        self.address,
                        self._disconnected,
                        use_services_cache=True,
                        ble_device_callback=lambda: self._ble_device,
                    )
            except BleakNotFoundError:
                _LOGGER.error(
                    "%s: device not found, not in range, or poor RSSI",
                    self.log_identity,
                )
                raise
            except BLEAK_EXCEPTIONS as ex:
                if "Bluetooth is already shutdown" in str(ex):
                    _LOGGER.debug(
                        "%s: Bluetooth is already shutdown, terminating connection attempt",
                        self.log_identity,
                    )
                    raise self._sanitized_transport_error(ex) from None
                raise self._sanitized_transport_error(ex) from None
            except Exception as ex:  # noqa: BLE001
                if "Bluetooth is already shutdown" in str(ex):
                    _LOGGER.debug(
                        "%s: Bluetooth is already shutdown, terminating connection attempt",
                        self.log_identity,
                    )
                    raise self._sanitized_transport_error(ex) from None
                raise self._sanitized_transport_error(ex) from None

            if not client or not client.is_connected:
                raise BleakNotFoundError()
            _LOGGER.debug("%s: Connected; RSSI: %s", self.log_identity, self.rssi)
            self._client = client
            self._physical_connection_active = True
            self._characteristic_notify = CHARACTERISTIC_NOTIFY
            self._characteristic_write = CHARACTERISTIC_WRITE
            for notify_uuid, write_uuid in SERVICE_CHARACTERISTICS.values():
                if client.services.get_characteristic(notify_uuid):
                    self._characteristic_notify = notify_uuid
                    self._characteristic_write = write_uuid
                    break
            try:
                notify_kwargs = (
                    {"bluez": {"use_start_notify": True}}
                    if self._requires_fd50_device_info_handshake()
                    else {}
                )
                await self._client.start_notify(
                    self._characteristic_notify,
                    self._notification_handler,
                    **notify_kwargs,
                )
                if not await self._send_packet_while_connected(
                    TuyaBLECode.FUN_SENDER_DEVICE_INFO,
                    (
                        b"\x00\xf3"
                        if self._requires_fd50_device_info_handshake()
                        else bytes(0)
                    ),
                    0,
                    True,
                ):
                    raise BleakError()
                if not await self._send_packet_while_connected(
                    TuyaBLECode.FUN_SENDER_PAIR,
                    self._build_pairing_request(),
                    0,
                    True,
                ):
                    raise BleakError()
            except Exception as ex:  # noqa: BLE001
                self._client = None
                self._mark_connection_lost()
                if "Bluetooth is already shutdown" in str(ex):
                    raise self._sanitized_transport_error(ex) from None
                raise self._sanitized_transport_error(ex) from None

        if self._client:
            if self._client.is_connected:
                if self._is_paired:
                    _LOGGER.debug("%s: Successfully connected", self.log_identity)
                    self._policy_state = (
                        ConnectionPolicyState.ALWAYS_CONNECTED_ACTIVE
                        if self._connection_mode is ConnectionMode.ALWAYS_CONNECTED
                        else ConnectionPolicyState.ON_DEMAND_ACTIVE
                    )
                    self._fire_connected_callbacks()
                    self._fire_connection_state_callbacks(True)
                else:
                    _LOGGER.error("%s: Connected but not paired", self.log_identity)
            else:
                _LOGGER.error("%s: Not connected", self.log_identity)
        else:
            _LOGGER.error("%s: No client device", self.log_identity)

    async def _reconnect(self) -> None:
        """Attempt a reconnect"""
        _LOGGER.debug("%s: Reconnect, ensuring connection", self.log_identity)
        async with self._seq_num_lock:
            self._current_seq_num = 1
        try:
            if self.effective_policy is not EffectiveConnectionPolicy.ALWAYS_CONNECTED:
                return
            async with self.connection_lease("policy reconnect", defer_connection=True):
                await self._ensure_connected()
            _LOGGER.debug("%s: Reconnect, connection ensured", self.log_identity)
        except BLEAK_EXCEPTIONS as ex:  # BleakNotFoundError:
            if "Bluetooth is already shutdown" in str(ex):
                _LOGGER.debug(
                    "%s: Reconnect failed because Bluetooth is already shutdown; not scheduling another reconnect",
                    self.log_identity,
                )
                return
            _LOGGER.debug(
                "%s: Reconnect, failed to ensure connection - backing off",
                self.log_identity,
            )
            async with self._policy_lock:
                if self._reconnect_task is asyncio.current_task():
                    self._reconnect_task = None
                if self.effective_policy is EffectiveConnectionPolicy.ALWAYS_CONNECTED:
                    self._schedule_reconnect_locked(BLEAK_BACKOFF_TIME)
        except (TuyaBLEControlSuspendedError, TuyaBLEConnectionUnavailableError):
            return
        except Exception:  # noqa: BLE001
            async with self._policy_lock:
                if self._reconnect_task is asyncio.current_task():
                    self._reconnect_task = None
                if self.effective_policy is EffectiveConnectionPolicy.ALWAYS_CONNECTED:
                    self._schedule_reconnect_locked(BLEAK_BACKOFF_TIME)

    def _schedule_reconnect(self, delay: float = 0) -> None:
        if self._terminal_stopped or self._suspension_requested:
            return
        if self._connection_mode is not ConnectionMode.ALWAYS_CONNECTED:
            return
        if self._reconnect_task is None:
            self._reconnect_task = self._create_policy_task(
                self._reconnect_after_delay(delay)
            )

    @staticmethod
    def _calc_crc16(data: bytes) -> int:
        crc = 0xFFFF
        for byte in data:
            crc ^= byte & 255
            for _ in range(8):
                tmp = crc & 1
                crc >>= 1
                if tmp != 0:
                    crc ^= 0xA001
        return crc

    @staticmethod
    def _pack_int(value: int) -> bytearray:
        curr_byte: int
        result = bytearray()
        while True:
            curr_byte = value & 0x7F
            value >>= 7
            if value != 0:
                curr_byte |= 0x80
            result += pack(">B", curr_byte)
            if value == 0:
                break
        return result

    @staticmethod
    def _unpack_int(data: bytes, start_pos: int) -> tuple(int, int):
        result: int = 0
        offset: int = 0
        while offset < 5:
            pos: int = start_pos + offset
            if pos >= len(data):
                raise TuyaBLEDataFormatError()
            curr_byte: int = data[pos]
            result |= (curr_byte & 0x7F) << (offset * 7)
            offset += 1
            if (curr_byte & 0x80) == 0:
                break
        if offset > 4:
            raise TuyaBLEDataFormatError()
        else:
            return (result, start_pos + offset)

    def _build_packets(
        self,
        seq_num: int,
        code: TuyaBLECode,
        data: bytes,
        response_to: int = 0,
    ) -> list[bytes]:
        key: bytes
        iv = secrets.token_bytes(16)
        security_flag: bytes
        fd50_device_info = (
            code == TuyaBLECode.FUN_SENDER_DEVICE_INFO
            and self._requires_fd50_device_info_handshake()
        )
        if code == TuyaBLECode.FUN_SENDER_DEVICE_INFO:
            key = self._login_key
            security_flag = pack(">B", self._security_material.login_flag)
        else:
            key = self._session_key
            security_flag = pack(">B", self._security_material.session_flag)

        raw = bytearray()
        raw += pack(">IIHH", seq_num, response_to, code.value, len(data))
        raw += data
        crc = self._calc_crc16(raw)
        raw += pack(">H", crc)
        while len(raw) % 16 != 0:
            raw += b"\x00"

        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = security_flag + iv + cipher.encrypt(raw)

        command = []
        packet_num = 0
        pos = 0
        length = len(encrypted)
        while pos < length:
            packet = bytearray()
            packet += self._pack_int(packet_num)

            if packet_num == 0:
                packet += self._pack_int(length)
                packet_protocol_version = (
                    2 if fd50_device_info else self._protocol_version
                )
                packet += pack(">B", packet_protocol_version << 4)

            data_part = encrypted[
                pos:pos + GATT_MTU - len(packet)  # fmt: skip
            ]
            packet += data_part
            command.append(packet)

            pos += len(data_part)
            packet_num += 1

        return command

    async def _get_seq_num(self) -> int:
        async with self._seq_num_lock:
            result = self._current_seq_num
            self._current_seq_num += 1
        return result

    async def _send_packet(
        self,
        code: TuyaBLECode,
        data: bytes,
        wait_for_response: bool = True,
        # retry: int | None = None,
    ) -> None:
        """Send packet to device and optional read response."""
        async with self.connection_lease("datapoint"):
            await self._send_packet_while_connected(code, data, 0, wait_for_response)

    async def _send_packet_once_confirmed(
        self,
        code: TuyaBLECode,
        data: bytes,
    ) -> None:
        """Send once without replay and require an explicit success response."""
        if (
            self._expected_disconnect and self._active_lease_count == 0
        ) or self._protocol_version != 3:
            raise TuyaBLECommandUnconfirmedError()
        async with self.connection_lease("confirmed datapoint"):
            if self._protocol_version != 3:
                raise TuyaBLECommandUnconfirmedError()
            confirmed = await self._send_packet_while_connected(
                code,
                data,
                0,
                True,
                resend_on_error=False,
                expected_response_code=code,
            )
            if not confirmed:
                raise TuyaBLECommandUnconfirmedError()

    async def _send_response(
        self,
        code: TuyaBLECode,
        data: bytes,
        response_to: int,
    ) -> None:
        """Send response to received packet."""
        if not self._client or not self._client.is_connected:
            return
        try:
            if _lease_context_depth(self) > 0:
                if self._client and self._client.is_connected:
                    await self._send_packet_while_connected(
                        code, data, response_to, False
                    )
            else:
                async with self.connection_lease(
                    "protocol response", defer_connection=True
                ):
                    if self._client and self._client.is_connected:
                        await self._send_packet_while_connected(
                            code, data, response_to, False
                        )
        except (TuyaBLEControlSuspendedError, TuyaBLEConnectionUnavailableError):
            return

    async def _send_packet_while_connected(
        self,
        code: TuyaBLECode,
        data: bytes,
        response_to: int,
        wait_for_response: bool,
        resend_on_error: bool = True,
        expected_response_code: TuyaBLECode | None = None,
        # retry: int | None = None
    ) -> bool:
        """Send packet to device and optional read response."""
        result = True
        future: asyncio.Future | None = None
        seq_num = await self._get_seq_num()
        if wait_for_response:
            future = asyncio.Future()
            self._input_expected_responses[seq_num] = future
            if expected_response_code is not None:
                self._input_expected_response_codes[seq_num] = expected_response_code

        if response_to > 0:
            _LOGGER.debug(
                "%s: Sending packet: #%s %s in response to #%s",
                self.log_identity,
                seq_num,
                code.name,
                response_to,
            )
        else:
            _LOGGER.debug(
                "%s: Sending packet: #%s %s",
                self.log_identity,
                seq_num,
                code.name,
            )
        try:
            packets: list[bytes] = self._build_packets(seq_num, code, data, response_to)
            await self._int_send_packet_while_connected(
                packets, resend_on_error=resend_on_error
            )
            if future:
                try:
                    await asyncio.wait_for(future, RESPONSE_WAIT_TIMEOUT)
                except asyncio.TimeoutError:
                    _LOGGER.error(
                        "%s: timeout receiving response, RSSI: %s",
                        self.log_identity,
                        self.rssi,
                    )
                    result = False
        finally:
            if future:
                self._input_expected_responses.pop(seq_num, None)
                self._input_expected_response_codes.pop(seq_num, None)

        return result

    async def _int_send_packet_while_connected(
        self,
        packets: list[bytes],
        resend_on_error: bool = True,
    ) -> None:
        if self._operation_lock.locked():
            _LOGGER.debug(
                "%s: Operation already in progress, "
                "waiting for it to complete; RSSI: %s",
                self.log_identity,
                self.rssi,
            )
        async with self._operation_lock:
            try:
                await self._send_packets_locked(
                    packets, resend_on_error=resend_on_error
                )
            except BleakNotFoundError:
                _LOGGER.error(
                    "%s: device not found, no longer in range, or poor RSSI: %s",
                    self.log_identity,
                    self.rssi,
                )
                raise
            except BLEAK_EXCEPTIONS:
                _LOGGER.error(
                    "%s: communication failed",
                    self.log_identity,
                )
                raise

    async def _resend_packets(self, packets: list[bytes]) -> None:
        if self._connection_mode is not ConnectionMode.ALWAYS_CONNECTED:
            return
        if self._expected_disconnect or self._suspension_requested:
            return
        try:
            async with self.connection_lease("transport resend", defer_connection=True):
                await self._ensure_connected()
                await self._int_send_packet_while_connected(packets)
        except (TuyaBLEControlSuspendedError, TuyaBLEConnectionUnavailableError):
            return
        except BLEAK_EXCEPTIONS:
            _LOGGER.debug(
                "%s: Transport resend failed",
                self.log_identity,
            )

    async def _send_packets_locked(
        self, packets: list[bytes], resend_on_error: bool = True
    ) -> None:
        """Send command to device and read response."""
        self.ensure_control_available()
        try:
            await self._int_send_packets_locked(packets)
        except BleakDBusError as ex:
            if "Bluetooth is already shutdown" in str(ex):
                _LOGGER.debug(
                    "%s: Bluetooth is already shutdown, not resending packets or reconnecting",
                    self.log_identity,
                )
                raise self._sanitized_transport_error(ex) from None
            # Disconnect so we can reset state and try again
            await asyncio.sleep(BLEAK_BACKOFF_TIME)
            _LOGGER.debug(
                "%s: RSSI: %s; Backing off %ss; Disconnecting after transport error",
                self.log_identity,
                self.rssi,
                BLEAK_BACKOFF_TIME,
            )
            if self._connection_mode is ConnectionMode.ALWAYS_CONNECTED:
                if self._is_paired and resend_on_error:
                    self._schedule_resend(packets)
                else:
                    self._schedule_reconnect()
            raise self._sanitized_transport_error(ex) from None
        except BleakError as ex:
            if "Bluetooth is already shutdown" in str(ex):
                _LOGGER.debug(
                    "%s: Bluetooth is already shutdown, not resending packets or reconnecting",
                    self.log_identity,
                )
                raise self._sanitized_transport_error(ex) from None
            # Disconnect so we can reset state and try again
            _LOGGER.debug(
                "%s: RSSI: %s; Disconnecting after transport error",
                self.log_identity,
                self.rssi,
            )
            if self._connection_mode is ConnectionMode.ALWAYS_CONNECTED:
                if self._is_paired and resend_on_error:
                    self._schedule_resend(packets)
                else:
                    self._schedule_reconnect()
            raise self._sanitized_transport_error(ex) from None

    async def _int_send_packets_locked(self, packets: list[bytes]) -> None:
        """Execute command and read response."""
        for packet in packets:
            if self._client:
                try:
                    await self._client.write_gatt_char(
                        self._characteristic_write,
                        packet,
                        False,
                    )
                except Exception as ex:  # noqa: BLE001
                    if "Bluetooth is already shutdown" in str(ex):
                        _LOGGER.debug(
                            "%s: Bluetooth is already shutdown during sending packet",
                            self.log_identity,
                        )
                        raise self._sanitized_transport_error(ex) from None
                    _LOGGER.error(
                        "%s: Error during sending packet",
                        self.log_identity,
                    )
                    if self._client and self._client.is_connected:
                        self._disconnected(self._client)
                    raise self._sanitized_transport_error(ex) from None
            else:
                _LOGGER.error(
                    "%s: Client disconnected during sending packet",
                    self.log_identity,
                )
                raise BleakError()

    def _get_key(self, security_flag: int) -> bytes:
        if security_flag == 1:
            return self._auth_key
        if security_flag == 4:
            return self._login_key
        if security_flag == 5:
            return self._session_key
        if security_flag == 14:
            return self._login_key
        if security_flag == 15:
            return self._session_key

    def _parse_timestamp(self, data: bytes, start_pos: int) -> tuple(float, int):
        timestamp: float
        pos = start_pos
        if pos >= len(data):
            raise TuyaBLEDataLengthError()
        time_type = data[pos]
        pos += 1
        end_pos = pos
        match time_type:
            case 0:
                end_pos += 13
                if end_pos > len(data):
                    raise TuyaBLEDataLengthError()
                timestamp = int(data[pos:end_pos].decode()) / 1000
                pass
            case 1:
                end_pos += 4
                if end_pos > len(data):
                    raise TuyaBLEDataLengthError()
                timestamp = int.from_bytes(data[pos:end_pos], "big") * 1.0
                pass
            case _:
                raise TuyaBLEDataFormatError()

        _LOGGER.debug(
            "%s: Received timestamp: %s",
            self.log_identity,
            time.ctime(timestamp),
        )
        return (timestamp, end_pos)

    def _parse_datapoints(
        self,
        timestamp: float,
        flags: int,
        data: bytes,
        start_pos: int,
        length_size: int,
    ) -> int:
        """Parse Tuya KLV datapoints with the requested value-length width."""
        if length_size not in (1, 2):
            raise ValueError("Tuya KLV length width must be one or two bytes")

        datapoints: list[TuyaBLEDataPoint] = []

        pos = start_pos
        header_size = 2 + length_size
        while len(data) - pos >= header_size:
            id: int = data[pos]
            pos += 1
            _type: int = data[pos]
            if _type > TuyaBLEDataPointType.DT_BITMAP.value:
                raise TuyaBLEDataFormatError()
            type: TuyaBLEDataPointType = TuyaBLEDataPointType(_type)
            pos += 1
            data_len = int.from_bytes(data[pos : pos + length_size], "big")
            pos += length_size
            next_pos = pos + data_len
            if next_pos > len(data):
                raise TuyaBLEDataLengthError()
            raw_value = data[pos:next_pos]
            match type:
                case TuyaBLEDataPointType.DT_RAW | TuyaBLEDataPointType.DT_BITMAP:
                    value = raw_value
                case TuyaBLEDataPointType.DT_BOOL:
                    value = int.from_bytes(raw_value, "big") != 0
                case TuyaBLEDataPointType.DT_VALUE | TuyaBLEDataPointType.DT_ENUM:
                    value = int.from_bytes(raw_value, "big", signed=True)
                case TuyaBLEDataPointType.DT_STRING:
                    value = raw_value.decode()

            _LOGGER.debug(
                "%s: Received datapoint update, id: %s, type: %s, length: %s",
                self.log_identity,
                id,
                type.name,
                data_len,
            )
            self._datapoints._update_from_device(id, timestamp, flags, type, value)
            datapoints.append(self._datapoints[id])
            pos = next_pos

        self._fire_callbacks(datapoints)
        return pos

    def _parse_datapoints_v3(
        self, timestamp: float, flags: int, data: bytes, start_pos: int
    ) -> int:
        """Parse Tuya BLE protocol-v3 datapoints."""
        return self._parse_datapoints(timestamp, flags, data, start_pos, 1)

    def _parse_datapoints_v4(
        self, timestamp: float, flags: int, data: bytes, start_pos: int
    ) -> int:
        """Parse Tuya BLE protocol-v4 datapoints."""
        return self._parse_datapoints(timestamp, flags, data, start_pos, 2)

    def _handle_command_or_response(
        self, seq_num: int, response_to: int, code: TuyaBLECode, data: bytes
    ) -> None:
        result: int = 0

        match code:
            case TuyaBLECode.FUN_SENDER_DEVICE_INFO:
                if len(data) < 46:
                    raise TuyaBLEDataLengthError()

                self._device_version = ("%s.%s") % (data[0], data[1])
                self._protocol_version_str = ("%s.%s") % (data[2], data[3])
                self._hardware_version = ("%s.%s") % (data[12], data[13])

                self._protocol_version = data[2]
                self._flags = data[4]
                self._is_bound = data[5] != 0

                srand = data[6:12]
                self._session_key = self._security_material.session_key(srand)
                self._auth_key = data[14:46]

            case TuyaBLECode.FUN_SENDER_PAIR:
                if len(data) != 1:
                    raise TuyaBLEDataLengthError()
                result = data[0]
                if result == 2:
                    _LOGGER.debug(
                        "%s: Device is already paired",
                        self.log_identity,
                    )
                    result = 0
                self._is_paired = result == 0

            case TuyaBLECode.FUN_SENDER_DEVICE_STATUS:
                if len(data) != 1:
                    raise TuyaBLEDataLengthError()
                result = data[0]

            case TuyaBLECode.FUN_SENDER_DPS:
                if len(data) != 1:
                    raise TuyaBLEDataLengthError()
                result = data[0]

            case TuyaBLECode.FUN_SENDER_DPS_V4:
                if len(data) != 6:
                    raise TuyaBLEDataLengthError()
                result = data[5]

            case TuyaBLECode.FUN_RECEIVE_TIME1_REQ:
                if len(data) != 0:
                    raise TuyaBLEDataLengthError()

                timestamp = int(time.time_ns() / 1000000)
                timezone = -int(time.timezone / 36)
                data = str(timestamp).encode() + pack(">h", timezone)
                self._schedule_response(code, data, seq_num)

            case TuyaBLECode.FUN_RECEIVE_TIME2_REQ:
                if len(data) != 0:
                    raise TuyaBLEDataLengthError()

                time_str: time.struct_time = time.localtime()
                timezone = -int(time.timezone / 36)
                data = pack(
                    ">BBBBBBBh",
                    time_str.tm_year % 100,
                    time_str.tm_mon,
                    time_str.tm_mday,
                    time_str.tm_hour,
                    time_str.tm_min,
                    time_str.tm_sec,
                    time_str.tm_wday,
                    timezone,
                )
                self._schedule_response(code, data, seq_num)

            case TuyaBLECode.FUN_RECEIVE_DP:
                self._parse_datapoints_v3(time.time(), 0, data, 0)
                self._schedule_response(code, bytes(0), seq_num)

            case TuyaBLECode.FUN_RECEIVE_SIGN_DP:
                dp_seq_num = int.from_bytes(data[:2], "big")
                flags = data[2]
                self._parse_datapoints_v3(time.time(), flags, data, 2)
                data = pack(">HBB", dp_seq_num, flags, 0)
                self._schedule_response(code, data, seq_num)

            case TuyaBLECode.FUN_RECEIVE_TIME_DP:
                timestamp: float
                pos: int
                timestamp, pos = self._parse_timestamp(data, 0)
                self._parse_datapoints_v3(timestamp, 0, data, pos)
                self._schedule_response(code, bytes(0), seq_num)

            case TuyaBLECode.FUN_RECEIVE_SIGN_TIME_DP:
                timestamp: float
                pos: int
                dp_seq_num = int.from_bytes(data[:2], "big")
                flags = data[2]
                timestamp, pos = self._parse_timestamp(data, 3)
                self._parse_datapoints_v3(time.time(), flags, data, pos)
                data = pack(">HBB", dp_seq_num, flags, 0)
                self._schedule_response(code, data, seq_num)

            case TuyaBLECode.FUN_RECEIVE_DP_V4:
                if len(data) < 7:
                    raise TuyaBLEDataLengthError()
                if data[0] != 0:
                    raise TuyaBLEDataFormatError()
                send_flags = data[5]
                mode = data[6]
                self._parse_datapoints_v4(time.time(), mode, data, 7)
                if (send_flags & 0x80) == 0:
                    self._schedule_response(code, data[:7] + b"\x00", seq_num)

            case TuyaBLECode.FUN_RECEIVE_TIME_DP_V4:
                if len(data) < 8:
                    raise TuyaBLEDataLengthError()
                if data[0] != 0:
                    raise TuyaBLEDataFormatError()
                send_flags = data[5]
                mode = data[6]
                timestamp, pos = self._parse_timestamp(data, 7)
                self._parse_datapoints_v4(timestamp, mode, data, pos)
                if (send_flags & 0x80) == 0:
                    self._schedule_response(code, data[:7] + b"\x00", seq_num)

        if response_to != 0:
            expected_code = self._input_expected_response_codes.get(response_to)
            if expected_code is not None and code is not expected_code:
                _LOGGER.debug(
                    "%s: Ignoring unexpected %s response to #%s",
                    self.log_identity,
                    code.name,
                    response_to,
                )
            else:
                future = self._input_expected_responses.pop(response_to, None)
                self._input_expected_response_codes.pop(response_to, None)
                if future:
                    _LOGGER.debug(
                        "%s: Received expected response to #%s, result: %s",
                        self.log_identity,
                        response_to,
                        result,
                    )
                    if result == 0:
                        future.set_result(result)
                    else:
                        future.set_exception(TuyaBLEDeviceError(result))

    def _clean_input(self) -> None:
        self._input_buffer = None
        self._input_expected_packet_num = 0
        self._input_expected_length = 0

    def _parse_input(self) -> None:
        security_flag = self._input_buffer[0]
        key = self._get_key(security_flag)
        iv = self._input_buffer[1:17]
        encrypted = self._input_buffer[17:]

        self._clean_input()

        cipher = AES.new(key, AES.MODE_CBC, iv)
        raw = cipher.decrypt(encrypted)

        seq_num: int
        response_to: int
        _code: int
        length: int
        seq_num, response_to, _code, length = unpack(">IIHH", raw[:12])

        data_end_pos = length + 12
        raw_length = len(raw)
        if raw_length < data_end_pos:
            raise TuyaBLEDataLengthError()
        if raw_length > data_end_pos:
            calc_crc = self._calc_crc16(raw[:data_end_pos])
            (data_crc,) = unpack(
                ">H",
                raw[data_end_pos:data_end_pos + 2]  # fmt: skip
            )
            if calc_crc != data_crc:
                raise TuyaBLEDataCRCError()
        data = raw[12:data_end_pos]

        code: TuyaBLECode
        try:
            code = TuyaBLECode(_code)
        except ValueError:
            _LOGGER.debug(
                "%s: Received unknown message: #%s %x, response to #%s, length: %s",
                self.log_identity,
                seq_num,
                _code,
                response_to,
                len(data),
            )
            return

        if response_to != 0:
            _LOGGER.debug(
                "%s: Received: #%s %s, response to #%s",
                self.log_identity,
                seq_num,
                code.name,
                response_to,
            )
        else:
            _LOGGER.debug(
                "%s: Received: #%s %s",
                self.log_identity,
                seq_num,
                code.name,
            )

        self._handle_command_or_response(seq_num, response_to, code, data)

    def _notification_handler(self, _sender: int, data: bytearray) -> None:
        """Handle notification responses."""
        pos: int = 0
        packet_num: int

        packet_num, pos = self._unpack_int(data, pos)
        _LOGGER.debug(
            "%s: Packet received, number: %s, length: %s",
            self.log_identity,
            packet_num,
            len(data),
        )

        if packet_num < self._input_expected_packet_num:
            if packet_num != 0:
                _LOGGER.warning(
                    "%s: Unexpected packet (number %s) in notifications, expected %s. Ignoring.",
                    self.log_identity,
                    packet_num,
                    self._input_expected_packet_num,
                )
                return
            _LOGGER.error(
                "%s: Unexpected packet (number %s) in notifications, " "expected %s",
                self.log_identity,
                packet_num,
                self._input_expected_packet_num,
            )
            self._clean_input()

        if packet_num == self._input_expected_packet_num:
            if packet_num == 0:
                self._input_buffer = bytearray()
                self._input_expected_length, pos = self._unpack_int(data, pos)
                pos += 1
            self._input_buffer += data[pos:]
            self._input_expected_packet_num += 1
        else:
            _LOGGER.error(
                "%s: Missing packet (number %s) in notifications, received %s",
                self.log_identity,
                self._input_expected_packet_num,
                packet_num,
            )
            self._clean_input()
            return

        if len(self._input_buffer) > self._input_expected_length:
            _LOGGER.error(
                "%s: Unexpected length of data in notifications, "
                "received %s expected %s",
                self.log_identity,
                len(self._input_buffer),
                self._input_expected_length,
            )
            self._clean_input()
            return

        if len(self._input_buffer) == self._input_expected_length:
            try:
                self._parse_input()
            except TuyaBLEError:
                _LOGGER.error(
                    "%s: Error parsing input",
                    self.log_identity,
                )
                self._clean_input()
                return

    def _encode_datapoints(self, datapoint_ids: list[int], length_size: int) -> bytes:
        """Encode datapoints with the requested Tuya KLV value-length width."""
        if length_size not in (1, 2):
            raise ValueError("Tuya KLV length width must be one or two bytes")

        data = bytearray()
        for dp_id in datapoint_ids:
            dp = self._datapoints[dp_id]
            value = dp._get_value()
            _LOGGER.debug(
                "%s: Sending datapoint update, id: %s, type: %s, length: %s",
                self.log_identity,
                dp.id,
                dp.type.name,
                len(value),
            )
            if length_size == 1:
                data += pack(">BBB", dp.id, int(dp.type.value), len(value))
            else:
                data += pack(">BBH", dp.id, int(dp.type.value), len(value))
            data += value

        return bytes(data)

    async def _send_datapoints_v3(self, datapoint_ids: list[int]) -> None:
        """Send new values using the protocol-v3 DP command."""
        data = self._encode_datapoints(datapoint_ids, 1)
        await self._send_packet(TuyaBLECode.FUN_SENDER_DPS, data)

    async def _send_datapoints_once(self, datapoint_ids: list[int]) -> None:
        """Send one protocol-v3 DP command without replay and require success."""
        if self._protocol_version != 3:
            raise TuyaBLECommandUnconfirmedError()
        data = self._encode_datapoints(datapoint_ids, 1)
        await self._send_packet_once_confirmed(TuyaBLECode.FUN_SENDER_DPS, data)

    async def _send_datapoints_v4(self, datapoint_ids: list[int]) -> None:
        """Send new values using the protocol-v4 DP command."""
        dp_seq_num = await self._get_seq_num()
        data = pack(">BI", 0, dp_seq_num)
        data += self._encode_datapoints(datapoint_ids, 2)
        await self._send_packet(TuyaBLECode.FUN_SENDER_DPS_V4, data)

    async def _send_datapoints(self, datapoint_ids: list[int]) -> None:
        """Send new values of datapoints to the device."""
        if self._protocol_version == 3:
            await self._send_datapoints_v3(datapoint_ids)
        elif self._protocol_version >= 4:
            await self._send_datapoints_v4(datapoint_ids)
        else:
            raise TuyaBLEDeviceError(0)

    async def set_multiple_values(self, dp_updates: dict[int, Any]) -> None:
        """Set multiple datapoint values in a single atomic BLE payload."""
        self.ensure_control_available()
        updated_dps = []
        for dp_id, value in dp_updates.items():
            dp = self._datapoints[dp_id]
            if not dp:
                continue

            # Update the internal state safely
            if dp.type in [TuyaBLEDataPointType.DT_RAW, TuyaBLEDataPointType.DT_BITMAP]:
                dp._value = bytes(value)
            elif dp.type == TuyaBLEDataPointType.DT_BOOL:
                dp._value = bool(value)
            elif dp.type == TuyaBLEDataPointType.DT_VALUE:
                dp._value = int(value)
            elif dp.type == TuyaBLEDataPointType.DT_ENUM:
                dp._value = int(value)
            elif dp.type == TuyaBLEDataPointType.DT_STRING:
                dp._value = str(value)
            dp._changed_by_device = False
            dp._received_from_device = False
            updated_dps.append(dp)

        if not updated_dps:
            return
        await self._send_datapoints([dp.id for dp in updated_dps])
        self._fire_callbacks(updated_dps)
