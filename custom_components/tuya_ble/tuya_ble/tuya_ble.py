from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import logging
import re
import secrets
import time
from collections.abc import Awaitable, Callable, Hashable
from contextlib import AbstractAsyncContextManager
from contextvars import ContextVar, Token, copy_context
from dataclasses import dataclass, field
from datetime import datetime, timezone
from struct import pack, unpack
from typing import Any, Self

from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData
from bleak.exc import BleakDBusError
from bleak_retry_connector import (
    BLEAK_BACKOFF_TIME,
    BLEAK_RETRY_EXCEPTIONS,
    BleakClientWithServiceCache,
    BleakError,
    BleakNotFoundError,
    establish_connection,
)
from Crypto.Cipher import AES

from ..const import (
    BLE_TARGET_WAIT_TIMEOUT_SECONDS,
    CONF_BLE_CONTROL_ENABLED,
    CONF_CONNECTION_MODE,
    CONF_ON_DEMAND_CONNECTION_HOLD_TIME,
    CONNECTION_POLICY_TRANSITION_TIMEOUT_SECONDS,
    DEFAULT_BLE_CONTROL_ENABLED,
    DEFAULT_CONNECTION_MODE,
    DEFAULT_ON_DEMAND_CONNECTION_HOLD_TIME,
    DEFAULT_ON_DEMAND_IDLE_DISCONNECT_SECONDS,
    RECONNECT_STABLE_RESET_SECONDS,
    S1_RECONNECT_COOLDOWN_SECONDS,
    S1_RECONNECT_FAILURES_BEFORE_COOLDOWN,
    S1_RECONNECT_STABLE_RESET_SECONDS,
    UNEXPECTED_RECONNECT_MAX_SECONDS,
    UNEXPECTED_RECONNECT_MIN_SECONDS,
    ConnectionMode,
    ConnectionPolicyState,
    DPType,
    EffectiveConnectionPolicy,
    PendingRelease,
    PendingReleaseReason,
    normalize_on_demand_connection_hold_time,
    validate_on_demand_connection_hold_time,
)
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
from .exceptions import (
    TuyaBLECommandUnconfirmedError,
    TuyaBLEConnectionUnavailableError,
    TuyaBLEControlSuspendedError,
    TuyaBLEDataCRCError,
    TuyaBLEDataFormatError,
    TuyaBLEDataLengthError,
    TuyaBLEDeviceError,
    TuyaBLEEnumValueError,
    TuyaBLEError,
    TuyaBLEPolicyTransitionError,
)
from .manager import AbstaractTuyaBLEDeviceManager, TuyaBLEDeviceCredentials
from .security import TuyaBLESecurityMaterial

_LOGGER = logging.getLogger(__name__)


_LOG_IDENTITY_ALPHABET = "ghjkmnpqrstuvwxyz"
_LOG_IDENTITY_LENGTH = 16
_TRANSPORT_ERROR_FALLBACK = "Tuya BLE transport error"
_HOLD_TIME_UNSET = object()
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
DEVICE_INFO_HANDSHAKE_MAJOR_THREE_PRODUCTS = frozenset({("jtmspro", "xqeob8h6")})
RECONNECT_STATUS_SYNC_PRODUCTS = frozenset(
    {
        ("jtmspro", "xqeob8h6"),
        ("ms", "7a4xvbtt"),
    }
)


# @dataclass
class TuyaBLEEntityDescription:
    # Added to info that we get from the cloud
    function: list[dict[str, dict]] | None = None
    status_range: list[dict[str, dict]] | None = None

    # Replace the values that we got from the cloud
    values_overrides: dict[str, dict] | None = None

    # Values if nothing was set from the cloud
    values_defaults: dict[str, dict] | None = None


@dataclass(frozen=True, eq=False, slots=True)
class ConnectionSessionToken:
    """Exact ownership token for one integration-managed BLE client."""

    client: BleakClientWithServiceCache
    epoch: int
    operation_lock: asyncio.Lock = field(
        default_factory=asyncio.Lock,
        repr=False,
    )


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
        received_session_epoch: int | None = None,
    ) -> None:
        self._owner = owner
        self._id = id
        self._timestamp = timestamp
        self._flags = flags
        self._type = type
        self._value = value
        self._changed_by_device = False
        self._received_session_epoch = received_session_epoch
        self._value_revision = 0

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
        session_epoch: int,
    ) -> None:
        self._timestamp = timestamp
        self._flags = flags
        self._type = type
        self._changed_by_device = self._value != value
        self._value = value
        self._received_session_epoch = session_epoch
        self._value_revision += 1

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
        """Return whether this value was received in the active exact session."""
        return self.received_in_current_session

    @property
    def received_session_epoch(self) -> int | None:
        """Return the exact session epoch that supplied the current value."""
        return self._received_session_epoch

    @property
    def received_in_current_session(self) -> bool:
        """Return whether this datapoint belongs to the active exact session."""
        epoch = self._received_session_epoch
        return epoch is not None and epoch == self._owner._owner.current_session_epoch

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
        self._received_session_epoch = None
        self._value_revision += 1

    def _restore_local_value_if_uncontested(
        self,
        local_revision: int,
        value: bytes | bool | int | str,
        changed_by_device: bool,
        received_session_epoch: int | None,
    ) -> None:
        """Roll back only if no newer local or inbound update won ownership."""
        if self._value_revision != local_revision:
            return
        self._value = value
        self._changed_by_device = changed_by_device
        self._received_session_epoch = received_session_epoch
        self._value_revision += 1

    async def set_value(self, value: bytes | bool | int | str) -> None:
        self._owner._owner.ensure_control_available()
        self._set_local_value(value)
        await self._owner._update_from_user(self._id)

    async def set_value_once(self, value: bytes | bool | int | str) -> None:
        """Send one confirmed command without automatic packet replay."""
        self._owner._owner.ensure_control_available()
        previous_value = self._value
        previous_changed_by_device = self._changed_by_device
        previous_received_session_epoch = self._received_session_epoch
        self._set_local_value(value)
        local_revision = self._value_revision
        try:
            await self._owner._update_from_user_once(self._id)
        except (Exception, asyncio.CancelledError):
            self._restore_local_value_if_uncontested(
                local_revision,
                previous_value,
                previous_changed_by_device,
                previous_received_session_epoch,
            )
            raise

    async def set_value_no_replay(self, value: bytes | bool | int | str) -> None:
        """Send one datapoint update without retaining it for a later replay."""
        self._owner._owner.ensure_control_available()
        previous_value = self._value
        previous_changed_by_device = self._changed_by_device
        previous_received_session_epoch = self._received_session_epoch
        self._set_local_value(value)
        local_revision = self._value_revision
        try:
            await self._owner._update_from_user_no_replay(self._id)
        except (Exception, asyncio.CancelledError):
            self._restore_local_value_if_uncontested(
                local_revision,
                previous_value,
                previous_changed_by_device,
                previous_received_session_epoch,
            )
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

    def _invalidate_session_receipt_provenance(self) -> None:
        """Invalidate aggregate receipt time without rewriting cached values."""
        self._last_data_received = None

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
        session_token: ConnectionSessionToken,
    ) -> None:
        if not self._owner._owns_connection_session(session_token):
            return
        self._last_data_received = datetime.now(timezone.utc)
        self._owner._mark_state_data_fresh(session_token)
        dp = self._datapoints.get(dp_id)
        if dp:
            dp._update_from_device(
                timestamp,
                flags,
                type,
                value,
                session_token.epoch,
            )
        else:
            self._datapoints[dp_id] = TuyaBLEDataPoint(
                self,
                dp_id,
                timestamp,
                flags,
                type,
                value,
                received_session_epoch=session_token.epoch,
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

    async def _update_from_user_no_replay(self, dp_id: int) -> None:
        """Send one datapoint without creating replayable transport state."""
        await self._owner._send_datapoints_no_replay([dp_id])


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
                if await self._device._finish_connection_lease_release():
                    raise asyncio.CancelledError()
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
        on_demand_connection_hold_time: object = _HOLD_TIME_UNSET,
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
        self._pending_release: PendingRelease | None = None
        self._policy_revision = 0
        self._disconnect_in_progress = False
        self._disconnect_idle_event = asyncio.Event()
        self._disconnect_idle_event.set()
        self._unload_quiescing = False
        self._idle_disconnect_task: asyncio.Task | None = None
        self._idle_disconnect_in_progress = False
        self._disconnect_retry_task: asyncio.Task | None = None
        self._reconnect_task: asyncio.Task | None = None
        self._scheduled_reconnect_delay: float | None = None
        self._pending_reconnect_delay: float | None = None
        self._active_reconnect_task: asyncio.Task | None = None
        self._reconnect_attempt_active = False
        self._response_tasks: set[asyncio.Task] = set()
        self._response_task_tokens: dict[asyncio.Task, ConnectionSessionToken] = {}
        self._session_setup_task_tokens: dict[asyncio.Task, ConnectionSessionToken] = {}
        self._status_task_tokens: dict[asyncio.Task, ConnectionSessionToken] = {}
        self._response_drain_tasks: set[asyncio.Task] = set()
        self._response_cleanup_tasks: set[asyncio.Task] = set()
        self._startup_task: asyncio.Task | None = None
        self._connection_epoch = 0
        self._connection_token: ConnectionSessionToken | None = None
        self._status_attempted_token: ConnectionSessionToken | None = None
        self._connected_notified_token: ConnectionSessionToken | None = None
        self._data_invalidated_token: ConnectionSessionToken | None = None
        self._session_active_since: float | None = None
        self._last_confirmed_activity_monotonic: float | None = None
        self._confirmed_activity_session: ConnectionSessionToken | None = None
        self._unexpected_reconnect_delay = UNEXPECTED_RECONNECT_MIN_SECONDS
        self._unexpected_reconnect_failures = 0
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
        self._on_demand_connection_hold_time = (
            None
            if on_demand_connection_hold_time is _HOLD_TIME_UNSET
            else normalize_on_demand_connection_hold_time(
                on_demand_connection_hold_time
            )
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
        self._notifications_active = False
        self._connection_state_callbacks: list[Callable[[bool], None]] = []
        self._session_invalidated_callbacks: list[Callable[[], None]] = []
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
        self._input_expected_responses: dict[
            tuple[ConnectionSessionToken, int], asyncio.Future[int] | None
        ] = {}
        self._input_expected_response_codes: dict[
            tuple[ConnectionSessionToken, int], TuyaBLECode
        ] = {}
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
    def supports_on_demand_connection_hold_time(self) -> bool:
        """Return whether this is the exact reviewed S1 product."""
        return (self.category, self.product_id) == ("jtmspro", "xqeob8h6")

    @property
    def on_demand_connection_hold_time(self) -> float:
        """Return the effective local S1 hold time in seconds."""
        if not self.supports_on_demand_connection_hold_time:
            return DEFAULT_ON_DEMAND_CONNECTION_HOLD_TIME
        if self._on_demand_connection_hold_time is None:
            # Preserve the established injectable delay for synthetic policy
            # tests while the production default remains exactly 15 seconds.
            return DEFAULT_ON_DEMAND_IDLE_DISCONNECT_SECONDS
        return self._on_demand_connection_hold_time

    @property
    def last_confirmed_activity_monotonic(self) -> float | None:
        """Return the current exact session's last confirmed activity time."""
        return self._last_confirmed_activity_monotonic

    @property
    def confirmed_activity_session(self) -> ConnectionSessionToken | None:
        """Return the exact session owning the confirmed activity deadline."""
        return self._confirmed_activity_session

    @property
    def effective_policy(self) -> EffectiveConnectionPolicy:
        """Return the effective policy after applying suspension and stop."""
        if self._terminal_stopped:
            return EffectiveConnectionPolicy.STOPPED
        if self._unload_quiescing:
            return EffectiveConnectionPolicy.SUSPENDED
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
        """Return whether the current GATT session is usable for traffic."""
        return self.is_gatt_connected and self._is_paired and self._notifications_active

    @property
    def active_lease_count(self) -> int:
        """Return the number of active connection leases."""
        return self._active_lease_count

    @property
    def state_data_fresh(self) -> bool:
        """Return whether current-session device data has been received."""
        return self._state_data_fresh

    @property
    def current_session_epoch(self) -> int | None:
        """Return the exact epoch only while its session is command-ready."""
        token = self._connection_token
        if token is None or not self._owns_connection_session(token):
            return None
        if not self.is_connection_active:
            return None
        return token.epoch

    def _claim_connection_session(
        self, client: BleakClientWithServiceCache
    ) -> ConnectionSessionToken:
        """Claim a newly established exact client with a never-reused epoch."""
        previous_token = self._connection_token
        if previous_token is not None:
            if previous_token.client.is_connected:
                raise TuyaBLEConnectionUnavailableError()
            self._mark_connection_lost(
                previous_token,
                unexpected=not self._expected_disconnect and self._is_paired,
            )
        self._connection_epoch += 1
        token = ConnectionSessionToken(client, self._connection_epoch)
        self._client = client
        self._connection_token = token
        self._operation_lock = token.operation_lock
        self._physical_connection_active = True
        self._notifications_active = False
        self._is_paired = False
        self._state_data_fresh = False
        self._data_invalidated_token = None
        self._session_active_since = None
        self._last_confirmed_activity_monotonic = None
        self._confirmed_activity_session = None
        self._current_seq_num = 1
        self._clean_input()
        return token

    def _owns_connection_session(
        self,
        token: ConnectionSessionToken,
        *,
        require_notifications: bool = False,
        require_ready: bool = False,
    ) -> bool:
        """Return whether one exact token still owns the integration client."""
        if (
            self._connection_token is not token
            or self._client is not token.client
            or self._connection_epoch != token.epoch
        ):
            return False
        if require_notifications and not self._notifications_active:
            return False
        return not require_ready or self.is_connection_active

    def _notification_callback_for_session(
        self, token: ConnectionSessionToken
    ) -> Callable[[int, bytearray], None]:
        """Return a notification callback permanently bound to one session."""

        def notification_callback(sender: int, data: bytearray) -> None:
            self._notification_handler(token, sender, data)

        return notification_callback

    def _owns_transport_work(
        self,
        token: ConnectionSessionToken,
        *,
        require_always_connected: bool = False,
    ) -> bool:
        """Return whether exact transport work still owns its policy boundary."""
        if not self._owns_connection_session(token, require_notifications=True):
            return False
        return not require_always_connected or (
            self.effective_policy is EffectiveConnectionPolicy.ALWAYS_CONNECTED
        )

    def connection_lease(
        self, reason: str, *, defer_connection: bool = False
    ) -> TuyaBLEConnectionLease:
        """Return a lease protecting a complete BLE operation."""
        return TuyaBLEConnectionLease(self, reason, defer_connection)

    def ensure_control_available(self) -> None:
        """Reject work that cannot safely use the current policy."""
        lease_active = _lease_context_depth(self) > 0
        if (
            self._pending_release is not None
            and self._pending_release.reason
            in {
                PendingReleaseReason.SETUP_FAILURE,
                PendingReleaseReason.SESSION_FAILURE,
            }
            and not lease_active
        ):
            raise TuyaBLEConnectionUnavailableError()
        if self._unload_quiescing and not lease_active:
            raise TuyaBLEConnectionUnavailableError()
        if self._terminal_stopped and not lease_active:
            raise TuyaBLEConnectionUnavailableError()
        if (
            self.is_gatt_connected
            and not self.is_connection_active
            and not lease_active
        ):
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

    def register_session_invalidated_callback(
        self, callback: Callable[[], None]
    ) -> Callable[[], None]:
        """Register an immediate exact-session provenance-loss callback."""
        self._session_invalidated_callbacks.append(callback)

        def unregister_callback() -> None:
            if callback in self._session_invalidated_callbacks:
                self._session_invalidated_callbacks.remove(callback)

        return unregister_callback

    def _fire_connection_state_callbacks(self, connected: bool) -> None:
        for callback in tuple(self._connection_state_callbacks):
            callback(connected)

    def _fire_session_invalidated_callbacks(self) -> None:
        for callback in tuple(self._session_invalidated_callbacks):
            callback()

    def _mark_state_data_fresh(self, token: ConnectionSessionToken) -> None:
        if self._owns_connection_session(token, require_notifications=True):
            self._state_data_fresh = True

    def _record_confirmed_activity(self, token: ConnectionSessionToken) -> None:
        """Move the S1 hold deadline for accepted current-session activity."""
        if not self.supports_on_demand_connection_hold_time or not (
            self._owns_connection_session(token, require_notifications=True)
        ):
            return
        self._last_confirmed_activity_monotonic = time.monotonic()
        self._confirmed_activity_session = token
        if (
            self._connection_mode is ConnectionMode.ON_DEMAND
            and self._ble_control_enabled
            and not self._suspension_requested
            and not self._terminal_stopped
            and not self._unload_quiescing
            and self.is_connection_active
            and self._active_lease_count == 0
        ):
            self._cancel_idle_disconnect_locked()
            self._schedule_idle_disconnect_locked()

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

    def _advance_policy_revision_locked(self) -> None:
        """Advance desired policy and supersede only reversible release work."""
        self._policy_revision += 1
        pending = self._pending_release
        if (
            pending is None
            or pending.reason
            not in {
                PendingReleaseReason.SUSPEND,
                PendingReleaseReason.ON_DEMAND_IDLE,
            }
            or self._disconnect_in_progress
        ):
            return
        self._pending_release = None
        self._cancel_disconnect_retry_locked()

    async def async_update_connection_policy(
        self,
        *,
        connection_mode: str | None = None,
        ble_control_enabled: bool | None = None,
        on_demand_connection_hold_time: object | None = None,
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

            if on_demand_connection_hold_time is None:
                new_hold_time = self._on_demand_connection_hold_time
            else:
                if not self.supports_on_demand_connection_hold_time:
                    raise TuyaBLEPolicyTransitionError()
                try:
                    new_hold_time = validate_on_demand_connection_hold_time(
                        on_demand_connection_hold_time
                    )
                except (OverflowError, ValueError):
                    raise TuyaBLEPolicyTransitionError() from None

            updates: dict[str, Any] = {}
            if new_mode is not self._connection_mode:
                updates[CONF_CONNECTION_MODE] = new_mode.value
            if new_enabled != self._ble_control_enabled:
                updates[CONF_BLE_CONTROL_ENABLED] = new_enabled
            if new_hold_time != self._on_demand_connection_hold_time:
                updates[CONF_ON_DEMAND_CONNECTION_HOLD_TIME] = new_hold_time
            if updates:
                await self._persist_policy_options(updates)

            policy_changed = (
                new_mode is not self._connection_mode
                or new_enabled != self._ble_control_enabled
                or new_hold_time != self._on_demand_connection_hold_time
            )
            self._connection_mode = new_mode
            self._ble_control_enabled = new_enabled
            self._on_demand_connection_hold_time = new_hold_time
            if policy_changed:
                async with self._policy_lock:
                    self._cancel_idle_disconnect_locked()
                    self._advance_policy_revision_locked()
            self._suspension_requested = not new_enabled
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
            new_hold_time = (
                normalize_on_demand_connection_hold_time(
                    options.get(
                        CONF_ON_DEMAND_CONNECTION_HOLD_TIME,
                        DEFAULT_ON_DEMAND_CONNECTION_HOLD_TIME,
                    )
                )
                if self.supports_on_demand_connection_hold_time
                else self._on_demand_connection_hold_time
            )
            policy_changed = (
                new_mode is not self._connection_mode
                or new_enabled != self._ble_control_enabled
                or new_hold_time != self._on_demand_connection_hold_time
            )
            self._connection_mode = new_mode
            self._ble_control_enabled = new_enabled
            self._on_demand_connection_hold_time = new_hold_time
            if policy_changed:
                async with self._policy_lock:
                    self._cancel_idle_disconnect_locked()
                    self._advance_policy_revision_locked()
            self._suspension_requested = not new_enabled
            await self._apply_connection_policy()

    async def _apply_connection_policy(self) -> None:
        if self._terminal_stopped:
            return
        async with self._policy_lock:
            if self._pending_release is not None and (
                self._pending_release.reason
                in {
                    PendingReleaseReason.SETUP_FAILURE,
                    PendingReleaseReason.SESSION_FAILURE,
                }
                or self._disconnect_in_progress
            ):
                self._cancel_reconnect_locked()
                self._cancel_idle_disconnect_locked()
                self._policy_state = (
                    ConnectionPolicyState.DISCONNECT_FAILED
                    if self._pending_release.reason
                    in {
                        PendingReleaseReason.SETUP_FAILURE,
                        PendingReleaseReason.SESSION_FAILURE,
                    }
                    else ConnectionPolicyState.DISCONNECTING
                )
                return
            if self._unload_quiescing:
                self._cancel_reconnect_locked()
                self._cancel_idle_disconnect_locked()
                self._policy_state = ConnectionPolicyState.DISCONNECTING
                return
        if not self._ble_control_enabled:
            await self._suspend_runtime()
            return

        self._suspension_requested = False
        if self._connection_mode is ConnectionMode.ON_DEMAND:
            async with self._policy_lock:
                self._cancel_startup_task_locked()
                self._cancel_reconnect_locked()
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
            self._pending_release = PendingRelease(
                PendingReleaseReason.SUSPEND,
                self._policy_revision,
            )
            self._cancel_startup_task_locked()
            self._cancel_reconnect_locked()
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
        await self._complete_pending_release(raise_on_error=True)

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
        context_token = _enter_lease_context(self)
        try:
            try:
                await self._ensure_connected()
            finally:
                try:
                    _CONNECTION_LEASE_CONTEXT.reset(context_token)
                except ValueError:
                    pass
            async with self._policy_lock:
                if self._connection_mode is ConnectionMode.ALWAYS_CONNECTED:
                    self._policy_state = ConnectionPolicyState.ALWAYS_CONNECTED_ACTIVE
                else:
                    self._policy_state = ConnectionPolicyState.ON_DEMAND_ACTIVE
        except asyncio.CancelledError:
            await self._finish_connection_lease_release()
            raise
        except (TuyaBLEControlSuspendedError, TuyaBLEConnectionUnavailableError):
            if await self._finish_connection_lease_release():
                raise asyncio.CancelledError() from None
            raise
        except Exception:
            if await self._finish_connection_lease_release():
                raise asyncio.CancelledError() from None
            raise TuyaBLEConnectionUnavailableError() from None

    async def _finish_connection_lease_release(self) -> bool:
        """Finish counted-lease release before propagating cancellation."""
        cleanup_task = self._create_policy_task(self._release_connection_lease())
        cancelled_during_cleanup = False
        while not cleanup_task.done():
            try:
                await asyncio.shield(cleanup_task)
            except asyncio.CancelledError:
                cancelled_during_cleanup = True
        await cleanup_task
        return cancelled_during_cleanup

    async def _release_connection_lease(self) -> None:
        async with self._policy_lock:
            if self._active_lease_count == 0:
                return
            self._active_lease_count -= 1
            if self._active_lease_count != 0:
                return
            self._lease_zero_event.set()
            pending_disconnect = self._pending_release is not None
            if (
                not pending_disconnect
                and self._connection_mode is ConnectionMode.ON_DEMAND
                and self._ble_control_enabled
                and not self._suspension_requested
                and not self._terminal_stopped
            ):
                if self.is_connection_active:
                    self._policy_state = ConnectionPolicyState.ON_DEMAND_ACTIVE
                    self._schedule_idle_disconnect_locked()
                else:
                    self._policy_state = ConnectionPolicyState.ON_DEMAND_IDLE
                    self._cancel_idle_disconnect_locked()
        if pending_disconnect:
            await self._complete_pending_release()

    async def _complete_pending_release(self, *, raise_on_error: bool = False) -> None:
        """Complete one owned physical release after protected work drains."""
        async with self._policy_lock:
            pending = self._pending_release
            if (
                pending is None
                or self._active_lease_count
                or self._active_response_drain_count
                or self._disconnect_in_progress
            ):
                return
            self._disconnect_in_progress = True
            self._disconnect_idle_event.clear()
            self._policy_state = ConnectionPolicyState.DISCONNECTING

        disconnect_failed = False
        reconcile_policy = False
        failure_reconnect_delay: float | None = None
        complete_newer_release = False
        try:
            await self._execute_disconnect(terminal=pending.terminal)
        except asyncio.CancelledError:
            disconnect_failed = True
            raise
        except Exception:
            disconnect_failed = True
            _LOGGER.error("%s: Deferred BLE disconnect failed", self.log_identity)
        finally:
            async with self._policy_lock:
                self._disconnect_in_progress = False
                self._disconnect_idle_event.set()
                request_current = self._pending_release is pending
                if disconnect_failed and request_current:
                    if pending.reason is PendingReleaseReason.STOP:
                        self._policy_state = ConnectionPolicyState.STOPPED
                    elif self.is_gatt_connected and not self.is_connection_active:
                        self._pending_release = PendingRelease(
                            (
                                PendingReleaseReason.SESSION_FAILURE
                                if pending.reason
                                is PendingReleaseReason.SESSION_FAILURE
                                else PendingReleaseReason.SETUP_FAILURE
                            ),
                            self._policy_revision,
                            reconnect_delay=pending.reconnect_delay,
                        )
                        self._policy_state = ConnectionPolicyState.DISCONNECT_FAILED
                    self._schedule_disconnect_retry_locked()
                elif request_current:
                    self._pending_release = None
                    if (
                        self._disconnect_retry_task is not None
                        and self._disconnect_retry_task is not asyncio.current_task()
                    ):
                        self._cancel_disconnect_retry_locked()
                    if pending.reason in {
                        PendingReleaseReason.SETUP_FAILURE,
                        PendingReleaseReason.SESSION_FAILURE,
                    }:
                        if pending.reason is PendingReleaseReason.SESSION_FAILURE:
                            failure_reconnect_delay = (
                                pending.reconnect_delay
                                or UNEXPECTED_RECONNECT_MIN_SECONDS
                            )
                        elif pending.reconnect_delay is not None:
                            failure_reconnect_delay = pending.reconnect_delay
                        else:
                            reconcile_policy = True
                    elif pending.reason is PendingReleaseReason.ON_DEMAND_IDLE:
                        if (
                            pending.revision != self._policy_revision
                            or not self._ble_control_enabled
                            or self._connection_mode is not ConnectionMode.ON_DEMAND
                        ):
                            reconcile_policy = True
                        else:
                            self._suspension_requested = False
                            self._policy_state = ConnectionPolicyState.ON_DEMAND_IDLE
                    elif pending.reason is PendingReleaseReason.SUSPEND:
                        if (
                            pending.revision != self._policy_revision
                            or self._ble_control_enabled
                        ):
                            reconcile_policy = True
                        else:
                            self._suspension_requested = True
                            self._policy_state = ConnectionPolicyState.SUSPENDED
                    elif pending.reason is PendingReleaseReason.STOP:
                        self._suspension_requested = True
                        self._policy_state = ConnectionPolicyState.STOPPED
                    elif pending.reason is PendingReleaseReason.UNLOAD:
                        self._policy_state = ConnectionPolicyState.DISCONNECTING
                else:
                    complete_newer_release = self._pending_release is not None

        if complete_newer_release:
            await self._complete_pending_release()

        if failure_reconnect_delay is not None:
            self._reconcile_after_verified_transport_loss(failure_reconnect_delay)
        elif reconcile_policy:
            await self._apply_connection_policy()

        if disconnect_failed and raise_on_error:
            raise TuyaBLEPolicyTransitionError() from None

    async def async_prepare_unload(self) -> bool:
        """Quiesce and release GATT without making the runtime terminal."""
        async with self._policy_transition_lock:
            async with self._policy_lock:
                if self._terminal_stopped:
                    return not self.is_gatt_connected
                if (
                    self._pending_release is not None
                    and self._pending_release.reason
                    in {
                        PendingReleaseReason.SETUP_FAILURE,
                        PendingReleaseReason.SESSION_FAILURE,
                        PendingReleaseReason.STOP,
                    }
                ):
                    return False
                self._unload_quiescing = True
                self._pending_release = PendingRelease(
                    PendingReleaseReason.UNLOAD,
                    self._policy_revision,
                )
                self._cancel_startup_task_locked()
                self._cancel_reconnect_locked()
                self._cancel_idle_disconnect_locked()
                self._policy_state = ConnectionPolicyState.DISCONNECTING
            try:
                await asyncio.wait_for(
                    asyncio.gather(
                        self._lease_zero_event.wait(),
                        self._response_drain_zero_event.wait(),
                        self._disconnect_idle_event.wait(),
                    ),
                    CONNECTION_POLICY_TRANSITION_TIMEOUT_SECONDS,
                )
            except asyncio.TimeoutError:
                await self._cancel_unload_locked_transition()
                return False
            await self._complete_pending_release()
            await self._disconnect_idle_event.wait()
            if self.is_gatt_connected or self._active_lease_count:
                await self._cancel_unload_locked_transition()
                return False
            return True

    async def _cancel_unload_locked_transition(self) -> None:
        """Restore the latest desired policy while transition ownership is held."""
        async with self._policy_lock:
            if (
                self._pending_release is not None
                and self._pending_release.reason is PendingReleaseReason.UNLOAD
            ):
                self._pending_release = None
                self._cancel_disconnect_retry_locked()
            self._expected_disconnect = False
        notifications_restored = (
            await self._restore_notifications_after_unload_failure()
        )
        async with self._policy_lock:
            self._unload_quiescing = False
            if self._terminal_stopped:
                self._policy_state = ConnectionPolicyState.STOPPED
                if self.is_gatt_connected:
                    if (
                        self._pending_release is None
                        or self._pending_release.reason is not PendingReleaseReason.STOP
                    ):
                        self._pending_release = PendingRelease(
                            PendingReleaseReason.STOP,
                            self._policy_revision,
                            terminal=True,
                        )
                    self._schedule_disconnect_retry_locked()
                return
            if (
                notifications_restored
                and self.is_connection_active
                and self._pending_release is not None
                and self._pending_release.reason is PendingReleaseReason.SETUP_FAILURE
            ):
                self._pending_release = None
                self._cancel_disconnect_retry_locked()
            if not notifications_restored and self.is_gatt_connected:
                self._pending_release = PendingRelease(
                    PendingReleaseReason.SETUP_FAILURE,
                    self._policy_revision,
                )
                self._cancel_reconnect_locked()
                self._cancel_idle_disconnect_locked()
                self._policy_state = ConnectionPolicyState.DISCONNECT_FAILED
                self._schedule_disconnect_retry_locked()
                return
            if (
                self._ble_control_enabled
                and self._connection_mode is ConnectionMode.ON_DEMAND
                and self.is_connection_active
                and not self._active_lease_count
            ):
                self._pending_release = PendingRelease(
                    PendingReleaseReason.ON_DEMAND_IDLE,
                    self._policy_revision,
                )
                self._policy_state = ConnectionPolicyState.ON_DEMAND_ACTIVE
                self._schedule_disconnect_retry_locked()
                return
        try:
            await self._apply_connection_policy()
        except TuyaBLEPolicyTransitionError:
            _LOGGER.error(
                "%s: Latest BLE policy still requires physical release after "
                "unload rollback",
                self.log_identity,
            )

    async def async_cancel_unload(self) -> None:
        """Rollback a prepared unload after platform teardown fails."""
        async with self._policy_transition_lock:
            await self._cancel_unload_locked_transition()

    def abort_unload_transaction(self) -> None:
        """Leave a timed-out unload fail-closed without awaiting more I/O."""
        self._unload_quiescing = False
        self._expected_disconnect = False
        self._cancel_reconnect_locked()
        self._cancel_idle_disconnect_locked()

        if self._terminal_stopped:
            self._policy_state = ConnectionPolicyState.STOPPED
            if self.is_gatt_connected:
                self._notifications_active = False
                self._pending_release = PendingRelease(
                    PendingReleaseReason.STOP,
                    self._policy_revision,
                    terminal=True,
                )
                self._schedule_disconnect_retry_locked()
            return

        if self.is_gatt_connected:
            self._notifications_active = False
            self._pending_release = PendingRelease(
                (
                    PendingReleaseReason.SESSION_FAILURE
                    if self._pending_release is not None
                    and self._pending_release.reason
                    is PendingReleaseReason.SESSION_FAILURE
                    else PendingReleaseReason.SETUP_FAILURE
                ),
                self._policy_revision,
            )
            self._policy_state = ConnectionPolicyState.DISCONNECT_FAILED
            self._schedule_disconnect_retry_locked()
            return

        if self._pending_release is not None and (
            self._pending_release.reason is PendingReleaseReason.UNLOAD
        ):
            self._pending_release = None
        self._cancel_disconnect_retry_locked()
        if not self._ble_control_enabled:
            self._policy_state = ConnectionPolicyState.SUSPENDED
        elif self._connection_mode is ConnectionMode.ON_DEMAND:
            self._policy_state = ConnectionPolicyState.ON_DEMAND_IDLE
        else:
            self._policy_state = ConnectionPolicyState.ALWAYS_CONNECTED_CONNECTING
            self._schedule_reconnect_locked(0)

    async def _restore_notifications_after_unload_failure(self) -> bool:
        """Restore notifications or report that the live session needs repair."""
        client = self._client
        token = self._connection_token
        if client is None or not client.is_connected:
            return True
        if token is None or token.client is not client:
            return False
        if not self._ble_control_enabled:
            return False
        if not self._is_paired:
            return False
        self._notifications_active = False
        try:
            notify_kwargs = (
                {"bluez": {"use_start_notify": True}}
                if self._requires_fd50_device_info_handshake()
                else {}
            )
            await client.start_notify(
                self._characteristic_notify,
                self._notification_callback_for_session(token),
                **notify_kwargs,
            )
            if (
                not self._owns_connection_session(token)
                or not self._is_paired
                or not self._ble_control_enabled
            ):
                return False
            self._notifications_active = True
            return True
        except Exception:  # noqa: BLE001
            _LOGGER.error(
                "%s: BLE notification restoration failed during unload rollback",
                self.log_identity,
            )
            return False

    def _cancel_idle_disconnect_locked(self) -> None:
        if (
            self._idle_disconnect_task is not None
            and not self._idle_disconnect_in_progress
        ):
            self._idle_disconnect_task.cancel()
            self._idle_disconnect_task = None

    def _cancel_reconnect_locked(self) -> None:
        self._scheduled_reconnect_delay = None
        self._pending_reconnect_delay = None
        if self._reconnect_task is not None:
            if self._active_reconnect_task is self._reconnect_task:
                self._active_reconnect_task = None
                self._reconnect_attempt_active = False
            self._reconnect_task.cancel()
            self._reconnect_task = None

    def _cancel_startup_task_locked(self) -> None:
        """Cancel tracked setup status work without self-cancellation."""
        task = self._startup_task
        if task is None or task is asyncio.current_task():
            return
        task.cancel()
        self._startup_task = None

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
        retry_failures = 0
        try:
            while self._pending_release is not None:
                retry_failures += 1
                await asyncio.sleep(self._disconnect_retry_delay(retry_failures))
                await self._complete_pending_release()
        except asyncio.CancelledError:
            return
        finally:
            async with self._policy_lock:
                if self._disconnect_retry_task is current_task:
                    self._disconnect_retry_task = None

    def _disconnect_retry_delay(self, retry_failures: int) -> float:
        """Return physical-release retry pacing without advancing reconnect state."""
        if not self._uses_s1_reconnect_protection:
            return BLEAK_BACKOFF_TIME
        if retry_failures > S1_RECONNECT_FAILURES_BEFORE_COOLDOWN:
            return S1_RECONNECT_COOLDOWN_SECONDS
        return min(
            UNEXPECTED_RECONNECT_MAX_SECONDS,
            UNEXPECTED_RECONNECT_MIN_SECONDS * (2 ** (retry_failures - 1)),
        )

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
        if self.supports_on_demand_connection_hold_time:
            token = self._connection_token
            if (
                token is None
                or self._confirmed_activity_session is not token
                or self._last_confirmed_activity_monotonic is None
                or not self._owns_connection_session(token, require_ready=True)
            ):
                return
            coroutine = self._idle_disconnect_after_deadline(token)
        else:
            coroutine = self._idle_disconnect_after_delay()
        self._idle_disconnect_task = self._create_policy_task(coroutine)

    async def _idle_disconnect_after_deadline(
        self, token: ConnectionSessionToken
    ) -> None:
        """Release one exact idle S1 session after confirmed activity expires."""
        current_task = asyncio.current_task()
        try:
            while True:
                async with self._policy_lock:
                    if (
                        not self._owns_connection_session(token, require_ready=True)
                        or self._confirmed_activity_session is not token
                        or self._last_confirmed_activity_monotonic is None
                        or self._connection_mode is not ConnectionMode.ON_DEMAND
                        or not self._ble_control_enabled
                        or self._suspension_requested
                        or self._terminal_stopped
                        or self._unload_quiescing
                    ):
                        return
                    observed_activity = self._last_confirmed_activity_monotonic
                    deadline = observed_activity + self.on_demand_connection_hold_time
                    lease_active = self._active_lease_count > 0
                    response_active = self._active_response_drain_count > 0

                if lease_active or response_active:
                    await asyncio.gather(
                        self._lease_zero_event.wait(),
                        self._response_drain_zero_event.wait(),
                    )
                    continue

                await asyncio.sleep(max(0.0, deadline - time.monotonic()))

                async with self._policy_lock:
                    if (
                        not self._owns_connection_session(token, require_ready=True)
                        or self._confirmed_activity_session is not token
                        or self._last_confirmed_activity_monotonic is None
                        or self._connection_mode is not ConnectionMode.ON_DEMAND
                        or not self._ble_control_enabled
                        or self._suspension_requested
                        or self._terminal_stopped
                        or self._unload_quiescing
                    ):
                        return
                    if self._last_confirmed_activity_monotonic != observed_activity:
                        continue
                    if self._active_lease_count or self._active_response_drain_count:
                        continue
                    self._pending_release = PendingRelease(
                        PendingReleaseReason.ON_DEMAND_IDLE,
                        self._policy_revision,
                    )
                    self._idle_disconnect_in_progress = True
                await self._complete_pending_release()
                return
        except asyncio.CancelledError:
            return
        except Exception:
            _LOGGER.error(
                "%s: On-demand hold release failed",
                self.log_identity,
            )
            async with self._policy_lock:
                if (
                    self._owns_connection_session(token)
                    and self._connection_mode is ConnectionMode.ON_DEMAND
                    and self._ble_control_enabled
                    and not self._terminal_stopped
                    and self.is_gatt_connected
                ):
                    self._pending_release = PendingRelease(
                        PendingReleaseReason.ON_DEMAND_IDLE,
                        self._policy_revision,
                    )
                    self._schedule_disconnect_retry_locked()
        finally:
            self._idle_disconnect_in_progress = False
            if self._idle_disconnect_task is current_task:
                self._idle_disconnect_task = None

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
                self._pending_release = PendingRelease(
                    PendingReleaseReason.ON_DEMAND_IDLE,
                    self._policy_revision,
                )
                self._idle_disconnect_in_progress = True
            await self._complete_pending_release()
        except asyncio.CancelledError:
            return
        except Exception:
            _LOGGER.error(
                "%s: On-demand idle disconnect failed",
                self.log_identity,
            )
            async with self._policy_lock:
                if (
                    self._connection_mode is ConnectionMode.ON_DEMAND
                    and self._ble_control_enabled
                    and not self._terminal_stopped
                    and self.is_gatt_connected
                ):
                    self._pending_release = PendingRelease(
                        PendingReleaseReason.ON_DEMAND_IDLE,
                        self._policy_revision,
                    )
                    self._schedule_disconnect_retry_locked()
        finally:
            self._idle_disconnect_in_progress = False
            if self._idle_disconnect_task is current_task:
                self._idle_disconnect_task = None

    def _schedule_reconnect_locked(self, delay: float) -> None:
        if (
            self._terminal_stopped
            or self._unload_quiescing
            or self._suspension_requested
            or not self._ble_control_enabled
            or self._connection_mode is not ConnectionMode.ALWAYS_CONNECTED
        ):
            return
        if self._reconnect_task is not None:
            if self._reconnect_attempt_active:
                self._pending_reconnect_delay = max(
                    delay,
                    self._pending_reconnect_delay or 0,
                )
            elif delay > (self._scheduled_reconnect_delay or 0):
                self._reconnect_task.cancel()
                self._reconnect_task = None
                self._scheduled_reconnect_delay = delay
                self._reconnect_task = self._create_policy_task(
                    self._reconnect_after_delay(delay)
                )
            return
        if (
            self._pending_release is not None
            or self._disconnect_in_progress
            or (self.is_gatt_connected and not self.is_connection_active)
        ):
            return
        self._scheduled_reconnect_delay = delay
        self._reconnect_task = self._create_policy_task(
            self._reconnect_after_delay(delay)
        )

    async def _reconnect_after_delay(self, delay: float) -> None:
        current_task = asyncio.current_task()
        try:
            if delay:
                await asyncio.sleep(delay)
            self._scheduled_reconnect_delay = None
            self._active_reconnect_task = current_task
            self._reconnect_attempt_active = True
            await self._reconnect()
        except asyncio.CancelledError:
            return
        finally:
            if self._active_reconnect_task is current_task:
                self._active_reconnect_task = None
                self._reconnect_attempt_active = False
            if self._reconnect_task is current_task:
                self._reconnect_task = None
                self._scheduled_reconnect_delay = None
                followup_delay = self._pending_reconnect_delay
                self._pending_reconnect_delay = None
                if followup_delay is not None:
                    self._schedule_reconnect_locked(followup_delay)

    def _schedule_response(
        self,
        token: ConnectionSessionToken,
        code: TuyaBLECode,
        data: bytes,
        response_to: int,
    ) -> None:
        if not self._owns_connection_session(token, require_notifications=True):
            return
        self._active_response_drain_count += 1
        self._response_drain_zero_event.clear()
        task = self._create_policy_task(
            self._response_task_runner(token, code, data, response_to)
        )
        self._response_tasks.add(task)
        self._response_task_tokens[task] = token
        self._response_drain_tasks.add(task)
        task.add_done_callback(self._response_task_done)

    def _response_task_done(self, task: asyncio.Task) -> None:
        """Release drain ownership when cancellation prevents task startup."""
        self._response_tasks.discard(task)
        self._response_task_tokens.pop(task, None)
        self._release_response_drain(task)

    def _release_response_drain(self, task: asyncio.Task | None) -> None:
        """Release exactly one response drain and resume pending policy work."""
        if task is None or task not in self._response_drain_tasks:
            return
        self._response_drain_tasks.remove(task)
        self._active_response_drain_count -= 1
        if self._active_response_drain_count == 0:
            self._response_drain_zero_event.set()
            cleanup_task = self._create_policy_task(self._complete_pending_release())
            self._response_cleanup_tasks.add(cleanup_task)
            cleanup_task.add_done_callback(self._response_cleanup_tasks.discard)

    async def _response_task_runner(
        self,
        token: ConnectionSessionToken,
        code: TuyaBLECode,
        data: bytes,
        response_to: int,
    ) -> None:
        try:
            if self._owns_connection_session(token, require_notifications=True):
                await self._send_response(token, code, data, response_to)
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

    def _device_info_handshake_protocol_major(self) -> int:
        """Return product-scoped wire metadata for the Device Info request."""
        if self._requires_fd50_device_info_handshake():
            return 2
        if (
            self.category,
            self.product_id,
        ) in DEVICE_INFO_HANDSHAKE_MAJOR_THREE_PRODUCTS:
            return 3
        return self._protocol_version

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
        await self._send_packet(TuyaBLECode.FUN_SENDER_DEVICE_STATUS, b"")

    async def startup_update(self) -> None:
        """Run the initial status path without failing config-entry setup."""
        try:
            if (self.category, self.product_id) in RECONNECT_STATUS_SYNC_PRODUCTS:
                async with self.connection_lease(
                    "startup status", defer_connection=True
                ):
                    await self._ensure_connected(request_status=True)
            else:
                await self.update()
        except Exception:
            if self.effective_policy is EffectiveConnectionPolicy.ALWAYS_CONNECTED:
                async with self._policy_lock:
                    if self._uses_s1_reconnect_protection:
                        self._retain_or_schedule_reconnect_locked(
                            self._next_unexpected_reconnect_delay()
                        )
                    else:
                        self._schedule_reconnect_locked(0)
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
        for callback in tuple(self._connected_callbacks):
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
        for callback in tuple(self._callbacks):
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
        for callback in tuple(self._disconnected_callbacks):
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
            self._pending_release = PendingRelease(
                PendingReleaseReason.STOP,
                self._policy_revision,
                terminal=True,
            )
            self._cancel_reconnect_locked()
            self._cancel_idle_disconnect_locked()
            for task in tuple(self._response_tasks):
                task.cancel()
                self._release_response_drain(task)
            self._response_tasks.clear()
            if self._startup_task is not None:
                self._startup_task.cancel()
                self._startup_task = None
        try:
            await asyncio.wait_for(
                asyncio.gather(
                    self._lease_zero_event.wait(),
                    self._disconnect_idle_event.wait(),
                ),
                CONNECTION_POLICY_TRANSITION_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            _LOGGER.error(
                "%s: Stop deferred while a BLE operation remained active",
                self.log_identity,
            )
            return
        await self._complete_pending_release()

    def _fail_session_response_futures(self, token: ConnectionSessionToken) -> None:
        """Fail response waiters owned by one retired exact session."""
        for key, future in tuple(self._input_expected_responses.items()):
            if key[0] is not token:
                continue
            self._input_expected_responses.pop(key, None)
            self._input_expected_response_codes.pop(key, None)
            if future is not None and not future.done():
                future.set_exception(TuyaBLEConnectionUnavailableError())

    def _cancel_session_response_tasks(self, token: ConnectionSessionToken) -> None:
        """Cancel protocol responses owned by one retired exact session."""
        try:
            current_task = asyncio.current_task()
        except RuntimeError:
            current_task = None
        for task, task_token in tuple(self._response_task_tokens.items()):
            if task_token is token and task is not current_task:
                task.cancel()

    def _cancel_session_transport_tasks(self, token: ConnectionSessionToken) -> None:
        """Cancel setup and status owners bound to one retired session."""
        try:
            current_task = asyncio.current_task()
        except RuntimeError:
            current_task = None
        tasks = {
            task
            for task, task_token in (
                *self._session_setup_task_tokens.items(),
                *self._status_task_tokens.items(),
            )
            if task_token is token and task is not current_task
        }
        for task in tasks:
            task.cancel()

    def _invalidate_session_data(self, token: ConnectionSessionToken | None) -> None:
        """Publish loss of exact-session datapoint validity once."""
        self._notifications_active = False
        self._state_data_fresh = False
        if token is not None and self._confirmed_activity_session is token:
            self._last_confirmed_activity_monotonic = None
            self._confirmed_activity_session = None
            self._cancel_idle_disconnect_locked()
        self._datapoints._invalidate_session_receipt_provenance()
        if token is not None:
            self._fail_session_response_futures(token)
            self._cancel_session_response_tasks(token)
            self._cancel_session_transport_tasks(token)
        if token is not None and self._data_invalidated_token is token:
            return
        self._data_invalidated_token = token
        self._fire_session_invalidated_callbacks()

    def _next_unexpected_reconnect_delay(self) -> float:
        """Return and advance bounded backoff for a short-lived session."""
        stable_reset_seconds = (
            S1_RECONNECT_STABLE_RESET_SECONDS
            if self._uses_s1_reconnect_protection
            else RECONNECT_STABLE_RESET_SECONDS
        )
        if (
            self._session_active_since is not None
            and time.monotonic() - self._session_active_since >= stable_reset_seconds
        ):
            self._unexpected_reconnect_delay = UNEXPECTED_RECONNECT_MIN_SECONDS
            self._unexpected_reconnect_failures = 0
            self._session_active_since = None
        self._unexpected_reconnect_failures += 1
        if (
            self._uses_s1_reconnect_protection
            and self._unexpected_reconnect_failures
            > S1_RECONNECT_FAILURES_BEFORE_COOLDOWN
        ):
            if (
                self._unexpected_reconnect_failures
                == S1_RECONNECT_FAILURES_BEFORE_COOLDOWN + 1
            ):
                _LOGGER.warning(
                    "%s: S1 reconnect cooldown active after repeated session failures",
                    self.log_identity,
                )
            self._unexpected_reconnect_delay = S1_RECONNECT_COOLDOWN_SECONDS
            return S1_RECONNECT_COOLDOWN_SECONDS
        delay = min(
            UNEXPECTED_RECONNECT_MAX_SECONDS,
            max(UNEXPECTED_RECONNECT_MIN_SECONDS, self._unexpected_reconnect_delay),
        )
        self._unexpected_reconnect_delay = min(
            UNEXPECTED_RECONNECT_MAX_SECONDS,
            delay * 2,
        )
        return delay

    @property
    def _uses_s1_reconnect_protection(self) -> bool:
        return (self.category, self.product_id) == ("jtmspro", "xqeob8h6")

    def _retain_or_schedule_reconnect_locked(self, delay: float) -> None:
        pending = self._pending_release
        if pending is not None and pending.reason in {
            PendingReleaseReason.SETUP_FAILURE,
            PendingReleaseReason.SESSION_FAILURE,
        }:
            self._pending_release = PendingRelease(
                pending.reason,
                pending.revision,
                terminal=pending.terminal,
                reconnect_delay=max(delay, pending.reconnect_delay or 0),
            )
            return
        self._schedule_reconnect_locked(delay)

    def _mark_connection_lost(
        self,
        token: ConnectionSessionToken | None = None,
        *,
        unexpected: bool = False,
    ) -> float | None:
        if token is not None and (
            self._connection_token is not token or self._client is not token.client
        ):
            return None
        if token is None:
            token = self._connection_token
        reconnect_delay = (
            self._next_unexpected_reconnect_delay() if unexpected else None
        )
        was_connected = self._physical_connection_active or self._is_paired
        self._physical_connection_active = False
        self._is_paired = False
        self._notifications_active = False
        self._connection_token = None
        self._last_confirmed_activity_monotonic = None
        self._confirmed_activity_session = None
        self._cancel_idle_disconnect_locked()
        if token is None or self._client is token.client:
            self._client = None
        self._invalidate_session_data(token)
        self._session_active_since = None
        self._session_key = None
        self._auth_key = None
        if was_connected:
            self._has_disconnected = True
        self._clean_input()
        if was_connected:
            self._fire_disconnected_callbacks()
            self._fire_connection_state_callbacks(False)
        return reconnect_delay

    def _reconcile_after_verified_transport_loss(self, reconnect_delay: float) -> None:
        """Restore only the policy-owned future session after a physical loss."""
        pending = self._pending_release
        if (
            pending is not None
            and pending.reason is PendingReleaseReason.SESSION_FAILURE
            and not self._disconnect_in_progress
        ):
            self._pending_release = None
            self._cancel_disconnect_retry_locked()

        if self._terminal_stopped:
            self._cancel_reconnect_locked()
            self._cancel_idle_disconnect_locked()
            self._policy_state = ConnectionPolicyState.STOPPED
            return
        if self._unload_quiescing:
            self._cancel_reconnect_locked()
            self._cancel_idle_disconnect_locked()
            self._policy_state = ConnectionPolicyState.DISCONNECTING
            return
        if not self._ble_control_enabled or self._suspension_requested:
            self._suspension_requested = True
            self._cancel_reconnect_locked()
            self._cancel_idle_disconnect_locked()
            self._policy_state = ConnectionPolicyState.SUSPENDED
            return
        if self._connection_mode is ConnectionMode.ON_DEMAND:
            self._cancel_reconnect_locked()
            self._cancel_idle_disconnect_locked()
            self._policy_state = ConnectionPolicyState.ON_DEMAND_IDLE
            return

        self._cancel_idle_disconnect_locked()
        self._policy_state = ConnectionPolicyState.ALWAYS_CONNECTED_CONNECTING
        self._schedule_reconnect_locked(reconnect_delay)

    def _disconnected(
        self,
        client: BleakClientWithServiceCache,
        token: ConnectionSessionToken,
    ) -> None:
        """Disconnected callback."""
        if (
            self._connection_token is not token
            or client is not self._client
            or token.client is not client
        ):
            _LOGGER.debug(
                "%s: Ignoring stale disconnected client callback", self.log_identity
            )
            return
        expected_disconnect = self._expected_disconnect
        pending = self._pending_release
        recorded_failure_delay = (
            pending.reconnect_delay or UNEXPECTED_RECONNECT_MIN_SECONDS
            if pending is not None
            and pending.reason is PendingReleaseReason.SESSION_FAILURE
            else None
        )
        reconnect_delay = self._mark_connection_lost(
            token,
            unexpected=not expected_disconnect and recorded_failure_delay is None,
        )
        if expected_disconnect:
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
        _LOGGER.debug(
            "%s: Scheduling reconnect; RSSI: %s",
            self.log_identity,
            self.rssi,
        )
        self._reconcile_after_verified_transport_loss(
            recorded_failure_delay
            or reconnect_delay
            or UNEXPECTED_RECONNECT_MIN_SECONDS
        )

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
            token = self._connection_token
            self._expected_disconnect = True
            if terminal:
                self._terminal_stopped = True
            stop_notify_error: BleakError | None = None
            disconnect_error: BleakError | None = None
            if client and client.is_connected:
                self._notifications_active = False
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
            if token is not None and self._connection_token is token:
                self._mark_connection_lost(token)
            elif token is None and self._client is client:
                self._mark_connection_lost()
        if stop_notify_error is not None:
            _LOGGER.warning("%s: BLE notification cleanup failed", self.log_identity)
        if disconnect_error is not None:
            _LOGGER.warning(
                "%s: BLE disconnect reported an error after release", self.log_identity
            )

    async def _cleanup_new_client(
        self,
        client: BleakClientWithServiceCache,
        token: ConnectionSessionToken,
        *,
        terminal: bool,
    ) -> None:
        """Retain a newly connected client until physical release is verified."""
        if not self._owns_connection_session(token):
            return
        self._notifications_active = False
        self._expected_disconnect = True
        try:
            await client.stop_notify(self._characteristic_notify)
        except Exception:  # noqa: BLE001
            pass
        try:
            await client.disconnect()
        except Exception:  # noqa: BLE001
            pass

        if not client.is_connected:
            self._mark_connection_lost(token)
            return

        async with self._policy_lock:
            self._pending_release = PendingRelease(
                (
                    PendingReleaseReason.STOP
                    if terminal
                    else PendingReleaseReason.SETUP_FAILURE
                ),
                self._policy_revision,
                terminal=terminal,
            )
            self._policy_state = ConnectionPolicyState.DISCONNECT_FAILED
            self._schedule_disconnect_retry_locked()

    async def _cleanup_cancelled_new_client(
        self,
        client: BleakClientWithServiceCache,
        token: ConnectionSessionToken,
    ) -> None:
        """Finish claimed-session cleanup before propagating cancellation."""
        cleanup_task = self._create_policy_task(
            self._cleanup_new_client(
                client,
                token,
                terminal=self._terminal_stopped,
            )
        )
        while not cleanup_task.done():
            try:
                await asyncio.shield(cleanup_task)
            except asyncio.CancelledError:
                continue
        await cleanup_task

    def _publish_connected_session(self, token: ConnectionSessionToken) -> None:
        """Publish one successfully finalized exact session once."""
        if (
            not self._owns_connection_session(token, require_ready=True)
            or self._terminal_stopped
            or self._unload_quiescing
            or self._suspension_requested
            or not self._ble_control_enabled
            or self._connected_notified_token is token
        ):
            return
        self._connected_notified_token = token
        self._session_active_since = time.monotonic()
        self._fire_connected_callbacks()
        self._fire_connection_state_callbacks(True)

    async def _ensure_connected(self, *, request_status: bool = False) -> None:
        """Ensure connection to device is established."""
        global global_connect_lock
        token: ConnectionSessionToken | None = None

        def disconnected_callback(client: BleakClientWithServiceCache) -> None:
            if token is None:
                _LOGGER.debug(
                    "%s: Ignoring disconnect before session ownership",
                    self.log_identity,
                )
                return
            self._disconnected(client, token)

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
            if self.is_connection_active:
                token = self._connection_token
                if token is None:
                    raise TuyaBLEConnectionUnavailableError()
                if request_status:
                    await self._request_status_while_connected(token)
                if not self._owns_connection_session(token, require_ready=True):
                    raise TuyaBLEConnectionUnavailableError()
                self._publish_connected_session(token)
                return
            if self._client and self._client.is_connected:
                raise TuyaBLEConnectionUnavailableError()
            stale_token = self._connection_token
            if stale_token is not None:
                self._mark_connection_lost(
                    stale_token,
                    unexpected=not self._expected_disconnect and self._is_paired,
                )
            if self._terminal_stopped:
                raise TuyaBLEConnectionUnavailableError()
            try:
                async with global_connect_lock:
                    if self._terminal_stopped:
                        raise TuyaBLEConnectionUnavailableError()
                    _LOGGER.debug(
                        "%s: Connecting; RSSI: %s",
                        self.log_identity,
                        self.rssi,
                    )
                    client = await establish_connection(
                        BleakClientWithServiceCache,
                        self._ble_device,
                        self.address,
                        disconnected_callback,
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
            setup_task: asyncio.Task | None = None
            try:
                token = self._claim_connection_session(client)
                setup_task = asyncio.current_task()
                if setup_task is not None:
                    self._session_setup_task_tokens[setup_task] = token
                if self._terminal_stopped:
                    await self._cleanup_new_client(client, token, terminal=True)
                    raise TuyaBLEConnectionUnavailableError()
                _LOGGER.debug("%s: Connected; RSSI: %s", self.log_identity, self.rssi)
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
                    await token.client.start_notify(
                        self._characteristic_notify,
                        self._notification_callback_for_session(token),
                        **notify_kwargs,
                    )
                    if not self._owns_connection_session(token):
                        raise TuyaBLEConnectionUnavailableError()
                    self._notifications_active = True
                    if not await self._send_packet_while_connected(
                        TuyaBLECode.FUN_SENDER_DEVICE_INFO,
                        (
                            b"\x00\xf3"
                            if self._requires_fd50_device_info_handshake()
                            else bytes(0)
                        ),
                        0,
                        True,
                        session_token=token,
                    ):
                        raise BleakError()
                    if not self._owns_connection_session(
                        token, require_notifications=True
                    ):
                        raise TuyaBLEConnectionUnavailableError()
                    if not await self._send_packet_while_connected(
                        TuyaBLECode.FUN_SENDER_PAIR,
                        self._build_pairing_request(),
                        0,
                        True,
                        session_token=token,
                    ):
                        raise BleakError()
                except Exception as ex:  # noqa: BLE001
                    await self._cleanup_new_client(
                        client,
                        token,
                        terminal=self._terminal_stopped,
                    )
                    if "Bluetooth is already shutdown" in str(ex):
                        raise self._sanitized_transport_error(ex) from None
                    raise self._sanitized_transport_error(ex) from None

                if not self._owns_connection_session(token, require_ready=True):
                    raise TuyaBLEConnectionUnavailableError()
                if request_status:
                    await self._request_status_while_connected(token)
                if not self._owns_connection_session(token, require_ready=True):
                    raise TuyaBLEConnectionUnavailableError()
                _LOGGER.debug("%s: Successfully connected", self.log_identity)
                self._policy_state = (
                    ConnectionPolicyState.ALWAYS_CONNECTED_ACTIVE
                    if self._connection_mode is ConnectionMode.ALWAYS_CONNECTED
                    else ConnectionPolicyState.ON_DEMAND_ACTIVE
                )
                self._publish_connected_session(token)
            except asyncio.CancelledError:
                if token is not None:
                    await self._cleanup_cancelled_new_client(client, token)
                raise
            finally:
                if (
                    setup_task is not None
                    and self._session_setup_task_tokens.get(setup_task) is token
                ):
                    self._session_setup_task_tokens.pop(setup_task, None)

    async def _request_status_while_connected(
        self, token: ConnectionSessionToken
    ) -> bool:
        """Request current status once for an Always-connected session.

        The request is intentionally not retried: once it has been handed to
        the transport, a failure is ambiguous and replaying it could create
        uncontrolled traffic during reconnect recovery.  Freshness remains
        false until an inbound datapoint report is parsed.
        """
        if (
            self.effective_policy is not EffectiveConnectionPolicy.ALWAYS_CONNECTED
            or not self._owns_connection_session(token, require_ready=True)
            or self._status_attempted_token is token
            or self._terminal_stopped
        ):
            return False

        # Mark before I/O so duplicate callbacks and an ambiguous transport
        # failure cannot replay the request within this physical session.
        self._status_attempted_token = token
        status_task = asyncio.current_task()
        if status_task is not None:
            self._status_task_tokens[status_task] = token
        try:
            try:
                result = await self._send_packet_while_connected(
                    TuyaBLECode.FUN_SENDER_DEVICE_STATUS,
                    b"",
                    0,
                    True,
                    session_token=token,
                    require_always_connected=True,
                )
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                _LOGGER.debug(
                    "%s: Current status request failed; not retrying this session",
                    self.log_identity,
                )
                return False
            if (
                self.effective_policy is not EffectiveConnectionPolicy.ALWAYS_CONNECTED
                or not self._owns_connection_session(token, require_ready=True)
                or self._terminal_stopped
            ):
                return False
            return result
        finally:
            if (
                status_task is not None
                and self._status_task_tokens.get(status_task) is token
            ):
                self._status_task_tokens.pop(status_task, None)

    async def _reconnect(self) -> None:
        """Attempt a reconnect for future operations without replaying a command."""
        _LOGGER.debug("%s: Reconnect, ensuring connection", self.log_identity)
        try:
            if self.effective_policy is not EffectiveConnectionPolicy.ALWAYS_CONNECTED:
                return
            async with self.connection_lease("policy reconnect", defer_connection=True):
                await self._ensure_connected(
                    request_status=(self.category, self.product_id)
                    in RECONNECT_STATUS_SYNC_PRODUCTS
                )
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
                if self.effective_policy is EffectiveConnectionPolicy.ALWAYS_CONNECTED:
                    reconnect_delay = (
                        self._next_unexpected_reconnect_delay()
                        if self._uses_s1_reconnect_protection
                        else BLEAK_BACKOFF_TIME
                    )
                    self._retain_or_schedule_reconnect_locked(reconnect_delay)
        except (TuyaBLEControlSuspendedError, TuyaBLEConnectionUnavailableError):
            return
        except Exception:  # noqa: BLE001
            async with self._policy_lock:
                if self.effective_policy is EffectiveConnectionPolicy.ALWAYS_CONNECTED:
                    reconnect_delay = (
                        self._next_unexpected_reconnect_delay()
                        if self._uses_s1_reconnect_protection
                        else BLEAK_BACKOFF_TIME
                    )
                    self._retain_or_schedule_reconnect_locked(reconnect_delay)

    def _schedule_reconnect(self, delay: float = 0) -> None:
        if self._terminal_stopped or self._suspension_requested:
            return
        if self._connection_mode is not ConnectionMode.ALWAYS_CONNECTED:
            return
        self._schedule_reconnect_locked(delay)

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
                    self._device_info_handshake_protocol_major()
                    if code == TuyaBLECode.FUN_SENDER_DEVICE_INFO
                    else self._protocol_version
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

    async def _get_seq_num(
        self, session_token: ConnectionSessionToken | None = None
    ) -> int:
        async with self._seq_num_lock:
            if session_token is not None and not self._owns_connection_session(
                session_token
            ):
                raise TuyaBLEConnectionUnavailableError()
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
            await self._send_packet_while_connected(
                code,
                data,
                0,
                wait_for_response,
            )

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
                expected_response_code=code,
            )
            if not confirmed:
                raise TuyaBLECommandUnconfirmedError()

    async def _send_response(
        self,
        session_token: ConnectionSessionToken,
        code: TuyaBLECode,
        data: bytes,
        response_to: int,
    ) -> None:
        """Send response to received packet."""
        if not self._owns_connection_session(session_token, require_notifications=True):
            return
        try:
            if _lease_context_depth(self) > 0:
                if self._owns_connection_session(
                    session_token, require_notifications=True
                ):
                    await self._send_packet_while_connected(
                        code,
                        data,
                        response_to,
                        False,
                        session_token=session_token,
                    )
            else:
                async with self.connection_lease(
                    "protocol response", defer_connection=True
                ):
                    if self._owns_connection_session(
                        session_token, require_notifications=True
                    ):
                        await self._send_packet_while_connected(
                            code,
                            data,
                            response_to,
                            False,
                            session_token=session_token,
                        )
        except (TuyaBLEControlSuspendedError, TuyaBLEConnectionUnavailableError):
            return

    async def _send_packet_while_connected(
        self,
        code: TuyaBLECode,
        data: bytes,
        response_to: int,
        wait_for_response: bool,
        expected_response_code: TuyaBLECode | None = None,
        *,
        session_token: ConnectionSessionToken | None = None,
        require_always_connected: bool = False,
        # retry: int | None = None
    ) -> bool:
        """Send packet to device and optional read response."""
        token = session_token or self._connection_token
        if token is None or not self._owns_transport_work(
            token,
            require_always_connected=require_always_connected,
        ):
            raise TuyaBLEConnectionUnavailableError()
        result = True
        future: asyncio.Future | None = None
        seq_num = await self._get_seq_num(token)
        if not self._owns_transport_work(
            token,
            require_always_connected=require_always_connected,
        ):
            raise TuyaBLEConnectionUnavailableError()
        response_key = (token, seq_num)
        if wait_for_response:
            future = asyncio.get_running_loop().create_future()
            self._input_expected_responses[response_key] = future
            if expected_response_code is not None:
                self._input_expected_response_codes[response_key] = (
                    expected_response_code
                )

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
            if require_always_connected:
                await self._int_send_packet_while_connected(
                    token,
                    packets,
                    require_always_connected=True,
                )
            else:
                await self._int_send_packet_while_connected(token, packets)
            if not self._owns_transport_work(
                token,
                require_always_connected=require_always_connected,
            ):
                raise TuyaBLEConnectionUnavailableError()
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
                if not self._owns_transport_work(
                    token,
                    require_always_connected=require_always_connected,
                ):
                    raise TuyaBLEConnectionUnavailableError()
        finally:
            if future:
                if future.done() and not future.cancelled():
                    future.exception()
                self._input_expected_responses.pop(response_key, None)
                self._input_expected_response_codes.pop(response_key, None)

        return result

    async def _int_send_packet_while_connected(
        self,
        session_token: ConnectionSessionToken,
        packets: list[bytes],
        *,
        require_always_connected: bool = False,
    ) -> None:
        operation_lock = session_token.operation_lock
        if operation_lock.locked():
            _LOGGER.debug(
                "%s: Operation already in progress, "
                "waiting for it to complete; RSSI: %s",
                self.log_identity,
                self.rssi,
            )
        async with operation_lock:
            if not self._owns_transport_work(
                session_token,
                require_always_connected=require_always_connected,
            ):
                raise TuyaBLEConnectionUnavailableError()
            try:
                if require_always_connected:
                    await self._send_packets_locked(
                        session_token,
                        packets,
                        require_always_connected=True,
                    )
                else:
                    await self._send_packets_locked(session_token, packets)
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

    async def _send_packets_locked(
        self,
        session_token: ConnectionSessionToken,
        packets: list[bytes],
        *,
        require_always_connected: bool = False,
    ) -> None:
        """Send command to device and read response."""
        self.ensure_control_available()
        if not self._owns_transport_work(
            session_token,
            require_always_connected=require_always_connected,
        ):
            raise TuyaBLEConnectionUnavailableError()
        try:
            if require_always_connected:
                await self._int_send_packets_locked(
                    session_token,
                    packets,
                    require_always_connected=True,
                )
            else:
                await self._int_send_packets_locked(session_token, packets)
        except BleakDBusError as ex:
            if "Bluetooth is already shutdown" in str(ex):
                _LOGGER.debug("%s: Bluetooth is already shutdown", self.log_identity)
                raise self._sanitized_transport_error(ex) from None
            # A future reconnect may restore the session, never this command.
            await asyncio.sleep(BLEAK_BACKOFF_TIME)
            _LOGGER.debug(
                "%s: RSSI: %s; Backing off %ss after transport error",
                self.log_identity,
                self.rssi,
                BLEAK_BACKOFF_TIME,
            )
            raise self._sanitized_transport_error(ex) from None
        except BleakError as ex:
            if "Bluetooth is already shutdown" in str(ex):
                _LOGGER.debug("%s: Bluetooth is already shutdown", self.log_identity)
                raise self._sanitized_transport_error(ex) from None
            # A future reconnect may restore the session, never this command.
            _LOGGER.debug(
                "%s: RSSI: %s; Transport error without command replay",
                self.log_identity,
                self.rssi,
            )
            raise self._sanitized_transport_error(ex) from None

    async def _record_write_transport_failure(
        self, session_token: ConnectionSessionToken
    ) -> None:
        """Keep the exact client owned until a failed write is physically resolved."""
        async with self._policy_lock:
            if not self._owns_connection_session(session_token):
                return
            client = session_token.client
            if not client.is_connected:
                reconnect_delay = self._mark_connection_lost(
                    session_token, unexpected=True
                )
                self._reconcile_after_verified_transport_loss(
                    reconnect_delay or UNEXPECTED_RECONNECT_MIN_SECONDS
                )
                return
            self._notifications_active = False
            self._invalidate_session_data(session_token)
            self._pending_release = PendingRelease(
                PendingReleaseReason.SESSION_FAILURE,
                self._policy_revision,
                reconnect_delay=self._next_unexpected_reconnect_delay(),
            )
            self._policy_state = ConnectionPolicyState.DISCONNECT_FAILED
            self._cancel_reconnect_locked()
            self._cancel_idle_disconnect_locked()
            self._schedule_disconnect_retry_locked()

    async def _int_send_packets_locked(
        self,
        session_token: ConnectionSessionToken,
        packets: list[bytes],
        *,
        require_always_connected: bool = False,
    ) -> None:
        """Execute command and read response."""
        client = session_token.client
        for packet in packets:
            if (
                self._owns_transport_work(
                    session_token,
                    require_always_connected=require_always_connected,
                )
                and client.is_connected
            ):
                try:
                    await client.write_gatt_char(
                        self._characteristic_write,
                        packet,
                        False,
                    )
                except Exception as ex:  # noqa: BLE001
                    await self._record_write_transport_failure(session_token)
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
                    raise self._sanitized_transport_error(ex) from None
                if not self._owns_transport_work(
                    session_token,
                    require_always_connected=require_always_connected,
                ):
                    raise TuyaBLEConnectionUnavailableError()
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
        session_token: ConnectionSessionToken,
        timestamp: float,
        flags: int,
        data: bytes,
        start_pos: int,
        length_size: int,
    ) -> int:
        """Parse Tuya KLV datapoints with the requested value-length width."""
        if not self._owns_connection_session(session_token, require_notifications=True):
            return start_pos
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
            self._datapoints._update_from_device(
                id,
                timestamp,
                flags,
                type,
                value,
                session_token,
            )
            datapoints.append(self._datapoints[id])
            pos = next_pos

        self._fire_callbacks(datapoints)
        return pos

    def _parse_datapoints_v3(
        self,
        session_token: ConnectionSessionToken,
        timestamp: float,
        flags: int,
        data: bytes,
        start_pos: int,
    ) -> int:
        """Parse Tuya BLE protocol-v3 datapoints."""
        return self._parse_datapoints(
            session_token, timestamp, flags, data, start_pos, 1
        )

    def _parse_datapoints_v4(
        self,
        session_token: ConnectionSessionToken,
        timestamp: float,
        flags: int,
        data: bytes,
        start_pos: int,
    ) -> int:
        """Parse Tuya BLE protocol-v4 datapoints."""
        return self._parse_datapoints(
            session_token, timestamp, flags, data, start_pos, 2
        )

    def _handle_command_or_response(
        self,
        seq_num: int,
        response_to: int,
        code: TuyaBLECode,
        data: bytes,
        *,
        session_token: ConnectionSessionToken | None = None,
    ) -> None:
        if session_token is not None and not self._owns_connection_session(
            session_token, require_notifications=True
        ):
            return
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
                if session_token is None:
                    return
                if len(data) != 0:
                    raise TuyaBLEDataLengthError()

                timestamp = int(time.time_ns() / 1000000)
                timezone = -int(time.timezone / 36)
                data = str(timestamp).encode() + pack(">h", timezone)
                self._schedule_response(session_token, code, data, seq_num)

            case TuyaBLECode.FUN_RECEIVE_TIME2_REQ:
                if session_token is None:
                    return
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
                self._schedule_response(session_token, code, data, seq_num)

            case TuyaBLECode.FUN_RECEIVE_DP:
                if session_token is None:
                    return
                self._parse_datapoints_v3(session_token, time.time(), 0, data, 0)
                self._record_confirmed_activity(session_token)
                self._schedule_response(session_token, code, bytes(0), seq_num)

            case TuyaBLECode.FUN_RECEIVE_SIGN_DP:
                if session_token is None:
                    return
                dp_seq_num = int.from_bytes(data[:2], "big")
                flags = data[2]
                self._parse_datapoints_v3(session_token, time.time(), flags, data, 2)
                self._record_confirmed_activity(session_token)
                data = pack(">HBB", dp_seq_num, flags, 0)
                self._schedule_response(session_token, code, data, seq_num)

            case TuyaBLECode.FUN_RECEIVE_TIME_DP:
                if session_token is None:
                    return
                timestamp: float
                pos: int
                timestamp, pos = self._parse_timestamp(data, 0)
                self._parse_datapoints_v3(session_token, timestamp, 0, data, pos)
                self._record_confirmed_activity(session_token)
                self._schedule_response(session_token, code, bytes(0), seq_num)

            case TuyaBLECode.FUN_RECEIVE_SIGN_TIME_DP:
                if session_token is None:
                    return
                timestamp: float
                pos: int
                dp_seq_num = int.from_bytes(data[:2], "big")
                flags = data[2]
                timestamp, pos = self._parse_timestamp(data, 3)
                self._parse_datapoints_v3(session_token, time.time(), flags, data, pos)
                self._record_confirmed_activity(session_token)
                data = pack(">HBB", dp_seq_num, flags, 0)
                self._schedule_response(session_token, code, data, seq_num)

            case TuyaBLECode.FUN_RECEIVE_DP_V4:
                if session_token is None:
                    return
                if len(data) < 7:
                    raise TuyaBLEDataLengthError()
                if data[0] != 0:
                    raise TuyaBLEDataFormatError()
                send_flags = data[5]
                mode = data[6]
                self._parse_datapoints_v4(session_token, time.time(), mode, data, 7)
                self._record_confirmed_activity(session_token)
                if (send_flags & 0x80) == 0:
                    self._schedule_response(
                        session_token, code, data[:7] + b"\x00", seq_num
                    )

            case TuyaBLECode.FUN_RECEIVE_TIME_DP_V4:
                if session_token is None:
                    return
                if len(data) < 8:
                    raise TuyaBLEDataLengthError()
                if data[0] != 0:
                    raise TuyaBLEDataFormatError()
                send_flags = data[5]
                mode = data[6]
                timestamp, pos = self._parse_timestamp(data, 7)
                self._parse_datapoints_v4(session_token, timestamp, mode, data, pos)
                self._record_confirmed_activity(session_token)
                if (send_flags & 0x80) == 0:
                    self._schedule_response(
                        session_token, code, data[:7] + b"\x00", seq_num
                    )

        if response_to != 0 and session_token is not None:
            response_key = (session_token, response_to)
            expected_code = self._input_expected_response_codes.get(response_key)
            if expected_code is not None and code is not expected_code:
                _LOGGER.debug(
                    "%s: Ignoring unexpected %s response to #%s",
                    self.log_identity,
                    code.name,
                    response_to,
                )
            else:
                future = self._input_expected_responses.pop(response_key, None)
                self._input_expected_response_codes.pop(response_key, None)
                if future:
                    _LOGGER.debug(
                        "%s: Received expected response to #%s, result: %s",
                        self.log_identity,
                        response_to,
                        result,
                    )
                    if result == 0:
                        self._record_confirmed_activity(session_token)
                        future.set_result(result)
                    else:
                        future.set_exception(TuyaBLEDeviceError(result))

    def _clean_input(self) -> None:
        self._input_buffer = None
        self._input_expected_packet_num = 0
        self._input_expected_length = 0

    def _parse_input(self, session_token: ConnectionSessionToken) -> None:
        if not self._owns_connection_session(session_token, require_notifications=True):
            self._clean_input()
            return
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

        if not self._owns_connection_session(session_token, require_notifications=True):
            return
        self._handle_command_or_response(
            seq_num,
            response_to,
            code,
            data,
            session_token=session_token,
        )

    def _notification_handler(
        self,
        session_token: ConnectionSessionToken,
        _sender: int,
        data: bytearray,
    ) -> None:
        """Handle notification responses."""
        if not self._owns_connection_session(session_token, require_notifications=True):
            return
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
                if not self._owns_connection_session(
                    session_token, require_notifications=True
                ):
                    self._clean_input()
                    return
                self._parse_input(session_token)
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

    async def _send_datapoints_no_replay(self, datapoint_ids: list[int]) -> None:
        """Send one datapoint update without retaining packet bytes for replay."""
        if self._protocol_version == 3:
            await self._send_datapoints_v3(datapoint_ids)
        elif self._protocol_version >= 4:
            await self._send_datapoints_v4(datapoint_ids)
        else:
            raise TuyaBLEConnectionUnavailableError()

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

            dp._set_local_value(value)
            updated_dps.append(dp)

        if not updated_dps:
            return
        await self._send_datapoints([dp.id for dp in updated_dps])
        self._fire_callbacks(updated_dps)
