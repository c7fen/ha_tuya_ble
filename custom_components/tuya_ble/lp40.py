"""LAVNA LP40 (jtmspro/jpfgaykg) FD50 BLE unlock helper.

Button-only unlock using Tuya door-lock issued-config check codes and
DP71 variants. No LockEntity is created for this product.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError

from .tuya_ble import TuyaBLEDataPoint, TuyaBLEDataPointType, TuyaBLEDevice

_LOGGER = logging.getLogger(__name__)

LP40_PRODUCT_ID = "jpfgaykg"
LP40_CATEGORY = "jtmspro"
LP40_CLOUD_DP70_CODE = "check_code_set"
LP40_CLOUD_DP71_CODE = "ble_unlock_check"
LP40_DP71_ACTION_INDEX = 12
LP40_CLOUD_TIMEOUT = 15
LP40_REPLY_TIMEOUT = 4.0
LP40_PERI_ID = b"\xff\xff"
LP40_DEFAULT_MEMBER_ID = b"\x00\x03"

LP40_DP_MOTOR_STATE = 47
LP40_DP_UNLOCK_REQUEST = 70
LP40_DP_UNLOCK_CONFIRM = 71


def build_lp40_dp71_v3(
    *,
    member_id: bytes,
    check_code: bytes,
    timestamp_bytes: bytes,
    action: int = 0x01,
    method: int = 0x00,
    info: bytes = b"\x01",
) -> bytes:
    """Build FD50 short-range DP71 (ShonP40 / issued-config layout).

    Wire order observed for FD50 + LP40 issued-config:
      Peripheral (ffff) | Member/central (2) | Random (8) | Action (1) |
      Timestamp (4) | Method (1) | Info (1=0x01)

    Official docs list Central|Peripheral, but live app/HCI and
    GET .../door-lock/issued-config lock_record.ins use ffff|member.
    """
    if len(member_id) != 2:
        raise ValueError("LP40 member_id must be 2 bytes")
    if len(check_code) != 8:
        raise ValueError("LP40 check_code must be 8 bytes")
    if len(timestamp_bytes) != 4:
        raise ValueError("LP40 timestamp must be 4 bytes")
    payload = (
        LP40_PERI_ID
        + member_id
        + check_code
        + bytes((action & 0xFF,))
        + timestamp_bytes
        + bytes((method & 0xFF,))
        + info
    )
    _LOGGER.debug("LP40 built DP71 len=%d", len(payload))
    return payload


def build_lp40_dp70_wake_v3(*, member_id: bytes, check_code: bytes) -> bytes:
    """Build 23-byte DP70 check-code wake (Tuya accessory pairing layout).

    Panel getIssuedConfig wake_up_ins / Variant C:
      ffff | member | 0000000000000000 | 00 | ffff | check_code
    """
    if len(member_id) != 2 or len(check_code) != 8:
        raise ValueError("LP40 DP70 wake needs 2-byte member and 8-byte random")
    return (
        LP40_PERI_ID + member_id + (b"\x00" * 8) + b"\x00" + LP40_PERI_ID + check_code
    )


class LP40UnlockHelper:
    """Owns LP40 unlock state and BLE waiters for one device."""

    def __init__(
        self,
        hass: HomeAssistant,
        device: TuyaBLEDevice,
        manager: Any,
    ) -> None:
        self._hass = hass
        self._device = device
        self._manager = manager
        self._operation_lock = asyncio.Lock()
        self._pending_dp71_reply: asyncio.Future[bytes] | None = None
        self._pending_motor_open: asyncio.Future[bool] | None = None
        self._cached_member_id: bytes = LP40_DEFAULT_MEMBER_ID
        self._cached_check_code: bytes | None = None
        self._cached_cloud_ts: bytes | None = None
        self._cached_distributed: bool = False
        self._unsub = device.register_callback(self._on_datapoints)

    def close(self) -> None:
        """Unregister device callback."""
        if self._unsub is not None:
            self._unsub()
            self._unsub = None

    def _on_datapoints(self, datapoints: list[TuyaBLEDataPoint]) -> None:
        for datapoint in datapoints:
            if (
                datapoint.id == LP40_DP_UNLOCK_CONFIRM
                and datapoint.received_from_device
                and isinstance(datapoint.value, (bytes, bytearray))
                and self._pending_dp71_reply is not None
                and not self._pending_dp71_reply.done()
            ):
                self._pending_dp71_reply.set_result(bytes(datapoint.value))
            if (
                datapoint.id == LP40_DP_MOTOR_STATE
                and datapoint.received_from_device
                and isinstance(datapoint.value, bool)
                and datapoint.value
                and self._pending_motor_open is not None
                and not self._pending_motor_open.done()
            ):
                self._pending_motor_open.set_result(True)

    async def _async_refresh_check_material(self) -> None:
        """Load member/random/ts from issued-config, else ble_unlock_check."""
        device_id = self._device.device_id
        issued: dict[str, Any] = {}
        try:
            async with asyncio.timeout(LP40_CLOUD_TIMEOUT):
                issued = await self._manager.async_get_lock_issued_config(device_id)
        except Exception:  # noqa: BLE001
            _LOGGER.debug("LP40 issued-config failed; using status fallback")
            issued = {}

        lock_random = issued.get("lock_random") if isinstance(issued, dict) else None
        if isinstance(lock_random, dict):
            ins = lock_random.get("ins")
            unlock_id = lock_random.get("dev_unlock_id")
            if isinstance(ins, str) and len(ins) >= 16:
                try:
                    code = bytes.fromhex(ins[:16])
                    if len(code) == 8:
                        self._cached_check_code = code
                except ValueError:
                    pass
            if isinstance(unlock_id, str) and len(unlock_id) >= 4:
                try:
                    member = bytes.fromhex(unlock_id[:4])
                    if len(member) == 2:
                        self._cached_member_id = member
                except ValueError:
                    pass
            self._cached_distributed = bool(lock_random.get("distributed"))

        try:
            async with asyncio.timeout(LP40_CLOUD_TIMEOUT):
                status = await self._manager.async_get_device_raw_status(
                    device_id, (LP40_CLOUD_DP71_CODE, LP40_CLOUD_DP70_CODE)
                )
        except Exception:  # noqa: BLE001
            status = {}
        dp71 = status.get(LP40_CLOUD_DP71_CODE) if status else None
        if isinstance(dp71, (bytes, bytearray)) and len(dp71) >= 17:
            if self._cached_check_code is None:
                self._cached_check_code = bytes(dp71[4:12])
            self._cached_cloud_ts = bytes(dp71[13:17])
            if self._cached_member_id == LP40_DEFAULT_MEMBER_ID and not (
                isinstance(lock_random, dict) and lock_random.get("dev_unlock_id")
            ):
                self._cached_member_id = bytes(dp71[0:2])
        if self._cached_check_code is None:
            raise HomeAssistantError(
                "LP40 check code unavailable "
                "(issued-config and ble_unlock_check failed)."
            )
        if self._cached_cloud_ts is None:
            self._cached_cloud_ts = int(time.time()).to_bytes(4, "big", signed=False)

    def _arm_success_waiters(
        self,
    ) -> tuple[asyncio.Future[bytes], asyncio.Future[bool]]:
        loop = asyncio.get_running_loop()
        dp71_fut: asyncio.Future[bytes] = loop.create_future()
        motor_fut: asyncio.Future[bool] = loop.create_future()
        self._pending_dp71_reply = dp71_fut
        self._pending_motor_open = motor_fut
        return dp71_fut, motor_fut

    def _disarm_success_waiters(
        self,
        dp71_fut: asyncio.Future[bytes],
        motor_fut: asyncio.Future[bool],
    ) -> None:
        if self._pending_dp71_reply is dp71_fut:
            self._pending_dp71_reply = None
        if self._pending_motor_open is motor_fut:
            self._pending_motor_open = None
        for fut in (dp71_fut, motor_fut):
            if not fut.done():
                fut.cancel()

    async def _async_wait_unlock_success(
        self,
        dp71_fut: asyncio.Future[bytes],
        motor_fut: asyncio.Future[bool],
    ) -> bool:
        try:
            async with asyncio.timeout(LP40_REPLY_TIMEOUT):
                done, _pending = await asyncio.wait(
                    {dp71_fut, motor_fut},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                return any(f in done and f.done() and not f.cancelled() for f in done)
        except TimeoutError:
            return False

    async def _async_send_dp71(self, payload: bytes) -> None:
        dp71 = self._device.datapoints.get_or_create(
            LP40_DP_UNLOCK_CONFIRM,
            TuyaBLEDataPointType.DT_RAW,
            payload,
        )
        await dp71.set_value_no_replay(payload)

    async def _async_send_dp70(self, payload: bytes) -> None:
        dp70 = self._device.datapoints.get_or_create(
            LP40_DP_UNLOCK_REQUEST,
            TuyaBLEDataPointType.DT_RAW,
            payload,
        )
        await dp70.set_value_no_replay(payload)

    async def async_unlock(self) -> None:
        """Unlock via DP71 variants A/B, optional DP70 wake (C)."""
        self._device.ensure_control_available()
        async with self._operation_lock:
            async with self._device.connection_lease("lp40 unlock"):
                await self._async_refresh_check_material()
                assert self._cached_check_code is not None
                assert self._cached_cloud_ts is not None
                member = self._cached_member_id
                check = self._cached_check_code
                cloud_ts = self._cached_cloud_ts

                payload_a = build_lp40_dp71_v3(
                    member_id=member,
                    check_code=check,
                    timestamp_bytes=cloud_ts,
                )
                dp71_fut, motor_fut = self._arm_success_waiters()
                try:
                    await self._async_send_dp71(payload_a)
                    if await self._async_wait_unlock_success(dp71_fut, motor_fut):
                        _LOGGER.info("LP40 unlock succeeded via variant A")
                        return
                finally:
                    self._disarm_success_waiters(dp71_fut, motor_fut)

                fresh_ts = int(time.time()).to_bytes(4, "big", signed=False)
                payload_b = build_lp40_dp71_v3(
                    member_id=member,
                    check_code=check,
                    timestamp_bytes=fresh_ts,
                )
                dp71_fut, motor_fut = self._arm_success_waiters()
                try:
                    await self._async_send_dp71(payload_b)
                    if await self._async_wait_unlock_success(dp71_fut, motor_fut):
                        _LOGGER.info("LP40 unlock succeeded via variant B")
                        return
                finally:
                    self._disarm_success_waiters(dp71_fut, motor_fut)

                wake = build_lp40_dp70_wake_v3(member_id=member, check_code=check)
                _LOGGER.debug(
                    "LP40 variant C wake distributed=%s", self._cached_distributed
                )
                await self._async_send_dp70(wake)
                await asyncio.sleep(0.8)
                dp71_fut, motor_fut = self._arm_success_waiters()
                try:
                    await self._async_send_dp71(payload_a)
                    if await self._async_wait_unlock_success(dp71_fut, motor_fut):
                        _LOGGER.info("LP40 unlock succeeded via variant C")
                        return
                finally:
                    self._disarm_success_waiters(dp71_fut, motor_fut)

                raise HomeAssistantError("The LP40 padlock did not respond")
