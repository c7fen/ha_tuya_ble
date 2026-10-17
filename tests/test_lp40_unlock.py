"""Synthetic tests for LP40 DP builders and unlock variants."""

from __future__ import annotations

import sys
import types
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

ROOT = Path(__file__).resolve().parents[1] / "custom_components" / "tuya_ble"


def _load_lp40():
    pkg = types.ModuleType("custom_components")
    sys.modules.setdefault("custom_components", pkg)
    tuya_pkg = types.ModuleType("custom_components.tuya_ble")
    tuya_pkg.__path__ = [str(ROOT)]
    sys.modules["custom_components.tuya_ble"] = tuya_pkg

    tuya_ble_sub = types.ModuleType("custom_components.tuya_ble.tuya_ble")

    class TuyaBLEDataPointType:
        DT_RAW = 0
        DT_BOOL = 1

    class TuyaBLEDataPoint:
        pass

    class TuyaBLEDevice:
        pass

    tuya_ble_sub.TuyaBLEDataPointType = TuyaBLEDataPointType
    tuya_ble_sub.TuyaBLEDataPoint = TuyaBLEDataPoint
    tuya_ble_sub.TuyaBLEDevice = TuyaBLEDevice
    sys.modules["custom_components.tuya_ble.tuya_ble"] = tuya_ble_sub
    tuya_pkg.tuya_ble = tuya_ble_sub

    ha = types.ModuleType("homeassistant")
    sys.modules["homeassistant"] = ha
    ha_core = types.ModuleType("homeassistant.core")
    ha_core.HomeAssistant = object
    sys.modules["homeassistant.core"] = ha_core
    ha_exc = types.ModuleType("homeassistant.exceptions")

    class HomeAssistantError(Exception):
        pass

    ha_exc.HomeAssistantError = HomeAssistantError
    sys.modules["homeassistant.exceptions"] = ha_exc

    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "custom_components.tuya_ble.lp40", ROOT / "lp40.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["custom_components.tuya_ble.lp40"] = mod
    spec.loader.exec_module(mod)
    return mod


class TestLP40Builders(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lp40 = _load_lp40()

    def test_dp71_layout_ffff_member_random(self):
        # Synthetic member/random/timestamp — not from a real device.
        member = b"\x00\x01"
        check = bytes.fromhex("0011223344556677")
        ts = bytes.fromhex("01020304")
        payload = self.lp40.build_lp40_dp71_v3(
            member_id=member, check_code=check, timestamp_bytes=ts
        )
        self.assertEqual(payload[:2], b"\xff\xff")
        self.assertEqual(payload[2:4], member)
        self.assertEqual(payload[4:12], check)
        self.assertEqual(payload[12], 0x01)
        self.assertEqual(payload[13:17], ts)
        self.assertEqual(len(payload), 19)

    def test_dp70_wake_layout(self):
        member = b"\x00\x01"
        check = bytes.fromhex("8899aabbccddeeff")
        wake = self.lp40.build_lp40_dp70_wake_v3(member_id=member, check_code=check)
        self.assertEqual(len(wake), 23)
        self.assertEqual(wake[:4], b"\xff\xff\x00\x01")
        self.assertEqual(wake[15:23], check)


class TestLP40UnlockPath(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.lp40 = _load_lp40()

    async def test_variant_a_success_synthetic(self):
        from homeassistant.exceptions import HomeAssistantError  # noqa: F401

        lp40 = self.lp40
        device = MagicMock()
        device.device_id = "testdeviceid00000001"
        device.ensure_control_available = MagicMock()
        lease = MagicMock()
        lease.__aenter__ = AsyncMock(return_value=None)
        lease.__aexit__ = AsyncMock(return_value=None)
        device.connection_lease = MagicMock(return_value=lease)
        listener = {}

        def register_callback(cb):
            listener["cb"] = cb
            return MagicMock()

        device.register_callback = register_callback
        dp = MagicMock()

        async def succeed_on_tx(payload):
            class DP:
                id = lp40.LP40_DP_UNLOCK_CONFIRM
                received_from_device = True
                value = b"\x00" * 8

            listener["cb"]([DP()])

        dp.set_value_no_replay = AsyncMock(side_effect=succeed_on_tx)
        device.datapoints.get_or_create = MagicMock(return_value=dp)

        manager = MagicMock()
        manager.async_get_lock_issued_config = AsyncMock(
            return_value={
                "lock_random": {
                    "ins": "0011223344556677ffffffff",
                    "dev_unlock_id": "0001",
                    "distributed": False,
                }
            }
        )
        manager.async_get_device_raw_status = AsyncMock(
            return_value={
                "ble_unlock_check": bytes.fromhex("0001001122334455667701010203040001")
            }
        )

        helper = lp40.LP40UnlockHelper(None, device, manager)
        await helper.async_unlock()
        sent = dp.set_value_no_replay.await_args.args[0]
        self.assertEqual(sent[:2], b"\xff\xff")
        self.assertEqual(sent[2:4], b"\x00\x01")
        helper.close()


if __name__ == "__main__":
    unittest.main()
