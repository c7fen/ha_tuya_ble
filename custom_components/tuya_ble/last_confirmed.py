"""Home Assistant presentation and restoration for retained S1 state."""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any


def _parse_restored_timestamp(value: object) -> datetime | None:
    """Parse a timezone-aware timestamp from Home Assistant state attributes."""
    if not isinstance(value, datetime | str):
        return None
    try:
        parsed = value if isinstance(value, datetime) else datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


class TuyaBLES1LastConfirmedEntity:
    """Plain mixin restoring only opted-in S1 values through HA's state store."""

    _mapping: Any

    @property
    def _last_confirmed_enabled(self) -> bool:
        return bool(getattr(self._mapping, "last_confirmed", False))

    @property
    def _last_confirmed_value(self):
        if not self._last_confirmed_enabled:
            return None
        return self._device.last_confirmed_s1_state.get(self._mapping.dp_id)

    @property
    def extra_state_attributes(self) -> dict[str, object] | None:
        attributes = super().extra_state_attributes
        value = self._last_confirmed_value
        if value is None:
            return attributes
        result = dict(attributes or {})
        result.update(
            {
                "last_confirmed_at": value.confirmed_at,
                "data_fresh": value.data_fresh,
                "value_source": value.value_source,
            }
        )
        return result

    async def async_added_to_hass(self) -> None:
        """Restore one validated scoped value without any BLE activity."""
        await super().async_added_to_hass()
        if not self._last_confirmed_enabled:
            return
        previous = await self.async_get_last_state()
        if previous is None:
            return
        timestamp = _parse_restored_timestamp(
            previous.attributes.get("last_confirmed_at")
        )
        if timestamp is None:
            return
        restored = self._restore_value(previous.state)
        if restored is None:
            return
        if self._device.last_confirmed_s1_state.restore(
            self._mapping.dp_id, restored, timestamp
        ):
            self.async_write_ha_state()

    def _restore_value(self, state: str) -> bool | int | None:
        """Validate the serialized state independently for each entity type."""
        dp_id = self._mapping.dp_id
        if dp_id == 33:
            if state == "on":
                return True
            if state == "off":
                return False
            return None
        if dp_id == 34:
            try:
                return self._attr_options.index(state)
            except ValueError:
                return None
        try:
            numeric = Decimal(state)
        except (InvalidOperation, TypeError, ValueError):
            return None
        if not numeric.is_finite() or numeric != numeric.to_integral_value():
            return None
        return int(numeric)
