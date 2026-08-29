#!/usr/bin/env python3
"""Temporary Issue-37 helper entry point — do not merge or run against live HA."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from custom_components.tuya_ble.phase_a_probe_helper import (
    HelperOperation,
    invoke_service,
    write_sanitized_evidence,
)


def main() -> int:
    """Use the shared helper path without printing headers, wrappers, or tokens."""
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=[item.value for item in HelperOperation])
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--nonce")
    parser.add_argument("--config-entry-id")
    parser.add_argument(
        "--mode", choices=("cold", "cold_then_retained"), default="cold"
    )
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    operation = HelperOperation(args.operation)
    payload: dict[str, str] = {}
    if args.nonce:
        payload[
            "nonce" if operation is not HelperOperation.PROBE else "invocation_nonce"
        ] = args.nonce
    if operation is HelperOperation.PROBE:
        if args.config_entry_id:
            payload["config_entry_id"] = args.config_entry_id
        payload["mode"] = args.mode
    token = os.environ.get("SUPERVISOR_TOKEN")
    if not token:
        return 65
    result = invoke_service(
        operation,
        args.endpoint,
        payload,
        {"Authorization": f"Bearer {token}"},
    )
    if result.response is not None and args.evidence is not None:
        write_sanitized_evidence(args.evidence, result.response)
    print(json.dumps({"outcome": result.outcome}, separators=(",", ":")))
    return int(result.exit_code)


if __name__ == "__main__":
    raise SystemExit(main())
