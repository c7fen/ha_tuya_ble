"""Validate downstream release metadata and repository links."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).parents[1]
MANIFEST = ROOT / "custom_components" / "tuya_ble" / "manifest.json"
README = ROOT / "README.md"
CHANGELOG = ROOT / "CHANGELOG.md"


def test_release_manifest_is_exact() -> None:
    """Require the reviewed beta version, owner order, and downstream URLs."""
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    assert manifest["version"] == "0.9.0b1"
    assert manifest["codeowners"] == [
        "@c7fen",
        "@PlusPlus-ua",
        "@Snuffy2",
        "@kancelott",
        "@scastiello",
        "@CloCkWeRX",
    ]
    assert manifest["documentation"] == "https://github.com/c7fen/ha_tuya_ble"
    assert manifest["issue_tracker"] == "https://github.com/c7fen/ha_tuya_ble/issues"


def test_release_links_are_downstream_and_versioned() -> None:
    """Require every release-facing README link and changelog version anchor."""
    readme = README.read_text(encoding="utf-8")
    changelog = CHANGELOG.read_text(encoding="utf-8")

    for expected in (
        "https://github.com/c7fen/ha_tuya_ble",
        "https://github.com/c7fen/ha_tuya_ble/issues",
        "owner=c7fen&repository=ha_tuya_ble&category=integration",
        "git clone https://github.com/c7fen/ha_tuya_ble.git",
        "https://github.com/c7fen/ha_tuya_ble/releases",
    ):
        assert expected in readme

    assert "c7fen/ha_tuya_ble-s1" not in readme
    assert (
        "## [0.9.0b1](https://github.com/c7fen/ha_tuya_ble/releases/tag/v0.9.0b1)"
        in changelog
    )
