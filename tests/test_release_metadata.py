"""Validate downstream release metadata and repository links."""

from __future__ import annotations

import json
import re
from pathlib import Path

from custom_components.tuya_ble import (
    binary_sensor,
    button,
    climate,
    cover,
    event,
    number,
    select,
    sensor,
    switch,
    text,
    vacuum,
)
from custom_components.tuya_ble.devices import devices_database

ROOT = Path(__file__).parents[1]
MANIFEST = ROOT / "custom_components" / "tuya_ble" / "manifest.json"
README = ROOT / "README.md"
CHANGELOG = ROOT / "CHANGELOG.md"
RELEASE_POLICY = ROOT / "docs" / "releasing.md"


def test_release_manifest_is_exact() -> None:
    """Require the reviewed beta version, owner order, and downstream URLs."""
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    assert manifest["version"] == "0.9.0b3"
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
        "## [0.9.0b3](https://github.com/c7fen/ha_tuya_ble/releases/tag/v0.9.0b3)"
        in changelog
    )
    assert "supersedes `v0.9.0b1` and `v0.9.0b2` for installation" in changelog
    assert "Although it was not the literal BLE address" in changelog


def test_release_automation_is_manually_gated() -> None:
    """Prevent stale automation from publishing on the stable cutover."""
    for retired_path in (
        ROOT / ".release-please-manifest.json",
        ROOT / "release-please-config.json",
        ROOT / ".github" / "workflows" / "release-please.yml",
    ):
        assert not retired_path.exists()

    policy = RELEASE_POLICY.read_text(encoding="utf-8")
    assert "canonical\n`v`-prefixed annotated tags" in policy
    assert "merely because `next` is merged into `main`" in policy
    assert "first stable `v0.9.0`" in policy


def test_readme_registered_products_match_source_and_platforms() -> None:
    """Keep the documented product census exact and all platform IDs registered."""
    readme = README.read_text(encoding="utf-8")
    table_match = re.search(
        r"## Supported registered products\n\n.*?\n\| Category \|.*?\n"
        r"\| --- \| --- \|\n(?P<rows>(?:\|[^\n]*\n)+)",
        readme,
        re.DOTALL,
    )
    assert table_match is not None

    documented: dict[str, set[str]] = {}
    for row in table_match.group("rows").splitlines():
        cells = [cell.strip() for cell in row.strip("|").split("|")]
        category_match = re.fullmatch(r"`([a-z0-9]+)`", cells[0])
        assert category_match is not None
        category = category_match.group(1)
        documented[category] = set(re.findall(r"`([a-z0-9]+)`", cells[1]))

    registered = {
        category: set(category_info.products)
        for category, category_info in devices_database.items()
    }
    assert documented == registered

    platform_modules = (
        binary_sensor,
        button,
        climate,
        cover,
        event,
        number,
        select,
        sensor,
        switch,
        text,
        vacuum,
    )
    platform_products: set[tuple[str, str]] = set()
    for platform_module in platform_modules:
        for category, category_mapping in platform_module.mapping.items():
            for product_id in category_mapping.products or {}:
                assert category in registered, platform_module.__name__
                platform_products.add((category, product_id))

    registered_products = {
        (category, product_id)
        for category, product_ids in registered.items()
        for product_id in product_ids
    }
    platform_only = platform_products - registered_products
    platform_section = readme.split("### Platform-only source mappings", 1)[1]
    documented_platform_only = set(
        re.findall(r"`([a-z0-9]+)/([a-z0-9]+)`", platform_section.split("\n\n", 2)[1])
    )
    assert documented_platform_only == platform_only
