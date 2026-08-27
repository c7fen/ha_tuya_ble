"""Validate downstream release metadata and repository links."""

# ruff: noqa: S101

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

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
INTEGRATION = ROOT / "custom_components" / "tuya_ble"
EXPECTED_RELEASE_VERSION = "0.10.0b1"
EXPECTED_RELEASE_TAG = "v0.10.0b1"
EXPECTED_TRACKED_PATH_COUNT = 92
EXPECTED_TRACKED_PATH_DIGEST = (
    "3d6d7f432942482ae5186d11877d31418d2e9d213b8acba36ecd88ffd32eb201"
)
EXPECTED_INTEGRATION_PATH_COUNT = 36
EXPECTED_INTEGRATION_PATH_DIGEST = (
    "246440f7c64b14c66e9ce62f150bcebf6d700b0ea04a1841c6b104d721c5532b"
)
EXPECTED_RUNTIME_PYTHON_PATH_COUNT = 27
EXPECTED_RUNTIME_PATH_BLOB_DIGEST = (
    "d66f63107bde813dfdecae565edfe508c362ccbfb73ac7987b898f34c2f2f6bc"
)
RELEASE_ATTESTATION_SKIP_REASON = (
    "exact immutable release attestation is performed only for a release branch, "
    "release tag, or explicit attestation run"
)


def _release_attestation_enabled(environ: Mapping[str, str]) -> bool:
    """Return whether this environment explicitly attests a release snapshot."""
    return (
        environ.get("TUYA_BLE_RELEASE_ATTESTATION") == "1"
        or environ.get("GITHUB_HEAD_REF", "").startswith("release/")
        or environ.get("GITHUB_REF", "").startswith("refs/tags/v")
    )


@pytest.fixture
def require_release_attestation() -> None:
    """Skip immutable release assertions outside a release-attestation context."""
    if not _release_attestation_enabled(os.environ):
        pytest.skip(RELEASE_ATTESTATION_SKIP_REASON)


def _path_digest(paths: list[str]) -> str:
    """Return the deterministic newline-delimited path inventory digest."""
    return hashlib.sha256("".join(f"{path}\n" for path in paths).encode()).hexdigest()


def _git_blob_id(path: Path) -> str:
    """Return the Git blob ID for one regular file without requiring Git."""
    contents = path.read_bytes()
    header = f"blob {len(contents)}\0".encode()
    return hashlib.sha1(header + contents, usedforsecurity=False).hexdigest()


def _tracked_paths() -> list[str]:
    """Return the repository's deterministic tracked-path inventory."""
    git = shutil.which("git")
    assert git is not None
    result = subprocess.run(  # noqa: S603
        [git, "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return sorted(path.decode() for path in result.stdout.split(b"\0") if path)


def test_manifest_repository_identity_and_ownership_are_current() -> None:
    """Keep manifest ownership and downstream repository identity current."""
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

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


@pytest.mark.release_freeze
def test_release_manifest_version_and_tag_are_exact(
    require_release_attestation: None,
) -> None:
    """Require the immutable published prerelease version and tag."""
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    assert manifest["version"] == EXPECTED_RELEASE_VERSION
    assert f"v{manifest['version']}" == EXPECTED_RELEASE_TAG
    assert re.fullmatch(r"0\.10\.0b[1-9][0-9]*", manifest["version"])


def test_readme_links_are_downstream() -> None:
    """Require every README repository link to retain downstream identity."""
    readme = README.read_text(encoding="utf-8")

    for expected in (
        "https://github.com/c7fen/ha_tuya_ble",
        "https://github.com/c7fen/ha_tuya_ble/issues",
        "owner=c7fen&repository=ha_tuya_ble&category=integration",
        "git clone https://github.com/c7fen/ha_tuya_ble.git",
        "https://github.com/c7fen/ha_tuya_ble/releases",
    ):
        assert expected in readme

    assert "c7fen/ha_tuya_ble-s1" not in readme


@pytest.mark.release_freeze
def test_release_changelog_is_exact(require_release_attestation: None) -> None:
    """Require the immutable published release and historical changelog text."""
    changelog = CHANGELOG.read_text(encoding="utf-8")

    assert (
        "## [0.10.0b1](https://github.com/c7fen/ha_tuya_ble/releases/tag/v0.10.0b1)"
        in changelog
    )
    assert "complete delta from stable `v0.9.0`" in changelog
    assert "This is a prerelease" in changelog
    assert "Stable `v0.9.0` remains available" in changelog
    assert "final confirmed-activity timestamp" in changelog
    assert "all four S1 devices" in changelog
    assert (
        "## [0.9.0](https://github.com/c7fen/ha_tuya_ble/releases/tag/v0.9.0)"
        in changelog
    )
    assert "supersedes `v0.9.0b1`, `v0.9.0b2`, and `v0.9.0b3`" in changelog
    assert "byte-identical to\n  `v0.9.0b3`" in changelog
    assert "one representative\n  S1 Lock/Unlock hardware smoke cycle" in changelog
    assert (
        "## [0.9.0b3](https://github.com/c7fen/ha_tuya_ble/releases/tag/v0.9.0b3)"
        in changelog
    )
    assert "supersedes `v0.9.0b1` and `v0.9.0b2` for installation" in changelog
    assert "Although it was not the literal BLE address" in changelog


def test_tracked_paths_are_relative_regular_and_nonsymlink() -> None:
    """Reject unsafe tracked paths in every repository validation run."""
    for relative in _tracked_paths():
        path = ROOT / relative
        assert ".." not in Path(relative).parts
        assert not Path(relative).is_absolute()
        mode = path.lstat().st_mode
        assert not stat.S_ISLNK(mode)
        assert stat.S_ISREG(mode)


@pytest.mark.release_freeze
def test_release_archive_path_inventory_is_exact(
    require_release_attestation: None,
) -> None:
    """Bind the release to its reviewed tracked and integration inventories."""
    tracked = _tracked_paths()
    integration = [
        path for path in tracked if path.startswith("custom_components/tuya_ble/")
    ]

    assert len(tracked) == EXPECTED_TRACKED_PATH_COUNT
    assert _path_digest(tracked) == EXPECTED_TRACKED_PATH_DIGEST
    assert len(integration) == EXPECTED_INTEGRATION_PATH_COUNT
    assert _path_digest(integration) == EXPECTED_INTEGRATION_PATH_DIGEST


@pytest.mark.release_freeze
def test_release_runtime_python_path_blob_digest_is_exact(
    require_release_attestation: None,
) -> None:
    """Keep every production Python path and blob identical to reviewed next."""
    paths = sorted(INTEGRATION.rglob("*.py"))
    inventory = "".join(
        f"{path.relative_to(ROOT).as_posix()}\t{_git_blob_id(path)}\n" for path in paths
    )

    assert len(paths) == EXPECTED_RUNTIME_PYTHON_PATH_COUNT
    assert hashlib.sha256(inventory.encode()).hexdigest() == (
        EXPECTED_RUNTIME_PATH_BLOB_DIGEST
    )


@pytest.mark.parametrize(
    ("environ", "expected"),
    (
        ({}, False),
        ({"TUYA_BLE_RELEASE_ATTESTATION": "1"}, True),
        ({"GITHUB_HEAD_REF": "release/0.11.0b1"}, True),
        ({"GITHUB_REF": "refs/tags/v0.11.0b1"}, True),
        (
            {
                "GITHUB_HEAD_REF": "feature/s1-last-confirmed-freshness",
                "GITHUB_REF": "refs/heads/feature/s1-last-confirmed-freshness",
            },
            False,
        ),
        ({"TUYA_BLE_RELEASE_ATTESTATION": "0"}, False),
        ({"TUYA_BLE_RELEASE_ATTESTATION": "false"}, False),
        (
            {
                "TUYA_BLE_RELEASE_ATTESTATION": "0",
                "GITHUB_HEAD_REF": "release/0.11.0b1",
            },
            True,
        ),
        (
            {
                "TUYA_BLE_RELEASE_ATTESTATION": "false",
                "GITHUB_REF": "refs/tags/v0.11.0b1",
            },
            True,
        ),
    ),
)
def test_release_attestation_activation_is_explicit_and_deterministic(
    environ: dict[str, str], expected: bool
) -> None:
    """Accept only the documented explicit, release-branch, and tag contexts."""
    assert _release_attestation_enabled(environ) is expected


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
