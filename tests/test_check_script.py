"""Validate the offline check contract implemented by scripts/check.sh."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[1]
CHECK = ROOT / "scripts" / "check.sh"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
MANIFEST = "custom_components/tuya_ble/manifest.json"
BASH = shutil.which("bash")
GIT = shutil.which("git")
SUMMARY_LINE = re.compile(r"^  (PASS|FAIL|NOT RUN|N/A) +(\S+)")


def _env(**overrides: str) -> dict[str, str]:
    """Return an environment isolated from CI markers and host Git config."""
    dropped = {
        "CI",
        "GITHUB_ACTIONS",
        "TUYA_BLE_CHECK_PYTHON",
        "ACTIONLINT",
        "GITLEAKS",
        "SHELLCHECK",
        "PYTEST_ADDOPTS",
    }
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in dropped and not key.startswith("GIT_")
    }
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    env.update(overrides)
    return env


def _git(repo: Path, *args: str) -> str:
    assert GIT is not None
    result = subprocess.run(  # noqa: S603
        [
            GIT,
            "-c",
            "user.name=Synthetic",
            "-c",
            "user.email=synthetic@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
            *args,
        ],
        cwd=repo,
        env=_env(),
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _fake_tool(path: Path, body: str) -> Path:
    _write(path, "#!/bin/sh\n" + body)
    path.chmod(0o755)
    return path


def _run(
    repo: Path, *args: str, cwd: Path | None = None, **env: str
) -> subprocess.CompletedProcess[str]:
    assert BASH is not None
    return subprocess.run(  # noqa: S603
        [BASH, str(repo / "scripts" / "check.sh"), *args],
        cwd=cwd or repo,
        env=_env(**env),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def _summary(output: str) -> dict[str, str]:
    section = output.split("\nSummary\n", 1)[1].split("\nNot evaluated", 1)[0]
    return {
        match.group(2): match.group(1)
        for match in map(SUMMARY_LINE.match, section.splitlines())
        if match
    }


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """Create a minimal synthetic repository containing the check script."""
    root = tmp_path / "repo"
    (root / "scripts").mkdir(parents=True)
    shutil.copy2(CHECK, root / "scripts" / "check.sh")
    _write(root / MANIFEST, json.dumps({"domain": "synthetic"}, indent=2) + "\n")
    _write(
        root / "custom_components/tuya_ble/translations/en.json",
        json.dumps({"title": "Synthetic"}, indent=4) + "\n",
    )
    _write(root / "notes/tracked.txt", "synthetic\n")
    _write(root / ".gitignore", "custom_components/tuya_ble/ignored.json\n")
    _git(root, "init", "-q")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "synthetic base")
    return root


def test_runs_from_another_directory_with_explicit_interpreter(
    repo: Path, tmp_path: Path
) -> None:
    """Check the containing repository, report the interpreter, and mark N/A."""
    result = _run(repo, "--python", sys.executable, "--only", "json,yaml", cwd=tmp_path)

    assert result.returncode == 0, result.stdout
    assert f"Repository: {repo.resolve()}" in result.stdout
    assert "selected by --python" in result.stdout
    assert _summary(result.stdout) == {"json": "PASS", "yaml": "N/A"}
    assert "NOT RUN  black (not selected)" in result.stdout
    assert "NOT RUN  hacs, hassfest" in result.stdout
    assert "selected checks only" in result.stdout


def test_missing_required_tools_are_not_run(repo: Path, tmp_path: Path) -> None:
    """Never report a missing interpreter or tool as passed."""
    _write(repo / ".github/workflows/ci.yml", "on: push\njobs: {}\n")
    missing = str(tmp_path / "missing")

    result = _run(
        repo,
        "--python",
        missing,
        "--only",
        "black,json,yaml,actionlint,gitleaks",
        ACTIONLINT=missing,
        GITLEAKS=missing,
    )

    assert result.returncode == 2, result.stdout
    assert set(_summary(result.stdout).values()) == {"NOT RUN"}
    assert "Result: INCOMPLETE" in result.stdout

    default = _run(repo, "--only", "json")
    assert default.returncode == 2
    assert "no usable interpreter" in default.stdout


def test_failure_sets_exit_one_and_other_checks_still_run(
    repo: Path, tmp_path: Path
) -> None:
    """Report every independent result and fail on an untracked invalid file."""
    _write(repo / "custom_components/tuya_ble/translations/de.json", "{\n")
    _write(repo / ".github/workflows/ci.yml", "on: push\njobs: {}\n")

    result = _run(
        repo,
        "--python",
        sys.executable,
        "--only",
        "json,yaml,actionlint",
        ACTIONLINT=str(tmp_path / "missing"),
    )

    assert result.returncode == 1, result.stdout
    assert _summary(result.stdout) == {
        "json": "FAIL",
        "yaml": "PASS",
        "actionlint": "NOT RUN",
    }
    assert "translations/de.json: invalid JSON" in result.stdout


@pytest.mark.parametrize("args", [("--only", "black,unknown"), ("--na", "yaml")])
def test_usage_errors_cannot_select_unknown_checks_or_force_na(
    repo: Path, args: tuple[str, str]
) -> None:
    """Reject unknown checks and any attempt to mark a check N/A."""
    assert _run(repo, *args).returncode == 64


def test_scope_includes_untracked_and_excludes_ignored_and_venv(
    repo: Path, tmp_path: Path
) -> None:
    """Limit scanned files to tracked and non-ignored untracked repository files."""
    _write(repo / "notes/new.txt", "synthetic\n")
    _write(repo / "custom_components/tuya_ble/ignored.json", "{\n")
    _write(repo / ".venv-synthetic/lib/module.py", "synthetic\n")
    listing = tmp_path / "scanned.txt"
    fake = _fake_tool(
        tmp_path / "gitleaks",
        '[ "$1" = dir ] || exit 0\n'
        'cd "$2" && find . -type f | sed "s|^./||" | sort > "$SCANNED"\n',
    )

    result = _run(
        repo,
        "--python",
        sys.executable,
        "--only",
        "json,gitleaks",
        GITLEAKS=str(fake),
        SCANNED=str(listing),
    )

    assert result.returncode == 0, result.stdout
    scanned = listing.read_text(encoding="utf-8").split()
    assert {"notes/new.txt", "notes/tracked.txt", MANIFEST} <= set(scanned)
    assert "custom_components/tuya_ble/ignored.json" not in scanned
    assert not any(path.startswith(".venv") for path in scanned)


def test_gitleaks_findings_are_redacted(repo: Path, tmp_path: Path) -> None:
    """Print only rule, path, and line for a secret finding."""
    fake = _fake_tool(
        tmp_path / "gitleaks",
        '[ "$1" = dir ] || exit 0\n'
        "scope=$2\nwhile [ $# -gt 0 ]; do\n"
        '  [ "$1" = --report-path ] && report=$2\n  shift\ndone\n'
        'printf \'[{"RuleID":"synthetic-rule","File":"%s/notes/tracked.txt",'
        '"StartLine":1,"Secret":"SYNTHETIC-REDACTION-PROBE",'
        '"Match":"SYNTHETIC-MATCH-PROBE"}]\' "$scope" > "$report"\n'
        "exit 1\n",
    )

    result = _run(
        repo, "--python", sys.executable, "--only", "gitleaks", GITLEAKS=str(fake)
    )

    assert result.returncode == 1
    assert "synthetic-rule notes/tracked.txt:1" in result.stdout
    output = result.stdout + result.stderr
    assert "SYNTHETIC-REDACTION-PROBE" not in output
    assert "SYNTHETIC-MATCH-PROBE" not in output


@pytest.mark.parametrize("available", [False, True])
def test_actionlint_reports_optional_shellcheck_availability(
    repo: Path, tmp_path: Path, available: bool
) -> None:
    """Never present an actionlint run without shellcheck as a shellcheck result."""
    _write(repo / ".github/workflows/ci.yml", "on: push\njobs: {}\n")
    args_file = tmp_path / "actionlint-args.txt"
    actionlint = _fake_tool(
        tmp_path / "actionlint",
        '[ "$1" = -version ] && exit 0\nprintf "%s\\n" "$@" > "$ARGS_FILE"\n',
    )
    shellcheck = (
        _fake_tool(tmp_path / "shellcheck", "echo 'version: 0.0.0-synthetic'\n")
        if available
        else tmp_path / "missing"
    )

    result = _run(
        repo,
        "--only",
        "actionlint",
        ACTIONLINT=str(actionlint),
        SHELLCHECK=str(shellcheck),
        ARGS_FILE=str(args_file),
    )

    assert result.returncode == 0, result.stdout
    passed_args = args_file.read_text(encoding="utf-8").splitlines()
    if available:
        assert f"-shellcheck={shellcheck}" in passed_args
        assert "PASS     actionlint (with shellcheck)" in result.stdout
        assert "NOT RUN  shellcheck" not in result.stdout
    else:
        assert "-shellcheck=" in passed_args
        assert "shellcheck not available" in result.stdout
        assert "NOT RUN  shellcheck of workflow run: scripts" in result.stdout


@pytest.mark.parametrize(
    ("change", "expected"),
    [("clean", 0), ("unstaged", 1), ("staged", 1), ("untracked", 1)],
)
def test_local_diff_scope(repo: Path, change: str, expected: int) -> None:
    """Check staged, unstaged, and untracked whitespace changes locally."""
    if change == "unstaged":
        _write(repo / "notes/tracked.txt", "synthetic \n")
    elif change == "staged":
        _write(repo / "notes/tracked.txt", "synthetic \n")
        _git(repo, "add", "notes/tracked.txt")
        _write(repo / "notes/tracked.txt", "synthetic\n")
    elif change == "untracked":
        _write(repo / "notes/new.txt", "synthetic \n")

    result = _run(repo, "--only", "diff")

    assert result.returncode == expected, result.stdout
    assert _summary(result.stdout)["diff"] == ("PASS" if expected == 0 else "FAIL")


def test_ci_diff_scope_requires_and_checks_the_committed_range(repo: Path) -> None:
    """Refuse an empty CI checkout diff and check exactly BASE..HEAD."""
    base = _git(repo, "rev-parse", "HEAD")

    no_base = _run(repo, "--only", "diff", CI="true")
    assert no_base.returncode == 2
    assert "CI requires --diff-base" in no_base.stdout

    unknown = _run(repo, "--only", "diff", "--diff-base", "0" * 40, CI="true")
    assert unknown.returncode == 2

    _write(repo / "notes/clean.txt", "synthetic\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "synthetic clean change")
    _write(repo / "notes/dirty.txt", "outside the range \n")
    clean = _run(repo, "--only", "diff", "--diff-base", base, CI="true")
    assert clean.returncode == 0, clean.stdout

    _write(repo / "notes/tracked.txt", "synthetic \n")
    _git(repo, "commit", "-q", "-am", "synthetic whitespace change")
    dirty = _run(repo, "--only", "diff", "--diff-base", base, CI="true")
    assert dirty.returncode == 1, dirty.stdout


def test_ci_runs_every_profile_check_exactly_once() -> None:
    """Keep CI on the shared contract without masking failures."""
    assert BASH is not None
    profile = subprocess.run(  # noqa: S603
        [BASH, str(CHECK), "--list"], check=True, capture_output=True, text=True
    ).stdout.split()
    workflow = yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))

    selected: list[str] = []
    for job in workflow["jobs"].values():
        assert "continue-on-error" not in job
        for step in job["steps"]:
            assert "continue-on-error" not in step
            run = step.get("run", "")
            if "scripts/check.sh" in run:
                match = re.search(r"--only (\S+)", run)
                assert match is not None
                selected += match.group(1).split(",")
                if "diff" in match.group(1).split(","):
                    assert "--diff-base" in run
                if "pytest" in match.group(1).split(","):
                    assert "--cov" in step["env"]["PYTEST_ADDOPTS"].split()

    assert sorted(selected) == sorted(profile)
