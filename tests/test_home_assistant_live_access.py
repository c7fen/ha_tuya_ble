"""Synthetic regressions for the local-only Home Assistant access helper."""

from __future__ import annotations

import ast
import io
import json
import os
import pty
import select
import sys
import traceback
from dataclasses import asdict
from pathlib import Path

import pytest

from tools import home_assistant_live_access as access

SYNTHETIC_PRIVATE_ROUTE_SENTINEL = "synthetic-private-route-sentinel.invalid"
SYNTHETIC_PRIVATE_INSTRUCTION_SENTINEL = "synthetic-private-instruction-sentinel"
SYNTHETIC_FORBIDDEN_TRANSCRIPT_SENTINELS = (
    "synthetic-config-entry-id-sentinel",
    "synthetic-device-id-sentinel",
    "synthetic-entity-id-sentinel",
    "synthetic-supervisor-token-sentinel",
    "synthetic-authorization-header-sentinel",
    "synthetic-ssh-agent-environment-sentinel",
    "synthetic-private-key-sentinel",
    "/synthetic/private/absolute/evidence/path-sentinel",
)


def _relevant(issue: object) -> bool:
    return isinstance(issue, dict) and issue.get("scope") == "integration"


def _critical(issue: object) -> bool:
    return isinstance(issue, dict) and issue.get("severity") == "critical"


def _private_spec(target: str = SYNTHETIC_PRIVATE_ROUTE_SENTINEL) -> io.StringIO:
    return io.StringIO(
        "PRIVATE_WRAPPER = "
        + repr(
            {
                "route": access.PRIVATE_ROUTE_ID,
                "argv": ["ssh", target],
            }
        )
    )


def _collect(response: str) -> access.RepairsGateResult:
    return access.collect_repairs_gate(
        access.RepairsGate.INITIAL, response, _relevant, _critical
    )


def _resolution_response(issues: list[object]) -> str:
    """Return the complete synthetic Supervisor response used by ``--raw-json``."""
    return json.dumps(
        {
            "result": "ok",
            "data": {
                "unsupported": [],
                "unhealthy": [],
                "issues": issues,
                "suggestions": [],
                "checks": [],
            },
        }
    )


_VALID_FRAMED_OBJECT = b'{"result":"ok","data":{"issues":[]}}'


@pytest.mark.parametrize(
    ("name", "payload", "accepted"),
    [
        ("J-M1", _VALID_FRAMED_OBJECT, True),
        ("J-M2", b"\r\n  " + _VALID_FRAMED_OBJECT + b" \t\r\n", True),
        ("J-M3", b"{BROKEN " + _VALID_FRAMED_OBJECT, False),
        ("J-M4", b"WARNING " + _VALID_FRAMED_OBJECT, False),
        ("J-M5", _VALID_FRAMED_OBJECT + b" TRAILING", False),
        ("J-M6", _VALID_FRAMED_OBJECT + b"\n" + _VALID_FRAMED_OBJECT, False),
        (
            "J-M7",
            b'{"outer":BROKEN,"nested":' + _VALID_FRAMED_OBJECT + b"}",
            False,
        ),
        ("J-M8", b"[" + _VALID_FRAMED_OBJECT + b"]", False),
        ("J-M9", b"\x1b[31m" + _VALID_FRAMED_OBJECT, False),
        ("J-M10", b"\xff" + _VALID_FRAMED_OBJECT, False),
        (
            "J-M11",
            b'{"result":"ok","data":{"issues":[],"note":"{still json}"}}',
            True,
        ),
        ("J-M12", b" \t\r\n", False),
        ("J-M13", b"", False),
        ("J-M14", b'{"result":"error","data":{"issues":[]}}', True),
    ],
)
def test_j_m1_to_j_m14_exact_framed_json_object_extraction(
    name: str, payload: bytes, accepted: bool
) -> None:
    """J-M1--14: only one complete framed JSON object crosses the boundary."""
    extracted = access._extract_exact_framed_json_object(payload)

    assert name.startswith("J-M")
    assert (extracted is not None) is accepted
    if extracted is not None:
        assert isinstance(json.loads(extracted), dict)


def test_j_m14_extraction_and_supervisor_semantics_remain_separate() -> None:
    """J-M14: a complete error envelope extracts but fails semantic decoding."""
    extracted = access._extract_exact_framed_json_object(
        b'{"result":"error","data":{"issues":[]}}'
    )

    assert extracted is not None
    assert access.decode_repairs_response(extracted) == access.DecodedRepairs(
        shape_valid=False, issues=None
    )


def test_s_m1_official_supervisor_envelope_empty_issues_is_shape_valid() -> None:
    """S-M1: the complete Supervisor wrapper is the canonical transport."""
    response = _resolution_response([])
    decoded = access.decode_repairs_response(response)
    result = _collect(response)

    assert decoded == access.DecodedRepairs(shape_valid=True, issues=())
    assert result.shape_valid is True
    assert result.classification == access.ADMISSION_VALID
    assert result.aggregate == access.RepairsAggregate(0, 0)
    assert asdict(access.repairs_evidence(result)) == {
        "shape_valid": True,
        "relevant_count": 0,
        "critical_count": 0,
    }


def test_s_m2_supervisor_envelope_preserves_issues_for_aggregation() -> None:
    """S-M2: strict internal decode preserves valid entries, public result does not."""
    issue = {"scope": "integration", "severity": "critical"}
    response = _resolution_response([issue])
    decoded = access.decode_repairs_response(response)
    result = _collect(response)

    assert decoded == access.DecodedRepairs(shape_valid=True, issues=(issue,))
    assert result.aggregate == access.RepairsAggregate(1, 1)
    assert "scope" not in repr(access.repairs_evidence(result))


@pytest.mark.parametrize(
    ("name", "response"),
    [
        ("S-M3", '{"issues": []}'),
        ("S-M4", "[]"),
        ("S-M5", '{"data": {"issues": []}}'),
        ("S-M6", '{"result": "error", "data": {"issues": []}}'),
        ("S-M7", '{"result": 1, "data": {"issues": []}}'),
        ("S-M8", '{"result": "ok"}'),
        ("S-M9", '{"result": "ok", "data": null}'),
        ("S-M10", '{"result": "ok", "data": []}'),
        ("S-M11", '{"result": "ok", "data": "wrong"}'),
        ("S-M12", '{"result": "ok", "data": {}}'),
        ("S-M13", '{"result": "ok", "data": {"issues": null}}'),
        ("S-M14", '{"result": "ok", "data": {"issues": {}}}'),
        ("S-M15", '{"result": "ok", "data": {"issues": "wrong"}}'),
        ("S-M16", "{"),
    ],
)
def test_repairs_invalid_shapes_fail_closed_without_empty_issue_fallback(
    name: str, response: str
) -> None:
    """S-M3 through S-M16: invalid shapes never become an empty list."""
    decoded = access.decode_repairs_response(response)
    result = _collect(response)

    assert name.startswith("S-M")
    assert decoded.shape_valid is False
    assert decoded.issues is None
    assert result.shape_valid is False
    assert result.classification == access.ADMISSION_COLLECTOR
    assert result.code == access.REPAIRS_RESPONSE_SHAPE_INVALID
    assert result.aggregate is None
    assert asdict(access.repairs_evidence(result)) == {
        "shape_valid": False,
        "relevant_count": None,
        "critical_count": None,
    }


def test_s_m13_unknown_wrapper_and_data_fields_are_accepted() -> None:
    """S-M13: only the mandatory Supervisor envelope shape is constrained."""
    decoded = access.decode_repairs_response(
        json.dumps(
            {
                "result": "ok",
                "future_wrapper": {},
                "data": {"issues": [], "future_data": {}},
            }
        )
    )

    assert decoded == access.DecodedRepairs(shape_valid=True, issues=())


def test_s_m14_and_s_m15_source_rejects_old_shape_and_permissive_fallbacks() -> None:
    """S-M14/15: reject old top-level parsing and every empty-list fallback."""
    source = Path(access.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    fallback_get_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "payload"
    ]
    list_or_empty = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.IfExp)
        and isinstance(node.orelse, ast.List)
        and not node.orelse.elts
    ]

    assert not fallback_get_calls
    assert not list_or_empty
    assert '"issues" not in payload' not in source
    assert '"result" not in payload' in source


def test_all_represented_gates_use_the_same_strict_decoder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Initial, post-activation, and post-rollback share one decoder path."""
    calls: list[str] = []
    original_decoder = access.decode_repairs_response

    def traced_decoder(response: str) -> access.DecodedRepairs:
        calls.append("decode")
        return original_decoder(response)

    monkeypatch.setattr(access, "decode_repairs_response", traced_decoder)
    responses = {gate: _resolution_response([]) for gate in access.RepairsGate}
    results = access.collect_represented_repairs_gates(responses, _relevant, _critical)

    assert [result.gate for result in results] == list(access.RepairsGate)
    assert all(result.shape_valid for result in results)
    assert calls == ["decode", "decode", "decode"]


def _fake_spawn(child: str):
    """Return the narrow spawn seam used to test without executing a wrapper."""

    def spawn(_: Path) -> tuple[int, int]:
        child_pid, master_fd = pty.fork()
        if child_pid == 0:
            os.execv(sys.executable, [sys.executable, "-u", "-c", child])
        return child_pid, master_fd

    return spawn


_RESPONSIVE_PTY_CHILD = r"""
import os
import re
import sys

assert os.isatty(0)
assert os.tcgetpgrp(0) == os.getpgrp()
print("SYNTHETIC_BANNER_IPV4=192.0.2.37", flush=True)
print("SYNTHETIC_BANNER_IPV6=2001:db8::37", flush=True)
print("SYNTHETIC_BANNER_HOST=private-host.invalid", flush=True)
print("SYNTHETIC_BANNER_URL=http://private-host.invalid:8123", flush=True)
print("SYNTHETIC_BANNER_OBSERVER=http://observer.invalid", flush=True)
login = False
for line in sys.stdin:
    if line.strip() == "exec bash -li":
        login = True
        continue
    values = re.findall(r"HA_BROKER_[A-Z_]+:[0-9a-f]+", line)
    if "HA_BROKER_REMOTE" in line and values:
        print("\x1e" + values[0] + "\x1f", flush=True)
    elif "HA_BROKER_LOGIN" in line and values and login:
        print("\x1e" + values[0] + "\x1f", flush=True)
    elif "ha resolution info --raw-json" in line and login and len(values) == 2:
        print("\x1e" + values[0] + "\x1f", flush=True)
        print('{"result": "ok", "data": {"issues": []}}', flush=True)
        print("\x1e" + values[1] + "\x1f", flush=True)
    elif line.strip() == "exit":
        print("SYNTHETIC_CLOSE_TARGET=private-host.invalid", flush=True)
        break
"""


def _resolution_pty_child(payload: bytes) -> str:
    """Return a controlling-PTY child that emits one synthetic framed payload."""
    return (
        "_PAYLOAD = "
        + repr(payload)
        + "\n"
        + r"""
import os
import re
import sys

assert os.isatty(0)
assert os.tcgetpgrp(0) == os.getpgrp()
login = False

def emit_frame(value):
    os.write(1, b"\x1e" + value.encode("ascii") + b"\x1f")

for line in sys.stdin:
    if line.strip() == "exec bash -li":
        login = True
        continue
    values = re.findall(r"HA_BROKER_[A-Z_]+:[0-9a-f]+", line)
    if "HA_BROKER_REMOTE" in line and values:
        emit_frame(values[0])
    elif "HA_BROKER_LOGIN" in line and values and login:
        emit_frame(values[0])
    elif "ha resolution info --raw-json" in line and login and len(values) == 2:
        emit_frame(values[0])
        os.write(1, _PAYLOAD)
        emit_frame(values[1])
    elif line.strip() == "exit":
        break
"""
    )


def _broker(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    child: str,
    *,
    max_capture_bytes: int = 64 * 1024,
):
    wrapper = tmp_path / "SYNTHETIC_REAL_WRAPPER_MUST_NOT_RUN"
    monkeypatch.setattr(
        access,
        "validate_private_wrapper",
        lambda path: access.WrapperValidationResult(access.PRIVATE_WRAPPER_VALID, ()),
    )
    monkeypatch.setattr(access, "_spawn_private_wrapper", _fake_spawn(child))
    return access.PrivateInteractiveSessionBroker(
        wrapper,
        timeout_seconds=0.2,
        max_capture_bytes=max_capture_bytes,
    )


@pytest.mark.parametrize(
    ("name", "payload", "expected"),
    [
        (
            "E-M1",
            _VALID_FRAMED_OBJECT,
            access.RepairsEvidence(True, 0, 0),
        ),
        (
            "E-M2",
            b"{BROKEN " + _VALID_FRAMED_OBJECT,
            access.RepairsEvidence(False, None, None),
        ),
        (
            "E-M3",
            b"WARNING " + _VALID_FRAMED_OBJECT,
            access.RepairsEvidence(False, None, None),
        ),
        (
            "E-M4",
            _VALID_FRAMED_OBJECT + b"\n" + _VALID_FRAMED_OBJECT,
            access.RepairsEvidence(False, None, None),
        ),
        (
            "E-M5",
            b"\r\n \t" + _VALID_FRAMED_OBJECT + b" \t\r\n",
            access.RepairsEvidence(True, 0, 0),
        ),
    ],
)
def test_e_m1_to_e_m5_broker_enforces_exact_framed_json_boundary(
    name: str,
    payload: bytes,
    expected: access.RepairsEvidence,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """E-M1--5: framed PTY payloads cross extraction and semantic validation."""
    broker = _broker(monkeypatch, tmp_path, _resolution_pty_child(payload))

    assert broker.open() is access.BrokerState.SESSION_ACTIVE
    try:
        evidence = broker.collect_resolution_info(
            access.RepairsGate.INITIAL, _relevant, _critical
        )
    finally:
        broker.close()

    assert name.startswith("E-M")
    assert evidence == expected


def test_malformed_inner_envelope_never_becomes_empty_valid_evidence() -> None:
    """A valid-looking inner object cannot rescue a malformed framed payload."""
    extracted = access._extract_exact_framed_json_object(
        b"{BROKEN " + _VALID_FRAMED_OBJECT
    )
    result = access.collect_repairs_gate(
        access.RepairsGate.INITIAL,
        extracted if extracted is not None else "",
        _relevant,
        _critical,
    )
    evidence = access.repairs_evidence(result)

    assert evidence == access.RepairsEvidence(False, None, None)
    assert evidence != access.RepairsEvidence(True, 0, 0)


def test_rejected_framed_payload_is_never_emitted(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Rejected private payload bytes never reach output, errors, or evidence."""
    sentinel = "SYNTHETIC_REJECTED_PRIVATE_PAYLOAD_SENTINEL"
    payload = sentinel.encode("ascii") + b" " + _VALID_FRAMED_OBJECT
    broker = _broker(monkeypatch, tmp_path, _resolution_pty_child(payload))

    broker.open()
    evidence = broker.collect_resolution_info(
        access.RepairsGate.INITIAL, _relevant, _critical
    )
    broker.close()

    captured = capsys.readouterr()
    rendered = captured.out + captured.err + repr(broker) + repr(evidence)
    assert evidence == access.RepairsEvidence(False, None, None)
    assert sentinel not in rendered


@pytest.mark.parametrize(
    "name,sentinel",
    [
        ("B-M1", "SYNTHETIC_BANNER_IPV4"),
        ("B-M2", "SYNTHETIC_BANNER_IPV6"),
        ("B-M3", "SYNTHETIC_BANNER_HOST"),
        ("B-M4", "SYNTHETIC_BANNER_URL"),
        ("B-M5", "SYNTHETIC_BANNER_OBSERVER"),
        ("B-M6", "SYNTHETIC_CLOSE_TARGET"),
    ],
)
def test_b_m1_to_b_m6_private_pty_output_never_reaches_transcript(
    name: str,
    sentinel: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """B-M1--6: banner/close leakage and pipe substitution are detected."""
    broker = _broker(monkeypatch, tmp_path, _RESPONSIVE_PTY_CHILD)

    assert broker.open() is access.BrokerState.SESSION_ACTIVE
    assert broker.collect_resolution_info(
        access.RepairsGate.INITIAL, _relevant, _critical
    ) == access.RepairsEvidence(shape_valid=True, relevant_count=0, critical_count=0)
    assert broker.collect_resolution_info(
        access.RepairsGate.POST_ACTIVATION, _relevant, _critical
    ) == access.RepairsEvidence(shape_valid=True, relevant_count=0, critical_count=0)
    broker.close()

    captured = capsys.readouterr()
    rendered = captured.out + captured.err + repr(broker)
    assert name.startswith("B-M")
    assert access.HA_INTERACTIVE_SESSION_READY in rendered
    assert sentinel not in rendered


def test_b_m7_wrapper_is_validated_then_spawned_without_arguments(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """B-M7: only a validated wrapper path reaches the production spawn seam."""
    wrapper = tmp_path / "synthetic-wrapper-path"
    validated: list[Path] = []
    spawned: list[Path] = []
    monkeypatch.setattr(
        access,
        "validate_private_wrapper",
        lambda path: (
            validated.append(path)
            or access.WrapperValidationResult(access.PRIVATE_WRAPPER_VALID, ())
        ),
    )

    def fake_spawn(path: Path) -> tuple[int, int]:
        spawned.append(path)
        return _fake_spawn(_RESPONSIVE_PTY_CHILD)(path)

    monkeypatch.setattr(access, "_spawn_private_wrapper", fake_spawn)
    broker = access.PrivateInteractiveSessionBroker(wrapper, timeout_seconds=0.2)
    broker.open()
    broker.close()

    assert validated == [wrapper, wrapper]
    assert spawned == [wrapper]


def test_b_m7_revalidates_wrapper_immediately_before_spawn(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """B-M7: a wrapper invalidated after construction is never spawned."""
    wrapper = tmp_path / "synthetic-wrapper-path"
    validation_calls = 0
    spawned: list[Path] = []

    def validate(_: Path) -> access.WrapperValidationResult:
        nonlocal validation_calls
        validation_calls += 1
        status = (
            access.PRIVATE_WRAPPER_VALID
            if validation_calls == 1
            else access.PRIVATE_WRAPPER_INVALID
        )
        return access.WrapperValidationResult(status, ())

    monkeypatch.setattr(access, "validate_private_wrapper", validate)
    monkeypatch.setattr(
        access, "_spawn_private_wrapper", lambda path: spawned.append(path)
    )
    broker = access.PrivateInteractiveSessionBroker(wrapper, timeout_seconds=0.2)

    with pytest.raises(access.SessionBrokerError, match="WRAPPER_INVALID"):
        broker.open()

    assert validation_calls == 2
    assert spawned == []


def test_b_m7_wrapper_contents_never_reach_retained_output(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """B-M7: wrapper-source leakage is detected even when launch otherwise works."""
    private_content = "SYNTHETIC_WRAPPER_CONTENT_PRIVATE_TARGET_SENTINEL"
    wrapper = tmp_path / "synthetic-wrapper-content"
    wrapper.write_text(
        "#!/bin/sh\n# " + private_content + "\nexit 99\n",
        encoding="utf-8",
    )
    os.chmod(wrapper, 0o700)
    monkeypatch.setattr(
        access,
        "validate_private_wrapper",
        lambda path: access.WrapperValidationResult(access.PRIVATE_WRAPPER_VALID, ()),
    )
    monkeypatch.setattr(
        access, "_spawn_private_wrapper", _fake_spawn(_RESPONSIVE_PTY_CHILD)
    )
    broker = access.PrivateInteractiveSessionBroker(wrapper, timeout_seconds=0.2)

    broker.open()
    evidence = broker.collect_resolution_info(
        access.RepairsGate.INITIAL, _relevant, _critical
    )
    broker.close()

    captured = capsys.readouterr()
    rendered = captured.out + captured.err + repr(broker) + repr(evidence)
    assert private_content not in rendered


def test_b_m9_login_readiness_requires_verified_interactive_login_bash(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """B-M9: ignoring ``exec bash -li`` cannot be rescued by a generic frame."""
    child = r"""
import os
import re
import sys

assert os.isatty(0)
for line in sys.stdin:
    values = re.findall(r"HA_BROKER_[A-Z_]+:[0-9a-f]+", line)
    if "HA_BROKER_REMOTE" in line and values:
        print("\x1e" + values[0] + "\x1f", flush=True)
    elif line.strip() == "exec bash -li":
        # A shell that ignores this must never be admitted as login Bash.
        continue
    elif line.startswith("printf ") and "HA_BROKER_LOGIN" in line and values:
        # This models the rejected generic post-exec challenge fallback.
        print("\x1e" + values[0] + "\x1f", flush=True)
"""
    broker = _broker(monkeypatch, tmp_path, child)

    with pytest.raises(access.SessionBrokerError, match="TIMEOUT"):
        broker.open()

    source = Path(access.__file__).read_text(encoding="utf-8")
    assert "BASH_VERSION" in source
    assert "shopt -q login_shell" in source
    assert "case $- in *i*" in source
    assert 'self._challenge("LOGIN")' not in source


def test_b_m6_production_spawn_has_a_controlling_tty(tmp_path: Path) -> None:
    """B-M6: the unpatched production primitive gives its child a controlling TTY."""
    wrapper = tmp_path / "synthetic-controlling-tty"
    wrapper.write_text(
        "#!/bin/sh\n"
        "exec python3 -c 'import os; "
        "assert os.isatty(0); "
        "assert os.tcgetpgrp(0) == os.getpgrp(); "
        'print("SYNTHETIC_CONTROLLING_TTY_OK", flush=True)\'\n',
        encoding="utf-8",
    )
    os.chmod(wrapper, 0o700)

    child_pid, master_fd = access._spawn_private_wrapper(wrapper)
    try:
        readable, _, _ = select.select([master_fd], [], [], 1)
        assert readable
        assert b"SYNTHETIC_CONTROLLING_TTY_OK" in os.read(master_fd, 4096)
        assert os.waitpid(child_pid, 0)[0] == child_pid
    finally:
        os.close(master_fd)


@pytest.mark.parametrize("name,child", [("B-M8", ""), ("B-M9", "")])
def test_b_m8_and_b_m9_static_banner_or_prompt_cannot_fake_challenges(
    name: str,
    child: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """B-M8/9: errors are generic and shell readiness needs fresh challenges."""
    if name == "B-M8":
        child = r"""
import os
import re
import sys
assert os.isatty(0)
print("SYNTHETIC_TIMEOUT_PRIVATE_START=private-host.invalid", flush=True)
for _ in sys.stdin:
    pass
"""
    else:
        child = r"""
import os
import re
import sys
assert os.isatty(0)
print("SYNTHETIC_STATIC_PROMPT=READY", flush=True)
for line in sys.stdin:
    values = re.findall(r"HA_BROKER_[A-Z_]+:[0-9a-f]+", line)
    if "HA_BROKER_REMOTE" in line and values:
        print("\x1e" + values[0] + "\x1f", flush=True)
    # Deliberately never acknowledge the post-exec login-shell challenge.
"""
    broker = _broker(monkeypatch, tmp_path, child)

    with pytest.raises(access.SessionBrokerError) as error:
        broker.open()

    captured = capsys.readouterr()
    rendered = captured.out + captured.err + str(error.value) + repr(broker)
    assert name.startswith("B-M")
    assert "PRIVATE_INTERACTIVE_SESSION_TIMEOUT" in rendered
    assert "SYNTHETIC_" not in rendered
    assert error.value.__cause__ is None
    assert error.value.__context__ is None


def test_b_m10_real_wrapper_is_never_executed_by_synthetic_tests(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """B-M10: a fake child can run only through the private spawn seam."""
    wrapper = tmp_path / "SYNTHETIC_REAL_WRAPPER_MUST_NOT_RUN"
    marker = tmp_path / "SYNTHETIC_REAL_WRAPPER_RAN"
    wrapper.write_text(
        "#!/bin/sh\nprintf x > '" + str(marker) + "'\n",
        encoding="utf-8",
    )
    os.chmod(wrapper, 0o700)
    spawns: list[Path] = []
    monkeypatch.setattr(
        access,
        "validate_private_wrapper",
        lambda path: access.WrapperValidationResult(access.PRIVATE_WRAPPER_VALID, ()),
    )

    def fake_spawn(path: Path) -> tuple[int, int]:
        spawns.append(path)
        return _fake_spawn(_RESPONSIVE_PTY_CHILD)(path)

    monkeypatch.setattr(access, "_spawn_private_wrapper", fake_spawn)
    broker = access.PrivateInteractiveSessionBroker(wrapper, timeout_seconds=0.2)
    broker.open()
    broker.close()
    assert spawns == [wrapper]
    assert not marker.exists()


@pytest.mark.parametrize(
    ("name", "child"),
    [
        ("B-M8-START", None),
        (
            "B-M8-EXIT",
            "raise SystemExit('SYNTHETIC_CHILD_EXIT_PRIVATE_SENTINEL')",
        ),
    ],
)
def test_b_m8_exception_paths_never_retain_private_failure_context(
    name: str,
    child: str | None,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """B-M8: spawn and child-exit errors expose only generic broker classes."""
    private_sentinel = "SYNTHETIC_START_PRIVATE_SENTINEL"
    if child is None:
        wrapper = tmp_path / "synthetic-wrapper"
        monkeypatch.setattr(
            access,
            "validate_private_wrapper",
            lambda path: access.WrapperValidationResult(
                access.PRIVATE_WRAPPER_VALID, ()
            ),
        )

        def fail_spawn(_: Path) -> tuple[int, int]:
            raise OSError(private_sentinel)

        monkeypatch.setattr(access, "_spawn_private_wrapper", fail_spawn)
        broker = access.PrivateInteractiveSessionBroker(wrapper, timeout_seconds=0.05)
        forbidden = private_sentinel
    else:
        broker = _broker(monkeypatch, tmp_path, child)
        forbidden = "SYNTHETIC_CHILD_EXIT_PRIVATE_SENTINEL"

    with pytest.raises(access.SessionBrokerError) as error:
        broker.open()

    rendered = "".join(traceback.format_exception(error.type, error.value, error.tb))
    context = repr(error.value.__context__)
    assert name.startswith("B-M8")
    assert forbidden not in str(error.value)
    assert forbidden not in repr(error.value)
    assert forbidden not in context
    assert forbidden not in rendered
    assert error.value.__cause__ is None
    assert error.value.__context__ is None


def test_b_m8_output_limit_precedes_a_valid_frame(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """B-M8: a valid frame after over-limit private bytes fails closed."""
    child = r"""
import os
import re
import sys

assert os.isatty(0)
for line in sys.stdin:
    values = re.findall(r"HA_BROKER_[A-Z_]+:[0-9a-f]+", line)
    if values:
        print("SYNTHETIC_OVER_LIMIT_PRIVATE_BYTES" * 4, flush=True)
        print("\x1e" + values[0] + "\x1f", flush=True)
"""
    broker = _broker(monkeypatch, tmp_path, child, max_capture_bytes=8)

    with pytest.raises(access.SessionBrokerError, match="OUTPUT_LIMIT") as error:
        broker.open()

    assert "SYNTHETIC_OVER_LIMIT_PRIVATE_BYTES" not in str(error.value)


def test_o_m6_private_instruction_never_reaches_bootstrap_stdout(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """O-M6: bootstrap reports a fixed status, never private recipe text."""
    os.chmod(tmp_path, 0o700)
    private_spec_path = tmp_path / "private-spec.py"
    private_spec_path.write_text(
        _private_spec(SYNTHETIC_PRIVATE_INSTRUCTION_SENTINEL).getvalue(),
        encoding="utf-8",
    )

    assert (
        access.main(
            [
                "bootstrap",
                "--private-spec",
                str(private_spec_path),
                "--wrapper",
                str(tmp_path / "wrapper"),
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    assert SYNTHETIC_PRIVATE_INSTRUCTION_SENTINEL not in output
    assert "PRIVATE_WRAPPER_BOOTSTRAPPED" in output


def test_o_m7_private_target_never_reaches_validation_stdout(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """O-M7: static validation emits status/reason codes, never the target."""
    os.chmod(tmp_path, 0o700)
    wrapper = tmp_path / "wrapper"
    access.bootstrap_private_wrapper(_private_spec(), wrapper)

    assert access.main(["validate", "--wrapper", str(wrapper)]) == 0
    output = capsys.readouterr().out
    assert SYNTHETIC_PRIVATE_ROUTE_SENTINEL not in output
    assert "PRIVATE_WRAPPER_VALID" in output


def test_o_m8_validation_rejects_0755_wrapper_and_returns_nonzero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """O-M8: non-owner-only wrappers are invalid and cannot report success."""
    os.chmod(tmp_path, 0o700)
    wrapper = tmp_path / "wrapper"
    access.bootstrap_private_wrapper(_private_spec(), wrapper)
    os.chmod(wrapper, 0o755)

    assert access.main(["validate", "--wrapper", str(wrapper)]) == 1
    assert "PRIVATE_WRAPPER_INVALID" in capsys.readouterr().out


def test_o_m9_broker_has_no_network_or_unbounded_terminal_passthrough() -> None:
    """O-M9: the broker may start the local wrapper but never opens a network API."""
    tree = ast.parse(Path(access.__file__).read_text(encoding="utf-8"))
    imported_roots = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert not imported_roots & {"socket", "urllib", "requests", "http"}
    source = Path(access.__file__).read_text(encoding="utf-8")
    assert "subprocess" not in source
    assert "DEVNULL" not in source
    assert "def execute(" not in source
    assert hasattr(access.PrivateInteractiveSessionBroker, "collect_resolution_info")


def test_o_m10_public_results_do_not_retain_private_host_or_path(
    tmp_path: Path,
) -> None:
    """O-M10: target and local wrapper path are absent from public evidence."""
    os.chmod(tmp_path, 0o700)
    wrapper = tmp_path / "private-wrapper-path-sentinel"
    access.bootstrap_private_wrapper(_private_spec(), wrapper)
    result = access.validate_private_wrapper(wrapper)

    rendered = repr(result)
    assert SYNTHETIC_PRIVATE_ROUTE_SENTINEL not in rendered
    assert str(wrapper) not in rendered


def test_transcript_privacy_regression_excludes_all_forbidden_categories() -> None:
    """Public aggregate evidence excludes every synthetic private category."""
    response = _resolution_response(
        [
            {
                "scope": "integration",
                "severity": "critical",
                "synthetic_private_values": SYNTHETIC_FORBIDDEN_TRANSCRIPT_SENTINELS,
            }
        ]
    )

    rendered = repr(access.repairs_evidence(_collect(response)))

    assert all(
        sentinel not in rendered
        for sentinel in SYNTHETIC_FORBIDDEN_TRANSCRIPT_SENTINELS
    )


def test_wrapper_validation_rejects_shell_metacharacters_and_symlinks(
    tmp_path: Path,
) -> None:
    """The direct exec command accepts only a simple private alias."""
    os.chmod(tmp_path, 0o700)
    with pytest.raises(ValueError, match="PRIVATE_WRAPPER_COMMAND_INVALID"):
        access.bootstrap_private_wrapper(_private_spec("alias;touch"), tmp_path / "bad")

    source = tmp_path / "source"
    source.write_text("#!/bin/sh\nexec ssh harmless-alias\n", encoding="utf-8")
    os.chmod(source, 0o700)
    symlink = tmp_path / "link"
    symlink.symlink_to(source)
    assert "SYMLINK" in access.validate_private_wrapper(symlink).reasons
