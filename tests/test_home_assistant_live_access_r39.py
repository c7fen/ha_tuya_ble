"""R39 exact-base blocker reproductions and regression contracts."""

from __future__ import annotations

import copy
import hashlib
import inspect
import json
from pathlib import Path

import pytest

from tests.test_home_assistant_live_access import (
    _r30_files,
    _r30_manifest,
    _r32_advance_to_a2,
    _r32_advance_to_post_activation_repairs,
    _r32_bundles,
    _r32_complete_restore_tail,
    _r33_controller,
    _run_synthetic_remote_program,
)
from tools import home_assistant_live_access as access

_R39_AUDIT_COUNTER_ORACLE = frozenset(
    {
        "connect_attempts",
        "gatt_sessions_claimed",
        "authenticated_sessions",
        "packets_sent_total",
        "device_status_requests",
        "device_info_requests",
        "pair_requests",
        "datapoint_write_operations",
        "datapoint_protocol_packets",
        "other_packets",
        "reconnect_schedules",
        "disconnects",
    }
)


@pytest.fixture(autouse=True)
def _r39_synthetic_authority(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(access, "_LIFECYCLE_STATE_ROOT", tmp_path / "lifecycle")
    for state_name in ("CANDIDATE", "RESTORE"):
        manifest = _r30_manifest(state_name)
        monkeypatch.setitem(
            access._AUTHORITY_MANIFEST_DIGESTS,
            manifest.state.value,
            access._source_manifest_digest(manifest.entries),
        )


def test_r39_red_01_preflight_advances_directly_to_a1() -> None:
    controller, broker = _r32_advance_to_post_activation_repairs()
    controller.collect_a0()
    controller.run_p0()
    controller.collect_ap0()
    controller.run_non_probe_preflight()

    controller.collect_a1()

    assert controller.state is access.LifecycleState.A1_COLLECTED
    assert all(
        detail[0] is not access.PhaseAOperation.RECEIPT
        for name, detail in broker.calls
        if name == "helper"
    )


def test_r39_red_02_exact_pr45_service_names() -> None:
    assert "SERVICES = {" in access._REMOTE_CONTROL_PROGRAM
    assert {
        "phase_a_status_probe",
        "phase_a_status_probe_preflight",
        "phase_a_status_probe_receipt",
        "phase_a_status_probe_audit",
    } == access._remote_service_names()


def test_r39_red_03_bool_exit_code_is_rejected() -> None:
    payload = (
        b'{"exit_code":false,"outcome":"preflight_ok",' b'"nonce":"dddddddddddddddd"}'
    )
    with pytest.raises(access.SessionBrokerError, match="PROTOCOL"):
        access._parse_phase_a_result(
            access.PhaseAOperation.PREFLIGHT,
            payload,
            expected_nonce="d" * 16,
        )


def test_r39_red_04_duplicate_json_members_are_rejected() -> None:
    payload = b'{"success":true,"success":true}'
    with pytest.raises(access.SessionBrokerError, match="PROTOCOL"):
        access._exact_payload(payload)


def test_r39_red_05_missing_journal_cannot_recreate_baseline(
    tmp_path: Path,
) -> None:
    journal = access._DurableLifecycleJournal()
    root = tmp_path / "lifecycle"
    journal.close()
    (root / access._LIFECYCLE_JOURNAL_NAME).unlink()

    with pytest.raises(
        access.LifecycleControllerError, match="RECOVERY_REQUIRED_MISSING_JOURNAL"
    ):
        access._DurableLifecycleJournal()


def test_r39_red_06_candidate_manifest_cannot_authorize_baseline_backup() -> None:
    controller, broker = _r33_controller()
    candidate, _restore = _r32_bundles()
    controller.admit_initial_repairs()
    with pytest.raises(
        access.LifecycleControllerError, match="BACKUP_MANIFEST_INVALID"
    ):
        controller.create_backup(candidate.manifest)
    assert not [call for call in broker.calls if call[0] == "backup"]


def test_r39_red_07_cross_lifecycle_backup_identity_is_rejected() -> None:
    journal = access._DurableLifecycleJournal()
    payload = access._baseline_backup_identity(
        lifecycle_generation="f" * 32,
        source_generation=journal._record["pr41_restore"]["generation"],
        backup_generation="e" * 32,
        manifest_identity="d" * 64,
        backup_digest="c" * 64,
    )
    with pytest.raises(
        access.LifecycleControllerError, match="BACKUP_IDENTITY_INVALID"
    ):
        journal.bind_baseline_backup(payload)
    journal.close()


def test_r39_red_08_verified_backup_cannot_be_overwritten(tmp_path: Path) -> None:
    source = access._REMOTE_CONTROL_PROGRAM
    backup = source[source.index("def backup") : source.index("def transfer")]
    assert "publish_noreplace" in backup
    assert "exchange(pending, BACKUP)" not in backup


def test_r39_red_09_root_replacement_does_not_split_lock_owner(tmp_path: Path) -> None:
    journal = access._DurableLifecycleJournal()
    root = tmp_path / "lifecycle"
    moved = tmp_path / "retained-lifecycle"
    root.rename(moved)
    root.mkdir(mode=0o700)
    with pytest.raises(access.LifecycleControllerError):
        access._DurableLifecycleJournal()
    assert not (root / access._LIFECYCLE_JOURNAL_NAME).exists()
    journal.close()


def test_r39_red_10_older_journal_cannot_drop_restart_tombstone(
    tmp_path: Path,
) -> None:
    controller, _broker = _r32_advance_to_a2()
    _candidate, restore = _r32_bundles()
    controller.stage_restore(restore)
    controller.restore_pr41(restore.manifest)
    controller.verify_restore_inventory(restore.manifest)
    controller.check_restore_core()
    path = tmp_path / "lifecycle" / access._LIFECYCLE_JOURNAL_NAME
    older = path.read_bytes()
    controller.restart_for_restore()
    controller.close()
    path.write_bytes(older)
    path.chmod(0o600)
    with pytest.raises(access.LifecycleControllerError, match="REVISION_INVALID"):
        access._DurableLifecycleJournal()


def test_r39_red_11_frame_completed_after_deadline_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    broker = object.__new__(access.PrivateInteractiveSessionBroker)
    broker._master_fd = 1
    broker._child_pid = 1
    broker._timeout_seconds = 0.5
    broker._max_capture_bytes = 1024
    broker._residual = bytearray(b"FRAME")
    broker._state = access.BrokerState.SESSION_ACTIVE
    broker.close = lambda: None
    calls = 0

    def monotonic() -> float:
        nonlocal calls
        calls += 1
        return 10.0 if calls == 1 else 10.6

    monkeypatch.setattr(access.time, "monotonic", monotonic)
    with pytest.raises(access.SessionBrokerError, match="TIMEOUT"):
        broker._read_until(b"FRAME")


def test_r39_red_12_residual_second_response_is_not_reused() -> None:
    source = inspect.getsource(
        access.PrivateInteractiveSessionBroker._PrivateInteractiveSessionBroker__execute_bounded_operation
    )
    assert source.index("self._start_fresh_exchange()") < source.index(
        "self.__write_wire("
    )


def test_r39_red_13_control_program_base64_is_strict() -> None:
    assert "base64.b64decode(source,validate=True)" in access._CONTROL_BOOTSTRAP


def test_r39_red_14_undeclared_trailing_chunks_are_rejected() -> None:
    assert "HA_R39_TRANSFER_END" in access._REMOTE_CONTROL_PROGRAM
    result = _run_synthetic_remote_program(
        Path.cwd(),
        "transfer",
        {"synthetic": True},
        payload_extra_chunks=("c3ludGhldGlj",),
    )
    assert result == {"error_class": "OPERATION_FAILED"}


def test_r39_red_15_manifest_extra_field_is_rejected(tmp_path: Path) -> None:
    candidate = access.build_source_bundle(
        access.SourceState.CANDIDATE, _r30_files(), _r30_manifest()
    )
    payload = access._bundle_payload(candidate)
    payload["manifest"]["extra"] = "synthetic"
    result = _run_synthetic_remote_program(tmp_path, "transfer", payload)
    assert result == {"error_class": "OPERATION_FAILED"}


def test_r39_red_16_regular_file_requires_exact_bool() -> None:
    files = list(_r30_files())
    original = files[0]
    files[0] = access.SourceBundleFile(
        original.relative_path, original.content, regular_file=1
    )
    with pytest.raises(access.SourceBundleError, match="REGULAR_FILES_ONLY"):
        access.build_source_bundle(access.SourceState.CANDIDATE, files, _r30_manifest())


def test_r39_red_17_synthetic_transport_consumes_real_transfer_stream(
    tmp_path: Path,
) -> None:
    candidate = access.build_source_bundle(
        access.SourceState.CANDIDATE, _r30_files(), _r30_manifest()
    )
    result = _run_synthetic_remote_program(
        tmp_path, "transfer", access._bundle_payload(candidate)
    )
    assert result == {
        "success": True,
        "file_count": len(candidate.files),
        "manifest_match": True,
        "regular_files_only": True,
    }


def test_r39_red_18_authoritative_controller_is_always_durable() -> None:
    signature = inspect.signature(access.FullPreflightLifecycleController)
    assert "_test_construction_token" not in signature.parameters
    controller, _broker = _r33_controller()
    assert type(controller._journal) is access._DurableLifecycleJournal
    controller.close()


def test_r39_f24_post_construction_journal_removal_fails_before_dispatch() -> None:
    controller, broker = _r33_controller()
    journal = controller._journal
    journal_path = journal._journal_path
    durable_before = journal_path.read_bytes()
    journal.close()
    controller._journal = None

    with pytest.raises(access.LifecycleControllerError, match="JOURNAL_REQUIRED"):
        controller.admit_initial_repairs()

    assert journal_path.read_bytes() == durable_before
    assert broker.calls == []
    assert controller._permits[access.LifecycleAction.INITIAL_REPAIRS].consumed is False


def test_r39_red_19_restore_install_reconciliation_is_read_only() -> None:
    source = access._REMOTE_CONTROL_PROGRAM
    start = source.index("def restore_tail_reconcile")
    reconcile = source[start : source.index("\ntry:\n", start)]
    guard = "original_phase == 'intent_durable'"
    assert guard in reconcile
    assert reconcile.index(guard) < reconcile.index("activate(", reconcile.index(guard))


def test_r39_red_20_restore_core_check_reconciliation_never_resubmits() -> None:
    source = access._REMOTE_CONTROL_PROGRAM
    start = source.index("def restore_tail_reconcile")
    reconcile = source[start : source.index("\ntry:\n", start)]
    assert "restore_core_check_readback" in reconcile
    assert reconcile.index("if restore_core_check_readback") < reconcile.index(
        "core = core_check()"
    )


def test_r39_red_21_terminal_tuple_must_be_exact() -> None:
    controller, _broker = _r32_advance_to_a2()
    _candidate, restore = _r32_bundles()
    _r32_complete_restore_tail(controller, restore)
    record = copy.deepcopy(controller._journal._record)
    record["terminal"] = None
    record["active"] = True
    with pytest.raises(access.LifecycleControllerError, match="JOURNAL_INVALID"):
        access._DurableLifecycleJournal._validate_record(record)
    controller.close()


def test_r39_red_22_durable_fallback_result_has_local_completion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SyntheticProcessLoss(BaseException):
        pass

    controller, broker = _r33_controller()
    candidate, restore = _r32_bundles()
    controller.admit_initial_repairs()
    controller.create_backup(restore.manifest)
    controller.stage_candidate(candidate)
    broker.queue("install_candidate", access.InstallResult(False, 4, 0, False))
    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        controller.install_candidate(candidate.manifest)
    broker.queue(
        "backup_fallback",
        access.SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_CHILD_EXITED"),
    )
    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        controller.restore_private_backup_fallback()
    monkeypatch.setattr(
        controller._journal,
        "finalize_fallback_reconciliation_from_durable_result",
        lambda **_kwargs: (_ for _ in ()).throw(SyntheticProcessLoss),
    )
    with pytest.raises(SyntheticProcessLoss):
        controller.reconcile_private_backup_fallback()
    operation = controller._journal.fallback_reconciliation_operation()
    assert operation["phase"] == "result_durable"
    controller.close()

    reconstructed, reconstructed_broker = _r33_controller()
    result = reconstructed.finalize_fallback_reconciliation_from_durable_result()
    durable_bytes = reconstructed._journal._journal_path.read_bytes()
    repeated = reconstructed.finalize_fallback_reconciliation_from_durable_result()

    assert (
        result
        == repeated
        == access.FallbackReconciliationResult("reconciled", True, True, 1)
    )
    assert reconstructed._journal._journal_path.read_bytes() == durable_bytes
    assert reconstructed_broker.calls == []
    reconstructed.close()


def test_r39_red_23_removal_restart_has_dispatch_possible_boundary() -> None:
    class SyntheticProcessLoss(BaseException):
        pass

    assert hasattr(access._DurableLifecycleJournal, "record_dispatch_possible")
    dispatch = inspect.getsource(access.FullPreflightLifecycleController._dispatch)
    assert dispatch.index("record_dispatch_possible") < dispatch.index(
        "result = callback(capability)"
    )
    controller, broker = _r32_advance_to_a2()
    _candidate, restore = _r32_bundles()
    controller.stage_restore(restore)
    controller.restore_pr41(restore.manifest)
    controller.verify_restore_inventory(restore.manifest)
    controller.check_restore_core()
    broker.queue("restart", SyntheticProcessLoss())
    with pytest.raises(SyntheticProcessLoss):
        controller.restart_for_restore()
    operation = controller._journal.restore_tail_original_operation()
    assert operation["action"] == access.LifecycleAction.REMOVAL_RESTART.value
    assert operation["phase"] == "ambiguous"
    controller.close()

    reconstructed, reconstructed_broker = _r33_controller()
    assert reconstructed._journal.restore_tail_restart_mode() == "possibly_dispatched"
    reconstructed.reconcile_restored_pr41(restore)
    assert [name for name, _ in reconstructed_broker.calls].count("restart") == 0
    reconstructed.close()


@pytest.mark.parametrize(
    "mutation",
    (
        "services_present_expected_count",
        "services_present_observed_count",
        "services_present_boolean",
        "services_absent_expected_count",
        "services_absent_observed_count",
        "services_absent_boolean",
        "inventory_expected_count",
        "inventory_observed_count",
        "inventory_manifest_boolean",
        "inventory_unexpected_count",
        "inventory_missing_count",
        "core_exception_success",
    ),
)
def test_r39_oracle_mutation_matrix_12_of_12(mutation: str, tmp_path: Path) -> None:
    controller = access.FullPreflightLifecycleController
    detections = {
        "services_present_expected_count": not controller._services_present_pass(
            access.ServiceInventoryResult(3, 4, True, 0, 0, True)
        ),
        "services_present_observed_count": not controller._services_present_pass(
            access.ServiceInventoryResult(4, 3, True, 0, 0, True)
        ),
        "services_present_boolean": not controller._services_present_pass(
            access.ServiceInventoryResult(4, 4, False, 0, 0, True)
        ),
        "services_absent_expected_count": not controller._services_absent_pass(
            access.ServiceInventoryResult(0, 0, True, 3, 4, True)
        ),
        "services_absent_observed_count": not controller._services_absent_pass(
            access.ServiceInventoryResult(0, 0, True, 4, 3, True)
        ),
        "services_absent_boolean": not controller._services_absent_pass(
            access.ServiceInventoryResult(0, 0, True, 4, 4, False)
        ),
        "inventory_expected_count": not controller._inventory_pass(
            access.SourceInventoryResult(2, 1, True, 0, 0), 1
        ),
        "inventory_observed_count": not controller._inventory_pass(
            access.SourceInventoryResult(1, 2, True, 0, 0), 1
        ),
        "inventory_manifest_boolean": not controller._inventory_pass(
            access.SourceInventoryResult(1, 1, False, 0, 0), 1
        ),
        "inventory_unexpected_count": not controller._inventory_pass(
            access.SourceInventoryResult(1, 1, True, 1, 0), 1
        ),
        "inventory_missing_count": not controller._inventory_pass(
            access.SourceInventoryResult(1, 1, True, 0, 1), 1
        ),
        "core_exception_success": _run_synthetic_remote_program(
            tmp_path,
            "core_check",
            {},
            source_replacements={
                "def core_check():\n    try:\n": (
                    "def core_check():\n    try:\n"
                    "        raise RuntimeError('synthetic_core_failure')\n"
                )
            },
        )
        == {
            "http_status": 0,
            "result": "error",
            "error_class": "REQUEST_FAILED",
        },
    }
    assert detections[mutation], mutation


def test_r39_independent_audit_counter_oracle() -> None:
    assert frozenset(access.AUDIT_COUNTER_NAMES) == _R39_AUDIT_COUNTER_ORACLE
    base = {
        "protocol_version": 1,
        "audit_instance_token": "a" * 32,
        "event_ordinal": 0,
        "history_overflow": False,
        "runtime_ms": 1,
        "counters": {name: 0 for name in _R39_AUDIT_COUNTER_ORACLE},
        "events": [],
    }
    assert dict(access._parse_audit_snapshot(base).counters) == base["counters"]
    for mutated in (
        {**base, "counters": {**base["counters"], "synthetic_extra": 0}},
        {
            **base,
            "counters": {
                name: value
                for name, value in base["counters"].items()
                if name != "disconnects"
            },
        },
    ):
        with pytest.raises(access.SessionBrokerError, match="PROTOCOL"):
            access._parse_audit_snapshot(mutated)


@pytest.mark.parametrize(
    "mutation",
    (
        "deadline_plus_epsilon",
        "residual_reuse",
        "local_duplicate_member",
        "remote_duplicate_member",
        "permissive_source_base64",
        "derived_program_digest",
        "unbounded_source_chunk_count",
        "trailing_payload_chunk",
        "missing_end_marker",
        "invalid_payload_base64",
        "manifest_extra_member",
        "manifest_entry_extra_member",
        "manifest_digest_not_hex",
        "regular_file_integer",
        "synthetic_skips_transfer_stream",
    ),
)
def test_r39_framer_mutation_matrix_15_of_15(mutation: str, tmp_path: Path) -> None:
    candidate = access.build_source_bundle(
        access.SourceState.CANDIDATE, _r30_files(), _r30_manifest()
    )
    payload = access._bundle_payload(candidate)
    if mutation == "deadline_plus_epsilon":
        source = inspect.getsource(access.PrivateInteractiveSessionBroker._read_until)
        detected = source.index("expired = time.monotonic() > deadline") < source.index(
            "return bytes(captured[:frame_index])"
        )
    elif mutation == "residual_reuse":
        source = inspect.getsource(
            access.PrivateInteractiveSessionBroker._PrivateInteractiveSessionBroker__execute_bounded_operation
        )
        detected = source.index("self._start_fresh_exchange()") < source.index(
            "self.__write_wire("
        )
    elif mutation == "local_duplicate_member":
        with pytest.raises(access.SessionBrokerError, match="PROTOCOL"):
            access._exact_payload(b'{"success":true,"success":true}')
        detected = True
    elif mutation == "remote_duplicate_member":
        files = json.dumps(payload["files"], separators=(",", ":"), sort_keys=True)
        manifest = json.dumps(
            payload["manifest"], separators=(",", ":"), sort_keys=True
        )
        raw = (
            '{"files":' + files + ',"files":' + files + ',"manifest":' + manifest + "}"
        ).encode()
        detected = _run_synthetic_remote_program(
            tmp_path, "transfer", {}, raw_payload=raw
        ) == {"error_class": "OPERATION_FAILED"}
    elif mutation == "permissive_source_base64":
        detected = "base64.b64decode(source,validate=True)" in access._CONTROL_BOOTSTRAP
    elif mutation == "derived_program_digest":
        detected = (
            hashlib.sha256(access._REMOTE_CONTROL_PROGRAM.encode()).hexdigest()
            == access._CONTROL_PROGRAM_DIGEST
            and "hashlib.sha256"
            not in inspect.getsource(access)[
                inspect.getsource(access)
                .index("_CONTROL_PROGRAM_DIGEST =") : inspect.getsource(access)
                .index("_CONTROL_BOOTSTRAP =")
            ]
        )
    elif mutation == "unbounded_source_chunk_count":
        detected = "assert 1<=count<=256" in access._CONTROL_BOOTSTRAP
    elif mutation == "trailing_payload_chunk":
        detected = _run_synthetic_remote_program(
            tmp_path,
            "transfer",
            payload,
            payload_extra_chunks=("c3ludGhldGlj",),
        ) == {"error_class": "OPERATION_FAILED"}
    elif mutation == "missing_end_marker":
        detected = _run_synthetic_remote_program(
            tmp_path, "transfer", payload, end_marker=None
        ) == {"error_class": "OPERATION_FAILED"}
    elif mutation == "invalid_payload_base64":
        detected = _run_synthetic_remote_program(
            tmp_path, "transfer", payload, payload_encoded_override="***"
        ) == {"error_class": "OPERATION_FAILED"}
    elif mutation == "manifest_extra_member":
        mutated = copy.deepcopy(payload)
        mutated["manifest"]["synthetic_extra"] = True
        detected = _run_synthetic_remote_program(tmp_path, "transfer", mutated) == {
            "error_class": "OPERATION_FAILED"
        }
    elif mutation == "manifest_entry_extra_member":
        mutated = copy.deepcopy(payload)
        mutated["manifest"]["entries"][0]["synthetic_extra"] = True
        detected = _run_synthetic_remote_program(tmp_path, "transfer", mutated) == {
            "error_class": "OPERATION_FAILED"
        }
    elif mutation == "manifest_digest_not_hex":
        manifest = _r30_manifest()
        first = manifest.entries[0]
        mutated = access.SourceManifest(
            manifest.state,
            (
                access.SourceManifestEntry(first.relative_path, first.size, "g" * 64),
                *manifest.entries[1:],
            ),
        )
        with pytest.raises(access.SourceBundleError):
            access.build_source_bundle(
                access.SourceState.CANDIDATE, _r30_files(), mutated
            )
        detected = True
    elif mutation == "regular_file_integer":
        files = list(_r30_files())
        first = files[0]
        files[0] = access.SourceBundleFile(
            first.relative_path, first.content, regular_file=1
        )
        with pytest.raises(access.SourceBundleError, match="REGULAR_FILES_ONLY"):
            access.build_source_bundle(
                access.SourceState.CANDIDATE, files, _r30_manifest()
            )
        detected = True
    else:
        result = _run_synthetic_remote_program(tmp_path, "transfer", payload)
        detected = result == {
            "success": True,
            "file_count": len(candidate.files),
            "manifest_match": True,
            "regular_files_only": True,
        }
    assert detected, mutation
