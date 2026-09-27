#!/usr/bin/env bash
# Offline validation profile shared by local work and CI. See docs/validation.md.
set -u -o pipefail

PROFILE=(black codespell pytest json yaml actionlint gitleaks diff)
MANIFEST=custom_components/tuya_ble/manifest.json

usage() {
    cat <<'EOF'
Usage: scripts/check.sh [--python PATH] [--only CHECK[,CHECK...]] [--diff-base REV]
       scripts/check.sh --list

Runs the complete offline profile unless --only selects a subset.

  --python PATH    Interpreter for black, codespell, pytest, JSON, and YAML
                   (default: $TUYA_BLE_CHECK_PYTHON, then <repo>/.venv/bin/python).
  --only LIST      Comma-separated subset of the profile checks.
  --diff-base REV  Check whitespace in the committed range REV..HEAD instead of
                   staged, unstaged, and untracked changes. Required in CI.
  --list           Print the profile checks and exit.

Exit codes: 0 all selected checks PASS or N/A, 1 at least one FAIL,
2 no FAIL but at least one NOT RUN, 64 usage error.
EOF
}

python_arg=""
only_arg=""
diff_base=""
while (($#)); do
    case $1 in
    --python | --only | --diff-base)
        if (($# < 2)) || [[ -z $2 ]]; then
            echo "check.sh: $1 requires a value" >&2
            exit 64
        fi
        case $1 in
        --python) python_arg=$2 ;;
        --only) only_arg=$2 ;;
        --diff-base) diff_base=$2 ;;
        esac
        shift 2
        ;;
    --list)
        printf '%s\n' "${PROFILE[@]}"
        exit 0
        ;;
    -h | --help)
        usage
        exit 0
        ;;
    *)
        echo "check.sh: unknown argument: $1" >&2
        usage >&2
        exit 64
        ;;
    esac
done

in_profile() {
    local check
    for check in "${PROFILE[@]}"; do
        [[ $check == "$1" ]] && return 0
    done
    return 1
}

SELECTED=()
partial=0
if [[ -n $only_arg ]]; then
    IFS=, read -r -a requested <<<"$only_arg"
    for check in "${requested[@]}"; do
        if ! in_profile "$check"; then
            echo "check.sh: unknown check: $check (see --list)" >&2
            exit 64
        fi
    done
    for check in "${PROFILE[@]}"; do
        for wanted in "${requested[@]}"; do
            if [[ $check == "$wanted" ]]; then
                SELECTED+=("$check")
                break
            fi
        done
    done
    ((${#SELECTED[@]} < ${#PROFILE[@]})) && partial=1
else
    SELECTED=("${PROFILE[@]}")
fi

# Resolve the interpreter before leaving the caller's working directory.
PY=""
PY_SOURCE="none"
if [[ -n $python_arg ]]; then
    PY=$python_arg
    PY_SOURCE="--python"
elif [[ -n ${TUYA_BLE_CHECK_PYTHON:-} ]]; then
    PY=$TUYA_BLE_CHECK_PYTHON
    PY_SOURCE="TUYA_BLE_CHECK_PYTHON"
fi
if [[ -n $PY && $PY != */* ]]; then
    PY=$(command -v -- "$PY" || echo "$PY")
elif [[ -n $PY && $PY != /* ]]; then
    PY="$(cd -- "$(dirname -- "$PY")" 2>/dev/null && pwd)/$(basename -- "$PY")"
fi

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
if ! ROOT=$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null); then
    echo "check.sh: $SCRIPT_DIR is not inside a Git work tree" >&2
    exit 64
fi
cd -- "$ROOT" || exit 64

if [[ $PY_SOURCE == none && -x $ROOT/.venv/bin/python ]]; then
    PY=$ROOT/.venv/bin/python
    PY_SOURCE="default <repo>/.venv"
fi
PY_OK=0
PY_VERSION=""
if [[ -n $PY && -x $PY ]] &&
    PY_VERSION=$("$PY" -c 'import sys; print(sys.version.split()[0])' 2>/dev/null); then
    PY_OK=1
fi

WORK=$(mktemp -d)
trap 'rm -rf -- "$WORK"' EXIT

# Scope: tracked plus untracked, non-ignored regular files; never virtualenvs.
list_scope() {
    git ls-files -z "$@" --exclude-standard | sort -zu |
        while IFS= read -r -d '' path; do
            case $path in
            .venv*/* | venv*/*) continue ;;
            esac
            [[ -f $path && ! -L $path ]] && printf '%s\0' "$path"
        done
}
mapfile -d '' -t SCOPE < <(list_scope --cached --others)
mapfile -d '' -t UNTRACKED < <(list_scope --others)

scope_matching() {
    local path pattern
    for path in "${SCOPE[@]}"; do
        for pattern in "$@"; do
            # shellcheck disable=SC2053
            if [[ $path == $pattern ]]; then
                printf '%s\0' "$path"
                break
            fi
        done
    done
}

declare -A STATUS REASON
record() {
    STATUS[$1]=$2
    REASON[$1]=${3:-}
}

is_ci() {
    [[ ${CI:-} == true || ${GITHUB_ACTIONS:-} == true ]]
}

need_python() {
    if ((PY_OK == 0)); then
        record "$1" "NOT RUN" "no usable interpreter; pass --python"
        return 1
    fi
    if [[ -n ${2:-} ]] && ! "$PY" -c "import $2" >/dev/null 2>&1; then
        record "$1" "NOT RUN" "module $2 is not importable by the interpreter"
        return 1
    fi
}

resolve_tool() {
    local override=${!1:-}
    if [[ -n $override ]]; then
        [[ -x $override ]] && echo "$override"
        return
    fi
    command -v -- "$2"
}

check_black() {
    need_python black black || return
    if "$PY" -m black --check --diff custom_components; then
        record black PASS
    else
        record black FAIL "formatting differences or black error"
    fi
}

check_codespell() {
    need_python codespell codespell_lib || return
    if "$PY" -m codespell_lib -- "${SCOPE[@]}"; then
        record codespell PASS
    else
        record codespell FAIL "spelling findings or codespell error"
    fi
}

check_pytest() {
    need_python pytest pytest || return
    if "$PY" -m pytest; then
        record pytest PASS
    else
        record pytest FAIL "test failures or collection error"
    fi
}

IFS= read -r -d '' JSON_CHECK <<'PYCODE'
import json
import sys


def reject_duplicates(pairs):
    keys = [key for key, _ in pairs]
    duplicates = sorted({key for key in keys if keys.count(key) > 1})
    if duplicates:
        raise ValueError("duplicate key(s): " + ", ".join(duplicates))
    return dict(pairs)


failed = 0
for name in sys.argv[1:]:
    indent = 4 if name.endswith("/strings.json") or "/translations/" in name else 2
    try:
        with open(name, encoding="utf-8") as handle:
            text = handle.read()
        data = json.loads(text, object_pairs_hook=reject_duplicates)
    except (OSError, UnicodeDecodeError, ValueError) as err:
        print(f"{name}: invalid JSON: {err}")
        failed += 1
        continue
    if text != json.dumps(data, indent=indent, ensure_ascii=False) + "\n":
        print(f"{name}: not canonical ({indent}-space indent, UTF-8, final newline)")
        failed += 1
print(f"{len(sys.argv) - 1} JSON file(s) checked, {failed} failed")
sys.exit(1 if failed else 0)
PYCODE

check_json() {
    need_python json || return
    local files
    mapfile -d '' -t files < <(scope_matching hacs.json 'custom_components/*.json')
    local missing=1 path
    for path in "${files[@]}"; do
        [[ $path == "$MANIFEST" ]] && missing=0
    done
    if ((missing)); then
        record json FAIL "required $MANIFEST is missing"
        return
    fi
    if "$PY" -c "$JSON_CHECK" "${files[@]}"; then
        record json PASS
    else
        record json FAIL "invalid or non-canonical JSON"
    fi
}

IFS= read -r -d '' YAML_CHECK <<'PYCODE'
import sys

import yaml

failed = 0
for name in sys.argv[1:]:
    try:
        with open(name, encoding="utf-8") as handle:
            list(yaml.safe_load_all(handle))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as err:
        print(f"{name}: invalid YAML: {err}")
        failed += 1
print(f"{len(sys.argv) - 1} YAML file(s) checked, {failed} failed")
sys.exit(1 if failed else 0)
PYCODE

check_yaml() {
    local files
    mapfile -d '' -t files < <(scope_matching '*.yml' '*.yaml')
    if ((${#files[@]} == 0)); then
        record yaml N/A "no YAML files in scope"
        return
    fi
    need_python yaml yaml || return
    if "$PY" -c "$YAML_CHECK" "${files[@]}"; then
        record yaml PASS
    else
        record yaml FAIL "invalid YAML"
    fi
}

check_actionlint() {
    local files tool integration="shellcheck not available; run: scripts were not shellchecked"
    mapfile -d '' -t files < <(scope_matching '.github/workflows/*.yml' '.github/workflows/*.yaml')
    if ((${#files[@]} == 0)); then
        record actionlint N/A "no workflow files in scope"
        return
    fi
    if ! tool=$(resolve_tool ACTIONLINT actionlint); then
        record actionlint "NOT RUN" "actionlint not found; set ACTIONLINT or add it to PATH"
        return
    fi
    if [[ -n $SHELLCHECK_TOOL ]]; then
        integration="with shellcheck"
    fi
    if "$tool" "-shellcheck=$SHELLCHECK_TOOL" "${files[@]}"; then
        record actionlint PASS "$integration"
    else
        record actionlint FAIL "workflow findings or actionlint error; $integration"
    fi
}

IFS= read -r -d '' GITLEAKS_SUMMARY <<'PYCODE'
import json
import sys

root = sys.argv[2].rstrip("/") + "/"
with open(sys.argv[1], encoding="utf-8") as handle:
    findings = json.load(handle)
for finding in findings:
    path = str(finding.get("File", "?")).removeprefix(root)
    print(f"  {finding.get('RuleID', '?')} {path}:{finding.get('StartLine', '?')}")
PYCODE

check_gitleaks() {
    local tool
    if ! tool=$(resolve_tool GITLEAKS gitleaks); then
        record gitleaks "NOT RUN" "gitleaks not found; set GITLEAKS or add it to PATH"
        return
    fi
    local copy=$WORK/gitleaks-scope report=$WORK/gitleaks.json
    mkdir -p "$copy"
    if ! printf '%s\0' "${SCOPE[@]}" | tar --null -T - -cf - | tar -xf - -C "$copy"; then
        record gitleaks FAIL "could not copy the scoped files"
        return
    fi
    "$tool" dir "$copy" --redact --no-banner --log-level error \
        --report-format json --report-path "$report" --exit-code 1 >/dev/null
    local rc=$?
    case $rc in
    0) record gitleaks PASS ;;
    1)
        # Print only rule, path, and line; never the secret or match text.
        echo "gitleaks findings (redacted):"
        if ! { ((PY_OK)) && "$PY" -c "$GITLEAKS_SUMMARY" "$report" "$copy"; }; then
            echo "  $(grep -o '"RuleID"' "$report" 2>/dev/null | wc -l) finding(s); details suppressed"
        fi
        record gitleaks FAIL "potential secrets found"
        ;;
    *) record gitleaks FAIL "gitleaks error (exit $rc)" ;;
    esac
}

# Adds $1's output to the problem report; returns 1 on a git error.
diff_step() {
    local out rc
    out=$("${@:2}" 2>&1)
    rc=$?
    if ((rc >= 128)); then
        printf '%s\n' "$out"
        return 1
    fi
    if [[ -n $out ]]; then
        printf '%s (%s):\n%s\n' "whitespace problems" "$1" "$out"
        diff_problems=1
    fi
}

check_diff() {
    diff_problems=0
    if [[ -n $diff_base ]]; then
        if ! git rev-parse --verify --quiet "$diff_base^{tree}" >/dev/null; then
            record diff "NOT RUN" "diff base is not available; fetch the history"
            return
        fi
        diff_step "committed range" git diff --check "$diff_base" HEAD -- ||
            { record diff FAIL "git error"; return; }
    elif is_ci; then
        record diff "NOT RUN" "CI requires --diff-base"
        return
    else
        diff_step "unstaged" git diff --check -- ||
            { record diff FAIL "git error"; return; }
        diff_step "staged" git diff --cached --check -- ||
            { record diff FAIL "git error"; return; }
        local path
        for path in "${UNTRACKED[@]}"; do
            diff_step "untracked $path" git diff --no-index --check -- /dev/null "$path" ||
                { record diff FAIL "git error"; return; }
        done
    fi
    if ((diff_problems)); then
        record diff FAIL "whitespace problems"
    else
        record diff PASS
    fi
}

module_versions() {
    ((PY_OK)) || return
    "$PY" - <<'PYCODE' 2>/dev/null
from importlib import metadata

names = ("black", "codespell", "pytest", "PyYAML", "homeassistant",
         "pytest-homeassistant-custom-component")
parts = []
for name in names:
    try:
        parts.append(f"{name} {metadata.version(name)}")
    except metadata.PackageNotFoundError:
        parts.append(f"{name} missing")
print("Python packages: " + ", ".join(parts))
PYCODE
}

tool_version() {
    local tool
    if tool=$(resolve_tool "$1" "$2"); then
        echo "$2: $tool ($("$tool" "$3" 2>/dev/null | head -n 1))"
    else
        echo "$2: missing"
    fi
}

echo "Tuya BLE offline check"
echo "Repository: $ROOT"
echo "Head: $(git rev-parse HEAD 2>/dev/null || echo none)"
echo "Checks: ${SELECTED[*]}"
if ((PY_OK)); then
    echo "Interpreter: $PY (Python $PY_VERSION; selected by $PY_SOURCE)"
else
    echo "Interpreter: none usable (${PY:-not set}; selected by $PY_SOURCE)"
fi
module_versions
tool_version ACTIONLINT actionlint -version
tool_version GITLEAKS gitleaks version
# Optional actionlint integrations; an empty -shellcheck= disables a missing one explicitly.
SHELLCHECK_TOOL=$(resolve_tool SHELLCHECK shellcheck || true)
if [[ -n $SHELLCHECK_TOOL ]]; then
    echo "shellcheck: $SHELLCHECK_TOOL ($("$SHELLCHECK_TOOL" --version 2>/dev/null | sed -n 's/^version: //p'))"
else
    echo "shellcheck: missing (optional actionlint integration)"
fi
echo "pyflakes: $(command -v pyflakes || echo missing) (optional actionlint integration, from PATH)"
if [[ -n ${PYTEST_ADDOPTS:-} && " ${SELECTED[*]} " == *" pytest "* ]]; then
    echo "PYTEST_ADDOPTS: $PYTEST_ADDOPTS"
fi
if [[ -n $diff_base ]]; then
    echo "Diff scope: committed range $diff_base..HEAD"
else
    echo "Diff scope: staged, unstaged, and untracked changes"
fi

for check in "${SELECTED[@]}"; do
    echo
    echo "==> $check"
    "check_$check"
    [[ -n ${STATUS[$check]:-} ]] || record "$check" FAIL "internal error: no result recorded"
done

failed=0
not_run=0
echo
echo "Summary"
for check in "${SELECTED[@]}"; do
    reason=${REASON[$check]}
    printf '  %-8s %s%s\n' "${STATUS[$check]}" "$check" "${reason:+ ($reason)}"
    case ${STATUS[$check]} in
    FAIL) failed=$((failed + 1)) ;;
    "NOT RUN") not_run=$((not_run + 1)) ;;
    esac
done
echo "Not evaluated by this run (never counted as passed):"
if ((partial)); then
    for check in "${PROFILE[@]}"; do
        [[ " ${SELECTED[*]} " == *" $check "* ]] || printf '  %-8s %s\n' "NOT RUN" "$check (not selected)"
    done
fi
printf '  %-8s %s\n' "NOT RUN" "hacs, hassfest (CI only: validate-hacs job)"
if [[ -z $SHELLCHECK_TOOL && " ${SELECTED[*]} " == *" actionlint "* && ${STATUS[actionlint]} != N/A ]]; then
    printf '  %-8s %s\n' "NOT RUN" "shellcheck of workflow run: scripts (optional; shellcheck not found)"
fi
printf '  %-8s %s\n' "NOT RUN" "hardware and deployment validation (docs/live-validation.md)"

if ((failed)); then
    echo "Result: FAIL ($failed failed, $not_run not run; exit 1)"
    exit 1
fi
if ((not_run)); then
    echo "Result: INCOMPLETE ($not_run required check(s) not run; exit 2)"
    exit 2
fi
if ((partial)); then
    echo "Result: PASS for the selected checks only; not a complete offline profile (exit 0)"
else
    echo "Result: PASS for the complete offline profile (exit 0)"
fi
echo "This is neither hardware validation nor release approval."
exit 0
