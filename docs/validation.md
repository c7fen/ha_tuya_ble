# Validation

`scripts/check.sh` is the single offline validation contract for local work
and CI. It makes no code corrections, installs nothing, and performs no network,
Home Assistant, Bluetooth, or hardware access.

```bash
scripts/check.sh --python /path/to/ci-base/bin/python
```

The script works from any working directory and from any linked worktree; it
always checks the Git work tree that contains it.

## Offline profile

The default run executes every check in the profile. `--only` selects a subset
(CI uses this to keep its parallel jobs), and `--list` prints the profile.

| Check | Scope | Tool |
| --- | --- | --- |
| `black` | `custom_components/`, filtered by `[tool.black]` in `pyproject.toml` | Black, check mode |
| `codespell` | All files in scope, filtered by `[tool.codespell]` | Codespell |
| `pytest` | The complete suite in `tests/` | pytest |
| `json` | `hacs.json` and `custom_components/**/*.json`; the manifest is required | Standard library |
| `yaml` | Every `*.yml` and `*.yaml` file in scope | PyYAML `safe_load_all` |
| `actionlint` | `.github/workflows/*.yml` | actionlint, with optional shellcheck and pyflakes integration |
| `gitleaks` | A temporary copy of all files in scope | Gitleaks `dir`, redacted |
| `diff` | See [Diff scope](#diff-scope) | `git diff --check` |

JSON must parse without duplicate keys and match the repository format:
UTF-8 without escaping, a final newline, and 4-space indentation for
`strings.json` and `translations/*.json` and 2-space indentation for other
files.

**Files in scope** are tracked files plus untracked files that Git does not
ignore, so new files are checked before they are staged. Ignored files,
`.venv*/` and `venv*/` directories, symlinks, other worktrees, and files outside
the repository are never read. Keep private local files ignored, for example
through `.git/info/exclude`.

Gitleaks runs with `--redact`. The script prints only the rule, path, and line
of each finding and never the secret or matched text. There is no allowlist or
baseline; resolve a finding instead of suppressing it.

### Diff scope

- **Local default:** unstaged changes (`git diff --check`), staged changes
  (`git diff --cached --check`), and every untracked file in scope.
- **`--diff-base REV`:** only the committed range `REV..HEAD`.
- **CI:** `--diff-base` is required. Without it, the check is NOT RUN because
  an empty checkout diff proves nothing. Pull requests use the base commit,
  pushes use the previous tip, and manual runs use the empty tree, which checks
  the whole tree.

## Results

| State | Meaning |
| --- | --- |
| PASS | Executed and passed. |
| FAIL | Executed and failed. |
| NOT RUN | Not executed; the reason is printed. |
| N/A | Not applicable to the computed scope, for example no YAML files. |

The script assigns N/A only from the computed scope; no option marks a check
N/A. A missing interpreter, module, or tool makes that check NOT RUN, never
PASS. Independent checks still run and report their own results.

| Exit code | Overall result |
| --- | --- |
| 0 | Every selected check is PASS or N/A. |
| 1 | At least one check is FAIL. |
| 2 | No FAIL, but at least one selected check is NOT RUN (incomplete). |
| 64 | Usage error. |

With `--only`, exit code 0 covers only the selected checks. The summary lists
the unselected checks as NOT RUN.

The summary always lists HACS, Hassfest, and hardware/deployment validation as
NOT RUN. HACS and Hassfest run only in CI (`validate-hacs` in
`.github/workflows/ci.yml`). Hardware and deployment validation need separate
approval; see [Live validation and hardware evidence](live-validation.md). A
passing offline profile is neither hardware validation nor release approval.
A local run of a changed workflow is not a CI result; only a GitHub Actions run
on the exact head is.

Shellcheck is not a separate required check. When it is unavailable, the
`actionlint` result says that `run:` scripts were not shellchecked and the
summary lists that shellcheck as NOT RUN, so an actionlint PASS without it is
never evidence for shellcheck.

## Interpreter and tools

The interpreter runs Black, Codespell, pytest, and the JSON and YAML checks. It
is selected in this order:

1. `--python PATH`
2. `TUYA_BLE_CHECK_PYTHON`
3. `<repository>/.venv/bin/python`, if present

An activated virtual environment is not used implicitly. A linked worktree
normally has no `.venv`, so pass `--python` there. The header prints the
interpreter, the Python package versions, the tool paths and versions, the
exact head, and the diff scope.

actionlint and Gitleaks are resolved from `ACTIONLINT` and `GITLEAKS` if set,
otherwise from `PATH`. CI pins their versions in the `env` block of
`.github/workflows/ci.yml` and builds them with `go install`; use the same
versions locally. Gitleaks must support the `dir` command (8.19 or later).
Gitleaks builds without version metadata print a placeholder version.

actionlint uses shellcheck from `SHELLCHECK` or `PATH` and pyflakes from `PATH`
when present; the header prints both. Neither is installed by CI. Whether the
GitHub runner image provides them is visible only in the header of a CI run.

The CI pytest job sets `PYTEST_ADDOPTS=--cov --disable-warnings -s` for
coverage collection and output; it has no coverage threshold. The header prints
`PYTEST_ADDOPTS` whenever it is set, because options there also change the
local pytest run.

## Test environments

| Role | Definition |
| --- | --- |
| CI base | Python from `PY_VERSION` in `.github/workflows/ci.yml` with `requirements_test.txt` installed. This is the reference for offline results. |
| Target runtime | No separate compatibility environment is defined in this repository. The Home Assistant runtime is its own Python and Home Assistant version; offline results do not establish compatibility with it. |

`requirements_test.txt` pins some packages exactly, including Home Assistant,
Black, and Codespell. Others, such as pytest-asyncio, pytest-cov, pyserial,
PyCryptodome, and tuya-device-sharing-sdk, are unpinned, and
pytest-homeassistant-custom-component and pycountry have only lower bounds.
Two CI-base environments created at different times can therefore differ.
Report the header of the run with each result. A result from another interpreter, such as a local
compatibility environment, is reported separately with its own header and
never substitutes for the CI base.
