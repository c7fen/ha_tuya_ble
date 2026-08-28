# Release policy

## Current manual policy

Release Please is intentionally disabled. The repository uses canonical
`v`-prefixed annotated tags and manually gated GitHub releases. No workflow may
publish merely because `next` is merged into `main`.

The first stable `v0.9.0` release is a controlled manual cutover. Until its
runtime, privacy, documentation, HACS, and hardware gates pass, `main` and the
default branch remain unchanged and beta releases are prepared from `next`.

For each release:

1. Create a release branch from the authorized exact base.
2. Change only the manifest version, changelog, release assertions, and other
   explicitly authorized metadata unless the release includes a separately
   reviewed runtime PR.
3. Run the complete validation matrix and obtain a fresh exact-head review.
4. Merge with a merge commit; do not rebase, amend, force-push, or move an
   existing tag.
5. Create an annotated `v`-prefixed tag from the exact reviewed merge target.
6. Publish the GitHub release with the intended prerelease/latest flags and no
   unexpected assets.
7. Verify the generated source archives and HACS visibility.

Version changes must never cause a duplicate release or a downgrade. Published
tag history is immutable.

## Release attestation mode

Ordinary feature pull requests run the always-on repository safety checks.
Immutable published-release snapshot assertions run only in release-attestation
mode. For local release preparation, run:

```bash
TUYA_BLE_RELEASE_ATTESTATION=1 pytest -q tests/test_release_metadata.py
```

GitHub pull requests whose head branch starts with `release/` and GitHub
contexts whose ref starts with `refs/tags/v` activate the same assertions
automatically. A feature branch must never update the last published release
digest merely to make ordinary development pass.

## Future automation

Release automation may return only in a dedicated, reviewed pull request after
the first stable 0.9 release. It must import the exact current stable version,
emit canonical `v`-prefixed tags, remain manual until explicitly enabled, and
prove that the first run cannot recreate, downgrade, or publish an existing
release. A write-capable workflow must not be introduced as part of an ordinary
development-to-stable merge.
