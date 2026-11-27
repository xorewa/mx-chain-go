# Optional isolated file-list profile portability

This helper does not execute tests or alter any coverage gate. It only
converts exact profile filenames from the four reviewed ordinary file-list
diagnostic groups. The original raw profile stays local.

| Group | Exact file-list source with coverage blocks |
| --- | --- |
| assessment_existing | cmd/assessment/benchmarks/results.go |
| assessment_report_boundary | cmd/assessment/benchmarks/results.go |
| host_display_wrap | common/hostParameters/hostInfo.go |
| memory_display_units | common/statistics/osLevel/memStats.go |

Node paths must be the exact absolute checkout path joined with the reviewed
source-relative filename. The output uses the immutable module import prefix
and source-relative suffix (no checkout prefix). For memory only, seventeen
exact Core import filenames are retained unchanged and counted separately.
Unknown filenames, incomplete file rosters, malformed blocks and duplicate
coordinates fail closed. Coordinates, statement counts, counters and row order
are preserved. No inferred counts or omission of unreviewed rows.

After a successful **separate** exact named-event receipt for
`command-line-arguments`, call from the checkout root, with distinct raw and
portable directories for each group and execution mode:

```sh
python3 -B .github/coverage/ordinary/file-list-portable/normalize.py \
  --profile "$raw_profile" --checkout "$(pwd -P)" \
  --group "$group" --mode "$mode" --output "$new_portable_dir"
```

Only on exit zero may the caller include the two explicit portable files
`coverage.cover` and `receipt.json`. Never upload the raw profile, raw events,
checkout paths, or the surrounding directory. The helper does not establish
the authenticity of the input profile or test run: the caller must bind the
candidate, exact file list, named-test receipt, toolchain, source blobs and
module locks independently. In particular the Core roster is conditional on
the reviewed v1.5.1 lock; a different compiler/lock/source roster requires
review, not a relaxed match. The mode label is caller-provided; do not use
one mode's raw profile for the other mode. Output is diagnostic only, not a
source census, qualification result or input to the hybrid gate.

In the `ordinary-named` CI job, normal and race are separate attempts. The
workflow allocates a fresh results directory under `RUNNER_TEMP` and uploads
only that attempt's curated `portable/` directory, provided the isolation
preflight and allocation succeeded and a directory output was supplied. The
runner retains raw
`<group>.raw.cover`, raw `<group>.events.jsonl`, and normalization scratch
outside `portable/`; retained local historical copies are not current uploads.

For each successfully verified and normalized file-list group, the runner
copies the three portable files as `<group>.cover`,
`<group>.normalization.json`, and `<group>.named-receipt.json`. It records
four separate phase status files, `<group>.test.exit`,
`<group>.receipt.exit`, `<group>.profile.exit`, and
`<group>.publish.exit`. Profile and publication status start at 2 when the
phase has not been attempted. If a group fails, the runner does not publish an incomplete profile/receipt set; it
retains the available phase statuses and other groups' successful artifacts.
An absent attempt or unavailable profile is not a measured zero. These
portable files remain scoped diagnostic evidence, not qualification or
hybrid-gate input.

Synthetic-only checks: from this directory, run
`python3 -B -m unittest -v test_normalize.py`. No product execution.
