# Optional Common65 direct-display diagnostic

Run only after the existing pinned dependency download, from the Node module
root, inside the same offline test enclosure as the existing test jobs:

    python3 -B .github/coverage/ordinary/common-direct/diagnostic.py --output common-direct-report

The helper uses the existing Node-effective Common replacement and exact
Go 1.26.2. It refuses unavailable or mismatched cached inputs; no fallback
network or module graph is used. It verifies the replacement, locked hashes,
archive and extracted bytes before running the published nominal
TestComputeTokenIdentifier and TestExtractTokenAndNonce roots only.

Normal and race each have their own atomic profile, raw test events, digest,
function manifest and optional reporter output. The checked-in census is
independent of observed hits: two functions, eight compiler blocks, 14
statements. A missing or incomplete mode has null complete counts; the helper
returns nonzero for an unavailable or incomplete mode. The output directory
must be new. Retain raw and result.json even if the optional diagnostic fails.

This is not the Common main-module dependency graph, full standard-token
scope, or a qualification result. Do not substitute the Node coverage.out
or the compiler census itself for an actual Common coverage artifact. The
mandatory hybrid gate and its primary profile are untouched.

## Portable CI artifacts

CI uses `run-portable.sh` to allocate a fresh output directory for each attempt
and publishes **only** that attempt's portable directory, not its parent. If
staging fails, no upload path is emitted. Earlier results are left unchanged.
If the current summary is absent, only a current unavailable/null summary is
published and the attempt retains a nonzero exit. A completed current summary
and its diagnostic exit are preserved, including partial nonzero results.
For local runs, upload **only** `common-direct-report/portable/`.
The portable roster is `summary.json` plus `normal.cover`,
`normal.manifest.json`, `normal.report.json` and their `race`
counterparts when that mode has a validated measurement. Profiles are copied
byte-for-byte only after their module-relative filenames and hashes match.
Manifests and reports contain only pinned source-relative coordinates and
typed measurement fields. Missing or nonportable inputs remain unavailable,
with null counts and no raw error text. A separate mode test exit, when
available, is retained without command arguments.

Raw module metadata, test and reporter streams, command receipts, the original
result, and the reporter executable remain in the parent output directory for
local inspection. None is part of the portable upload roster.
