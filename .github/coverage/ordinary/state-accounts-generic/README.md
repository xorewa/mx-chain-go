# Optional state/accounts generic DTO diagnostic

This static census binds the 11 previously reviewed Lane B/C display, getter
and size test roots (37 functions / 229 statements), all present at the signed
source census candidate in `census.json`. It is **not** a direct standard-token
coverage denominator, a product test runner, or a qualification gate. The
published EF8 hosted profile omitted this package. Historical local results
must not be relabelled as hosted or as a fresh combined run.

The adapter is offline and read-only with respect to source. It validates
source, test and lock hashes, independently retained mode receipts and event
streams, then delegates profile/source/declaration/block validation to the
existing `.github/coverage/ordinary` reporter (built by its authorized caller).
It does not build that reporter or launch any Go/product test. A future caller
must preserve the actual outer execution envelope, tool/module graph and raw
results separately; this adapter does not establish execution authority, graph
provenance, or the authenticity of a claimed receipt.

For each mode supply the untouched atomic profile, its raw `go test -json`
stream and an execution binding with `candidate`, `common`, `exit`, `argv`,
`stdout_sha256` and `profile_sha256`. `argv` is the exact inner Go command from
that retained execution, not a command for this adapter to execute. The
census's anchored selector, exact package and fixed ordinary test options
are verified; `-race` is the only mode delta. The accepted options are
`-mod=readonly -p=2 -short -count=1 -timeout=120s -covermode=atomic
-coverprofile=<file> -run <exact selector> -json`, with `-race` for race only.
All 11 root terminals and the retained named subtest terminals must pass.
The candidate must equal HEAD at the supplied source root. Source pin changes
require a new reviewed census, not a silent refresh.

Example (paths refer to already-produced evidence, not to an invocation grant):

```sh
python3 -B .github/coverage/ordinary/state-accounts-generic/diagnostic.py \
  --source-root . --reporter ./ordinary-reporter --output ./new-diagnostic \
  --normal-profile normal.cover --normal-events normal.json --normal-receipt normal-receipt.json \
  --race-profile race.cover --race-events race.json --race-receipt race-receipt.json
```

`summary.json` records mode-specific status, profile/receipt/manifest/report
hashes and complete counts only when observed. A mode with no inputs is
`profile_absent` (null aggregate); a missing companion, unavailable reporter,
wrong source or invalid receipt/report remains null, with nonzero adapter
status. A valid incomplete profile is `partial` (null complete aggregate),
while measured zero is numeric. Per-function `*.report.json` and bound
`*.manifest.json` are separate for each mode. Do not use this optional
summary as a gate, merge modes, or upload any raw argv, output, module metadata,
or local paths. No workflow or mandatory coverage behavior is changed here.
