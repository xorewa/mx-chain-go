# Optional coverage-profile package report

This is a read-only, opt-in report over a single Go cover profile. It is
separate from the mandatory hybrid diff coverage tool and does not adopt a
package scope, change CI, apply exceptions, or make a qualification decision.

Supply exact, whitespace-separated package import paths, matching the directory
part of each Go profile filename. For example, with a toy profile:

```sh
go run ./.github/coverage/ordinary -profile toy.out \
  -packages 'example.invalid/toy/alpha example.invalid/toy/beta' > report.json
```

The report contains the covered and total statements for each requested package,
using Go's profile block statement counts and positive hit counts. It reports:

- `measured` with numeric counts, including measured zero, when that exact
  package has profile records;
- `package_absent` with null counts if the supplied profile has no records for
  that package;
- `profile_absent` with null counts when no profile was supplied or the named
  profile was not found.

`observed_statements` sums only the measured packages. `aggregate_statements`
is null unless all requested packages have profile records. A measured `0/0`
does not establish a percentage. Malformed profiles and invalid or duplicate
package lists return an error rather than a report. The report includes the
profile mode and SHA-256 of the exact profile bytes when present.

### Optional expected-file manifest

To check presence of specifically expected source files, supply a separate
text file of whitespace-separated, exact profile filenames (package import
path plus Go filename). For example, `toy-files.txt` can contain:

```text
example.invalid/toy/alpha/one.go
example.invalid/toy/beta/one.go
```

```sh
go run ./.github/coverage/ordinary -profile toy.out \
  -packages 'example.invalid/toy/alpha example.invalid/toy/beta' \
  -manifest toy-files.txt
```

Every requested package must have at least one expected file. A missing or
empty manifest file, or a malformed, duplicate, or out-of-scope entry, is an
error, not a coverage result. The optional `manifest` object records the exact
manifest SHA-256, expected file count, missing filenames in manifest order,
and whether every expected file has a profile record. Without a profile,
all expected files are unobserved. When even one expected file is missing,
`aggregate_statements` is null, even if all requested packages are present.
Observed counts remain available; a file with recorded zero hits is present,
not missing. Additional recorded files in requested packages still contribute
to those packages' observed counts; the manifest checks presence rather than
filtering or asserting an exhaustive census. Without `-manifest`, the JSON
shape and package-only aggregation behavior are unchanged.

Package presence alone does not establish that every build-mode file or
statement was instrumented. The caller remains responsible for a reviewed
scope, compiler/source census, applicable ordinary test roster, receipt binding
and any qualification or CI gate. The DRWA coverage workflow publishes this
optional report as a diagnostic only; no coverage policy or threshold consumes it.

### Optional source-bound function report

For a caller-reviewed function/block census, use `-functions functions.json`
with `-source-root /path/to/exact/source`. This mode is separate from
`-packages` and `-manifest`. The JSON manifest requires `profile_sha256`
(the expected profile digest) and a nonempty `functions` array. Each entry
contains:

- `source`: relative Go filename beneath the source root;
- `source_sha256`: lowercase SHA-256 of the exact source bytes;
- `profile_file`: exact filename in the Go profile;
- `name` and `span`: declaration name and `[startLine,startColumn,endLine,endColumn]`
  (Go parser coordinates, end exclusive);
- `blocks`: explicit compiler block census, each with `start` and `end`
  `[line,column]` coordinates and `statements` count.

```sh
go run ./.github/coverage/ordinary -profile toy.out \
  -functions functions.json -source-root ./toy > functions-report.json
```

Source bytes, declaration spans, and profile identity must match. Unexpected
overlapping function-span block coordinates or statement counts are errors.
The explicit census requires non-overlapping blocks; a source with overlapping
compiler blocks is outside this mode rather than counted ambiguously. `measured`
means all listed blocks are observed (including recorded zero hits); `partial`
means only some are observed; `blocks_absent` means no listed block occurs;
`profile_absent` means the profile was not supplied or found. Missing blocks
are enumerated, with complete-function counts null when incomplete. The
aggregate is null unless every listed function is measured. Observed totals
count only matched blocks, not unobserved statements. The expected denominator
comes from the explicit census, not a guess from source lines.

The caller must establish the compiler census, source/profile provenance,
ordinary test scope, and any qualification applicability separately; matching
coordinates and digests do not themselves establish those facts. This option
changes no coverage gate or threshold.

### Partial Node direct-reporting CI diagnostic

`node-direct-r25.json` contains 29 Node direct ordinary reporting functions
(147 statements). It preserves the reviewed R24 source-only partial census
(28 functions, 144 statements; SHA-256
`f098ec5afffc1cc4283a7a9e88bd61fab7f07d64474f302f4b9c93e2ed74487e`) and adds
the independently anchored ordinary scalar formatter from R25, SHA-256
`2a210fc2f84c50e22b6676688ed6503ac3e74a3abe2cbbb5046f3627c18b3f57`.
The added three compiler statements match the earlier hosted census and the
distinct retained normal and race profiles. All exact source digests match.
The template is deliberately static; it does not discover or expand the
expected denominator from `coverage.out`.

The optional normal CI steps use the same offline module settings as the
existing package diagnostic. A read-only observation establishes whether
`coverage.out` was absent before the primary coverage step. Only an observed
prior absence, a successful current primary step and an available regular,
non-symlink profile permit a current input snapshot. The primary invocation,
raw artifacts and mandatory gate are unchanged. Both optional reporters read
the same snapshot in a freshly allocated current-attempt directory in runner
temporary storage. The R25 reporter binds its static template to that
snapshot's SHA-256. The accompanying `input.json` records the pre-primary
observation, primary outcome, binding status, reason and snapshot digest.

If prior absence cannot be established, the primary is skipped or fails, or
the current input is absent or unreadable, neither optional reporter reads
the root profile or invokes the coverage reporter. The package reports mark
the requested packages `profile_absent` with null observed and aggregate
counts; the R25 report records unavailable with a null aggregate. Optional
steps retain a nonzero, nonblocking status. Artifacts produced by a failed
primary remain on the existing mandatory artifact path, but are not used as
current optional measurements. Retained earlier files are not
removed or reused. If a bound input exists but a package reporter fails, its
scope note records failure without publishing a JSON result for that roster.

The current-attempt upload allowlist comprises exactly these seven files,
when present:

- `input.json`
- `scope.txt`
- `node.json`
- `common.json`
- `node-direct-scope.txt`
- `node-direct-r25.json`
- `node-direct-r25-bound-manifest.json`

No earlier directory, temporary output, raw profile or snapshot is part
of this diagnostic upload. If allocation or binding setup fails before an
upload path is emitted, no prior output is substituted.

The all-zero digest in the static template is a placeholder, not a measured
profile. Missing profile records produce null complete-function and aggregate
counts; an unavailable function reporter produces an explicit null aggregate.
A changed source digest or unexpected compiler coordinates invalidate the
report rather than silently revising the census. These diagnostics are
nonblocking. No full ordinary-token denominator, standalone Common result,
threshold attainment, or qualification is implied.

### Separate Node direct race diagnostic

The optional race diagnostic uses the R25 census unchanged. Its independent
R28 selector review (SHA-256
`8bd94f4dd795da74a2522c6d5b006bca1310fa352c9d1b1c818b678f449b7554`)
admits 12 exact nominal reporting roots in five packages. The checked-in
selector manifest binds the reviewed source, test, fixture and lock bytes.
The remaining parser function (17 statements) has no admitted standalone
pure reporting root and is intentionally not exercised by this diagnostic.

The workflow allocates a fresh runner-temporary parent directory for each
input attempt and passes its new `input` child path to the optional producer
as `--output "$NODE_DIRECT_RACE_INPUT"`. The producer requires an explicit
absolute output path that does not already exist; it runs separately in the
existing offline network namespace, with one anchored selection and an
independent atomic race profile per package. It requires exact root and
package pass events before combining their disjoint profiles. It publishes
its profile digest and source/census/selector binding only after every
selected package succeeds. The read-only reader receives the same current
attempt path, or an empty input when allocation failed or was skipped. It
never falls back to the former fixed checkout path or reuses prior inputs.
The reader accepts only that explicitly race-labelled input, validates its
receipt against the checkout and static census, and never substitutes the
normal profile. Missing or invalid input yields null counts. Since the
parser is absent, a complete R25 aggregate is not expected; observed counts
are separate from the full denominator. The reader allocates a fresh output
directory in runner temporary storage for each attempt. Only its
`scope.txt`, `provenance.json`, `bound-manifest.json` and `report.json`
are eligible for upload. An invalid or failed read removes incomplete
manifest/provenance output and writes current unavailable provenance and
null aggregate counts; it does not reuse an earlier report. Raw test events,
local profiles and executables are not uploaded. This diagnostic is
nonblocking; existing race checks, normal coverage and all mandatory gates
are unchanged.

### Separate Common65 direct-display CI diagnostic

The optional Common diagnostic invokes the `common-direct` helper inside
the existing offline network namespace, after cached pinned dependencies are
available. It reports the two reviewed Common65 display functions (14
statements) on the Node-effective dependency graph with separate normal and
race profiles. The `common-direct/run-portable.sh` wrapper allocates a fresh
output directory per attempt, and emits its portable upload path only after
the current summary exists. The workflow uploads only `summary.json` and,
for a validated mode, its `*.cover`, `*.manifest.json` and `*.report.json`
from that attempt's allowlist. Raw receipts, module metadata and executables
remain local. If the helper cannot produce a summary, the wrapper publishes
only a current unavailable/null summary and retains a nonzero nonblocking
status. Earlier results remain untouched; a completed current summary is
preserved even if its diagnostic exit is nonzero. This diagnostic does not
feed the Node or hybrid coverage denominator and does not change the primary
test selectors, mandatory checks, or threshold.

### Focused ordinary-named CI diagnostic

The `ordinary-named` job runs the 18 reviewed groups in
`.github/ci/ordinary_named.sh` (14 package selections and four isolated
file-list selections). Normal and race are separate matrix attempts with
atomic profiles. Each attempt allocates a new results directory in runner
temporary storage; the runner refuses reuse rather than treating previous
artifacts as current. Only that attempt's `portable/` directory is uploaded.

For each group, the runner verifies the exact named test events and terminal
package pass, then validates the package-profile structure or normalizes the
reviewed file-list profile. Successful groups publish the named receipt,
portable profile and, for file lists, the normalization receipt. The four
phase exit files distinguish test, receipt, profile and publication status;
a failed group retains status files rather than publishing an incomplete
receipt/profile pair (status 2 means not attempted). Other successful groups
retain their own artifacts. Raw events, absolute checkout paths and raw
file-list profiles are not uploaded. An absent attempt is not a measured
zero. These focused ordinary results do not establish a full source census,
standard-token denominator or qualification and never feed the hybrid gate.
