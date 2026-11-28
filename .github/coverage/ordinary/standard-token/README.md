# Provisional standard-token statement diagnostic

This read-only CI step joins the current-attempt, already-produced ordinary
Node direct normal/race and Common65 direct normal/race diagnostics. It runs no
Go tests, opens no network connections, and does not change the mandatory test,
race, or hybrid coverage jobs. The 34 Node and five Common import paths match
the installed diagnostic package roster. They are proposed attribution scope,
not an adopted ordinary-only coverage denominator.

Only a reviewed compiler-block manifest is attributed: Node R25 (29 functions,
147 statements) and Common65 direct (two functions, 14 statements). Source
hashes, current checkout identity, bound profile and manifest hashes, producer
provenance and existing validated reports are reconciled before counting hits.
Node and Common inputs remain separately bound to each mode; the Common subset
is the Node-effective pinned module graph, not a standalone Common profile.
Identical block hits within compatible inputs are combined logically; conflicting
widths, ambiguous overlapping manifest blocks, and duplicate manifest blocks are
rejected. Missing attributed blocks are counted as missing, not zero hits. A
recorded zero counter is observed but uncovered. Packages without reviewed
attribution have a null expected denominator; the full §6 denominator and
percentage are always null, status `NOT_EVALUATED`. Mixed normal package counts
from the bound Node primary profile, when available, are explicitly labelled
mixed and are not the attributed subset. Neither a complete attributed subset
nor any mixed figure establishes 90% standard-token coverage.

The workflow creates a new runner-temporary output directory for each attempt,
passes only current producer paths (no fallback or reuse), and uploads only
`report.json`. A missing or invalid input has null measurements for its mode
and module; valid other inputs remain independent. A malformed static census or
checkout identity fails the nonblocking step. The full standalone Common
module profile is not supplied. The report never executes a test, selects a
new root, modifies the existing gates or publishes a qualification result.

Local pure-fixture tests: `python3 -B -m unittest discover -s
.github/coverage/ordinary/standard-token -p 'test_*.py'`. No product tests or
modules are needed.

## Independent compiler roster census

`producer.py` adds a separate whole-package **mixed** census for the 39 paths,
not an expansion of reviewed ordinary-only attribution. It reads Go 1.26.2
production-file selection separately for normal and race Linux/amd64, CGO on,
checks Node files against HEAD and the effective Common module against its
locked archive (reusing the existing full archive/extracted-file verifier),
and uses the Go coverage instrumenter and metadata converter without compiling
or running product code. Each manifest includes selected source SHA-256s and
all compiler block coordinates and widths. Metadata zero counters are not
observations. Missing source, unsupported Cgo/SWIG packages or missing metadata
is reported as unavailable rather than assigned a denominator.

The second JSON joins only existing current-attempt, already bound inputs:
Node primary normal (mixed), Node R28 selected nominal race, and Common65
selected two-root normal/race. Known compiler widths are checked; an unexpected
block or conflicting width invalidates that package's measurement. Missing
blocks remain null/incomplete; compatible duplicates count only once. The
package result separately inventories compiler coordinates and observed
coordinates, with explicit absent, partial, complete, invalid and unavailable
observation states. Zero-statement coordinates count as metadata or observed
coordinates, not a statement denominator; a metadata-only package is not a
missing compiler census. Aggregate coordinate inventory is a known subtotal,
not a claim of the full ordinary-only denominator. No
source paths outside the import-path roster are emitted. Per-mode package and
aggregate counts are diagnostic only, with full ordinary-only scope still
`NOT_EVALUATED`: the existing selectors and admitted attribution do not supply
full coverage of these mixed packages. The source-bound compiler census is a
necessary inventory, not authority to classify all statements as ordinary.
The existing tests, primary profile, gate and race selectors are not changed.

## Reviewed ordinary-only attribution reconciliation

The metadata producer additionally emits `reviewed-attribution.json`, bound
to the generated compiler manifest SHA-256. It admits **only** explicitly
reviewed Node R25 and Common65 direct-display function templates with exact
review hashes. It checks each function's full positive compiler-block set,
source digest, package and mode; it does not infer ordinary scope from covered
blocks, function names, a package name, or a successful test. The R28 exact
nominal selector/test/source/lock manifest is independently hash-checked; its
producer-mode admission is race only. Common's nominal roots are admitted
in both modes only with the effective pinned module lock. The reviewed Node
normal source subset remains a direct-block diagnostic over a mixed primary
profile, not a standalone ordinary-only execution. The 17-statement reviewed
Node parser function has no admitted standalone nominal root; it stays in the
static reviewed subset but outside explicit nominal selector provenance.

Each of the 39 rows in each mode identifies its reviewed blocks (if any) and
counts the remaining mixed statements as unresolved, not ordinary statements
or exclusions. It also reports unresolved **positive-width** compiler blocks
and separately counts zero-statement coordinates. Missing census rows retain
null coordinate/statement counts; aggregate known subtotals are explicitly
separate from any full denominator. State/accounts generic DTO, proposed direct file/function
manifests and historical mixed package profiles do not grant ordinary-only
attribution. Mode-specific root provenance does not itself imply any execution
or coverage. The complete §6 ordinary-only denominator remains null. No test
selector, gate, or existing diagnostics are changed; the existing metadata
artifact upload adds this one portable manifest.

### Offline cross-receipt reconciliation

`consolidation.py` is a standalone diagnostic for comparing the previously
reviewed block manifest to a later consolidated ordinary-test evidence record.
Pass the reviewed attribution, its compiler manifest, the consolidated receipt
and roster audit, and clean exact Node/Common checkout roots, with `--output`
pointing to a new report file. It verifies the cross-receipt subject and digest
bindings, pinned Common identity, current Node module lock, and reviewed file
bytes from the exact current Git subjects. It keeps normal and race distinct.
Only already-reviewed blocks are represented as reviewed: source equality is
not a new compiler census or a transferable profile. New or intersecting
observations remain separate receipts without adopted coverage, and unavailable
current coverage remains null rather than zero. This does not run tests, alter
CI, change a selector/manifest or define a full ordinary-only denominator.

### Detached representation proposals (not admitted)

The compiler attribution artifact includes a separate, digest-locked
`detached_representation_proposals` table for a small set of token DTO
representation functions. The supply DTO encoded-size accessor and wrapper
are arithmetic/representation helpers; the two Common event DTO helpers
assemble in-memory reporting metadata. These are ordinary-relevant
representations, not proof of an ordinary-exclusive production call population.
They remain unclassified in the existing reviewed totals and unresolved
mixed inventory. The table checks whole positive function block sets and
source identities in each compiler mode and the effective Common lock.
Absent or inconsistent sources remain unbound, without invented counters.
The proposed table references no executable selectors, adopts no profiles,
and returns null coverage and denominator. The existing reviewed manifests,
selector contracts, roster and gate are unchanged.
