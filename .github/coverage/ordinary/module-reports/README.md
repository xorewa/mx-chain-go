# Independent ordinary package report index

This optional, read-only helper indexes independently retained package reports
from `../main.go`. It does not run tests, calculate new coverage, combine
modules/modes, adopt a denominator, verify execution authenticity, or affect CI
or qualification. It labels caller-declared module revision and execution mode;
those identities must be independently authenticated by the evidence owner.

Supply a JSON manifest (`ordinary-module-reports-input-v1`) with an ordered
nonempty `groups` list. Each group has `id`, `module` (the import-path prefix),
`revision` (full lowercase commit digest), `mode` (`normal` or `race`),
`packages` (ordered exact import paths), and `evidence`. Use at most one group
per module and mode. When an independently captured report is available,
`evidence` has `report` and `profile` objects, each with `file` (relative to the
manifest directory) and `sha256` (exact lowercase SHA-256 of the retained bytes).
When it is unavailable, specify `evidence: null`. For example:

```json
{
  "schema": "ordinary-module-reports-input-v1",
  "groups": [
    {
      "id": "toy-normal",
      "module": "example.invalid/toy",
      "revision": "0000000000000000000000000000000000000000",
      "mode": "normal",
      "packages": ["example.invalid/toy/labels"],
      "evidence": null
    }
  ]
}
```

```sh
python3 -B report.py --manifest retained-groups.json > module-report-index.json
```

For supplied pairs the helper checks both byte digests, report/profile binding,
coverage-mode header, exact ordered package roster and internal reported count
consistency. It deliberately does not parse profile blocks again: this is an
index of existing trusted reports, not another coverage reporter. It preserves
per-group observed and aggregate counts from the input report, with incomplete
aggregates null. An unavailable input, or a report with no measured package,
does not become a count of zero. A reported measured zero is preserved.
`not_supplied` records intentional absence; `artifact_absent` records a missing
file. A malformed or inconsistent supplied artifact fails the entire invocation
with nonzero exit and no JSON result. No path names are copied to the index.

All groups, their execution modes, and their identities remain separate. The
cross-module aggregate is always null; no eligibility, acceptance or coverage
percentage is established by this tool.

## Using current CI diagnostics as provenance

The normal optional package reports (`node.json` and `common.json`) read
the same snapshot of the current **Node** primary profile. Before supplying
a Node normal pair, independently establish the exact checkout and execution
identity, a bound `input.json` (prior absence and successful primary outcome),
and the matching package report and retained profile bytes. The portable
diagnostic upload contains the binding metadata, not the profile snapshot.
Do not reconstruct a missing profile or substitute a different attempt.
The Node report has mixed package-block attribution, not a full ordinary-only
statement census.

The normal `common.json` is not a standalone Common main-module profile or
report, even if some Common packages appear in the Node graph. The separate
Common65 direct normal/race diagnostic measures two reviewed functions on
the Node-effective dependency graph. The separate Node direct race diagnostic
also reports a function subset. Their function reports and partial portable
artifacts are not the independently retained package-report pairs required
by this schema. Do not relabel either subset, or the Node-derived
`common.json`, as a standalone Common package-roster measurement.

Keep `evidence: null` for any requested independently identified module/mode
whose matching package report and profile are unavailable. In particular,
a skipped, failed or unbound primary or an unavailable diagnostic with null
counts is not a present profile report; do not supply that outcome as a pair
or invent zero counts. A supplied report must declare `profile_status: present`
and match the supplied profile digest and the exact requested package roster.
`reported_complete` means only that all declared package rows are measured
(and the optional expected-file check is complete); it does not authenticate
standalone execution, prove an exhaustive source census, or establish the
full standard-token coverage requirement. The evidence owner must verify
module graph, revision and normal/race mode independently; an atomic profile
header alone does not distinguish those execution modes.
