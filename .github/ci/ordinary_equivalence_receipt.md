# Ordinary equivalence receipt index

This optional read-only comparator complements `ordinary_pair_receipt.py`.
It performs no test, native execution, signature check or provenance acquisition.
The evidence owner authenticates the exact subjects, fixture/source bytes,
dependency locks, commands and independently expected ordinary outputs first.

`python3 -B .github/ci/ordinary_equivalence_receipt.py --manifest index.json`

The manifest has schema `ordinary-equivalence-receipt-v1` and a nonempty
`cohorts` array. Each cohort has a unique `id`, one exact `package`, exact
named `tests` (including any expected leaves), and subject records named
`candidate`, `reference` and `third`. The third record may be null;
individual modes on any subject may also be null. The two required subjects
have distinct full revision identities. A third record may use the same
revision when it denotes a separately evidenced execution context.

Each non-null subject has the same `revision`, `locks`, `sources` and
`modes` fields as the pair tool. The declared fixture/source digest maps
must agree. Distinct full dependency lock digests are retained, not assumed
equal. Both normal and race modes are present as keys; a supplied mode has
`exit`, `events`, `profile`, and `output`. Artifact references have a
`file` relative to the manifest directory and its lowercase SHA-256. All
artifact paths must be distinct across the manifest. A passed mode requires
an exact named test stream, terminal package pass and nonempty atomic
profile. A nonzero exit is recorded as nonpassing, without positive event
or output-equivalence credit; its profile may be null.

An `output` may be null, or an independently captured canonical ordinary
output artifact. The tool compares its exact bytes by hash only; it does
not normalize outputs, infer equivalence from passing tests, compare log
timings, or derive observations from a coverage profile. It reports
candidate/reference, candidate/third and reference/third separately in each
mode. Missing comparisons have null results; actual nonpassing exits are
reported distinctly from missing evidence. A matching receipt is not an
independent oracle, installed-system qualification, aggregate coverage,
or acceptance gate.
