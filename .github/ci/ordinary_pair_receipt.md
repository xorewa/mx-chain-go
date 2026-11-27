# Retained ordinary named-test pair receipt

This optional read-only tool validates a single package-scoped ordinary
fixture pair after the evidence owner has independently authenticated the
subjects and the execution commands. It never launches a test.

`python3 -B .github/ci/ordinary_pair_receipt.py --manifest pair.json`

The `ordinary-pair-receipt-v1` manifest contains:

- `package`: the exact import path used by both Go event streams and profiles;
- `tests`: a nonempty list of exact named roots or nested leaves;
- `candidate` and `reference`: distinct full Git `revision` values, their
  respective `locks` (`go.mod` and `go.sum` SHA-256), byte-identical declared
  `sources` (source and fixture relative-name to SHA-256 map), and `modes`;
- `modes`: exactly `normal` and `race`; each leg is `null` if not supplied,
  or an object with the actual integer `exit`, and `events` and `profile`
  artifact objects. Artifact objects contain `file` relative to the manifest
  directory and its exact lowercase `sha256`.

Each supplied leg must independently contain the exact passing Go test
events, terminal package pass and a nonempty atomic package profile.
Separate artifact paths are required for each leg. Missing legs remain null;
invalid supplied legs fail the invocation without a result. The result binds
the manifest and artifact digests, preserving independent subject and mode
identities. It does not compare test timings, raw counts or coverage metrics.

A `true` paired named-pass status means only the two supplied legs met this
receipt contract for the declared source and fixture set. The tool cannot
authenticate that the declared revisions, modes, sources or locks produced
the artifacts; atomic profile headers alone do not distinguish normal from
race. The owner must independently bind those facts. This is not a matched
operational output oracle, complete package coverage, standard-token
coverage, qualification or a CI gate.
