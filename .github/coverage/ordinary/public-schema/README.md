# Optional SP2-80 public schema conformance

This standalone diagnostic checks the adopted R86 v1 **structural** public display
schema using the standard `python-jsonschema` Draft202012Validator API. It is
not a replacement for the Go codec tests or a source/admission check. It installs
nothing and does not change CI or any existing response. Nine fixed public
display documents exercise version, required keys, null versus empty arrays,
optional extensions and timestamp representation.

## Supplier intake

Run only with an independently admitted, offline, read-only installation of
`jsonschema` supporting Draft 2020-12, its complete dependencies and distribution
metadata, and an approved Python runtime. The supplied root is a materialized
import directory (such as an isolated installation target, not a virtual
environment root). The independent supplier receipt must pin its exact version,
the interpreter executable SHA-256, and the full installed tree SHA-256.

The tree digest is SHA-256 of compact JSON containing sorted pairs
`[source_relative_POSIX_file_name, SHA256(file_bytes)]`. Paths are sorted as
relative pathlib paths, JSON uses ASCII escaping, no whitespace, no trailing
newline. Directories are not records; symbolic links and nonregular entries are
not accepted. This is an installed-tree identity, not an archive checksum; the
supplier's archive/lock provenance must be independently established. The
runner compares supplied pins; a digest it computes does not itself admit the
supplier.

Within the existing offline execution enclosure, invoke the pinned Python
interpreter with `-I -S -B`, from the repository root:

```text
python3 -I -S -B .github/coverage/ordinary/public-schema/validate.py \
  --validator-root <admitted-installation-root> \
  --validator-tree-sha256 <approved-installed-tree-sha256> \
  --validator-version <approved-jsonschema-version> \
  --python-sha256 <approved-interpreter-sha256>
```

The runner binds the exact adopted schema and fixed fixture bytes. It checks
the validator's installed distribution, source location, version and declared
metaschema before calling its schema checker and document validator. No
network resolution or dependency acquisition is requested by this harness.
The existing offline enclosure remains required for actual tool execution.

The single JSON result uses fixed status/reason labels and hashes, no absolute
paths or raw exception text. Exit 0 is a matched structural conformance result;
exit 1 is a failed check or execution error; exit 2 is unavailable or unverified
input. Missing or unverified validators return `blocked`, with compilation and
case results null. A structural pass does not qualify source provenance,
producer bindings, native behaviour or end-to-end client composition.

The unit suite (`python3 -B -m unittest -v test_validate` in this directory)
uses mocked interfaces and synthetic files only. Those unit tests verify
harness behavior, not actual Draft 2020-12 conformance.
