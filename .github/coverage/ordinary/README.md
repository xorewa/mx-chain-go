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
and any qualification or CI gate. No existing coverage policy, threshold or
workflow consumes this optional report.
