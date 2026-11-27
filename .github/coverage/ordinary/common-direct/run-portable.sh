#!/usr/bin/env bash
# Keep the portable upload bound to this single diagnostic attempt.
set -euo pipefail

stage=$(mktemp -d "${RUNNER_TEMP:?}/common-direct-report.XXXXXXXX")
out="$stage/output"
portable="$out/portable"
status=0
"$@" --output "$out" || status=$?

if [ ! -f "$portable/summary.json" ]; then
    mkdir -p "$portable"
    # Only this attempt's interrupted exports can be removed.
    rm -f "$portable/normal.cover" "$portable/normal.manifest.json" "$portable/normal.report.json" \
        "$portable/race.cover" "$portable/race.manifest.json" "$portable/race.report.json"
    printf '%s\n' '{"scope":"partial Common65 direct display diagnostic; Node-effective graph; not a qualification gate","normal":{"status":"unavailable","statements":null},"race":{"status":"unavailable","statements":null}}' > "$portable/summary.json"
    if [ "$status" -eq 0 ]; then status=1; fi
fi

# Do not expose a publish path until its current summary is available.
printf 'portable=%s\n' "$portable" >> "${GITHUB_OUTPUT:?}"
exit "$status"
