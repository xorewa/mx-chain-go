#!/usr/bin/env bash

export MULTIVERSXTESTNETSCRIPTSDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
if [[ $# -eq 5 && $1 == --expect-package-sha256 && $3 == --restart-view-receipt ]]; then
  source "$MULTIVERSXTESTNETSCRIPTSDIR/include/config.sh" || exit $?
  preflightRestartOverride "$2" "$4" "$5" || exit $?
  source "$MULTIVERSXTESTNETSCRIPTSDIR/variables.sh" || exit $?
  validateNativeLocalnetOptions || exit $?
  preflightExpectedRestartView "$2" "$4" "$5"
  exit $?
fi

if [[ $# -ne 0 && ( $# -ne 2 || $1 != --expect-package-sha256 ) ]]; then
  printf '%s\n' 'usage: preflight.sh --expect-package-sha256 <digest> [--restart-view-receipt <path> <digest>] (expected a lowercase SHA-256 digest)' >&2
  exit 1
fi

source "$MULTIVERSXTESTNETSCRIPTSDIR/variables.sh" || exit $?
source "$MULTIVERSXTESTNETSCRIPTSDIR/include/config.sh" || exit $?

if [[ $# -eq 0 ]]; then
  preflightConfig
  exit $?
fi


preflightExpectedPackage "$2"
