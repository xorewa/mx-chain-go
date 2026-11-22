#!/usr/bin/env bash

export MULTIVERSXTESTNETSCRIPTSDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
source "$MULTIVERSXTESTNETSCRIPTSDIR/variables.sh" || exit $?
source "$MULTIVERSXTESTNETSCRIPTSDIR/include/tools.sh" || exit $?
[[ ${NATIVE_CONFIG_PREFLIGHT:-0} == 1 && ${LOCALNET_HEALTH_SECONDS:-} =~ ^[0-9]{1,3}$ ]] || exit 1
seconds=$((10#$LOCALNET_HEALTH_SECONDS))
((seconds >= 1 && seconds <= 120)) || exit 1
/usr/bin/timeout --signal=INT --kill-after=5s "${seconds}s" /bin/bash --noprofile --norc -c '
source "$MULTIVERSXTESTNETSCRIPTSDIR/include/tools.sh" || exit
until nativeLocalnetHealth; do sleep 1; done
'
result=$?
if [[ "$result" -ne 0 ]]; then
  nativeLocalnetDiagnostics >&2 || :
fi
exit "$result"
