#!/usr/bin/env bash

export MULTIVERSXTESTNETSCRIPTSDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
[[ -n ${LOCAL_OVERRIDES:-} ]] || exit 1
source "$MULTIVERSXTESTNETSCRIPTSDIR/variables.sh" || exit $?
source "$MULTIVERSXTESTNETSCRIPTSDIR/include/config.sh" || exit $?
source "$MULTIVERSXTESTNETSCRIPTSDIR/include/tools.sh" || exit $?
validateNativeLocalnetOptions || exit $?
nativeRuntimeLimit >/dev/null || exit $?

active=0
shutdownSmoke() {
  local result=$?
  trap - EXIT INT TERM
  if [[ "$active" == 1 ]]; then
    if [[ "$result" != 0 ]]; then
      tmuxCommand capture-pane -p -t sp2-termui:0.0 >&2 || :
    fi
    "$MULTIVERSXTESTNETSCRIPTSDIR/stop.sh" || { [[ "$result" != 0 ]] || result=1; }
  fi
  exit "$result"
}
trap shutdownSmoke EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

"$MULTIVERSXTESTNETSCRIPTSDIR/config.sh" || exit $?
"$MULTIVERSXTESTNETSCRIPTSDIR/start.sh" || exit $?
active=1
tmuxCommand list-sessions || exit $?
sessions=$(tmuxCommand list-sessions -F '#{session_name}') || exit $?
[[ "$sessions" == $'sp2-runtime\nsp2-termui' ]] || exit 1
tmuxCommand list-panes -a -F '#{session_name} #{pane_id} #{pane_pid} #{pane_current_command}' || exit $?
panes=$(tmuxCommand list-panes -a -F '#{pane_pid}') || exit $?
while read -r pid; do
  [[ "$pid" =~ ^[0-9]+$ && "$pid" -gt 1 ]] || exit 1
  ps -p "$pid" -o args= || exit $?
done <<< "$panes"
sha256sum "$TESTNETDIR/node/termui" || exit $?
"$MULTIVERSXTESTNETSCRIPTSDIR/health.sh" || exit $?
nativeTermUIStatus || exit $?
