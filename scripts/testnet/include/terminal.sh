# Determine which terminal emulator is available 
# (currently, one of "konsole", "gnome-terminal" or "none").
# TMUX support is in development.
TERMWRAPPER="none"

if [ -n "$(command -v "konsole")" ]
then
  export TERMWRAPPER="konsole"
elif [ -n "$(command -v "gnome-terminal")" ]
then
  export TERMWRAPPER="gnome-terminal"
fi

export CURRENT_TMUX_SESSION=""
export CURRENT_TMUX_LAYOUT="tiled"
declare -A TMUX_SESSION_PANES

nativeRuntimeLimit() {
  [[ ${LOCALNET_MAX_SECONDS:-} =~ ^[0-9]{1,3}$ ]] || return 1
  local seconds=$((10#$LOCALNET_MAX_SECONDS))
  [[ "$seconds" -ge 1 && "$seconds" -le 600 && -x /usr/bin/timeout ]] || return 1
  printf '%ss\n' "$seconds"
}

tmuxCommand() {
  if [[ ${NATIVE_CONFIG_PREFLIGHT:-0} -eq 1 ]]; then
    [[ -n ${TESTNETDIR:-} && -n ${TMUX_SOCKET:-} && ! -L "$TESTNETDIR" && ! -L "$TMUX_SOCKET" ]] || return 1
    local package_root socket_path
    package_root=$(realpath -e -- "$TESTNETDIR") || return
    socket_path=$(realpath -m -- "$TMUX_SOCKET") || return
    [[ "$package_root" != / && "$socket_path" == "$package_root/"* ]] || return 1
  fi
  if [[ -n ${TMUX_SOCKET:-} ]]; then
    command tmux -f /dev/null -S "$TMUX_SOCKET" "$@"
  else
    command tmux "$@"
  fi
}

setTerminalSession() {
  if [[ ${NATIVE_CONFIG_PREFLIGHT:-0} -eq 1 ]]; then
    [[ ${USETMUX:-0} == 1 ]] || return 1
    nativeRuntimeLimit >/dev/null || return
  fi
  if [ $USETMUX -eq 1 ]
  then
    local session_name=$1
    if [ -z "$session_name" ]
    then
      session_name=$CURRENT_TMUX_SESSION
    fi
    if [[ ${NATIVE_CONFIG_PREFLIGHT:-0} -eq 1 ]]; then
      case "$session_name" in
        multiversx-tools|multiversx-nodes) session_name="sp2-runtime" ;;
      esac
    fi

    if [ "$(tmuxSessionAlreadyExists "$session_name")" -eq 0 ]
    then
      CURRENT_TMUX_SESSION=$session_name
      if [[ ${NATIVE_CONFIG_PREFLIGHT:-0} -eq 1 && "$session_name" == sp2-termui ]]; then
        tmuxCommand new-session -d -s "$session_name" -x 160 -y 48 || return
      else
        tmuxCommand new-session -d -s "$session_name" || return
      fi
      TMUX_SESSION_PANES[$session_name]=1
    else
      CURRENT_TMUX_SESSION=$session_name
    fi
  fi
}

setTerminalLayout() {
  CURRENT_TMUX_LAYOUT=$1
}

showTerminalSession() {
  local session_name=$1
  local keepopen=$2
  # Private localnet sessions stay on their own server and are attached manually.
  if [[ -n ${TMUX_SOCKET:-} ]]; then
    return 0
  fi
  if [ $USETMUX -eq 1 ]
  then
    if [ $TERMWRAPPER == "none" ]
    then
      echo "No terminal emulator found. The tmux session will continue to run in background, and can be attached to manually."
    else
      executeCommandInTerminalEmulator "tmux attach-session -t $session_name" $keepopen
    fi
  fi
}

setWorkdirForNextCommands() {
  CURRENT_COMMAND_WORKDIR=$1
}

runCommandInTerminal() {
  local command_to_run=$1
  local keepopen=$2
  local runtime_limit
  if [[ ${NATIVE_CONFIG_PREFLIGHT:-0} -eq 1 ]]; then
    [[ ${USETMUX:-0} == 1 ]] || return 1
    runtime_limit=$(nativeRuntimeLimit) || return
  fi

  if [ $USETMUX -eq 1 ]
  then
    local pane_to_use=${TMUX_SESSION_PANES[$CURRENT_TMUX_SESSION]}
    if [ "$pane_to_use" -gt 1 ]
    then
      tmuxCommand split-window -t "$CURRENT_TMUX_SESSION:0" || return
      tmuxCommand select-layout -t "$CURRENT_TMUX_SESSION:0" "$CURRENT_TMUX_LAYOUT" || return
      let TMUX_SESSION_PANES[$CURRENT_TMUX_SESSION]=${TMUX_SESSION_PANES[$CURRENT_TMUX_SESSION]}+1
    fi
    
    let pane_id=$pane_to_use-1
    local directory_command
    printf -v directory_command 'cd -- %q' "$CURRENT_COMMAND_WORKDIR"
    if [[ ${NATIVE_CONFIG_PREFLIGHT:-0} -eq 1 ]]; then
      command_to_run="exec /usr/bin/timeout --signal=INT --kill-after=5s $runtime_limit $command_to_run"
    fi
    tmuxCommand send-keys -t "$CURRENT_TMUX_SESSION:0.$pane_id" "$directory_command" C-m || return
    tmuxCommand send-keys -t "$CURRENT_TMUX_SESSION:0.$pane_id" "$command_to_run" C-m || return

    if [ "$pane_to_use" -eq 1 ]
    then
      let TMUX_SESSION_PANES[$CURRENT_TMUX_SESSION]=${TMUX_SESSION_PANES[$CURRENT_TMUX_SESSION]}+1
    fi
  else
    executeCommandInTerminalEmulator "$command_to_run" $keepopen
  fi
}

executeCommandInTerminalEmulator() {
  local command_to_run=$1
  local keepopen=$2
  if [[ ${NATIVE_CONFIG_PREFLIGHT:-0} -eq 1 ]]; then
    return 1
  fi

  cd "$CURRENT_COMMAND_WORKDIR" || return

  if [ $TERMWRAPPER == "konsole" ]
  then
    if [ -z "$keepopen" ]
    then
      konsole -e $command_to_run &
    else
      konsole --noclose -e $command_to_run &
    fi
  fi

  if [ $TERMWRAPPER == "gnome-terminal" ]
  then
    gnome-terminal -- $command_to_run &
  fi

  if [ $TERMWRAPPER == "none" ]
  then
    echo "No terminal emulator found, command could not be run."
  fi

}

stopProcessByPort() {
  sendSignalToProcessByPort $1 2
}

pauseProcessByPort() {
  sendSignalToProcessByPort $1 19
}

resumeProcessByPort() {
  sendSignalToProcessByPort $1 18
}

sendSignalToProcessByPort() {
  local port=$1
  local pid=$(lsof -t -i:$port)
  local signal=$2

  if [ -n "$pid" ]
  then
    echo "Sending signal $signal to process $pid..."
    kill -n $signal $pid
  fi
}

tmuxSessionAlreadyExists() {
  local session_name=$1

  tmuxCommand has-session -t "$session_name" 2>/dev/null

  if [ $? != 0 ]
  then
    echo 0
  else
    echo 1
  fi
}

stopNativeLocalnet() {
  [[ ${NATIVE_CONFIG_PREFLIGHT:-0} -eq 1 && ${USETMUX:-0} == 1 ]] || return 1
  local panes pane pid attempt alive
  local pids=()
  panes=$(tmuxCommand list-panes -a -F '#{pane_id} #{pane_pid}') || return
  while read -r pane pid; do
    [[ -n "$pane" ]] || continue
    [[ "$pane" =~ ^%[0-9]+$ && "$pid" =~ ^[0-9]+$ && "$pid" -gt 1 ]] || return 1
    pids+=("$pid")
    tmuxCommand send-keys -t "$pane" C-c || return
  done <<< "$panes"

  for ((attempt=0; attempt<300; attempt++)); do
    alive=0
    for pid in "${pids[@]}"; do
      if kill -0 "$pid" 2>/dev/null; then
        alive=1
      fi
    done
    if [[ "$alive" -eq 0 ]]; then
      if tmuxCommand list-sessions >/dev/null 2>&1; then
        tmuxCommand kill-server || return
      fi
      return 0
    fi
    sleep 0.1
  done
  echo "Package-owned terminal processes did not exit after interrupt" >&2
  return 1
}
