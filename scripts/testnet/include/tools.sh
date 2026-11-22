source "$MULTIVERSXTESTNETSCRIPTSDIR/include/terminal.sh"

nativeHTTPResponse() (
  set -o pipefail
  export LC_ALL=C
  local port=$1 path=$2 response
  [[ "$port" =~ ^[0-9]{1,5}$ ]] || return 1
  ((10#$port > 0 && 10#$port <= 65535)) || return 1
  [[ "$path" == /node/status || "$path" == /network/config || "$path" == '/debug/pprof/goroutine?debug=2' ]] || return 1
  response=$(curl --fail --silent --show-error --noproxy '*' --proto '=http' \
    --connect-timeout 1 --max-time 2 --max-filesize 1048576 \
    --write-out '\n%{http_code}' \
    "http://127.0.0.1:$port$path" | head -c 1048581) || return
  [[ "$response" == *$'\n200' ]] || return 1
  response=${response%$'\n200'}
  [[ ${#response} -le 1048576 ]] || return 1
  printf '%s\n' "$response"
)

nativeNodeStatus() (
  local port=$1 expected=${2:-} response
  [[ -z "$expected" || "$expected" =~ ^(0|1|2|4294967295)$ ]] || return 1
  response=$(nativeHTTPResponse "$port" /node/status) || return
  jq -e --arg expected "$expected" '
    # Native MetricNonce is uint64. Keep jq decimal literals intact: floor
    # rounds through floating point and can accept an out-of-range fraction.
    # A jq build that loses literal precision must deny rather than round.
    def native_nonce:
      if 18446744073709551615 == 18446744073709551616 or type != "number" then false
      elif . < 1 or . > 18446744073709551615 then false
      else tostring
        | capture("^[0-9]+(?:\\.(?<fraction>[0-9]+))?(?:E\\+(?<exponent>[0-9]+))?$")
        | ((.fraction // "" | sub("0+$"; "") | length)
           <= (.exponent // "0" | tonumber))
      end;
    .data.metrics.erd_shard_id as $shard |
    .code == "successful" and .error == "" and
    ($shard == 0 or $shard == 1 or $shard == 2 or $shard == 4294967295) and
    ($expected == "" or ($shard | tostring) == $expected) and
    .data.metrics.erd_is_syncing == 0 and
    (.data.metrics.erd_nonce | native_nonce)
  ' <<< "$response" >/dev/null || return
  printf '%s\n' "$response"
)

nativeProxyConfig() (
  local response
  response=$(nativeHTTPResponse "$1" /network/config) || return
  jq -e '.code == "successful" and .error == "" and .data.config.erd_num_shards_without_meta == 3' <<< "$response" >/dev/null || return
  printf '%s\n' "$response"
)

nativeLocalnetHealth() (
  [[ ${NATIVE_CONFIG_PREFLIGHT:-0} == 1 && ${SHARDCOUNT:-} == 3 && ${USE_PROXY:-0} == 1 ]] || return 1
  local name count origin index shard response all_status="" proxy
  local -A validators=([0]=0 [1]=0 [2]=0 [4294967295]=0)
  for name in SHARD_VALIDATORCOUNT META_VALIDATORCOUNT SHARD_OBSERVERCOUNT META_OBSERVERCOUNT PORT_ORIGIN_VALIDATOR_REST PORT_ORIGIN_OBSERVER_REST PORT_PROXY; do
    [[ ${!name} =~ ^[0-9]{1,5}$ ]] || return 1
    ((10#${!name} > 0 && 10#${!name} <= 65535)) || return 1
  done
  for name in validator observer; do
    if [[ "$name" == validator ]]; then
      count=$((3 * 10#$SHARD_VALIDATORCOUNT + 10#$META_VALIDATORCOUNT))
      origin=$((10#$PORT_ORIGIN_VALIDATOR_REST))
    else
      count=$((3 * 10#$SHARD_OBSERVERCOUNT + 10#$META_OBSERVERCOUNT))
      origin=$((10#$PORT_ORIGIN_OBSERVER_REST))
    fi
    ((origin + count <= 65536)) || return 1
    for ((index=0; index<count; index++)); do
      shard=""
      if [[ "$name" == observer ]]; then
        shard=$((index / 10#$SHARD_OBSERVERCOUNT))
        if ((shard >= 3)); then shard=4294967295; fi
      fi
      response=$(nativeNodeStatus "$((origin + index))" "$shard") || return
      if [[ "$name" == validator ]]; then
        shard=$(jq -er '.data.metrics.erd_shard_id | tostring' <<< "$response") || return
        [[ "$shard" =~ ^(0|1|2|4294967295)$ ]] || return 1
        validators[$shard]=$((validators[$shard] + 1))
      fi
      all_status+="$name $((origin + index)) $response"$'\n'
    done
  done
  for shard in 0 1 2; do
    ((validators[$shard] == 10#$SHARD_VALIDATORCOUNT)) || return 1
  done
  ((validators[4294967295] == 10#$META_VALIDATORCOUNT)) || return 1
  proxy=$(nativeProxyConfig "$PORT_PROXY") || return
  printf '%sproxy %s %s\n' "$all_status" "$PORT_PROXY" "$proxy"
)

nativeLocalnetDiagnostics() (
  [[ ${NATIVE_CONFIG_PREFLIGHT:-0} == 1 && ${SHARDCOUNT:-} == 3 ]] || return 1
  local role count origin index name response
  for name in SHARD_VALIDATORCOUNT META_VALIDATORCOUNT SHARD_OBSERVERCOUNT META_OBSERVERCOUNT PORT_ORIGIN_VALIDATOR_REST PORT_ORIGIN_OBSERVER_REST; do
    [[ ${!name} =~ ^[0-9]{1,5}$ ]] || return 1
    ((10#${!name} > 0 && 10#${!name} <= 65535)) || return 1
  done
  for role in validator observer; do
    if [[ "$role" == validator ]]; then
      count=$((3 * 10#$SHARD_VALIDATORCOUNT + 10#$META_VALIDATORCOUNT))
      origin=$((10#$PORT_ORIGIN_VALIDATOR_REST))
    else
      count=$((3 * 10#$SHARD_OBSERVERCOUNT + 10#$META_OBSERVERCOUNT))
      origin=$((10#$PORT_ORIGIN_OBSERVER_REST))
    fi
    ((origin + count <= 65536)) || return 1
    for ((index=0; index<count; index++)); do
      printf 'Unaccepted native status: %s %d\n' "$role" "$((origin + index))"
      response=$(nativeHTTPResponse "$((origin + index))" /node/status) || continue
      printf '%s\n' "$response"
      if jq -e '.data.metrics.erd_nonce == 0' <<< "$response" >/dev/null; then
        printf 'Native zero-nonce goroutines: %s %d\n' "$role" "$((origin + index))"
        nativeHTTPResponse "$((origin + index))" '/debug/pprof/goroutine?debug=2' || :
      fi
    done
  done
)

startProxy() {
  setTerminalSession "multiversx-tools" || return
  setTerminalLayout "even-vertical"

  setWorkdirForNextCommands "$TESTNETDIR/proxy"
  local proxyCommand="./proxy"
  if [[ ${NATIVE_CONFIG_PREFLIGHT:-0} -eq 1 ]]; then
    printf -v proxyCommand './proxy --rest-api-interface %q' "127.0.0.1:$PORT_PROXY"
  fi
  runCommandInTerminal "$proxyCommand" "$1"
}

startTermUI() {
  [[ ${NATIVE_CONFIG_PREFLIGHT:-0} -eq 1 ]] || return 1
  [[ ${SHARDCOUNT:-} =~ ^[0-9]+$ && ${SHARD_OBSERVERCOUNT:-} =~ ^[0-9]+$ && ${PORT_ORIGIN_OBSERVER_REST:-} =~ ^[0-9]+$ ]] || return 1
  local observer_index=$((10#$SHARD_OBSERVERCOUNT))
  local shard_count=$((10#$SHARDCOUNT))
  local port=$((10#$PORT_ORIGIN_OBSERVER_REST + observer_index))
  [[ "$shard_count" -ge 2 && "$observer_index" -ge 1 && "$port" -gt 0 && "$port" -le 65535 ]] || return 1
  [[ ${SKIP_OBSERVER_IDX:--1} != "$observer_index" ]] || return 1

  setTerminalSession "sp2-termui" || return
  setTerminalLayout "tiled"
  setWorkdirForNextCommands "$TESTNETDIR/node"
  local termuiCommand
  printf -v termuiCommand './termui --address %q' "127.0.0.1:$port"
  runCommandInTerminal "$termuiCommand" "$1"
}

nativeTermUIStatus() {
  [[ ${NATIVE_CONFIG_PREFLIGHT:-0} == 1 ]] || return 1
  local attempt pane
  for ((attempt=0; attempt<10; attempt++)); do
    pane=$(tmuxCommand capture-pane -p -t sp2-termui:0.0) || return
    if [[ "$pane" =~ \(Shard\ 1\ -\ observer(\ -\ [^\)]*)?\) ]]; then
      printf '%s\n' "$pane"
      return 0
    fi
    sleep 1
  done
  printf '%s\n' "$pane" >&2
  echo "TermUI has not displayed the shard-1 observer" >&2
  return 1
}

pauseProxy() {
  pauseProcessByPort $PORT_PROXY
}

resumeProxy() {
  resumeProcessByPort $PORT_PROXY
}

stopProxy() {
  stopProcessByPort $PORT_PROXY
}

startTxGen_NewAccounts() {
  setTerminalSession "multiversx-tools"
  setTerminalLayout "even-vertical"

  setWorkdirForNextCommands "$TESTNETDIR/txgen" v

  runCommandInTerminal "./txgen -num-accounts $NUMACCOUNTS -new-accounts |& tee stdout.txt" $1
}

startTxGen_ExistingAccounts() {
  setTerminalSession "multiversx-tools"
  setTerminalLayout "even-vertical"

  setWorkdirForNextCommands "$TESTNETDIR/txgen" v

  runCommandInTerminal "./txgen |& tee stdout.txt" $1
}

pauseTxGen() {
  pauseProcessByPort $PORT_TXGEN
}

resumeTxGen() {
  resumeProcessByPort $PORT_TXGEN
}

stopTxGen() {
  stopProcessByPort $PORT_TXGEN
}

startSeednode() {
  setTerminalSession "multiversx-tools" || return
  setTerminalLayout "even-horizontal"

  setWorkdirForNextCommands "$TESTNETDIR/seednode"

  if [ -n "$NODE_NICENESS" ]
  then
    seednodeCommand="nice -n $NODE_NICENESS ./seednode"
  else
    seednodeCommand="./seednode"
  fi

  runCommandInTerminal "$seednodeCommand" $1
}

pauseSeednode() {
  pauseProcessByPort $PORT_SEEDNODE
}

resumeSeednode() {
  resumeProcessByPort $PORT_SEEDNODE
}

stopSeednode() {
  stopProcessByPort $PORT_SEEDNODE
}
