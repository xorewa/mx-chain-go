requireNativeDRWAProvenanceAdmission() {
  if [[ -z ${NATIVE_DRWA_STARTUP_RECORD:-} && -z ${NATIVE_DRWA_OVERLAY:-} ]]; then
    return 0
  fi
  local admission=/opt/original-generation-release/operator.json
  [[ -f "$admission" && ! -L "$admission" ]] || return 1
  nativeRestartCanonical "${admission%/*}" && nativeRestartMountAt "${admission%/*}" ro || return 1
  jq -e --arg anchor "${NATIVE_DRWA_STARTUP_RECORD:-}" --arg overlay "${NATIVE_DRWA_OVERLAY:-}" '
    type == "object" and . == {mode:"original",startup_anchor:$anchor,overlay:$overlay}
    and ($anchor|length)>0 and ($overlay|length)>0
  ' "$admission" >/dev/null || return
}

validateNativeLocalnetOptions() {
  requireNativeDRWAProvenanceAdmission || return
  [[ ${NATIVE_CONFIG_PREFLIGHT:-0} == 1 && ${SHARDCOUNT:-} == 3 && ${USETMUX:-0} == 1 && ${USE_PROXY:-0} == 1 ]] || return 1
  local name
  for name in USE_TXGEN USE_HARDFORK COPY_BACK_CONFIGS NODE_WATCHER MULTI_KEY_NODES; do
    [[ ${!name} == 0 ]] || return 1
  done
  [[ ${SKIP_VALIDATOR_IDX:-} == -1 && ${SKIP_OBSERVER_IDX:-} == -1 ]] || return 1
}

nativePackageIdentity() (
  set -o pipefail
  cd -P -- "$TESTNETDIR" || exit
  # The loaders open this exact path, so hash only a canonical directory.
  if [[ "$TESTNETDIR" != "$PWD" ]]; then
    printf '%s\n' 'expected a canonical package directory' >&2
    exit 1
  fi
  [[ -z $(find . ! -type d ! -type f -print -quit) ]] || exit 1
  for binary in filegen/filegen seednode/seednode node/node node/termui proxy/proxy; do
    [[ -f "$binary" && -x "$binary" ]] || exit 1
  done
  printf 'Native execution package SHA-256: '
  find . -type f -print0 | sort -z | xargs -0 sha256sum --zero | sha256sum
)

generateConfig() {
  echo "Generating configuration using values from scripts/variables.sh..."

  local native_config_args=()
  if [[ ${NATIVE_CONFIG_PREFLIGHT:-0} -eq 1 ]]; then
    native_config_args=(
      -node-config "$TESTNETDIR/node/config/config_validator.toml"
      -epoch-config "$TESTNETDIR/node/config/enableEpochs.toml"
      -output-rollback-epoch "${OUTPUT_ROLLBACK_EPOCH:?explicit rollback epoch required}"
    )
  fi

  TMP_SHARD_OBSERVERCOUNT=$SHARD_OBSERVERCOUNT
  TMP_META_OBSERVERCOUNT=$META_OBSERVERCOUNT
  # set num of observers to 0, they will start with generated keys
  if [[ $MULTI_KEY_NODES -eq 1 ]]; then
    TMP_SHARD_OBSERVERCOUNT=0
    TMP_META_OBSERVERCOUNT=0
  fi

  pushd "$TESTNETDIR/filegen" || return
  local result=0
  ./filegen \
    -output-directory "$CONFIGGENERATOROUTPUTDIR"               \
    -num-of-shards $SHARDCOUNT                                \
    -num-of-nodes-in-each-shard $SHARD_VALIDATORCOUNT         \
    -num-of-observers-in-each-shard $TMP_SHARD_OBSERVERCOUNT  \
    -consensus-group-size $SHARD_CONSENSUS_SIZE               \
    -num-of-metachain-nodes $META_VALIDATORCOUNT              \
    -num-of-observers-in-metachain $TMP_META_OBSERVERCOUNT    \
    -metachain-consensus-group-size $META_CONSENSUS_SIZE      \
    -stake-type $GENESIS_STAKE_TYPE \
    -hysteresis $HYSTERESIS \
    -round-duration $ROUND_DURATION_IN_MS \
    "${native_config_args[@]}" "$@" || result=$?
  popd || return
  return "$result"
}

preflightConfig() {
  requireNativeDRWAProvenanceAdmission || return
  [[ ${NATIVE_CONFIG_PREFLIGHT:-0} -eq 1 ]] || return 1
  local role
  for role in validator observer; do
    assembleNativeDRWAStartupConfigArgs "$role" >/dev/null || return
    generateConfig \
      --validate-only --loopback-only \
      --output-directory "$TESTNETDIR/node/config" \
      --node-config "$TESTNETDIR/node/config/config_$role.toml" \
      --economics-config "$TESTNETDIR/node/config/economics.toml" \
      --node-p2p-config "$TESTNETDIR/node/config/p2p.toml" \
      --seednode-p2p-config "$TESTNETDIR/seednode/config/p2p.toml" \
      --node-preferences "$TESTNETDIR/node/config/prefs.toml" || return
  done
}

preflightExpectedPackage() {
  requireNativeDRWAProvenanceAdmission || return
  if [[ ! $1 =~ ^[0-9a-f]{64}$ ]]; then
    printf '%s\n' 'expected a lowercase SHA-256 digest' >&2
    return 1
  fi
  local expected="Native execution package SHA-256: $1  -"
  local observed
  observed=$(nativePackageIdentity) || return
  if [[ $observed != "$expected" ]]; then
    printf '%s\n' 'package identity mismatch before loader checks' >&2
    return 1
  fi
  preflightConfig || return
  observed=$(nativePackageIdentity) || return
  if [[ $observed != "$expected" ]]; then
    printf '%s\n' 'package identity mismatch after loader checks' >&2
    return 1
  fi
  printf '%s\n' "$observed"
}

# Restart receipts bind only cleanly stopped views. Their expected digest is
# supplied by the supervisor after checking the previous stop and mount record.
readNativeRestartReceipt() {
  local receipt=$1 expected=$2 actual
  [[ $expected =~ ^[0-9a-f]{64}$ && -f $receipt && ! -L $receipt ]] || return 1
  nativeRestartCanonical "$receipt" || return
  nativeRestartMountAt "$receipt" ro || return
  actual=$(sha256sum < "$receipt") || return
  [[ $actual == "$expected  -" ]] || return 1
  jq -ers '
    def path: type == "string" and startswith("/") and (test("[[:cntrl:]\\\\]") | not);
    def digest: type == "string" and test("^[0-9a-f]{64}$");
    def inode: type == "string" and test("^[0-9]+:[0-9]+$");
    select(length == 1) | .[0] |
    select(keys == ["mounts","operator_sha256","prior_stop","prior_stop_sha256","schema","seal",
                    "socket","state_identity","state_root","static_root","view_root"]) |
    select(.schema == "sp2-native-restart-view-v1" and
           (.static_root | path) and (.view_root | path) and (.state_root | path) and
           (.socket | path) and (.prior_stop | path) and (.state_identity | inode) and
           (.seal | digest) and (.operator_sha256 | digest) and (.prior_stop_sha256 | digest) and
           (.mounts | type == "array" and all(.[];
            keys == ["identity","relative"] and
            (.relative | type == "string" and test("^[a-z0-9_/]+$")) and (.identity | inode)))) |
    (.seal,.static_root,.view_root,.state_root,.state_identity,.socket,
     .operator_sha256,.prior_stop,.prior_stop_sha256, (.mounts[] | .relative + "=" + .identity))
  ' "$receipt"
}

nativeRestartCanonical() {
  local path=$1 actual
  [[ $path == /* && $path != / && $path != *[$'\n\r\t\\']* ]] || return 1
  actual=$(realpath -e -- "$path") || return
  [[ $actual == "$path" ]]
}

nativeRestartMountAt() {
  local want=$1 mode=$2 flat=${3:-} raw options hits=0
  # mountinfo encodes spaces. The receipt excludes remaining escaped characters.
  want=${want// /\\040}
  while IFS=' ' read -r _ _ _ _ raw options _; do
    [[ $flat != flat || $raw != "$want/"* ]] || return 1
    [[ $raw == "$want" ]] || continue
    [[ ,$options, == *",$mode,"* ]] || return 1
    ((hits += 1))
  done < /proc/self/mountinfo
  [[ $hits -eq 1 ]]
}

# Project the common record explicitly selected by the external supervisor.
assembleNativeDRWAStartupConfigArgs() {
  local role=$1 startup overlay digest bytes record tail config nodes q_config q_nodes q_overlay q_startup
  case "$role" in validator|observer) ;; *) return 1 ;; esac
  startup=${NATIVE_DRWA_STARTUP_RECORD:-}
  overlay=${NATIVE_DRWA_OVERLAY:-}
  if [[ -z $startup && -z $overlay ]]; then
    printf '%s\n' "-config ./config/config_$role.toml"
    return
  fi
  [[ -n $startup && -n $overlay && $startup == *:*:* ]] || return 1
  digest=${startup%%:*}
  tail=${startup#*:}
  bytes=${tail%%:*}
  record=${tail#*:}
  [[ $digest =~ ^[0-9a-f]{64}$ && $bytes =~ ^[1-9][0-9]*$ ]] || return 1
  config=$TESTNETDIR/node/config/config_$role.toml
  nodes=$TESTNETDIR/node/config/nodesSetup.json
  local file
  for file in "$record" "$overlay" "$config" "$nodes"; do
    [[ $file == "$TESTNETDIR/"* && -f $file && ! -L $file ]] || return 1
    nativeRestartCanonical "$file" && nativeRestartMountAt "$file" ro || return 1
  done
  [[ $(sha256sum < "$record") == "$digest  -" && $(stat -Lc '%s' -- "$record") == "$bytes" ]] || return 1
  printf -v q_config '%q' "$config"
  printf -v q_nodes '%q' "$nodes"
  printf -v q_overlay '%q' "$overlay"
  printf -v q_startup '%q' "$startup"
  printf '%s\n' "-config $q_config --nodes-setup-file $q_nodes --drwa-config $q_overlay --drwa-startup-record $q_startup"
}

nativeRestartOperatorIdentity() (
  set -o pipefail
  cd -P -- "$MULTIVERSXTESTNETSCRIPTSDIR" || exit
  local file
  local files=(variables.sh include/config.sh include/build.sh include/terminal.sh
    include/tools.sh include/validators.sh include/observers.sh preflight.sh start.sh stop.sh health.sh)
  for file in "${files[@]}"; do
    [[ -f $PWD/$file && ! -L $PWD/$file ]] || exit 1
    nativeRestartCanonical "$PWD/$file" || exit
    nativeRestartMountAt "$PWD/$file" ro || exit
  done
  sha256sum --zero -- "${files[@]}" | sha256sum
)

nativeRestartStaticSource() {
  local source=$1 expected=$2 observed
  [[ -d $source ]] && nativeRestartCanonical "$source" && nativeRestartMountAt "$source" ro flat || return
  observed=$(TESTNETDIR="$source" nativePackageIdentity) || return
  [[ $observed == "Native execution package SHA-256: $expected  -" ]]
}

# Verify the mounted override before variables.sh has a chance to source it.
preflightRestartOverride() {
  local expected=$1 receipt=$2 receipt_digest=$3 binding source view retained_stop identity
  local -a rows
  binding=$(readNativeRestartReceipt "$receipt" "$receipt_digest") || return
  mapfile -t rows <<< "$binding"
  [[ ${#rows[@]} -ge 9 && $expected == "${rows[0]}" ]] || return 1
  source=${rows[1]}
  view=${rows[2]}
  retained_stop=${rows[7]}
  [[ $view != "$source" && ${LOCAL_OVERRIDES:-} == "$view/local-overrides.sh" ]] || return 1
  [[ -d $view ]] && nativeRestartCanonical "$view" && nativeRestartMountAt "$view" rw || return
  nativeRestartStaticSource "$source" "$expected" || return
  [[ -f $LOCAL_OVERRIDES && $LOCAL_OVERRIDES -ef $source/local-overrides.sh ]] || return 1
  nativeRestartCanonical "$LOCAL_OVERRIDES" && nativeRestartMountAt "$LOCAL_OVERRIDES" ro || return
  identity=$(nativeRestartOperatorIdentity) || return
  [[ $identity == "${rows[6]}  -" && -f $retained_stop ]] || return 1
  nativeRestartCanonical "$retained_stop" && nativeRestartMountAt "$retained_stop" ro || return
  identity=$(sha256sum < "$retained_stop") || return
  [[ $identity == "${rows[8]}  -" ]]
}

nativeRestartCheckStaticMembers() (
  set -o pipefail
  local source=$1 view=$2 member
  cd -P -- "$source" || exit
  find . -type f -print0 | while IFS= read -r -d '' member; do
    member=${member#./}
    [[ -f $view/$member && $view/$member -ef $source/$member ]] || exit 1
    nativeRestartCanonical "$source/$member" && nativeRestartCanonical "$view/$member" || exit
    nativeRestartMountAt "$view/$member" ro || exit
  done
)

nativeRestartCheckViewEntries() (
  set -o pipefail
  local source=$1 view=$2 entry
  shift 2
  local -a exclusions=(-false)
  for entry in "$@"; do
    exclusions+=(-o -path "./$entry")
  done
  cd -P -- "$view" || exit
  find . \( "${exclusions[@]}" \) -prune -o -print0 | while IFS= read -r -d '' entry; do
    case "$entry" in
      .|./node_working_dirs) [[ -d $entry && ! -L $entry ]] || exit 1 ;;
      *) [[ ! -L $entry && ( -d $entry && -d $source/$entry || -f $entry && -f $source/$entry ) ]] || exit 1 ;;
    esac
  done
)

nativeRestartViewIdentity() {
  local expected=$1 receipt=$2 receipt_digest=$3 binding view source state name count i index identity
  local -a rows writable=()
  preflightRestartOverride "$expected" "$receipt" "$receipt_digest" || return
  binding=$(readNativeRestartReceipt "$receipt" "$receipt_digest") || return
  mapfile -t rows <<< "$binding"
  [[ ${#rows[@]} -ge 9 ]] || return 1
  source=${rows[1]}
  view=${rows[2]}
  state=${rows[3]}
  [[ $view == "$TESTNETDIR" && $state != "$view" && $state != "$source" ]] || return 1
  [[ $state != "$view/"* && $state != "$source/"* && $source != "$view/"* && $view != "$source/"* &&
     $view != "$state/"* && $source != "$state/"* ]] || return 1
  [[ -d $state ]] && nativeRestartCanonical "$state" || return
  identity=$(stat -Lc '%d:%i' -- "$state") || return
  [[ $identity == "${rows[4]}" ]] || return 1
  # Confirmed stop leaves this exact socket absent. Do not unlink or replace it.
  [[ ${TMUX_SOCKET:-} == "$view/operator.sock" && $TMUX_SOCKET == "${rows[5]}" &&
     ! -e $TMUX_SOCKET && ! -L $TMUX_SOCKET ]] || return 1
  [[ $SHARDCOUNT == 3 && $MULTI_KEY_NODES == 0 ]] || return 1
  for name in SHARD_VALIDATORCOUNT META_VALIDATORCOUNT SHARD_OBSERVERCOUNT META_OBSERVERCOUNT; do
    [[ ${!name} =~ ^[1-9][0-9]{0,4}$ ]] || return 1
    ((10#${!name} <= 65535)) || return 1
  done
  count=$((3 * SHARD_VALIDATORCOUNT + META_VALIDATORCOUNT))
  ((count <= 65535)) || return 1
  for ((i=0; i<count; i++)); do writable+=("node_working_dirs/validator$i"); done
  count=$((3 * SHARD_OBSERVERCOUNT + META_OBSERVERCOUNT))
  ((count <= 65535)) || return 1
  for ((i=0; i<count; i++)); do writable+=("node_working_dirs/observer$i"); done
  writable+=(node/logs seednode/logs proxy/logs)
  [[ ${#rows[@]} -eq $((9 + ${#writable[@]})) ]] || return 1
  index=9
  for name in "${writable[@]}"; do
    [[ ! -e $source/$name && ! -L $source/$name &&
       -d $view/$name && -d $state/$name && $view/$name -ef $state/$name ]] || return 1
    nativeRestartCanonical "$view/$name" && nativeRestartCanonical "$state/$name" || return
    nativeRestartMountAt "$view/$name" rw flat || return
    identity=$(stat -Lc '%d:%i' -- "$state/$name") || return
    [[ ${rows[index]} == "$name=$identity" ]] || return 1
    ((index += 1))
  done
  nativeRestartCheckStaticMembers "$source" "$view" &&
    nativeRestartCheckViewEntries "$source" "$view" "${writable[@]}"
}

preflightExpectedRestartView() {
  requireNativeDRWAProvenanceAdmission || return
  nativeRestartViewIdentity "$@" || { printf '%s\n' 'restart view mismatch before loader checks' >&2; return 1; }
  preflightConfig || return
  nativeRestartViewIdentity "$@" || { printf '%s\n' 'restart view mismatch after loader checks' >&2; return 1; }
  printf 'Native execution package SHA-256: %s  -\n' "$1"
}

copyConfig() (
  cd "$TESTNETDIR" || exit

  cp ./filegen/"$CONFIGGENERATOROUTPUTDIR"/genesis.json ./node/config || exit
  cp ./filegen/"$CONFIGGENERATOROUTPUTDIR"/nodesSetup.json ./node/config || exit
  cp ./filegen/"$CONFIGGENERATOROUTPUTDIR"/*.pem ./node/config || exit #there might be more .pem files there
  if [[ $MULTI_KEY_NODES -eq 1 ]]; then
      mv ./node/config/"$VALIDATOR_KEY_PEM_FILE" ./node/config/"$MULTI_KEY_PEM_FILE" || exit
      if [[ $EXTRA_KEYS -eq 1 ]]; then
        cat "$NODEDIR/config/testKeys/${EXTRA_KEY_PEM_FILE}" >> ./node/config/"$MULTI_KEY_PEM_FILE" || exit
      fi
  fi
  echo "Configuration files copied from the configuration generator to the working directories of the executables."
)

copySeednodeConfig() {
  local keyDir="$TESTNETDIR/seednode/config"
  [[ ! -L "$keyDir/p2pKey.pem" && ! -L "$TESTNETDIR/seednode/keygenerator" ]] || return 1
  cp "$SEEDNODEDIR"/config/{config.toml,p2p.toml} "$keyDir" || return

  if [[ ! -f "$keyDir/p2pKey.pem" ]]; then
    (
      umask 077
      cd "$MULTIVERSXDIR/cmd/keygenerator" || exit
      go build -o "$TESTNETDIR/seednode/keygenerator" .
    ) || return
    (
      umask 077
      cd "$keyDir" || exit
      ../keygenerator --key-type p2p
    ) || return
  fi

  local GENERATED_P2P_PUB_KEY
  GENERATED_P2P_PUB_KEY=$(sed -n '1s/^-----BEGIN PRIVATE KEY for \(.*\)-----$/\1/p' "$keyDir/p2pKey.pem") || return
  [[ -n "$GENERATED_P2P_PUB_KEY" ]] || return 1
  export P2P_SEEDNODE_ADDRESS="/ip4/$SEEDNODE_IP/tcp/$PORT_SEEDNODE/p2p/$GENERATED_P2P_PUB_KEY"
}

updateSeednodeConfig() (
  cd "$TESTNETDIR/seednode/config" || exit
  cp p2p.toml p2p_edit.toml || exit

  updateTOMLValue p2p_edit.toml "Port" "\"$PORT_SEEDNODE\"" || exit
  if [[ ${NATIVE_CONFIG_PREFLIGHT:-0} -eq 1 ]]; then
    [[ "$SEEDNODE_IP" == "127.0.0.1" ]] || exit 1
    updateLoopbackTransports p2p_edit.toml || exit
    updateTOMLValue p2p_edit.toml "InitialPeerList" "[]" || exit
  fi

  cp p2p_edit.toml p2p.toml || exit
  rm p2p_edit.toml || exit

  echo "Updated configuration for the Seednode."
)

updateLoopbackTransports() {
  updateTOMLValue "$1" "ListenAddress" '"/ip4/127.0.0.1/tcp/%d"' || return
  updateTOMLValue "$1" "QUICAddress" '""' || return
  updateTOMLValue "$1" "WebSocketAddress" '""' || return
  updateTOMLValue "$1" "WebTransportAddress" '""'
}

copyNodeConfig() (
  cd "$TESTNETDIR" || exit
  cp "$NODEDIR"/config/{api.toml,economics.toml,ratings.toml,prefs.toml,external.toml,p2p.toml,fullArchiveP2P.toml,enableEpochs.toml,enableRounds.toml,systemSmartContractsConfig.toml,genesisSmartContracts.json} ./node/config || exit
  cp "$NODEDIR/config/config.toml" ./node/config/config_validator.toml || exit
  cp "$NODEDIR/config/config.toml" ./node/config/config_observer.toml || exit
  mkdir -p ./node/config/genesisContracts ./node/config/gasSchedules || exit
  cp "$NODEDIR"/config/genesisContracts/*.* ./node/config/genesisContracts || exit
  cp "$NODEDIR"/config/gasSchedules/*.* ./node/config/gasSchedules || exit

  echo "Configuration files copied from the Node to the working directories of the executables."
)

updateNodeConfig() (
  cd "$TESTNETDIR/node/config" || exit
  cp p2p.toml p2p_edit.toml || exit

  updateTOMLValue p2p_edit.toml "InitialPeerList" "[\"$P2P_SEEDNODE_ADDRESS\"]" || exit
  if [[ ${NATIVE_CONFIG_PREFLIGHT:-0} -eq 1 ]]; then
    [[ "$SEEDNODE_IP" == "127.0.0.1" && "$P2P_SEEDNODE_ADDRESS" == /ip4/127.0.0.1/tcp/* ]] || exit 1
    updateLoopbackTransports p2p_edit.toml || exit
    updateTOMLValue config_validator.toml "Hosts" "[]" || exit
    updateTOMLValue config_observer.toml "Hosts" "[]" || exit
    updateTOMLValue config_validator.toml "StableTagLocation" '""' || exit
    updateTOMLValue config_observer.toml "StableTagLocation" '""' || exit
    updateTOMLValue config_validator.toml "URL" '""' || exit
    updateTOMLValue config_observer.toml "URL" '""' || exit
  fi

  cp p2p_edit.toml p2p.toml || exit
  rm p2p_edit.toml || exit

  cp nodesSetup.json nodesSetup_edit.json
  
  let startTime="$(date +%s) + $GENESIS_DELAY"
  updateJSONValue nodesSetup_edit.json "startTime" "$startTime"

  updateJSONValue nodesSetup_edit.json "minTransactionVersion" "1"

	if [ $ALWAYS_NEW_CHAINID -eq 1 ]; then
		updateTOMLValue config_validator.toml "ChainID" "\"local-testnet"\"
		updateTOMLValue config_observer.toml "ChainID" "\"local-testnet"\"
	fi

  cp nodesSetup_edit.json nodesSetup.json
  rm nodesSetup_edit.json

  if [ $OBSERVERS_ANTIFLOOD_DISABLE -eq 1 ]
  then
     sed -i '/\[Antiflood\]/,/\[Logger\]/ s/true/false/' config_observer.toml
  fi

  updateConfigsForStakingV4

  # Update chain parameters
  updateChainParameters config_observer.toml
  updateChainParameters config_validator.toml

  echo "Updated configuration for Nodes."
)

updateChainParameters() {
  local tomlFile=$1
  local hysteresis=$HYSTERESIS
  # The CLI accepts integral floats, but native TOML decoding requires a float literal.
  if [[ "$hysteresis" =~ ^[+-]?[0-9]+$ ]]; then
    hysteresis+=.0
  fi

  sed -i "s,ShardConsensusGroupSize\([^,]*\),ShardConsensusGroupSize = $SHARD_CONSENSUS_SIZE," "$tomlFile" || return
  sed -i "s,ShardMinNumNodes\([^,]*\),ShardMinNumNodes = $SHARD_VALIDATORCOUNT," "$tomlFile" || return
  sed -i "s,MetachainConsensusGroupSize\([^,]*\),MetachainConsensusGroupSize = $META_CONSENSUS_SIZE," "$tomlFile" || return
  sed -i "s,MetachainMinNumNodes\([^,]*\),MetachainMinNumNodes = $META_VALIDATORCOUNT," "$tomlFile" || return
  sed -i "s,RoundDuration = 6000,RoundDuration = $ROUND_DURATION_IN_MS," "$tomlFile" || return
  sed -i "s,Hysteresis\([^,]*\),Hysteresis = $hysteresis," "$tomlFile" || return

  if [ $ROUNDS_PER_EPOCH -ne 0 ]; then
    local NEW_ROUNDS_PER_EPOCH=$((ROUNDS_PER_EPOCH*ROUND_DURATION_IN_MS / 600))
    sed -i "s,RoundsPerEpoch = 2000,RoundsPerEpoch = $NEW_ROUNDS_PER_EPOCH," "$tomlFile" || return
    sed -i "s,RoundsPerEpoch = 200,RoundsPerEpoch = $ROUNDS_PER_EPOCH," "$tomlFile" || return
    sed -i "s,MinRoundsBetweenEpochs = 20,MinRoundsBetweenEpochs = $ROUNDS_PER_EPOCH," "$tomlFile" || return
  fi
}

updateConfigsForStakingV4() {
  config=$(cat enableEpochs.toml)

  echo "Updating staking v4 configs"

  # Get the StakingV4Step3EnableEpoch value
  staking_enable_epoch=$(echo "$config" | awk -F '=' '/  StakingV4Step3EnableEpoch/{gsub(/^[ \t]+|[ \t]+$/,"", $2); print $2; exit}')
  # Count the number of entries in MaxNodesChangeEnableEpoch
  entry_count=$(echo "$config" | awk '/MaxNodesChangeEnableEpoch/,/\]/{if ($0 ~ /\{/) {count++}} END {print count}')

  # Check if entry_count is less than 2
  if [ "$entry_count" -lt 2 ]; then
    echo "Not enough entries found to update"
  else
    # Find all entries in MaxNodesChangeEnableEpoch
    all_entries=$(awk '/MaxNodesChangeEnableEpoch/,/\]/{if ($0 ~ /^[[:space:]]*\{/) {p=1}; if (p) print; if ($0 ~ /\]/) p=0}' enableEpochs.toml | grep -vE '^\s*#' | sed '/^\s*$/d')

    # Get the index of the entry with EpochEnable equal to StakingV4Step3EnableEpoch
    index=$(echo "$all_entries" | grep -n "EpochEnable = $staking_enable_epoch" | cut -d: -f1)

    if [[ -z "${index// }" ]]; then
      echo -e "\033[1;33mWarning: MaxNodesChangeEnableEpoch does not contain an entry enable epoch for StakingV4Step3EnableEpoch, nodes might fail to start...\033[0m"
    else
      prev_entry=$(echo "$all_entries" | sed -n "$((index-1))p")
      curr_entry=$(echo "$all_entries" | sed -n "$((index))p")

      # Extract the value of MaxNumNodes & NodesToShufflePerShard from prev_entry
      max_nodes_from_prev_epoch=$(echo "$prev_entry" | awk -F 'MaxNumNodes = ' '{print $2}' | cut -d ',' -f1)
      nodes_to_shuffle_per_shard=$(echo "$prev_entry" | awk -F 'NodesToShufflePerShard = ' '{gsub(/[^0-9]+/, "", $2); print $2}')

      # Calculate the new MaxNumNodes value based on the formula
      new_max_nodes=$((max_nodes_from_prev_epoch - (SHARDCOUNT + 1) * nodes_to_shuffle_per_shard))
      curr_entry_updated=$(echo "$curr_entry" | awk -v new_max_nodes="$new_max_nodes" '{gsub(/MaxNumNodes = [0-9]+,/, "MaxNumNodes = " new_max_nodes ",")}1')

      echo "Updating entry in MaxNodesChangeEnableEpoch from $curr_entry to $curr_entry_updated"

      sed -i "/$staking_enable_epoch/,/$staking_enable_epoch/ s|.*$curr_entry.*|$curr_entry_updated|" enableEpochs.toml
    fi
  fi
}

copyProxyConfig() (
  cd "$TESTNETDIR" || exit

  cp -r "$PROXYDIR/config/apiConfig" ./proxy/config/ || exit
  cp "$PROXYDIR/config/config.toml" ./proxy/config/ || exit

  cp ./node/config/economics.toml ./proxy/config/ || exit
  cp ./node/config/external.toml ./proxy/config/ || exit
  cp ./node/config/walletKey.pem ./proxy/config || exit

  echo "Copied configuration for the Proxy."
)

updateProxyConfig() (
  cd "$TESTNETDIR/proxy/config" || exit
  cp config.toml config_edit.toml || exit

  # Truncate config.toml before the [[Observers]] list
  sed -i -n '/\[\[Observers\]\]/q;p' config_edit.toml || exit
  
  updateTOMLValue config_edit.toml "ServerPort" "$PORT_PROXY" || exit
  generateProxyObserverList config_edit.toml || exit

  cp config_edit.toml config.toml || exit
  rm config_edit.toml || exit

  echo "Updated configuration for the Proxy."
)

copyTxGenConfig() {
  pushd $TESTNETDIR

  cp $TXGENDIR/config/config.toml ./txgen/config/

  cp $TXGENDIR/config/sc.toml ./txgen/config/
  cp $TXGENDIR/config/*.wasm ./txgen/config/

  cp ./node/config/economics.toml ./txgen/config/
  cp ./node/config/walletKey.pem ./txgen/config
  cp ./node/config/enableEpochs.toml ./txgen/config/nodeConfig/config

  echo "Copied configuration for the TxGen."
  popd
}

updateTxGenConfig() {
  pushd $TESTNETDIR/txgen/config
  cp config.toml config_edit.toml

  updateTOMLValue config_edit.toml "ServerPort" $PORT_TXGEN
  updateTOMLValue config_edit.toml "ProxyServerURL" "\"http://127.0.0.1:$PORT_PROXY\""
  sed -i "/Scenarios = \[/c ${TXGEN_SCENARIOS_LINE}" config_edit.toml

  cp config_edit.toml config.toml
  rm config_edit.toml

  echo "Updated configuration for the TxGen."
  popd
}


generateProxyObserverList() {
  OBSERVER_INDEX=0
  OUTPUTFILE=$!
  # Start Shard Observers
  (( max_shard_id=$SHARDCOUNT - 1 ))
  for SHARD in $(seq 0 1 $max_shard_id); do
    for _ in $(seq $SHARD_OBSERVERCOUNT); do
      (( PORT=$PORT_ORIGIN_OBSERVER_REST+$OBSERVER_INDEX))

      echo "[[Observers]]" >> config_edit.toml
      echo "   ShardId = $SHARD" >> config_edit.toml
      echo "   Address = \"http://127.0.0.1:$PORT\"" >> config_edit.toml
      echo ""$'\n' >> config_edit.toml

      (( OBSERVER_INDEX++ ))
    done
  done
  # Start Meta Observers
  for META_OBSERVER in $(seq $META_OBSERVERCOUNT); do
    (( PORT=$PORT_ORIGIN_OBSERVER_REST+$OBSERVER_INDEX ))

      echo "[[Observers]]" >> config_edit.toml
      echo "   ShardId = $METASHARD_ID" >> config_edit.toml
      echo "   Address = \"http://127.0.0.1:$PORT\"" >> config_edit.toml
      echo ""$'\n' >> config_edit.toml

      (( OBSERVER_INDEX++ ))
    done
}

updateTOMLValue() {
  local filename=$1
  local key=$2
  local value=$3

  local escaped_value
  escaped_value=$(printf "%q" "$value") || return

  sed -i "s,$key = .*\$,$key = $escaped_value," "$filename"
}


updateJSONValue() {
  local filename=$1
  local key=$2
  local value=$3

  local escaped_value
  escaped_value=$(printf "%q" "$value") || return

  sed -i "s,\"$key\": .*\$,\"$key\": $escaped_value\,," "$filename"
}

changeConfigForHardfork(){
  pushd $TESTNETDIR/node/config

  export FIRST_PUBKEY=$(cat nodesSetup.json | grep pubkey -m 1 | sed -E 's/^.*"([0-9a-f]+)".*$/\1/g')
  updateTOMLValue config_observer.toml "PublicKeyToListenFrom" "\"$FIRST_PUBKEY\""
  updateTOMLValue config_validator.toml "PublicKeyToListenFrom" "\"$FIRST_PUBKEY\""

  popd
}

copyBackConfigs(){
  pushd $TESTNETDIR

  echo "trying to copy-back the configs"
  cp ./node/config/*.* $NODEDIR/config
  cp $NODEDIR/config/config_validator.toml $NODEDIR/config/config.toml

  popd
}
