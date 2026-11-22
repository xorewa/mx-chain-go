source "$MULTIVERSXTESTNETSCRIPTSDIR/include/terminal.sh"

startValidators() {
  setTerminalSession "multiversx-nodes" || return
  setTerminalLayout "tiled"
  setWorkdirForNextCommands "$TESTNETDIR/node"
  if [[ $MULTI_KEY_NODES -eq 1 ]]; then
    iterateOverValidatorsMultiKey startSingleValidator
  else
    iterateOverValidators startSingleValidator
  fi
}

pauseValidators() {
  iterateOverValidators pauseSingleValidator
}

resumeValidators() {
  iterateOverValidators resumeSingleValidator
}

stopValidators() {
  iterateOverValidators stopSingleValidator
}

iterateOverValidators() {
  local callback=$1
  local VALIDATOR_INDEX=0

  # Iterate over Shard Validators
  (( max_shard_id=$SHARDCOUNT - 1 ))
  for SHARD in $(seq 0 1 $max_shard_id); do
    for _ in $(seq $SHARD_VALIDATORCOUNT); do
      if [ $VALIDATOR_INDEX -ne $SKIP_VALIDATOR_IDX ]; then
        $callback $SHARD $VALIDATOR_INDEX || return
        sleep 0.5
      fi
      (( VALIDATOR_INDEX++ ))
    done
  done

  # Iterate over Metachain Validators
  SHARD="metachain"
  for _ in $(seq $META_VALIDATORCOUNT); do
    if [ $VALIDATOR_INDEX -ne $SKIP_VALIDATOR_IDX ]; then
      $callback $SHARD $VALIDATOR_INDEX || return
      sleep 0.5
    fi
     (( VALIDATOR_INDEX++ ))
  done
}

iterateOverValidatorsMultiKey() {
  local callback=$1
  local VALIDATOR_INDEX=0

  # Iterate over shards and start validators
  (( max_shard_id=$SHARDCOUNT - 1 ))
  for SHARD in $(seq 0 1 $max_shard_id); do
    if [ $VALIDATOR_INDEX -ne $SKIP_VALIDATOR_IDX ]; then
      $callback $SHARD $VALIDATOR_INDEX || return
      sleep 0.5
    fi
    (( VALIDATOR_INDEX++ ))
  done

  # Start Metachain Validator
  SHARD="metachain"
  if [ $VALIDATOR_INDEX -ne $SKIP_VALIDATOR_IDX ]; then
    $callback $SHARD $VALIDATOR_INDEX || return
    sleep 0.5
  fi
   (( VALIDATOR_INDEX++ ))
}

startSingleValidator() {
  local SHARD=$1
  local VALIDATOR_INDEX=$2

  local DIR_NAME="validator"
  if [[ $MULTI_KEY_NODES -eq 1 ]]; then
    DIR_NAME="multikey"
  fi

  local startCommand=""
  if [ "$NODE_WATCHER" -eq 1 ]; then
    setWorkdirForNextCommands "$TESTNETDIR/node_working_dirs/$DIR_NAME$VALIDATOR_INDEX"
    startCommand="$(assembleCommand_startValidatorNodeWithWatcher $VALIDATOR_INDEX $DIR_NAME $SHARD)" || return
  else
    startCommand="$(assembleCommand_startValidatorNode $VALIDATOR_INDEX $DIR_NAME $SHARD)" || return
  fi
  runCommandInTerminal "$startCommand"
}

pauseSingleValidator() {
  local SHARD=$1
  local VALIDATOR_INDEX=$2
  (( PORT=$PORT_ORIGIN_VALIDATOR + $VALIDATOR_INDEX ))
  pauseProcessByPort $PORT
}

resumeSingleValidator() {
  local SHARD=$1
  local VALIDATOR_INDEX=$2
  (( PORT=$PORT_ORIGIN_VALIDATOR + $VALIDATOR_INDEX ))
  resumeProcessByPort $PORT
}

stopSingleValidator() {
  local SHARD=$1
  local VALIDATOR_INDEX=$2

  local DIR_NAME="validator"
  if [[ $MULTI_KEY_NODES -eq 1 ]]; then
    DIR_NAME="multikey"
  fi

  if [ "$NODE_WATCHER" == "1" ]; then
    WORKING_DIR=$TESTNETDIR/node_working_dirs/$DIR_NAME$VALIDATOR_INDEX
    mkdir -p $WORKING_DIR
    touch $WORKING_DIR/norestart
  fi

  (( PORT=$PORT_ORIGIN_VALIDATOR + $VALIDATOR_INDEX ))
  stopProcessByPort $PORT
}


assembleCommand_startValidatorNodeWithWatcher() {
  VALIDATOR_INDEX=$1
  DIR_NAME=$2
  SHARD=$3
  (( PORT=$PORT_ORIGIN_VALIDATOR + $VALIDATOR_INDEX ))
  WORKING_DIR=$TESTNETDIR/node_working_dirs/$DIR_NAME$VALIDATOR_INDEX

  local source_command="source $MULTIVERSXTESTNETSCRIPTSDIR/include/watcher.sh"
  local watcher_command="node-start-with-watcher $VALIDATOR_INDEX $PORT &"
  local node_command
  node_command=$(assembleCommand_startValidatorNode $VALIDATOR_INDEX $DIR_NAME $SHARD) || return
  mkdir -p $WORKING_DIR
  echo "$node_command" > $WORKING_DIR/node-command
  echo "$PORT" > $WORKING_DIR/node-port

  echo "$source_command ; $watcher_command"
}

assembleCommand_startValidatorNode() {
  VALIDATOR_INDEX=$1
  DIR_NAME=$2
  SHARD=$3
  (( PORT=$PORT_ORIGIN_VALIDATOR + $VALIDATOR_INDEX ))
  (( RESTAPIPORT=$PORT_ORIGIN_VALIDATOR_REST + $VALIDATOR_INDEX ))
  (( KEY_INDEX=$VALIDATOR_INDEX ))
  WORKING_DIR=$TESTNETDIR/node_working_dirs/$DIR_NAME$VALIDATOR_INDEX

  local quoted_working_dir rest_host="localhost"
  printf -v quoted_working_dir '%q' "$WORKING_DIR"
  if [[ ${NATIVE_CONFIG_PREFLIGHT:-0} -eq 1 ]]; then
    rest_host="127.0.0.1"
  fi
  local drwaConfigArgs="-config ./config/config_validator.toml"
  if [[ -n ${NATIVE_DRWA_STARTUP_RECORD:-} || -n ${NATIVE_DRWA_OVERLAY:-} ]]; then
    drwaConfigArgs=$(assembleNativeDRWAStartupConfigArgs validator) || return
  fi
  local node_command="./node \
        -port $PORT --profile-mode -log-save -log-level $LOGLEVEL --log-logger-name --log-correlation --use-health-service -rest-api-interface $rest_host:$RESTAPIPORT \
        -sk-index $KEY_INDEX \
        -working-directory $quoted_working_dir $drwaConfigArgs"

  if [[ $MULTI_KEY_NODES -eq 1 ]]; then
      node_command="$node_command --destination-shard-as-observer $SHARD"
  fi

  if [ -n "$NODE_NICENESS" ]
  then
    node_command="nice -n $NODE_NICENESS $node_command"
  fi

  printf '%s\n' "$node_command"
}
