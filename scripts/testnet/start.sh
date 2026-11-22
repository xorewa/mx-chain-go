#!/usr/bin/env bash

export MULTIVERSXTESTNETSCRIPTSDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

prepared_package=0
restart_view=0
if [[ ${1:-} == --expect-package-sha256 ]]; then
  prepared_package=1
  expected_package_digest=${2:-}
  if [[ $# -eq 5 && $3 == --restart-view-receipt ]]; then
    restart_view=1
    restart_receipt=$4
    restart_receipt_digest=$5
    shift 5
  elif [[ $# -eq 2 ]]; then
    shift 2
  else
    printf '%s\n' 'usage: start.sh --expect-package-sha256 <digest> [--restart-view-receipt <path> <digest>]' >&2
    exit 1
  fi
elif [[ ${1:-} == --restart-view-receipt || ${2:-} == --restart-view-receipt ]]; then
  printf '%s\n' 'restart requires an expected package seal' >&2
  exit 1
fi

export TESTNETMODE=$1
export EXTRA=$2

if [[ "$restart_view" -eq 1 ]]; then
  source "$MULTIVERSXTESTNETSCRIPTSDIR/include/config.sh" || exit $?
  preflightRestartOverride "$expected_package_digest" "$restart_receipt" "$restart_receipt_digest" || exit $?
fi
source "$MULTIVERSXTESTNETSCRIPTSDIR/variables.sh" || exit $?
if [[ "$restart_view" -eq 0 ]]; then
  source "$MULTIVERSXTESTNETSCRIPTSDIR/include/config.sh" || exit $?
fi
requireNativeDRWAProvenanceAdmission || exit $?
source "$MULTIVERSXTESTNETSCRIPTSDIR/include/build.sh" || exit $?
source "$MULTIVERSXTESTNETSCRIPTSDIR/include/validators.sh" || exit $?
source "$MULTIVERSXTESTNETSCRIPTSDIR/include/observers.sh" || exit $?
source "$MULTIVERSXTESTNETSCRIPTSDIR/include/tools.sh" || exit $?

if [[ "$prepared_package" -eq 1 && ${NATIVE_CONFIG_PREFLIGHT:-0} -ne 1 ]]; then
  printf '%s\n' 'prepared package requires native localnet mode' >&2
  exit 1
fi

if [[ ${NATIVE_CONFIG_PREFLIGHT:-0} -eq 1 ]]; then
  validateNativeLocalnetOptions || exit $?
  nativeRuntimeLimit >/dev/null || exit $?
fi

if [[ "$restart_view" -eq 1 ]]; then
  preflightExpectedRestartView "$expected_package_digest" "$restart_receipt" "$restart_receipt_digest" || exit $?
elif [[ "$prepared_package" -eq 1 ]]; then
  preflightExpectedPackage "$expected_package_digest" || exit $?
else
  prepareFolders || exit $?

  # Phase 1: build seednode and node executables
  buildSeednode || exit $?
  buildNode || exit $?
  if [[ ${NATIVE_CONFIG_PREFLIGHT:-0} -eq 1 ]]; then
    buildTermUI || exit $?
  fi

  # Phase 2: generate configuration
  if [ $ALWAYS_UPDATE_CONFIGS -eq 1 ]; then
    copyConfig || exit $?
  fi

  copySeednodeConfig || exit $?
  updateSeednodeConfig || exit $?

  if [ $ALWAYS_UPDATE_CONFIGS -eq 1 ]; then
    copyNodeConfig || exit $?
    updateNodeConfig || exit $?
  fi

  if [[ ${NATIVE_CONFIG_PREFLIGHT:-0} -eq 1 ]]; then
    if [[ $USE_PROXY -eq 1 ]]; then
      prepareFolders_Proxy || exit $?
      buildProxy || exit $?
    fi
    preflightConfig || exit $?
    nativePackageIdentity || exit $?
  fi
fi

if [[ ${NATIVE_CONFIG_PREFLIGHT:-0} -eq 1 ]]; then
  cleanupFailedNativeLaunch() {
    local result=$?
    trap - EXIT INT TERM
    if [[ "$result" -ne 0 ]]; then
      stopNativeLocalnet || echo "Partial localnet shutdown requires inspection" >&2
    fi
    exit "$result"
  }
  trap cleanupFailedNativeLaunch EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
fi

# Phase 3: start the Seednode
startSeednode || exit $?
showTerminalSession "multiversx-tools" || exit $?
echo "Waiting for the Seednode to start ($SEEDNODE_DELAY s)..."
sleep "$SEEDNODE_DELAY" || exit $?

# Phase 4: start the Observer Nodes and Validator Nodes
startObservers || exit $?
startValidators || exit $?
showTerminalSession "multiversx-nodes" || exit $?
echo "Waiting for the Nodes to start ($NODE_DELAY s)..."
sleep "$NODE_DELAY" || exit $?

# Phase 5: build the Proxy and TxGen
if [[ $USE_PROXY -eq 1 && ${NATIVE_CONFIG_PREFLIGHT:-0} -ne 1 ]]; then
  prepareFolders_Proxy
  buildProxy
fi
if [ $USE_TXGEN -eq 1 ]; then
  prepareFolders_TxGen
  buildTxGen
fi

if [[ ${NATIVE_CONFIG_PREFLIGHT:-0} -eq 1 ]]; then
  startTermUI || exit $?
fi

# Phase 6: start the Proxy
if [ $USE_PROXY -eq 1 ]; then
  startProxy || exit $?
  echo "Waiting for the Proxy to start ($PROXY_DELAY s)..."
  sleep "$PROXY_DELAY" || exit $?
fi

# Phase 7: start the TxGen, with or without regenerating the accounts
if [ $USE_TXGEN -eq 1 ]; then
  if [ -n "$TXGEN_REGENERATE_ACCOUNTS" ]
  then
    echo "Starting TxGen with account generation..."
    startTxGen_NewAccounts
  else
    echo "Starting TxGen with existing accounts..."
    startTxGen_ExistingAccounts
  fi
fi
