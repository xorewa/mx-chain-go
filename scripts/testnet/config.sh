#!/usr/bin/env bash

# Prepare the configuration files for a testnet:
#		Build the mx-chain-deploy-go binary and run it
#		Copy the generated files to the testnet folder
#		Copy configuration for the seednode, nodes, proxy and txgen into the testnet folder

export MULTIVERSXTESTNETSCRIPTSDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

source "$MULTIVERSXTESTNETSCRIPTSDIR/variables.sh" || exit $?
source "$MULTIVERSXTESTNETSCRIPTSDIR/include/config.sh" || exit $?
source "$MULTIVERSXTESTNETSCRIPTSDIR/include/build.sh" || exit $?

if [[ ${NATIVE_CONFIG_PREFLIGHT:-0} -eq 1 ]]; then
  validateNativeLocalnetOptions || exit $?
fi

prepareFolders || exit $?

buildConfigGenerator || exit $?

copyNodeConfig || exit $?

if [[ ${NATIVE_CONFIG_PREFLIGHT:-0} -eq 1 ]]; then
  (
    cd "$TESTNETDIR/node/config" || exit
    updateChainParameters config_observer.toml || exit
    updateChainParameters config_validator.toml
  ) || exit $?
fi

generateConfig || exit $?

copyConfig || exit $?

copySeednodeConfig || exit $?
updateSeednodeConfig || exit $?

updateNodeConfig || exit $?

if [ $USE_PROXY -eq 1 ]; then
  prepareFolders_Proxy || exit $?
  copyProxyConfig || exit $?
  updateProxyConfig || exit $?
fi

if [ $USE_TXGEN -eq 1 ]; then
  prepareFolders_TxGen
  copyTxGenConfig
  updateTxGenConfig
fi

if [ $USE_HARDFORK -eq 1 ]; then
  changeConfigForHardfork
fi

if [ $COPY_BACK_CONFIGS -eq 1 ]; then
  copyBackConfigs
fi
