prepareFolders() {
  mkdir -p "$TESTNETDIR" || return
  cd "$TESTNETDIR" || return
  mkdir -p filegen node/config seednode/config node_working_dirs
}

prepareFolders_Proxy() {
  mkdir -p "$TESTNETDIR" || return
  cd "$TESTNETDIR" || return
  mkdir -p proxy/config
}

prepareFolders_TxGen() {
  mkdir -p "$TESTNETDIR" || return
  cd "$TESTNETDIR" || return
  mkdir -p txgen/config/nodeConfig/config
}

buildConfigGenerator() (
  echo "Building Configuration Generator..."
  cd "$CONFIGGENERATORDIR" || exit
  go build -o "$TESTNETDIR/filegen/filegen" . || exit
  echo "Configuration Generator built..."
)


buildNode() (
  echo "Building Node executable..."
  cd "$NODEDIR" || exit

  APP_VERSION="v1.0.0"
  if [ $ALWAYS_NEW_APP_VERSION -eq 1 ]; then
    APP_VERSION="$(date +"v%Y.%m.%d.%H.%M.%S")"
  fi

  go build -o "$TESTNETDIR/node/node" -gcflags="all=-N -l" -ldflags="-X main.appVersion=$APP_VERSION" . || exit
  echo "Node executable built."
)

buildSeednode() (
  echo "Building Seednode executable..."
  cd "$SEEDNODEDIR" || exit
  go build -o "$TESTNETDIR/seednode/seednode" . || exit
  echo "Seednode executable built."
)

buildTermUI() (
  echo "Building TermUI executable..."
  cd "$MULTIVERSXDIR/cmd/termui" || exit
  go build -o "$TESTNETDIR/node/termui" . || exit
  echo "TermUI executable built."
)

buildProxy() (
  echo "Building Proxy executable..."
  cd "$PROXYDIR" || exit
  go build -o "$TESTNETDIR/proxy/proxy" . || exit
  echo "Proxy executable built."
)

buildTxGen() (
  echo "Building TxGen executable..."
  cd "$TXGENDIR" || exit
  go build -o "$TESTNETDIR/txgen/txgen" . || exit
  echo "TxGen executable built."
)
