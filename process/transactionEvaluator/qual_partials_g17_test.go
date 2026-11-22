package transactionEvaluator

import (
	"testing"

	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/stretchr/testify/require"
)

func TestQualPartialsG17CollectorTagStaysLocal(t *testing.T) {
	writes := 0
	underlying := &stateMock.AccountsStub{SetTxHashForLatestStateAccessesCalled: func([]byte) { writes++ }}
	accounts, err := NewSimulationAccountsDB(underlying)
	require.NoError(t, err)
	accounts.SetTxHashForLatestStateAccesses([]byte("experimental-query-tag"))
	accounts.SetTxHashForLatestStateAccesses(nil)
	require.Zero(t, writes, "simulation must not forward collector tags")
}
