package systemSmartContracts

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-go/state/accounts"
	"github.com/multiversx/mx-chain-go/testscommon/trie"
	"github.com/multiversx/mx-chain-go/vm/mock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func TestQualG31DeployOutputPersistedBalance(t *testing.T) {
	address := bytes.Repeat([]byte{7}, 32)
	persisted, err := accounts.NewUserAccount(address, &trie.DataTrieTrackerStub{}, &trie.TrieLeafParserStub{})
	require.NoError(t, err)
	require.NoError(t, persisted.AddToBalance(big.NewInt(1000)))
	args := createDefaultEeiArgs()
	reads := 0
	args.BlockChainHook = &mock.BlockChainHookStub{GetUserAccountCalled: func(got []byte) (vmcommon.UserAccountHandler, error) {
		require.Equal(t, address, got)
		reads++
		return persisted, nil
	}}
	host, err := NewVMContext(args)
	require.NoError(t, err)
	host.addContractDeployToOutput(address, []byte("owner"), []byte("code"))
	out := host.outputAccounts[string(address)]
	require.Equal(t, big.NewInt(1000), out.Balance)
	require.Zero(t, out.BalanceDelta.Sign())
	require.Equal(t, 1, reads)
	out.BalanceDelta.SetInt64(25)
	require.Equal(t, big.NewInt(1025), host.GetBalance(address))
	host.addContractDeployToOutput(address, []byte("new owner"), []byte("new code"))
	require.Same(t, out, host.outputAccounts[string(address)])
	require.Equal(t, big.NewInt(1000), out.Balance)
	require.Equal(t, big.NewInt(25), out.BalanceDelta)
	require.Equal(t, 1, reads)
	out.Balance.SetInt64(3)
	require.Equal(t, big.NewInt(1000), persisted.GetBalance())
}
