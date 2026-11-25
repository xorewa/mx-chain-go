package systemSmartContracts

import (
	"errors"
	"math/big"
	"testing"

	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/vm/mock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Exercise the numeric getter on inert fixtures, without invoking VM execution.
func TestQualOrdinaryPersistedBalanceRead(t *testing.T) {
	t.Parallel()

	address := []byte("synthetic-account")
	t.Run("no hook", func(t *testing.T) {
		host := &vmContext{}
		require.Equal(t, big.NewInt(0), host.getPersistedBalance(address))
	})

	stored := big.NewInt(73)
	for _, tc := range []struct {
		name    string
		account vmcommon.UserAccountHandler
		err     error
		want    *big.Int
	}{
		{name: "missing account", want: big.NewInt(0)},
		{name: "read unavailable", err: errors.New("mock read unavailable"), want: big.NewInt(0)},
		{name: "missing balance", account: &stateMock.UserAccountStub{}, want: big.NewInt(0)},
		{name: "numeric balance", account: &stateMock.UserAccountStub{Balance: stored}, want: stored},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			host := &vmContext{blockChainHook: &mock.BlockChainHookStub{
				GetUserAccountCalled: func(got []byte) (vmcommon.UserAccountHandler, error) {
					calls++
					require.Equal(t, address, got)
					return tc.account, tc.err
				},
			}}
			got := host.getPersistedBalance(address)
			require.Equal(t, tc.want, got)
			require.NotSame(t, tc.want, got)
			require.Equal(t, 1, calls)
		})
	}
}
