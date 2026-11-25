package facade

import (
	"context"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/api"
	"github.com/multiversx/mx-chain-go/facade/mock"
	"github.com/stretchr/testify/require"
)

// Exercise only the facade's ordinary DTO forwarding, using a synthetic node stub.
func TestQualFacadeMockIterateKeysForwarding(t *testing.T) {
	t.Parallel()

	const address = "synthetic-account"
	const count = uint(2)
	options := api.AccountQueryOptions{}
	state := [][]byte{[]byte("mock-position")}
	expectedValues := map[string]string{"sample": "value"}
	expectedNext := [][]byte{[]byte("next-position")}
	expectedBlock := api.BlockInfo{Nonce: 7, Hash: "mock-block"}
	calls := 0
	arg := createMockArguments()
	arg.Node = &mock.NodeStub{
		IterateKeysCalled: func(gotAddress string, gotCount uint, gotState [][]byte, gotOptions api.AccountQueryOptions, _ context.Context) (map[string]string, [][]byte, api.BlockInfo, error) {
			calls++
			require.Equal(t, address, gotAddress)
			require.Equal(t, count, gotCount)
			require.Equal(t, state, gotState)
			require.Equal(t, options, gotOptions)
			return expectedValues, expectedNext, expectedBlock, nil
		},
	}
	nf, err := NewNodeFacade(arg)
	require.NoError(t, err)

	values, next, block, err := nf.IterateKeys(context.Background(), address, count, state, options)
	require.NoError(t, err)
	require.Equal(t, expectedValues, values)
	require.Equal(t, expectedNext, next)
	require.Equal(t, expectedBlock, block)
	require.Equal(t, 1, calls)
}

func TestQualFacadeMockAccountWithKeysForwarding(t *testing.T) {
	t.Parallel()

	const address = "synthetic-account"
	options := api.AccountQueryOptions{WithKeys: true}
	expected := api.AccountResponse{
		Address:  address,
		Username: "sample-user",
		CodeHash: []byte("mock-code-hash"),
		Pairs:    map[string]string{"sample": "value"},
	}
	expectedBlock := api.BlockInfo{Nonce: 8, Hash: "mock-block"}
	accountCalls, codeCalls := 0, 0
	arg := createMockArguments()
	arg.Node = &mock.NodeStub{
		GetAccountWithKeysCalled: func(gotAddress string, gotOptions api.AccountQueryOptions, _ context.Context) (api.AccountResponse, api.BlockInfo, error) {
			accountCalls++
			require.Equal(t, address, gotAddress)
			require.Equal(t, options, gotOptions)
			return expected, expectedBlock, nil
		},
		GetCodeCalled: func(gotHash []byte, gotOptions api.AccountQueryOptions) ([]byte, api.BlockInfo) {
			codeCalls++
			require.Equal(t, expected.CodeHash, gotHash)
			require.Equal(t, options, gotOptions)
			return []byte{0x12, 0x34}, expectedBlock
		},
	}
	nf, err := NewNodeFacade(arg)
	require.NoError(t, err)

	account, block, err := nf.GetAccount(context.Background(), address, options)
	require.NoError(t, err)
	expected.Code = "1234"
	require.Equal(t, expected, account)
	require.Equal(t, expectedBlock, block)
	require.Equal(t, 1, accountCalls)
	require.Equal(t, 1, codeCalls)
}
