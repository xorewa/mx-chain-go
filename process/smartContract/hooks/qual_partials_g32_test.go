package hooks_test

import (
	"bytes"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	contextMock "github.com/multiversx/mx-chain-vm-go/mock/context"
	"github.com/multiversx/mx-chain-vm-go/vmhost"
	"github.com/multiversx/mx-chain-vm-go/vmhost/contexts"
	"github.com/stretchr/testify/require"
	"testing"
)

// G32.02: actual VM code-hash/output contexts select the actual hook cache.
// The account dependency and unused executor are mocks. This is neither a
// guest upgrade nor owning-journal rollback, and supplies no G32.03 credit.
func TestQualPartialsG32CrossAccountCompiledCode(t *testing.T) {
	args := createMockBlockChainHookArgs()
	t.Cleanup(func() { require.NoError(t, args.DataPool.Close()) })
	addressA, addressB := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	codeA, codeB, codeNew := []byte("synthetic-code-A"), []byte("synthetic-code-B"), []byte("synthetic-code-A-new")
	hasher := blake2b.NewBlake2b()
	hashA, hashB, hashNew := hasher.Compute(string(codeA)), hasher.Compute(string(codeB)), hasher.Compute(string(codeNew))
	accountA, accountB := createAccount(addressA), createAccount(addressB)
	accountA.SetCodeHash(hashA)
	accountB.SetCodeHash(hashB)
	args.Accounts = &stateMock.AccountsStub{GetExistingAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
		if bytes.Equal(address, addressA) {
			return accountA, nil
		}
		require.Equal(t, addressB, address)
		return accountB, nil
	}}
	hook, err := hooks.NewBlockChainHookImpl(args)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, hook.Close()) })
	host := &contextMock.VMHostMock{BlockChainHook: hook, EnableEpochsHandlerField: args.EnableEpochsHandler}
	output, err := contexts.NewOutputContext(host)
	require.NoError(t, err)
	host.OutputContext = output
	runtime, err := contexts.NewRuntimeContext(host, []byte{5, 0}, args.BuiltInFunctions, &contextMock.ExecutorMock{}, hasher)
	require.NoError(t, err)
	host.RuntimeContext = runtime
	blockchain, err := contexts.NewBlockchainContext(host, hook)
	require.NoError(t, err)
	host.BlockchainContext = blockchain
	compiledA, compiledB, compiledNew := []byte("compiled-A"), []byte("compiled-B"), []byte("compiled-A-new")
	blockchain.SaveCompiledCode(hashA, compiledA)
	blockchain.SaveCompiledCode(hashB, compiledB)
	get := func(address, wantHash, wantCode []byte) {
		t.Helper()
		hash := blockchain.GetCodeHash(address)
		require.Equal(t, wantHash, hash)
		found, code := blockchain.GetCompiledCode(hash)
		require.True(t, found)
		require.Equal(t, wantCode, code)
	}
	get(addressA, hashA, compiledA)
	get(addressB, hashB, compiledB)
	output.PushState()
	output.DeployCode(vmhost.CodeDeployInput{ContractAddress: addressA, ContractCode: codeNew})
	blockchain.SaveCompiledCode(hashNew, compiledNew)
	get(addressA, hashNew, compiledNew)
	get(addressB, hashB, compiledB)
	output.PopSetActiveState()
	get(addressA, hashA, compiledA)
	get(addressB, hashB, compiledB)
	// A separate current-output code update chooses the new hash again.
	output.DeployCode(vmhost.CodeDeployInput{ContractAddress: addressA, ContractCode: codeNew})
	hook.DeleteCompiledCode(hashA)
	get(addressA, hashNew, compiledNew)
	get(addressB, hashB, compiledB)
	found, code := blockchain.GetCompiledCode(hashA)
	require.False(t, found)
	require.Nil(t, code)
	blockchain.ClearCompiledCodes()
	for _, hash := range [][]byte{hashA, hashB, hashNew} {
		found, code = blockchain.GetCompiledCode(hash)
		require.False(t, found)
		require.Nil(t, code)
	}
}
