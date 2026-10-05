package wasmer

import (
	"bytes"
	"os"
	"testing"

	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	vmtest "github.com/multiversx/mx-chain-vm-go/testcommon"
	"github.com/multiversx/mx-chain-vm-go/vmhost"
	"github.com/multiversx/mx-chain-vm-go/wasmer2"
	"github.com/stretchr/testify/require"
)

// AT-04/SQ-04–06: actual host upgrade calls and native execution, with a
// hook-backed committed snapshot and compiled cache. The successful-upgrade
// output is deliberately not committed. This observes the host boundary;
// it does not prove node rollback, historical replay or process restart.
func TestQualDRWAHostUpgradeCacheIsolation(t *testing.T) {
	codeA, err := os.ReadFile("../testdata/hello-v2/output/answer.wasm")
	require.NoError(t, err)
	codeB, err := os.ReadFile("../testdata/counter/output/counter.wasm")
	require.NoError(t, err)
	hashA := blake2b.NewBlake2b().Compute(string(codeA))
	hashB := blake2b.NewBlake2b().Compute(string(codeB))
	require.NotEqual(t, hashA, hashB)
	for _, seed := range []string{"warm", "compiled"} {
		for _, outcome := range []string{"discarded_success", "wrong_owner", "invalid_code"} {
			t.Run(seed+"/"+outcome, func(t *testing.T) {
				target := vmtest.MakeTestSCAddress("upgrade-target")
				sibling := vmtest.MakeTestSCAddress("original-code")
				hook := vmtest.BlockchainHookStubForContracts([]*vmtest.InstanceTestSmartContract{
					vmtest.CreateInstanceContract(target).WithOwner(vmtest.UserAddress).WithCode(codeA),
					vmtest.CreateInstanceContract(sibling).WithOwner(vmtest.UserAddress).WithCode(codeA),
				})
				cache := make(map[string][]byte)
				var writes, reads [][]byte
				hook.SaveCompiledCodeCalled = func(hash, compiled []byte) {
					writes = append(writes, bytes.Clone(hash))
					cache[string(hash)] = bytes.Clone(compiled)
				}
				hook.GetCompiledCodeCalled = func(hash []byte) (bool, []byte) {
					reads = append(reads, bytes.Clone(hash))
					compiled, found := cache[string(hash)]
					return found, bytes.Clone(compiled)
				}
				host := vmtest.NewTestHostBuilder(t).WithBlockchainHook(hook).
					WithExecutorFactory(wasmer2.ExecutorFactory()).Build()
				t.Cleanup(host.Reset)
				callOriginal := func(address []byte) {
					t.Helper()
					input := vmtest.CreateTestContractCallInputBuilder().WithRecipientAddr(address).
						WithCallerAddr(vmtest.UserAddress).WithGasProvided(1000000).
						WithFunction("getUltimateAnswer").Build()
					output, callErr := host.RunSmartContractCall(input)
					require.NoError(t, callErr)
					require.NotNil(t, output)
					require.Equal(t, vmcommon.Ok, output.ReturnCode, output.ReturnMessage)
					// The independent upstream C fixture calls int64finish(42).
					require.Equal(t, [][]byte{{42}}, output.ReturnData)
				}
				callOriginal(target)
				oldCompiled := bytes.Clone(cache[string(hashA)])
				require.NotEmpty(t, oldCompiled)
				if seed == "compiled" {
					host.Runtime().ClearWarmInstanceCache()
				}
				writes = nil
				input := vmtest.CreateTestContractCallInputBuilder().WithRecipientAddr(target).
					WithCallerAddr(vmtest.UserAddress).WithGasProvided(1000000).
					WithFunction(vmhost.UpgradeFunctionName).
					WithArguments(codeB, vmtest.DefaultCodeMetadata).Build()
				if outcome == "wrong_owner" {
					input.CallerAddr = vmtest.ChildAddress
				}
				if outcome == "invalid_code" {
					input.Arguments[0] = []byte("not WebAssembly")
				}
				output, callErr := host.RunSmartContractCall(input)
				require.NoError(t, callErr)
				require.NotNil(t, output)
				switch outcome {
				case "discarded_success":
					require.Equal(t, vmcommon.Ok, output.ReturnCode, output.ReturnMessage)
					require.Contains(t, output.OutputAccounts, string(target))
					require.Equal(t, codeB, output.OutputAccounts[string(target)].Code)
					require.Equal(t, [][]byte{hashB}, writes)
				case "wrong_owner":
					require.Equal(t, vmcommon.ExecutionFailed, output.ReturnCode)
					require.Equal(t, vmhost.ErrUpgradeNotAllowed.Error(), output.ReturnMessage)
					require.Empty(t, writes)
				case "invalid_code":
					require.Equal(t, vmcommon.ContractInvalid, output.ReturnCode)
					require.Equal(t, vmhost.ErrContractInvalid.Error(), output.ReturnMessage)
					require.Empty(t, writes)
				}
				if outcome != "discarded_success" {
					for _, account := range output.OutputAccounts {
						require.Empty(t, account.Code)
					}
				}
				require.Equal(t, oldCompiled, cache[string(hashA)], "upgrade must not replace original compiled code")
				// The hook deliberately retains both original accounts: no output
				// from the upgrade is applied. A fresh host invocation resets its
				// transient output state, while the compiled cache survives.
				host.Runtime().ClearWarmInstanceCache()
				reads, writes = nil, nil
				callOriginal(target)
				require.Equal(t, [][]byte{hashA}, reads)
				require.Empty(t, writes, "original compiled cache must remain reusable")
				callOriginal(sibling)
				require.NoError(t, host.Runtime().ValidateInstances())
			})
		}
	}
}
