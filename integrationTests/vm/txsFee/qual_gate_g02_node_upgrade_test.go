package txsFee

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"os"
	"testing"

	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/integrationTests/vm"
	"github.com/multiversx/mx-chain-go/integrationTests/vm/txsFee/utils"
	"github.com/multiversx/mx-chain-go/process/factory"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	vmtest "github.com/multiversx/mx-chain-vm-go/testcommon"
	"github.com/multiversx/mx-chain-vm-go/vmhost"
	"github.com/stretchr/testify/require"
)

// Experimental gas/balance coordinates; ordinary local native execution only.
// Root recreation and warm-cache clearing are not process restart, factory
// admission, native-lifetime qualification or a regulated execution proof.
func TestQualGateG02NodeUpgradeJournalCache(t *testing.T) {
	codeA, err := os.ReadFile("../wasm/testdata/hello-v1/output/answer.wasm")
	require.NoError(t, err)
	codeB, err := os.ReadFile("../wasm/testdata/hello-v2/output/answer.wasm")
	require.NoError(t, err)
	for _, seed := range []string{"warm", "compiled", "cold"} {
		for _, outcome := range []string{"invalid_code", "wrong_owner", "revert_valid_upgrade"} {
			t.Run(seed+"/"+outcome, func(t *testing.T) {
				ctx, e := vm.CreatePreparedTxProcessorWithVMs(config.EnableEpochs{}, 1)
				require.NoError(t, e)
				t.Cleanup(ctx.Close)
				target, owner := utils.DoDeployWithCustomParams(t, ctx, "../wasm/testdata/hello-v1/output/answer.wasm", big.NewInt(1000000000), 1000000, nil)
				sibling, other := utils.DoDeployWithCustomParams(t, ctx, "../wasm/testdata/hello-v1/output/answer.wasm", big.NewInt(1000000000), 1000000, nil)
				require.NotEqual(t, target, sibling)
				vmExec, e := ctx.VMContainer.Get(factory.WasmVirtualMachine)
				require.NoError(t, e)
				host, ok := vmExec.(vmhost.VMHost)
				require.True(t, ok, "exercise the integrated current VM host")
				query := func(address []byte, answer byte) {
					t.Helper()
					out, queryErr := host.RunSmartContractCall(vmtest.CreateTestContractCallInputBuilder().
						WithRecipientAddr(address).WithCallerAddr(owner).WithGasProvided(1000000).
						WithFunction("getUltimateAnswer").Build())
					require.NoError(t, queryErr)
					require.Equal(t, vmcommon.Ok, out.ReturnCode, out.ReturnMessage)
					require.Equal(t, [][]byte{{answer}}, out.ReturnData)
				}
				account := func(address []byte) state.UserAccountHandler {
					t.Helper()
					a, loadErr := ctx.Accounts.GetExistingAccount(address)
					require.NoError(t, loadErr)
					return a.(state.UserAccountHandler)
				}
				query(target, 24)
				query(sibling, 24)
				oldHash := bytes.Clone(account(target).GetCodeHash())
				oldMetadata := bytes.Clone(account(target).GetCodeMetadata())
				oldBalance := new(big.Int).Set(account(target).GetBalance())
				require.Equal(t, oldHash, account(sibling).GetCodeHash())
				require.Equal(t, codeA, ctx.Accounts.GetCode(oldHash))
				found, compiledA := ctx.BlockchainHook.GetCompiledCode(oldHash)
				require.True(t, found)
				compiledA = bytes.Clone(compiledA)
				require.NotEmpty(t, compiledA)
				if seed != "warm" {
					host.Runtime().ClearWarmInstanceCache()
				}
				if seed == "cold" {
					ctx.BlockchainHook.(interface{ ClearCompiledCodes() }).ClearCompiledCodes()
				}
				root, e := ctx.Accounts.Commit()
				require.NoError(t, e)
				snapshot := ctx.Accounts.JournalLen()
				caller, newCode := owner, codeB
				if outcome == "invalid_code" {
					newCode = []byte("not WebAssembly")
				}
				if outcome == "wrong_owner" {
					caller = other
				}
				tx := vm.CreateTransaction(account(caller).GetNonce(), big.NewInt(0), caller, target, 10, 1000000,
					[]byte("upgradeContract@"+hex.EncodeToString(newCode)+"@0100"))
				code, processErr := ctx.TxProcessor.ProcessTransaction(tx)
				require.NoError(t, processErr)
				if outcome == "revert_valid_upgrade" {
					require.Equal(t, vmcommon.Ok, code)
					newHash := bytes.Clone(account(target).GetCodeHash())
					require.NotEqual(t, oldHash, newHash)
					require.Equal(t, codeB, ctx.Accounts.GetCode(newHash))
					query(target, 42)
					query(sibling, 24)
					foundB, compiledB := ctx.BlockchainHook.GetCompiledCode(newHash)
					require.True(t, foundB)
					require.NotEmpty(t, compiledB)
					require.NotEqual(t, compiledA, compiledB)
				} else {
					require.Equal(t, vmcommon.UserError, code)
					require.Equal(t, oldHash, account(target).GetCodeHash())
					require.Equal(t, oldMetadata, account(target).GetCodeMetadata())
					require.Equal(t, owner, account(target).GetOwnerAddress())
					require.Equal(t, oldBalance, account(target).GetBalance())
					query(target, 24)
				}
				require.Equal(t, oldHash, account(sibling).GetCodeHash())
				require.NoError(t, ctx.Accounts.RevertToSnapshot(snapshot))
				restored, e := ctx.Accounts.RootHash()
				require.NoError(t, e)
				require.Equal(t, root, restored, "outer candidate journal restores code references and sender state")
				require.Equal(t, oldHash, account(target).GetCodeHash())
				require.Equal(t, codeA, ctx.Accounts.GetCode(oldHash))
				host.Runtime().ClearWarmInstanceCache()
				query(target, 24)
				query(sibling, 24)
				found, restoredCompiled := ctx.BlockchainHook.GetCompiledCode(oldHash)
				require.True(t, found)
				if seed == "cold" {
					require.NotEmpty(t, restoredCompiled, "cold reconstruction repopulates the original hash")
				} else {
					require.Equal(t, compiledA, restoredCompiled, "original compiled bytes retain their hash owner")
				}
			})
		}
	}
}
