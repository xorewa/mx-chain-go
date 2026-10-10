package txsFee

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/integrationTests/vm"
	"github.com/multiversx/mx-chain-go/integrationTests/vm/txsFee/utils"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
)

// T25 model04 H07-H10: actual native account/hook/builtin/SCR dispatcher.
// Only the receiver executes; no source debit, canonical incoming item, DRWA
// refund authority, consumption, isolated funding or durable retry is proved.
// Native integration services/forwarder remain doubles; no guest WASM runs.
func TestQualDRWAOutcomeRealCreditFailure(t *testing.T) {
	for _, name := range []string{"valid", "wrong_type", "malformed", "frozen"} {
		t.Run(name, func(t *testing.T) {
			coordinator, err := sharding.NewMultiShardCoordinator(2, 0)
			require.NoError(t, err)
			ctx, err := vm.CreatePreparedTxProcessorWithVMsWithShardCoordinator(config.EnableEpochs{}, coordinator, 1)
			require.NoError(t, err)
			t.Cleanup(ctx.Close)
			require.True(t, ctx.EnableEpochsHandler.IsFlagEnabledInEpoch(common.SCProcessorV2Flag, 0))
			sender, receiver := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
			sender[31], receiver[31] = 1, 0
			require.Equal(t, uint32(1), coordinator.ComputeId(sender))
			require.Equal(t, uint32(0), coordinator.ComputeId(receiver))
			token := []byte("TOKEN-abcdef")
			utils.CreateAccountWithESDTBalance(t, ctx.Accounts, receiver, big.NewInt(100000000), token, 0, big.NewInt(5), uint32(core.Fungible))
			key := append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), token...)
			account, err := ctx.Accounts.LoadAccount(receiver)
			require.NoError(t, err)
			user := account.(state.UserAccountHandler)
			if name != "valid" {
				record := &esdt.ESDigitalToken{Value: big.NewInt(5), Type: uint32(core.Fungible), Properties: []byte{0, 0}}
				if name == "wrong_type" {
					record.Type = uint32(core.NonFungible)
				}
				if name == "frozen" {
					record.Properties = []byte{1, 0} // independent native Frozen bit
				}
				raw, marshalErr := ctx.Marshalizer.Marshal(record)
				require.NoError(t, marshalErr)
				if name == "malformed" {
					raw = []byte{0xff}
				}
				require.NoError(t, user.SaveKeyValue(key, raw))
				require.NoError(t, ctx.Accounts.SaveAccount(user))
			}
			root, err := ctx.Accounts.Commit()
			require.NoError(t, err)
			read := func() []byte {
				a, readErr := ctx.Accounts.GetExistingAccount(receiver)
				require.NoError(t, readErr)
				raw, _, readErr := a.(state.UserAccountHandler).RetrieveValue(key)
				require.NoError(t, readErr)
				return bytes.Clone(raw)
			}
			before := read()
			input := &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{
				CallerAddr: sender, CallValue: big.NewInt(0), Arguments: [][]byte{token, {30}},
				GasProvided: 100000, GasPrice: 10, ReturnCallAfterError: true,
			}, RecipientAddr: receiver, Function: core.BuiltInFunctionESDTTransfer}
			output, hookErr := ctx.BlockchainHook.ProcessBuiltInFunction(input)
			failed := name == "wrong_type" || name == "malformed"
			if failed {
				require.Error(t, hookErr)
				if name == "wrong_type" {
					require.ErrorIs(t, hookErr, builtInFunctions.ErrOnlyFungibleTokensHaveBalanceTransfer)
				}
				require.Nil(t, output)
				require.Equal(t, before, read())
			} else {
				require.NoError(t, hookErr)
				require.Equal(t, vmcommon.Ok, output.ReturnCode)
				credited := &esdt.ESDigitalToken{}
				require.NoError(t, ctx.Marshalizer.Unmarshal(credited, read()))
				require.Equal(t, big.NewInt(35), credited.Value)
			}
			require.NoError(t, ctx.Accounts.RevertToSnapshot(0))
			restored, err := ctx.Accounts.RootHash()
			require.NoError(t, err)
			require.Equal(t, root, restored, "direct probe must not feed dispatcher state")
			require.Equal(t, before, read())

			scr := &smartContractResult.SmartContractResult{SndAddr: sender, RcvAddr: receiver, Value: big.NewInt(0),
				Data: []byte("ESDTTransfer@544f4b454e2d616263646566@1e"), ReturnMessage: []byte("denied"), GasLimit: 100000, GasPrice: 10}
			code, err := ctx.ScProcessor.ProcessSmartContractResult(scr)
			require.NoError(t, err)
			require.Equal(t, vmcommon.Ok, code, "outer status does not establish credit")
			require.Empty(t, ctx.GetIntermediateTransactions(t))
			expectedFee := big.NewInt(0)
			if failed {
				expectedFee.SetInt64(1000000) // 100000 gas * price10 * modifier1
			}
			require.Equal(t, expectedFee, ctx.TxFeeHandler.GetAccumulatedFees())
			finalRoot, err := ctx.Accounts.Commit()
			require.NoError(t, err)
			if failed {
				require.Equal(t, before, read(), "native credit failed despite outer Ok")
				require.Equal(t, root, finalRoot)
			} else {
				actual := &esdt.ESDigitalToken{}
				require.NoError(t, ctx.Marshalizer.Unmarshal(actual, read()))
				require.Equal(t, big.NewInt(35), actual.Value)
				require.Equal(t, uint32(core.Fungible), actual.Type)
				if name == "frozen" {
					require.Equal(t, []byte{1, 0}, actual.Properties)
				}
				require.NotEqual(t, root, finalRoot)
			}
		})
	}
}
