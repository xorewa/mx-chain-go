package systemSmartContracts

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/vm/mock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Part A 5.1: observes native issuance output before any network transport.
// Three shards are a test fixture, not a selected DRWA resource parameter.
func TestQualDRWARegistrationFanoutFlagOrdering(t *testing.T) {
	for _, cleanup := range []bool{false, true} {
		for _, dynamic := range []bool{false, true} {
			t.Run(fmt.Sprintf("cleanup_%t_dynamic_%t", cleanup, dynamic), func(t *testing.T) {
				args := createMockArgumentsForESDT()
				flags := args.EnableEpochsHandler.(*enableEpochsHandlerMock.EnableEpochsHandlerStub)
				flags.RemoveActiveFlags(common.ESDTMetadataContinuousCleanupFlag, common.DynamicESDTFlag)
				if cleanup {
					flags.AddActiveFlags(common.ESDTMetadataContinuousCleanupFlag)
				}
				if dynamic {
					flags.AddActiveFlags(common.DynamicESDTFlag)
				}
				ctxArgs := createDefaultEeiArgs()
				ctxArgs.BlockChainHook.(*mock.BlockChainHookStub).NumberOfShardsCalled = func() uint32 { return 3 }
				eei, err := NewVMContext(ctxArgs)
				require.NoError(t, err)
				args.Eei = eei
				args.ESDTSCAddress = bytes.Clone(core.ESDTSCAddress)
				e, err := NewESDTSmartContract(args)
				require.NoError(t, err)
				tokenID, token, err := e.createNewToken(bytes.Repeat([]byte{1}, 32), []byte("TokenName"), []byte("TOKEN"), big.NewInt(0), 0, nil, []byte(core.FungibleESDT))
				require.NoError(t, err)
				require.NotEmpty(t, tokenID)
				require.Equal(t, cleanup, checkIfDefinedRoleExistsInToken(token, []byte(vmcommon.ESDTRoleBurnForAll)))
				var calls []string
				if cleanup {
					calls = append(calls, vmcommon.BuiltInFunctionESDTSetBurnRoleForAll+"@"+hex.EncodeToString(tokenID))
				}
				if dynamic {
					calls = append(calls, core.ESDTSetTokenType+"@"+hex.EncodeToString(tokenID)+"@"+hex.EncodeToString([]byte(core.FungibleESDT)))
				}
				if len(calls) == 0 {
					require.Empty(t, eei.outputAccounts)
				} else {
					require.Len(t, eei.outputAccounts, 3)
				}
				for shard := byte(0); shard < 3 && len(calls) > 0; shard++ {
					destination := bytes.Clone(core.SystemAccountAddress)
					destination[len(destination)-1] = shard
					out := eei.outputAccounts[string(destination)]
					require.NotNil(t, out)
					require.Equal(t, destination, out.Address)
					require.Zero(t, out.BalanceDelta.Sign())
					require.Len(t, out.OutputTransfers, len(calls))
					for step, call := range calls {
						transfer := out.OutputTransfers[step]
						require.Equal(t, []byte(call), transfer.Data)
						require.Equal(t, 1+uint32(step*3)+uint32(shard), transfer.Index)
						require.Empty(t, transfer.SenderAddress, "global helper does not install its sender parameter")
						require.Equal(t, vmData.DirectCall, transfer.CallType)
						require.Zero(t, transfer.Value.Sign())
						require.Zero(t, transfer.GasLimit)
						require.Zero(t, transfer.GasLocked)
					}
				}
				require.Equal(t, 1+uint32(3*len(calls)), eei.GetCrtTransferIndex())
				stored, err := e.getExistingToken(tokenID)
				require.NoError(t, err)
				require.Equal(t, core.FungibleESDT, string(stored.TokenType))
				require.Zero(t, stored.MintedValue.Sign())
			})
		}
	}
}

func TestQualDRWAGlobalFanoutSenderParameter(t *testing.T) {
	for _, sender := range [][]byte{core.ESDTSCAddress, bytes.Repeat([]byte{0x42}, 32)} {
		t.Run(hex.EncodeToString(sender), func(t *testing.T) {
			args := createDefaultEeiArgs()
			args.BlockChainHook.(*mock.BlockChainHookStub).NumberOfShardsCalled = func() uint32 { return 3 }
			host, err := NewVMContext(args)
			require.NoError(t, err)
			data := []byte(core.ESDTSetTokenType + "@544f4b454e2d303030303031@" + hex.EncodeToString([]byte(core.FungibleESDT)))
			host.SendGlobalSettingToAll(sender, data)
			require.Len(t, host.outputAccounts, 3)
			for _, out := range host.outputAccounts {
				require.Len(t, out.OutputTransfers, 1)
				require.Empty(t, out.OutputTransfers[0].SenderAddress)
				require.Equal(t, data, out.OutputTransfers[0].Data)
			}
		})
	}
}
