package systemSmartContracts

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/vm"
	"github.com/multiversx/mx-chain-go/vm/mock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// These native public-route controls close T15 CP-01 before F02/F03 relies on
// them (Part A L2301-2305). They do not implement a DRWA handover or authorize
// any profile adaptation. Only metachain storage and pending outputs are read;
// receiving-shard effects, counters, finality and persistence remain unproved.
func TestQualDRWACreatorPublicRoutes(t *testing.T) {
	for _, family := range []struct {
		name, method string
		arguments    [][]byte
	}{
		{core.NonFungibleESDTv2, "issueNonFungible", [][]byte{[]byte("TokenName"), []byte("TOKEN")}},
		{core.SemiFungibleESDT, "issueSemiFungible", [][]byte{[]byte("TokenName"), []byte("TOKEN")}},
		{core.MetaESDT, "registerMetaESDT", [][]byte{[]byte("TokenName"), []byte("TOKEN"), {}}},
		{core.DynamicNFTESDT, "registerDynamic", [][]byte{[]byte("TokenName"), []byte("TOKEN"), []byte("NFT")}},
		{core.DynamicSFTESDT, "registerDynamic", [][]byte{[]byte("TokenName"), []byte("TOKEN"), []byte("SFT")}},
		{core.DynamicMetaESDT, "registerDynamic", [][]byte{[]byte("TokenName"), []byte("TOKEN"), []byte("META"), {}}},
	} {
		t.Run(family.name, func(t *testing.T) {
			args := createMockArgumentsForESDT()
			contextArgs := createDefaultEeiArgs()
			// Swept exercised hook paths: GetStorage/ID generation/global type
			// output construction. Other context dependencies are nil-checked
			// only; no account or crypto callback is executed by these calls.
			contextArgs.BlockChainHook = &mock.BlockChainHookStub{
				GetStorageDataCalled:    func([]byte, []byte) ([]byte, uint32, error) { return nil, 0, nil },
				CurrentRandomSeedCalled: func() []byte { return []byte("creator-public-routes") },
				NumberOfShardsCalled:    func() uint32 { return 3 },
			}
			context, err := NewVMContext(contextArgs)
			require.NoError(t, err)
			args.Eei = context
			flags := args.EnableEpochsHandler.(*enableEpochsHandlerMock.EnableEpochsHandlerStub)
			flags.RemoveActiveFlags(common.GlobalMintBurnFlag)
			flags.AddActiveFlags(common.DynamicESDTFlag, common.ManagedCryptoAPIsFlag, common.NFTStopCreateFlag)
			contract, err := NewESDTSmartContract(args)
			require.NoError(t, err)
			owner := bytes.Repeat([]byte{1}, 32)
			origin := bytes.Repeat([]byte{2}, 32)
			successor := bytes.Repeat([]byte{3}, 32)
			properties := [][]byte{
				[]byte(upgradable), []byte("false"),
				[]byte(canTransferNFTCreateRole), []byte("false"),
				[]byte(canCreateMultiShard), []byte("false"),
				[]byte(canAddSpecialRoles), []byte("true"),
			}
			issue := getDefaultVmInputForFunc(family.method, append(family.arguments, properties...))
			issue.CallerAddr = owner
			issue.CallValue = new(big.Int).Set(contract.baseIssuingCost)
			context.gasRemaining = 1000000 // Explicit fixture budget, not an admitted bound.
			require.Equal(t, vmcommon.Ok, contract.Execute(issue), context.returnMessage)
			require.Len(t, context.output, 1)
			identifier := bytes.Clone(context.output[0])
			call := func(method string, address []byte) vmcommon.ReturnCode {
				context.gasRemaining = 1000000
				context.returnMessage = ""
				input := getDefaultVmInputForFunc(method, [][]byte{identifier, address, []byte(core.ESDTRoleNFTCreate)})
				input.CallerAddr = owner
				return contract.Execute(input)
			}
			require.Equal(t, vmcommon.Ok, call("setSpecialRole", origin), context.returnMessage)
			before := bytes.Clone(context.GetStorage(identifier))
			outputCount := func() int {
				count := 0
				for _, account := range context.outputAccounts {
					count += len(account.OutputTransfers)
				}
				return count
			}
			beforeOutputs := outputCount()
			t.Run("second_grant", func(t *testing.T) {
				require.Equal(t, vmcommon.UserError, call("setSpecialRole", successor))
				require.Equal(t, vm.ErrNFTCreateRoleAlreadyExists.Error(), context.returnMessage)
				require.Equal(t, before, context.GetStorage(identifier))
				require.Equal(t, beforeOutputs, outputCount())
			})
			t.Run("unset", func(t *testing.T) {
				require.Equal(t, vmcommon.UserError, call("unSetSpecialRole", origin))
				require.Equal(t, "cannot un set NFT create role", context.returnMessage)
				require.Equal(t, before, context.GetStorage(identifier))
				require.Equal(t, beforeOutputs, outputCount())
			})
		})
	}
}
