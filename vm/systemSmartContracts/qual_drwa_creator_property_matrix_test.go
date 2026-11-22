package systemSmartContracts

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/vm/mock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// This SP1 investigation separates A02 from the native creator-transfer gate.
// True property values are comparison fixtures, not an approved DRWA profile.
// It observes metachain storage and emitted messages, not shard execution,
// collection-counter continuity, protected manager authorization or finality.
func TestQualDRWACreatorPropertyMatrix(t *testing.T) {
	families := []struct {
		family string
		method string
		args   [][]byte
	}{
		{core.NonFungibleESDTv2, "issueNonFungible", [][]byte{[]byte("TokenName"), []byte("TOKEN")}},
		{core.SemiFungibleESDT, "issueSemiFungible", [][]byte{[]byte("TokenName"), []byte("TOKEN")}},
		{core.MetaESDT, "registerMetaESDT", [][]byte{[]byte("TokenName"), []byte("TOKEN"), {}}},
		{core.DynamicNFTESDT, "registerDynamic", [][]byte{[]byte("TokenName"), []byte("TOKEN"), []byte("NFT")}},
		{core.DynamicSFTESDT, "registerDynamic", [][]byte{[]byte("TokenName"), []byte("TOKEN"), []byte("SFT")}},
		{core.DynamicMetaESDT, "registerDynamic", [][]byte{[]byte("TokenName"), []byte("TOKEN"), []byte("META"), {}}},
	}
	for _, family := range families {
		for _, canUpgrade := range []bool{false, true} {
			for _, canTransfer := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/upgrade=%t/transfer=%t", family.family, canUpgrade, canTransfer), func(t *testing.T) {
					args := createMockArgumentsForESDT()
					eeiArgs := createDefaultEeiArgs()
					// Full callback sweep: storage misses during issuance, seed for
					// token ID, and all-shard type/BurnForAll output construction.
					eeiArgs.BlockChainHook = &mock.BlockChainHookStub{
						GetStorageDataCalled:    func(_ []byte, _ []byte) ([]byte, uint32, error) { return nil, 0, nil },
						CurrentRandomSeedCalled: func() []byte { return []byte("creator-matrix-seed") },
						NumberOfShardsCalled:    func() uint32 { return 3 },
					}
					eei, err := NewVMContext(eeiArgs)
					require.NoError(t, err)
					args.Eei = eei
					flags := args.EnableEpochsHandler.(*enableEpochsHandlerMock.EnableEpochsHandlerStub)
					flags.RemoveActiveFlags(common.GlobalMintBurnFlag)
					flags.AddActiveFlags(common.DynamicESDTFlag, common.ManagedCryptoAPIsFlag, common.NFTStopCreateFlag)
					e, err := NewESDTSmartContract(args)
					require.NoError(t, err)
					owner := bytes.Repeat([]byte{1}, 32)
					origin := bytes.Repeat([]byte{2}, 32)
					successor := bytes.Repeat([]byte{3}, 32)
					properties := [][]byte{
						[]byte(upgradable), []byte(strconv.FormatBool(canUpgrade)),
						[]byte(canTransferNFTCreateRole), []byte(strconv.FormatBool(canTransfer)),
						[]byte(canAddSpecialRoles), []byte("true"),
						[]byte(canCreateMultiShard), []byte("false"),
						[]byte(canChangeOwner), []byte("false"),
					}
					argv := append(append([][]byte{}, family.args...), properties...)
					input := getDefaultVmInputForFunc(family.method, argv)
					input.CallerAddr = owner
					input.CallValue = new(big.Int).Set(e.baseIssuingCost)
					eei.gasRemaining = 1000000 // Fixture budget; not a protocol bound.
					require.Equal(t, vmcommon.Ok, e.Execute(input), eei.returnMessage)
					require.Len(t, eei.output, 1)
					tokenID := bytes.Clone(eei.output[0])
					read := func() *ESDTDataV2 {
						token, readErr := e.getExistingToken(tokenID)
						require.NoError(t, readErr)
						return token
					}
					call := func(method string, caller []byte, values ...[]byte) vmcommon.ReturnCode {
						eei.returnMessage = ""
						eei.gasRemaining = 1000000
						in := getDefaultVmInputForFunc(method, append([][]byte{tokenID}, values...))
						in.CallerAddr = caller
						return e.Execute(in)
					}
					transferCount := func(address []byte) int {
						account := eei.outputAccounts[string(address)]
						if account == nil {
							return 0
						}
						return len(account.OutputTransfers)
					}
					require.Equal(t, vmcommon.Ok, call("setSpecialRole", owner, origin, []byte(core.ESDTRoleNFTCreate)))
					before := bytes.Clone(eei.GetStorage(tokenID))
					require.Equal(t, vmcommon.UserError, call("transferNFTCreateRole", successor, origin, successor))
					require.Equal(t, "can be called by owner only", eei.returnMessage)
					require.Equal(t, before, eei.GetStorage(tokenID))
					oldOutputCount := transferCount(origin)
					code := call("transferNFTCreateRole", owner, origin, successor)
					currentCreator := origin
					if canTransfer {
						require.Equal(t, vmcommon.Ok, code, eei.returnMessage)
						creator, creatorErr := getFirstAddressWithGivenRole(read(), []byte(core.ESDTRoleNFTCreate))
						require.NoError(t, creatorErr)
						require.Equal(t, successor, creator)
						transfers := eei.outputAccounts[string(origin)].OutputTransfers
						require.Len(t, transfers, oldOutputCount+1)
						require.Equal(t, []byte(core.BuiltInFunctionESDTNFTCreateRoleTransfer+"@"+hex.EncodeToString(tokenID)+"@"+hex.EncodeToString(successor)), transfers[len(transfers)-1].Data)
						currentCreator = successor
					} else {
						require.Equal(t, vmcommon.UserError, code)
						require.Equal(t, "NFT create role transfer is not allowed", eei.returnMessage)
						require.Equal(t, before, eei.GetStorage(tokenID))
						require.Equal(t, oldOutputCount, transferCount(origin))
					}
					require.Equal(t, canUpgrade, read().Upgradable)
					require.Equal(t, canTransfer, read().CanTransferNFTCreateRole)
					require.False(t, read().CanCreateMultiShard)
					require.Equal(t, owner, read().OwnerAddress)
					require.Zero(t, read().MintedValue.Sign())
					require.Zero(t, read().BurntValue.Sign())
					beforeStop := transferCount(currentCreator)
					require.Equal(t, vmcommon.Ok, call("stopNFTCreate", owner), eei.returnMessage)
					require.True(t, read().NFTCreateStopped)
					require.False(t, checkIfDefinedRoleExistsInToken(read(), []byte(core.ESDTRoleNFTCreate)))
					require.Equal(t, beforeStop+1, transferCount(currentCreator))
					stopped := bytes.Clone(eei.GetStorage(tokenID))
					require.Equal(t, vmcommon.UserError, call("setSpecialRole", owner, origin, []byte(core.ESDTRoleNFTCreate)))
					require.Contains(t, eei.returnMessage, "NFT creation was stopped")
					require.Equal(t, stopped, eei.GetStorage(tokenID))
					require.Equal(t, vmcommon.UserError, call("stopNFTCreate", owner))
					require.Equal(t, "NFT create was already stopped", eei.returnMessage)
					code = call("controlChanges", owner, []byte(canPause), []byte("true"))
					if canUpgrade {
						require.Equal(t, vmcommon.Ok, code, eei.returnMessage)
						require.True(t, read().CanPause)
					} else {
						require.Equal(t, vmcommon.UserError, code)
						require.Equal(t, "token is not upgradable", eei.returnMessage)
						require.Equal(t, stopped, eei.GetStorage(tokenID))
					}
				})
			}
		}
	}
}
