package systemSmartContracts

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// TestQualDRWAUpstreamCreationProfile is a non-normative W05/W07 experiment
// for Part A 2.5, 4.1 AR-11/F02/F03 and E.20. It observes the existing System
// SC with the intended immutable properties; it does not implement protected
// registration, prove shard ACKs, or admit A02/TERMINAL_SAFE_V1.
func TestQualDRWAUpstreamCreationProfile(t *testing.T) {
	cases := []struct {
		family string
		method string
		args   [][]byte
	}{
		{core.FungibleESDT, "issue", [][]byte{[]byte("TokenName"), []byte("TOKEN"), {}, {}}},
		{core.NonFungibleESDTv2, "issueNonFungible", [][]byte{[]byte("TokenName"), []byte("TOKEN")}},
		{core.SemiFungibleESDT, "issueSemiFungible", [][]byte{[]byte("TokenName"), []byte("TOKEN")}},
		{core.MetaESDT, "registerMetaESDT", [][]byte{[]byte("TokenName"), []byte("TOKEN"), {}}},
		{core.DynamicNFTESDT, "registerDynamic", [][]byte{[]byte("TokenName"), []byte("TOKEN"), []byte("NFT")}},
		{core.DynamicSFTESDT, "registerDynamic", [][]byte{[]byte("TokenName"), []byte("TOKEN"), []byte("SFT")}},
		{core.DynamicMetaESDT, "registerDynamic", [][]byte{[]byte("TokenName"), []byte("TOKEN"), []byte("META"), {}}},
	}
	for _, tc := range cases {
		t.Run(tc.family, func(t *testing.T) {
			args := createMockArgumentsForESDT()
			eei := createDefaultEei()
			args.Eei = eei
			flags := args.EnableEpochsHandler.(*enableEpochsHandlerMock.EnableEpochsHandlerStub)
			flags.RemoveActiveFlags(common.GlobalMintBurnFlag)
			flags.AddActiveFlags(common.DynamicESDTFlag, common.ManagedCryptoAPIsFlag, common.NFTStopCreateFlag)
			e, err := NewESDTSmartContract(args)
			require.NoError(t, err)
			owner := bytes.Repeat([]byte{1}, 32)
			origin := bytes.Repeat([]byte{2}, 32)
			replacement := bytes.Repeat([]byte{3}, 32)
			properties := [][]byte{
				[]byte(upgradable), []byte("false"),
				[]byte(canAddSpecialRoles), []byte("true"),
				[]byte(canFreeze), []byte("false"),
				[]byte(canWipe), []byte("false"),
				[]byte(canPause), []byte("false"),
				[]byte(canChangeOwner), []byte("false"),
				[]byte(canTransferNFTCreateRole), []byte("false"),
			}
			if tc.family == core.FungibleESDT {
				properties = append(properties, []byte(mintable), []byte("false"), []byte(burnable), []byte("false"))
			} else {
				properties = append(properties, []byte(canCreateMultiShard), []byte("false"))
			}
			input := getDefaultVmInputForFunc(tc.method, append(tc.args, properties...))
			input.CallerAddr = owner
			input.CallValue = new(big.Int).Set(e.baseIssuingCost)
			eei.gasRemaining = 1000000 // Bounded fixture budget; not a DRWA parameter.
			require.Equal(t, vmcommon.Ok, e.Execute(input), eei.returnMessage)
			require.Len(t, eei.output, 1)
			tokenID := bytes.Clone(eei.output[0])
			read := func() *ESDTDataV2 {
				t.Helper()
				token, err := e.getExistingToken(tokenID)
				require.NoError(t, err)
				return token
			}
			token := read()
			require.Equal(t, tc.family, string(token.TokenType))
			require.Zero(t, token.MintedValue.Sign())
			require.Zero(t, token.BurntValue.Sign())
			require.Equal(t, owner, token.OwnerAddress)
			require.False(t, token.Upgradable)
			require.True(t, token.CanAddSpecialRoles)
			require.False(t, token.CanFreeze || token.CanWipe || token.CanPause || token.CanChangeOwner || token.CanTransferNFTCreateRole || token.CanCreateMultiShard || token.Mintable || token.Burnable)
			// Upstream cleanup-enabled issuance still grants BurnForAll; false
			// canUpgrade and GlobalMintBurnFlag do not remove that separate role.
			require.True(t, checkIfDefinedRoleExistsInToken(token, []byte(vmcommon.ESDTRoleBurnForAll)))
			call := func(method string, argv ...[]byte) vmcommon.ReturnCode {
				t.Helper()
				eei.returnMessage = ""
				eei.gasRemaining = 1000000
				in := getDefaultVmInputForFunc(method, append([][]byte{tokenID}, argv...))
				in.CallerAddr = owner
				return e.Execute(in)
			}
			require.Equal(t, vmcommon.UserError, call("controlChanges", []byte(upgradable), []byte("true")))
			require.Contains(t, eei.returnMessage, "token is not upgradable")
			require.False(t, read().Upgradable)
			require.Equal(t, vmcommon.UserError, call("transferOwnership", replacement))
			require.Equal(t, owner, read().OwnerAddress)
			require.Equal(t, vmcommon.Ok, call("unsetBurnRoleGlobally"), eei.returnMessage)
			require.False(t, checkIfDefinedRoleExistsInToken(read(), []byte(vmcommon.ESDTRoleBurnForAll)))
			burnRole := core.ESDTRoleNFTBurn
			if tc.family == core.FungibleESDT {
				burnRole = core.ESDTRoleLocalBurn
			}
			require.Equal(t, vmcommon.Ok, call("setSpecialRole", origin, []byte(burnRole)), eei.returnMessage)
			require.True(t, checkIfDefinedRoleExistsInToken(read(), []byte(burnRole)))
			require.Equal(t, vmcommon.Ok, call("unSetSpecialRole", origin, []byte(burnRole)), eei.returnMessage)
			require.False(t, checkIfDefinedRoleExistsInToken(read(), []byte(burnRole)))
			if tc.family != core.FungibleESDT {
				require.Equal(t, vmcommon.Ok, call("setSpecialRole", origin, []byte(core.ESDTRoleNFTCreate)), eei.returnMessage)
				beforeHandover := bytes.Clone(eei.GetStorage(tokenID))
				require.Equal(t, vmcommon.UserError, call("unSetSpecialRole", origin, []byte(core.ESDTRoleNFTCreate)))
				require.Contains(t, eei.returnMessage, "cannot un set NFT create role")
				require.Equal(t, beforeHandover, eei.GetStorage(tokenID))
				require.Equal(t, vmcommon.UserError, call("setSpecialRole", replacement, []byte(core.ESDTRoleNFTCreate)))
				require.Equal(t, beforeHandover, eei.GetStorage(tokenID))
				require.Equal(t, vmcommon.UserError, call("transferNFTCreateRole", origin, replacement))
				require.Contains(t, eei.returnMessage, "NFT create role transfer is not allowed")
				require.Equal(t, beforeHandover, eei.GetStorage(tokenID))
				// The permanent stop is available but is not a creator handover.
				require.Equal(t, vmcommon.Ok, call("stopNFTCreate"), eei.returnMessage)
				require.True(t, read().NFTCreateStopped)
				require.False(t, checkIfDefinedRoleExistsInToken(read(), []byte(core.ESDTRoleNFTCreate)))
				require.Equal(t, vmcommon.UserError, call("setSpecialRole", replacement, []byte(core.ESDTRoleNFTCreate)))
				require.Contains(t, eei.returnMessage, "NFT creation was stopped")
			}
			require.False(t, read().Upgradable)
			require.Zero(t, read().MintedValue.Sign())
		})
	}
}
