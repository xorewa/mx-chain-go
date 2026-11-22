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

// Part A 5.1 and W05: exercise the real public creation dispatcher and EEI.
// This is native zero-supply output coverage, not DRWA registration or delivery.
func TestQualDRWAPublicRegistrationFanoutFamilies(t *testing.T) {
	cases := []struct {
		name, method, family string
		args                 [][]byte
		roles, dynamicOnly   bool
	}{
		{"issue_FT", "issue", core.FungibleESDT, [][]byte{[]byte("TokenName"), []byte("TOKEN"), {}, {}}, false, false},
		{"issue_NFT", "issueNonFungible", core.NonFungibleESDTv2, [][]byte{[]byte("TokenName"), []byte("TOKEN")}, false, false},
		{"issue_SFT", "issueSemiFungible", core.SemiFungibleESDT, [][]byte{[]byte("TokenName"), []byte("TOKEN")}, false, false},
		{"register_META", "registerMetaESDT", core.MetaESDT, [][]byte{[]byte("TokenName"), []byte("TOKEN"), {}}, false, false},
		{"roles_FT", "registerAndSetAllRoles", core.FungibleESDT, [][]byte{[]byte("TokenName"), []byte("TOKEN"), []byte("FNG"), {}}, true, false},
		{"roles_NFT", "registerAndSetAllRoles", core.NonFungibleESDTv2, [][]byte{[]byte("TokenName"), []byte("TOKEN"), []byte("NFT"), {}}, true, false},
		{"roles_SFT", "registerAndSetAllRoles", core.SemiFungibleESDT, [][]byte{[]byte("TokenName"), []byte("TOKEN"), []byte("SFT"), {}}, true, false},
		{"roles_META", "registerAndSetAllRoles", core.MetaESDT, [][]byte{[]byte("TokenName"), []byte("TOKEN"), []byte("META"), {}}, true, false},
		{"dynamic_NFT", "registerDynamic", core.DynamicNFTESDT, [][]byte{[]byte("TokenName"), []byte("TOKEN"), []byte("NFT")}, false, true},
		{"dynamic_SFT", "registerDynamic", core.DynamicSFTESDT, [][]byte{[]byte("TokenName"), []byte("TOKEN"), []byte("SFT")}, false, true},
		{"dynamic_META", "registerDynamic", core.DynamicMetaESDT, [][]byte{[]byte("TokenName"), []byte("TOKEN"), []byte("META"), {}}, false, true},
		{"dynamic_roles_NFT", "registerAndSetAllRolesDynamic", core.DynamicNFTESDT, [][]byte{[]byte("TokenName"), []byte("TOKEN"), []byte("NFT")}, true, true},
		{"dynamic_roles_SFT", "registerAndSetAllRolesDynamic", core.DynamicSFTESDT, [][]byte{[]byte("TokenName"), []byte("TOKEN"), []byte("SFT")}, true, true},
		{"dynamic_roles_META", "registerAndSetAllRolesDynamic", core.DynamicMetaESDT, [][]byte{[]byte("TokenName"), []byte("TOKEN"), []byte("META"), {}}, true, true},
	}
	for _, tc := range cases {
		for _, cleanup := range []bool{false, true} {
			for _, dynamic := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/cleanup_%t_dynamic_%t", tc.name, cleanup, dynamic), func(t *testing.T) {
					args := createMockArgumentsForESDT()
					flags := args.EnableEpochsHandler.(*enableEpochsHandlerMock.EnableEpochsHandlerStub)
					flags.RemoveActiveFlags(common.GlobalMintBurnFlag, common.ESDTMetadataContinuousCleanupFlag, common.DynamicESDTFlag)
					flags.AddActiveFlags(common.ManagedCryptoAPIsFlag)
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
					owner := bytes.Repeat([]byte{1}, 32)
					input := getDefaultVmInputForFunc(tc.method, tc.args)
					input.CallerAddr = owner
					input.RecipientAddr = bytes.Clone(core.ESDTSCAddress)
					input.CallValue = new(big.Int).Set(e.baseIssuingCost)
					eei.SetGasProvided(1000000) // Fixture budget, not a DRWA parameter.
					code := e.Execute(input)
					if tc.dynamicOnly && !dynamic {
						require.Equal(t, vmcommon.FunctionNotFound, code)
						require.Equal(t, "invalid method to call", eei.returnMessage)
						require.Empty(t, eei.output)
						require.Empty(t, eei.outputAccounts)
						require.Empty(t, eei.storageUpdate)
						require.Empty(t, eei.logs)
						return
					}
					require.Equal(t, vmcommon.Ok, code, eei.returnMessage)
					require.Len(t, eei.output, 1)
					tokenID := eei.output[0]
					family := tc.family
					if family == core.NonFungibleESDTv2 && !dynamic {
						family = core.NonFungibleESDT // Native pre-flag control, not an admitted DRWA family.
					}
					token, err := e.getExistingToken(tokenID)
					require.NoError(t, err)
					require.Equal(t, family, string(token.TokenType))
					require.Equal(t, owner, token.OwnerAddress)
					require.Zero(t, token.MintedValue.Sign())
					require.Zero(t, token.BurntValue.Sign())
					require.Equal(t, cleanup, checkIfDefinedRoleExistsInToken(token, []byte(vmcommon.ESDTRoleBurnForAll)))
					var globalCalls []string
					if cleanup {
						globalCalls = append(globalCalls, vmcommon.BuiltInFunctionESDTSetBurnRoleForAll+"@"+hex.EncodeToString(tokenID))
					}
					if dynamic {
						globalCalls = append(globalCalls, core.ESDTSetTokenType+"@"+hex.EncodeToString(tokenID)+"@"+hex.EncodeToString([]byte(family)))
					}
					for shard := byte(0); shard < 3; shard++ {
						destination := bytes.Clone(core.SystemAccountAddress)
						destination[len(destination)-1] = shard
						out := eei.outputAccounts[string(destination)]
						if len(globalCalls) == 0 {
							require.Nil(t, out)
							continue
						}
						require.NotNil(t, out)
						require.Equal(t, destination, out.Address)
						require.Len(t, out.OutputTransfers, len(globalCalls))
						for i, want := range globalCalls {
							transfer := out.OutputTransfers[i]
							require.Equal(t, []byte(want), transfer.Data)
							require.Equal(t, uint32(1+i*3+int(shard)), transfer.Index)
							require.Empty(t, transfer.SenderAddress)
						}
					}
					wantTransfers := 3 * len(globalCalls)
					if tc.roles {
						// Independent native role order from esdt.go:548-594; never call
						// getAllRolesForTokenType to generate its own expected result.
						roles := []string{core.ESDTRoleNFTCreate, core.ESDTRoleNFTBurn}
						switch family {
						case core.FungibleESDT:
							roles = []string{core.ESDTRoleLocalMint, core.ESDTRoleLocalBurn}
						case core.SemiFungibleESDT, core.MetaESDT:
							roles = append(roles, core.ESDTRoleNFTAddQuantity)
						case core.DynamicSFTESDT, core.DynamicMetaESDT:
							roles = append(roles, core.ESDTRoleNFTAddQuantity, core.ESDTRoleNFTUpdateAttributes, core.ESDTRoleNFTAddURI)
						default:
							roles = append(roles, core.ESDTRoleNFTUpdateAttributes, core.ESDTRoleNFTAddURI)
						}
						if dynamic && family != core.FungibleESDT && family != core.SemiFungibleESDT && family != core.MetaESDT {
							roles = append(roles, core.ESDTRoleNFTRecreate, core.ESDTRoleModifyCreator, core.ESDTRoleModifyRoyalties, core.ESDTRoleSetNewURI, core.ESDTRoleNFTUpdate)
						}
						want := core.BuiltInFunctionSetESDTRole + "@" + hex.EncodeToString(tokenID)
						var roleBytes [][]byte
						for _, role := range roles {
							want += "@" + hex.EncodeToString([]byte(role))
							roleBytes = append(roleBytes, []byte(role))
						}
						out := eei.outputAccounts[string(owner)]
						require.NotNil(t, out)
						require.Len(t, out.OutputTransfers, 1)
						require.Equal(t, []byte(want), out.OutputTransfers[0].Data)
						require.Equal(t, uint32(1+wantTransfers), out.OutputTransfers[0].Index)
						storedRoles, isNew := getRolesForAddress(token, owner)
						require.False(t, isNew)
						require.Equal(t, roleBytes, storedRoles.Roles)
						wantTransfers++
					}
					actualTransfers := 0
					for _, out := range eei.outputAccounts {
						require.Zero(t, out.BalanceDelta.Sign())
						actualTransfers += len(out.OutputTransfers)
						for _, transfer := range out.OutputTransfers {
							require.Zero(t, transfer.Value.Sign())
							require.Zero(t, transfer.GasLimit)
							require.Zero(t, transfer.GasLocked)
							require.Equal(t, vmData.DirectCall, transfer.CallType)
						}
					}
					require.Equal(t, wantTransfers, actualTransfers, "no unclassified extra output")
					require.Equal(t, uint32(1+wantTransfers), eei.GetCrtTransferIndex())
				})
			}
		}
	}
}

// The native updateTokenID crawler path deliberately does not require the token
// owner. A genuine System-SC type message need not originate in registration.
// Part A 5.1 requires classification before these repeated effects as well.
func TestQualDRWATypeRefreshFanout(t *testing.T) {
	for _, family := range []string{core.FungibleESDT, core.NonFungibleESDT, core.NonFungibleESDTv2, core.SemiFungibleESDT, core.MetaESDT, core.DynamicNFTESDT, core.DynamicSFTESDT, core.DynamicMetaESDT} {
		for _, enabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/dynamic_%t", family, enabled), func(t *testing.T) {
				args := createMockArgumentsForESDT()
				flags := args.EnableEpochsHandler.(*enableEpochsHandlerMock.EnableEpochsHandlerStub)
				flags.RemoveActiveFlags(common.DynamicESDTFlag)
				if enabled {
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
				owner := bytes.Repeat([]byte{1}, 32)
				stranger := bytes.Repeat([]byte{2}, 32)
				// Seed a native record, including pre-flag NFT history. This does
				// not assert public admission of dynamic families with the flag off.
				tokenID, _, err := e.createNewToken(owner, []byte("TokenName"), []byte("TOKEN"), big.NewInt(0), 0, nil, []byte(family))
				require.NoError(t, err)
				before := bytes.Clone(eei.GetStorage(tokenID))
				// Reset the fixture output only; preserve the seeded record exactly.
				eei.outputAccounts = make(map[string]*vmcommon.OutputAccount)
				eei.output = nil
				eei.logs = nil
				eei.crtTransferIndex = 1
				eei.SetGasProvided(1000000)
				input := getDefaultVmInputForFunc("updateTokenID", [][]byte{tokenID})
				input.CallerAddr = stranger
				input.RecipientAddr = bytes.Clone(core.ESDTSCAddress)
				if !enabled {
					require.Equal(t, vmcommon.FunctionNotFound, e.Execute(input))
					require.Equal(t, "invalid method to call", eei.returnMessage)
					require.Empty(t, eei.outputAccounts)
					require.Empty(t, eei.logs)
					require.Equal(t, before, eei.GetStorage(tokenID))
					return
				}
				wantFamily := family
				if family == core.NonFungibleESDT {
					wantFamily = core.NonFungibleESDTv2
				}
				for replay := 0; replay < 2; replay++ {
					require.Equal(t, vmcommon.Ok, e.Execute(input), eei.returnMessage)
					require.Len(t, eei.outputAccounts, 3)
					for shard := byte(0); shard < 3; shard++ {
						destination := bytes.Clone(core.SystemAccountAddress)
						destination[len(destination)-1] = shard
						out := eei.outputAccounts[string(destination)]
						require.NotNil(t, out)
						require.Len(t, out.OutputTransfers, replay+1)
						transfer := out.OutputTransfers[replay]
						want := core.ESDTSetTokenType + "@" + hex.EncodeToString(tokenID) + "@" + hex.EncodeToString([]byte(wantFamily))
						require.Equal(t, []byte(want), transfer.Data)
						require.Equal(t, uint32(1+replay*3+int(shard)), transfer.Index)
						require.Empty(t, transfer.SenderAddress)
						require.Zero(t, transfer.Value.Sign())
						require.Zero(t, transfer.GasLimit)
						require.Zero(t, transfer.GasLocked)
						require.Equal(t, vmData.DirectCall, transfer.CallType)
					}
					token, err := e.getExistingToken(tokenID)
					require.NoError(t, err)
					require.Equal(t, wantFamily, string(token.TokenType))
					require.Equal(t, owner, token.OwnerAddress)
					require.Zero(t, token.MintedValue.Sign())
					if family != core.NonFungibleESDT {
						require.Equal(t, before, eei.GetStorage(tokenID))
					}
				}
				require.Empty(t, eei.output)
				require.Equal(t, uint32(7), eei.GetCrtTransferIndex())
			})
		}
	}
}
