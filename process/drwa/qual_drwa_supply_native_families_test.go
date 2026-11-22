package drwa

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	nativeBuiltins "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
)

// Shared synthetic policy callbacks are not native authority or admission.
type qualSupplyOperationPolicy struct {
	classify func(string, []byte) (bool, error)
	check    func(string, vmcommon.DRWASupplyEffect, *vmcommon.ContractCallInput) error
}

func (g *qualSupplyOperationPolicy) ClassifySupply(name string, token []byte) (bool, error) {
	return g.classify(name, token)
}
func (g *qualSupplyOperationPolicy) CheckSupply(name string, effect vmcommon.DRWASupplyEffect, input *vmcommon.ContractCallInput) error {
	return g.check(name, effect, input)
}
func (g *qualSupplyOperationPolicy) IsInterfaceNil() bool { return g == nil }

// Ordinary equivalence at the native supply seam (Architecture §1/§4.5.1).
// "On" means the seam classifies this absent registry member as ordinary;
// it does not claim configured-node, canonical-classifier or startup coverage.
// Expectations below come from native balance/role/quantity/gas rules, not
// from the other side's result. Both sides use the actual factory/AccountsDB.
func TestQualDRWASupplyNativeFactoryOrdinaryEquivalence(t *testing.T) {
	for _, family := range []core.ESDTType{core.Fungible, core.NonFungibleV2, core.SemiFungible, core.MetaFungible, core.DynamicNFT, core.DynamicSFT, core.DynamicMeta} {
		functions := []string{core.BuiltInFunctionESDTNFTCreate, core.BuiltInFunctionESDTNFTBurn}
		if family == core.Fungible {
			functions = []string{core.BuiltInFunctionESDTLocalMint, core.BuiltInFunctionESDTLocalBurn, core.BuiltInFunctionESDTBurn}
		} else if family != core.NonFungibleV2 && family != core.DynamicNFT {
			functions = append(functions, core.BuiltInFunctionESDTNFTAddQuantity)
		}
		for _, name := range functions {
			modes := []string{"success", "zero", "bad arguments", "insufficient gas"}
			if name != core.BuiltInFunctionESDTBurn {
				modes = append(modes, "missing role")
			}
			if name == core.BuiltInFunctionESDTLocalBurn || name == core.BuiltInFunctionESDTBurn || name == core.BuiltInFunctionESDTNFTBurn {
				modes = append(modes, "excess burn", "full burn")
			}
			if name == core.BuiltInFunctionESDTLocalBurn || name == core.BuiltInFunctionESDTNFTBurn {
				modes = append(modes, "burn for all without role")
			}
			for _, mode := range modes {
				t.Run(family.String()+"/"+name+"/"+mode, func(t *testing.T) {
					quantity := int64(7)
					before, after := int64(100), int64(107)
					nonce := uint64(0)
					if family != core.Fungible {
						nonce = 4
					}
					if name == core.BuiltInFunctionESDTNFTCreate {
						before, quantity = 0, 2
						if family == core.NonFungibleV2 || family == core.DynamicNFT {
							quantity = 1
						}
						after = quantity
					} else if name == core.BuiltInFunctionESDTLocalBurn || name == core.BuiltInFunctionESDTBurn || name == core.BuiltInFunctionESDTNFTBurn {
						after = 93
						if family == core.NonFungibleV2 || family == core.DynamicNFT {
							before, quantity, after = 1, 1, 0
						}
					}
					var wantError error
					switch mode {
					case "zero":
						quantity, after = 0, before
						if family == core.Fungible {
							wantError = nativeBuiltins.ErrNegativeValue
						} else if name == core.BuiltInFunctionESDTNFTCreate {
							wantError = nativeBuiltins.ErrInvalidArguments
						}
					case "bad arguments":
						wantError = nativeBuiltins.ErrInvalidArguments
					case "insufficient gas":
						wantError = nativeBuiltins.ErrNotEnoughGas
					case "missing role":
						wantError = nativeBuiltins.ErrActionNotAllowed
					case "excess burn":
						quantity = before + 1
						wantError = nativeBuiltins.ErrInsufficientFunds
						if family != core.Fungible {
							wantError = nativeBuiltins.ErrInvalidNFTQuantity
						}
					case "full burn":
						quantity, after = before, 0
					}
					var baselineRoot, resultRoot []byte
					var baselineOutput *vmcommon.VMOutput
					var baselineError error
					var baselineJournal int
					for _, enabled := range []bool{false, true} {
						f, function, storage, token := qualOrdinarySupplyFactory(t, family, name, quantity, mode)
						root, err := f.store.RootHash()
						require.NoError(t, err)
						root = bytes.Clone(root)
						if !enabled {
							baselineRoot = root
						} else {
							require.Equal(t, baselineRoot, root, "identical ordinary prestate")
						}
						account, err := f.store.GetExistingAccount(f.source)
						require.NoError(t, err)
						user := account.(vmcommon.UserAccountHandler)
						nativeNonce, nativeBalance := user.GetNonce(), new(big.Int).Set(user.GetBalance())
						inputBefore := *f.input
						inputBefore.CallerAddr = bytes.Clone(f.input.CallerAddr)
						inputBefore.RecipientAddr = bytes.Clone(f.input.RecipientAddr)
						inputBefore.CallValue = new(big.Int).Set(f.input.CallValue)
						if f.input.Arguments != nil {
							inputBefore.Arguments = make([][]byte, len(f.input.Arguments))
							for i, arg := range f.input.Arguments {
								inputBefore.Arguments[i] = bytes.Clone(arg)
							}
						}
						owner, err := NewRollbackContainment(f.store)
						require.NoError(t, err)
						classified, checked := 0, 0
						gate := &qualSupplyOperationPolicy{classify: func(fn string, id []byte) (bool, error) {
							classified++
							require.Equal(t, name, fn)
							if mode == "bad arguments" {
								require.Empty(t, id)
							} else {
								require.Equal(t, token, id)
							}
							return false, nil // Explicit ordinary membership fixture, never authority.
						}, check: func(string, vmcommon.DRWASupplyEffect, *vmcommon.ContractCallInput) error {
							checked++
							return errors.New("ordinary supply must not request DRWA approval")
						}}
						var output *vmcommon.VMOutput
						err = owner.Execute(func() (*vmcommon.VMOutput, error) {
							var e error
							if enabled {
								output, e = function.ProcessBuiltinFunctionWithDRWASupplyGate(f.input, func(*vmcommon.ContractCallInput, bool) (vmcommon.UserAccountHandler, vmcommon.UserAccountHandler, error) {
									return user, nil, nil
								}, gate)
							} else {
								output, e = function.ProcessBuiltinFunction(user, nil, f.input)
							}
							if e == nil {
								e = f.store.SaveAccount(user)
							}
							return output, e
						})
						if wantError != nil {
							require.ErrorIs(t, err, wantError)
							require.Nil(t, output)
						} else {
							require.NoError(t, err)
							require.NotNil(t, output)
							require.Equal(t, vmcommon.Ok, output.ReturnCode)
							gas := f.args.GasMap[core.BuiltInCostString][name]
							if name == core.BuiltInFunctionESDTNFTCreate {
								for _, arg := range f.input.Arguments {
									gas += uint64(len(arg)) * f.args.GasMap[core.BaseOperationCostString]["StorePerByte"]
								}
								require.Equal(t, [][]byte{{4}}, output.ReturnData)
							}
							// Fixture schedule is synthetic; the debit formula is native.
							require.Equal(t, f.input.GasProvided-gas, output.GasRemaining)
							require.Len(t, output.Logs, 1)
							require.Equal(t, []byte(name), output.Logs[0].Identifier)
							require.Equal(t, token, output.Logs[0].Topics[0])
							require.Equal(t, new(big.Int).SetUint64(nonce).Bytes(), output.Logs[0].Topics[1])
							require.Equal(t, big.NewInt(quantity).Bytes(), output.Logs[0].Topics[2])
						}
						if enabled {
							require.Equal(t, 1, classified)
						}
						require.Zero(t, checked)
						require.Equal(t, inputBefore, *f.input)
						actualRoot, e := f.store.RootHash()
						require.NoError(t, e)
						if wantError != nil {
							require.Equal(t, root, actualRoot)
							require.Zero(t, f.store.JournalLen())
						}
						if !enabled {
							resultRoot, baselineOutput, baselineError, baselineJournal = bytes.Clone(actualRoot), output, err, f.store.JournalLen()
						} else {
							require.Equal(t, resultRoot, actualRoot)
							require.Equal(t, baselineOutput, output, "entire native output, gas, logs and transfers")
							require.Equal(t, baselineError, err)
							require.Equal(t, baselineJournal, f.store.JournalLen())
						}
						current, e := f.store.GetExistingAccount(f.source)
						require.NoError(t, e)
						require.Equal(t, nativeNonce, current.GetNonce())
						require.Equal(t, nativeBalance, current.(vmcommon.UserAccountHandler).GetBalance())
						wantBalance := after
						if wantError != nil {
							wantBalance = before
						}
						// Nonce zero uses native fungible balance storage directly.
						if family == core.Fungible {
							if wantBalance == 0 {
								// Native saveESDTData deletes an empty-property zero
								// balance; do not decode absence as a stored proto.
								raw, _, e := current.(vmcommon.UserAccountHandler).AccountDataHandler().RetrieveValue(routeOperationTokenKey())
								require.NoError(t, e)
								require.Empty(t, raw)
							} else {
								require.Equal(t, big.NewInt(wantBalance), f.balance(t, f.source))
							}
						} else {
							key := append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), token...)
							value, _, e := storage.GetESDTNFTTokenOnDestination(current.(vmcommon.UserAccountHandler), key, nonce)
							require.NoError(t, e)
							require.Zero(t, big.NewInt(wantBalance).Cmp(value.Value))
							if wantBalance > 0 {
								require.Equal(t, uint32(family), value.Type)
								require.NotNil(t, value.TokenMetaData)
								require.Equal(t, uint64(4), value.TokenMetaData.Nonce)
								require.Equal(t, f.source, value.TokenMetaData.Creator)
							}
							latest, _, e := current.(vmcommon.UserAccountHandler).AccountDataHandler().RetrieveValue(append([]byte(core.ProtectedKeyPrefix+core.ESDTNFTLatestNonceIdentifier), token...))
							require.NoError(t, e)
							wantNonce := byte(4)
							if name == core.BuiltInFunctionESDTNFTCreate && wantError != nil {
								wantNonce = 3
							}
							require.Equal(t, []byte{wantNonce}, latest)
						}
						if wantError == nil {
							require.NoError(t, owner.Abort())
							restored, e := f.store.RootHash()
							require.NoError(t, e)
							require.Equal(t, root, restored)
						}
					}
				})
			}
		}
	}
}

func qualOrdinarySupplyFactory(t *testing.T, family core.ESDTType, name string, quantity int64, mode string) (*routeOperationTestFixture, vmcommon.BuiltinFunctionWithDRWASupplyGate, vmcommon.ESDTNFTStorageHandler, []byte) {
	t.Helper()
	f := routeOperationFixture(t)
	f.args.EnableEpochsHandler = enableEpochsHandlerMock.NewEnableEpochsHandlerStub(
		nativeBuiltins.SaveToSystemAccountFlag, nativeBuiltins.SendAlwaysFlag, nativeBuiltins.ESDTNFTImprovementV1Flag,
		nativeBuiltins.EGLDInESDTMultiTransferFlag, nativeBuiltins.CheckTransferFlag, nativeBuiltins.CheckCorrectTokenIDForTransferRoleFlag,
		nativeBuiltins.DynamicEsdtFlag, nativeBuiltins.ValueLengthCheckFlag, nativeBuiltins.GlobalMintBurnFlag)
	factory, err := nativeBuiltins.NewBuiltInFunctionsCreator(f.args)
	require.NoError(t, err)
	require.NoError(t, factory.CreateBuiltInFunctionContainer())
	storage := factory.NFTStorageHandler().(vmcommon.ESDTNFTStorageHandler)
	token := []byte("ORDINARY-abcdef")
	if family != core.Fungible {
		token = []byte("COLLECT-abcdef")
		global := factory.ESDTGlobalSettingsHandler().(vmcommon.GlobalMetadataHandler)
		require.NoError(t, global.SetTokenType(append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), token...), uint32(family)))
	}
	account, err := f.store.GetExistingAccount(f.source)
	require.NoError(t, err)
	user := account.(vmcommon.UserAccountHandler)
	roles := [][]byte{[]byte(core.ESDTRoleLocalMint), []byte(core.ESDTRoleLocalBurn), []byte(core.ESDTRoleNFTCreate), []byte(core.ESDTRoleNFTBurn)}
	if family != core.NonFungibleV2 && family != core.DynamicNFT {
		roles = append(roles, []byte(core.ESDTRoleNFTAddQuantity))
	}
	if mode == "missing role" || mode == "burn for all without role" {
		roles = nil
	}
	raw, err := f.args.Marshalizer.Marshal(&esdt.ESDTRoles{Roles: roles})
	require.NoError(t, err)
	require.NoError(t, user.AccountDataHandler().SaveKeyValue(append([]byte(core.ProtectedKeyPrefix+core.ESDTRoleIdentifier+core.ESDTKeyIdentifier), token...), raw))
	if family != core.Fungible {
		latest := byte(4)
		if name == core.BuiltInFunctionESDTNFTCreate {
			latest = 3
		} else {
			key := append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), token...)
			balance := int64(100)
			if family == core.NonFungibleV2 || family == core.DynamicNFT {
				balance = 1
			}
			data := &esdt.ESDigitalToken{Type: uint32(family), Value: big.NewInt(balance), TokenMetaData: &esdt.MetaData{Nonce: 4, Name: []byte("existing"), Creator: bytes.Clone(f.source)}}
			_, err = storage.SaveESDTNFTToken(f.source, user, key, 4, data, vmcommon.NftSaveArgs{MustUpdateAllFields: true})
			require.NoError(t, err)
			require.NoError(t, storage.AddToLiquiditySystemAcc(key, uint32(family), 4, big.NewInt(balance), false))
		}
		require.NoError(t, user.AccountDataHandler().SaveKeyValue(append([]byte(core.ProtectedKeyPrefix+core.ESDTNFTLatestNonceIdentifier), token...), []byte{latest}))
	}
	require.NoError(t, f.store.SaveAccount(user))
	if mode == "burn for all without role" {
		setter, e := factory.BuiltInFunctionContainer().Get(vmcommon.BuiltInFunctionESDTSetBurnRoleForAll)
		require.NoError(t, e)
		out, e := setter.ProcessBuiltinFunction(nil, nil, &vmcommon.ContractCallInput{
			VMInput:       vmcommon.VMInput{CallerAddr: bytes.Clone(core.ESDTSCAddress), CallValue: big.NewInt(0), Arguments: [][]byte{bytes.Clone(token)}},
			RecipientAddr: bytes.Clone(vmcommon.SystemAccountAddress), Function: vmcommon.BuiltInFunctionESDTSetBurnRoleForAll,
		})
		require.NoError(t, e)
		require.Equal(t, vmcommon.Ok, out.ReturnCode)
		require.True(t, factory.ESDTGlobalSettingsHandler().(vmcommon.ExtendedESDTGlobalSettingsHandler).IsBurnForAll(append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), token...)))
	}
	_, err = f.store.AccountsAdapter.Commit()
	require.NoError(t, err)
	require.Empty(t, qualRegistryValue(t, f.store, registryMemberKeyPrefix+string(token)))
	f.input.Function, f.input.RecipientAddr, f.input.GasProvided = name, bytes.Clone(f.source), 1000000
	f.input.Arguments = [][]byte{bytes.Clone(token), big.NewInt(quantity).Bytes()}
	if name == core.BuiltInFunctionESDTBurn {
		f.input.RecipientAddr = bytes.Clone(core.ESDTSCAddress)
	} else if name == core.BuiltInFunctionESDTNFTCreate {
		f.input.Arguments = append(f.input.Arguments, []byte("ordinary-native-name"), nil, []byte("hash"), []byte("attributes"), []byte("uri"))
	} else if family != core.Fungible {
		f.input.Arguments = [][]byte{bytes.Clone(token), {4}, big.NewInt(quantity).Bytes()}
	}
	if mode == "bad arguments" {
		f.input.Arguments = nil
	} else if mode == "insufficient gas" {
		f.input.GasProvided = 6 // Fixture native base cost is seven.
	}
	function, err := factory.BuiltInFunctionContainer().Get(name)
	require.NoError(t, err)
	return f, function.(vmcommon.BuiltinFunctionWithDRWASupplyGate), storage, token
}

// Native factory, roles, type conversion, storage, ESDT effects and original
// journal execute. Classification/approval is synthetic. Numeric comparison is
// not a persisted SupplyState/per-nonce/position co-commit or native authority.
func TestQualDRWASupplyNativeFactoryNonceFamiliesAndAbort(t *testing.T) {
	for _, family := range []core.ESDTType{core.NonFungibleV2, core.SemiFungible, core.MetaFungible, core.DynamicNFT, core.DynamicSFT, core.DynamicMeta} {
		t.Run(family.String(), func(t *testing.T) {
			f := routeOperationFixture(t)
			f.args.EnableEpochsHandler = enableEpochsHandlerMock.NewEnableEpochsHandlerStub(
				nativeBuiltins.SaveToSystemAccountFlag, nativeBuiltins.SendAlwaysFlag, nativeBuiltins.ESDTNFTImprovementV1Flag,
				nativeBuiltins.EGLDInESDTMultiTransferFlag, nativeBuiltins.CheckTransferFlag, nativeBuiltins.CheckCorrectTokenIDForTransferRoleFlag,
				nativeBuiltins.DynamicEsdtFlag, nativeBuiltins.ValueLengthCheckFlag)
			factory, err := nativeBuiltins.NewBuiltInFunctionsCreator(f.args)
			require.NoError(t, err)
			require.NoError(t, factory.CreateBuiltInFunctionContainer())
			global, ok := factory.ESDTGlobalSettingsHandler().(vmcommon.GlobalMetadataHandler)
			require.True(t, ok)
			storage, ok := factory.NFTStorageHandler().(vmcommon.ESDTNFTStorageHandler)
			require.True(t, ok)
			token := []byte("COLLECT-abcdef")
			key := append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), token...)
			require.NoError(t, global.SetTokenType(key, uint32(family)))
			actualType, e := global.GetTokenType(key)
			require.NoError(t, e)
			require.Equal(t, uint32(family), actualType)
			a, e := f.store.GetExistingAccount(f.source)
			require.NoError(t, e)
			u := a.(vmcommon.UserAccountHandler)
			quantityCapable := family != core.NonFungibleV2 && family != core.DynamicNFT
			roles := [][]byte{[]byte(core.ESDTRoleNFTCreate), []byte(core.ESDTRoleNFTBurn)}
			if quantityCapable {
				roles = append(roles, []byte(core.ESDTRoleNFTAddQuantity))
			}
			raw, e := f.args.Marshalizer.Marshal(&esdt.ESDTRoles{Roles: roles})
			require.NoError(t, e)
			require.NoError(t, u.AccountDataHandler().SaveKeyValue(append([]byte(core.ProtectedKeyPrefix+core.ESDTRoleIdentifier+core.ESDTKeyIdentifier), token...), raw))
			nonceKey := append([]byte(core.ProtectedKeyPrefix+core.ESDTNFTLatestNonceIdentifier), token...)
			require.NoError(t, u.AccountDataHandler().SaveKeyValue(nonceKey, big.NewInt(3).Bytes()))
			require.NoError(t, f.store.SaveAccount(u))
			_, err = f.store.AccountsAdapter.Commit()
			require.NoError(t, err)
			root, err := f.store.RootHash()
			require.NoError(t, err)
			root = bytes.Clone(root)
			owner, err := NewRollbackContainment(f.store)
			require.NoError(t, err)
			read := func() (*esdt.ESDigitalToken, bool) {
				account, e := f.store.GetExistingAccount(f.source)
				require.NoError(t, e)
				value, isNew, e := storage.GetESDTNFTTokenOnDestination(account.(vmcommon.UserAccountHandler), key, 4)
				require.NoError(t, e)
				return value, isNew
			}
			accounting := newSupplyAccounting()
			step := func(name string, quantity, expectedBefore, expectedAfter int64, increase bool) {
				f.input.Function = name
				f.input.RecipientAddr = bytes.Clone(f.source)
				f.input.GasProvided = 1000000
				if name == core.BuiltInFunctionESDTNFTCreate {
					f.input.Arguments = [][]byte{bytes.Clone(token), big.NewInt(quantity).Bytes(), []byte("synthetic-native-name"), nil, []byte("hash"), []byte("attributes"), []byte("uri")}
				} else {
					f.input.Arguments = [][]byte{bytes.Clone(token), big.NewInt(4).Bytes(), big.NewInt(quantity).Bytes()}
				}
				op, e := newSupplyNativeOperation(f.args, name)
				require.NoError(t, e)
				journal := f.store.JournalLen()
				checks := 0
				policy := &qualSupplyOperationPolicy{classify: func(fn string, id []byte) (bool, error) {
					require.Equal(t, name, fn)
					require.Equal(t, token, id)
					return true, nil
				}, check: func(fn string, effect vmcommon.DRWASupplyEffect, input *vmcommon.ContractCallInput) error {
					checks++
					require.Equal(t, name, fn)
					require.Equal(t, token, effect.TokenIdentifier)
					require.Equal(t, uint32(family), effect.TokenType)
					require.Equal(t, f.source, effect.RoleAddress)
					require.Zero(t, big.NewInt(quantity).Cmp(effect.Quantity))
					require.Equal(t, uint64(4), effect.Nonce)
					if name == core.BuiltInFunctionESDTNFTCreate {
						require.Equal(t, uint64(3), effect.PreviousNonce)
					} else {
						require.Zero(t, effect.PreviousNonce)
					}
					before, _ := read()
					require.Zero(t, big.NewInt(expectedBefore).Cmp(before.Value))
					require.Equal(t, journal, f.store.JournalLen())
					require.Equal(t, f.source, input.CallerAddr)
					require.Equal(t, f.source, input.RecipientAddr)
					return nil
				}}
				var output *vmcommon.VMOutput
				e = owner.Execute(func() (*vmcommon.VMOutput, error) {
					var inner error
					output, inner = op.execute(f.input, policy, f.resolve)
					return output, inner
				})
				require.NoError(t, e)
				require.Equal(t, 1, checks)
				require.NotNil(t, output)
				require.Equal(t, vmcommon.Ok, output.ReturnCode)
				if name == core.BuiltInFunctionESDTNFTCreate {
					require.Equal(t, [][]byte{{4}}, output.ReturnData)
				}
				after, isNew := read()
				require.Zero(t, big.NewInt(expectedAfter).Cmp(after.Value))
				if expectedAfter == 0 {
					require.True(t, isNew)
				} else {
					require.False(t, isNew)
					require.Equal(t, uint32(family), after.Type)
				}
				// Native liquidity is a local metadata cross-check here, not global DRWA supply.
				liquidity, liquidityErr := storage.GetMetaDataFromSystemAccount(key, 4)
				require.NoError(t, liquidityErr)
				if !quantityCapable || expectedAfter == 0 {
					require.Nil(t, liquidity)
				} else {
					require.NotNil(t, liquidity)
					require.Zero(t, big.NewInt(expectedAfter).Cmp(liquidity.Value))
				}
				accounting, e = accounting.advance(accounting.nextSupplyNonce, increase, big.NewInt(quantity), big.NewInt(100), 32)
				require.NoError(t, e)
				require.Zero(t, big.NewInt(expectedAfter).Cmp(accounting.liveSupply))
			}
			initial, total := int64(1), int64(1)
			if quantityCapable {
				initial, total = 2, 5
			}
			step(core.BuiltInFunctionESDTNFTCreate, initial, 0, initial, true)
			if quantityCapable {
				step(core.BuiltInFunctionESDTNFTAddQuantity, 3, 2, 5, true)
			}
			step(core.BuiltInFunctionESDTNFTBurn, total, total, 0, false)
			require.Zero(t, big.NewInt(total).Cmp(accounting.cumulativeIssued))
			if quantityCapable {
				// The real full burn removed the origin record: installed role alone
				// cannot top up this absent nonce, and policy is never reached.
				f.input.Function = core.BuiltInFunctionESDTNFTAddQuantity
				f.input.Arguments = [][]byte{bytes.Clone(token), {4}, {1}}
				beforeRefusal, rootErr := f.store.RootHash()
				require.NoError(t, rootErr)
				beforeRefusal = bytes.Clone(beforeRefusal)
				op, e := newSupplyNativeOperation(f.args, f.input.Function)
				require.NoError(t, e)
				checks := 0
				policy := &qualSupplyOperationPolicy{classify: func(string, []byte) (bool, error) { return true, nil }, check: func(string, vmcommon.DRWASupplyEffect, *vmcommon.ContractCallInput) error { checks++; return nil }}
				var output *vmcommon.VMOutput
				e = owner.Execute(func() (*vmcommon.VMOutput, error) {
					var inner error
					output, inner = op.execute(f.input, policy, f.resolve)
					return output, inner
				})
				require.ErrorIs(t, e, nativeBuiltins.ErrNewNFTDataOnSenderAddress)
				require.Nil(t, output)
				require.Zero(t, checks)
				afterRefusal, rootErr := f.store.RootHash()
				require.NoError(t, rootErr)
				require.Equal(t, beforeRefusal, afterRefusal)
				require.Equal(t, uint64(3), accounting.nextSupplyNonce)
			} else {
				require.Equal(t, uint64(2), accounting.nextSupplyNonce)
			}
			account, e := f.store.GetExistingAccount(f.source)
			require.NoError(t, e)
			latest, _, e := account.(vmcommon.UserAccountHandler).AccountDataHandler().RetrieveValue(nonceKey)
			require.NoError(t, e)
			require.Equal(t, big.NewInt(4).Bytes(), latest)
			require.NoError(t, owner.Abort())
			restored, e := f.store.RootHash()
			require.NoError(t, e)
			require.Equal(t, root, restored)
			_, isNew := read()
			require.True(t, isNew)
			account, e = f.store.GetExistingAccount(f.source)
			require.NoError(t, e)
			latest, _, e = account.(vmcommon.UserAccountHandler).AccountDataHandler().RetrieveValue(nonceKey)
			require.NoError(t, e)
			require.Equal(t, big.NewInt(3).Bytes(), latest)
		})
	}
}
