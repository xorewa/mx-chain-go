package systemSmartContracts

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/process"
	processMock "github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/process/smartContract"
	"github.com/multiversx/mx-chain-go/process/smartContract/processorV2"
	"github.com/multiversx/mx-chain-go/process/smartContract/scrCommon"
	"github.com/multiversx/mx-chain-go/state"

	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/economicsmocks"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"

	"github.com/multiversx/mx-chain-go/txcache"
	"github.com/multiversx/mx-chain-go/vm"
	"github.com/multiversx/mx-chain-go/vm/mock"
	vmProcess "github.com/multiversx/mx-chain-go/vm/process"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
)

// Native route effects are joined to the local output consumer and account journal.
// Distributed execution, fee economics and finality remain separate obligations.
func qualTransitionContract(t *testing.T, fix bool) (*esdt, *vmContext, *enableEpochsHandlerMock.EnableEpochsHandlerStub) {
	t.Helper()
	ctxArgs := createDefaultEeiArgs()
	ctxArgs.BlockChainHook.(*mock.BlockChainHookStub).NumberOfShardsCalled = func() uint32 { return 3 }
	host, err := NewVMContext(ctxArgs)
	require.NoError(t, err)
	host.SetSCAddress(core.ESDTSCAddress)
	args := createMockArgumentsForESDT()
	flags := args.EnableEpochsHandler.(*enableEpochsHandlerMock.EnableEpochsHandlerStub)
	flags.RemoveActiveFlags(common.ESDTMetadataContinuousCleanupFlag, common.DynamicESDTFlag, common.FixCorrectSmallIntAndGasLimitsFlag)
	if fix {
		flags.AddActiveFlags(common.FixCorrectSmallIntAndGasLimitsFlag)
	}
	args.Eei = host
	args.ESDTSCAddress = core.ESDTSCAddress
	args.Marshalizer = &marshal.GogoProtoMarshalizer{}
	args.Hasher = blake2b.NewBlake2b()
	args.GasCost.MetaChainSystemSCsCost.ESDTOperations = 7
	e, err := NewESDTSmartContract(args)
	require.NoError(t, err)
	host.SetGasProvided(1000)
	return e, host, flags
}

func qualTransitionInput(method string, args [][]byte, creation bool) *vmcommon.ContractCallInput {
	in := getDefaultVmInputForFunc(method, args)
	in.CallerAddr = bytes.Repeat([]byte{1}, 32)
	in.RecipientAddr = bytes.Clone(core.ESDTSCAddress)
	in.CallValue = big.NewInt(0)
	if creation {
		in.CallValue.SetInt64(1000)
	}
	return in
}

func qualTransitionReset(host *vmContext) {
	host.outputAccounts = make(map[string]*vmcommon.OutputAccount)
	host.output = nil
	host.logs = nil
	host.returnMessage = ""
	host.crtTransferIndex = 1
	host.SetGasProvided(1000)
}

func qualTransitionNoOutput(t *testing.T, host *vmContext) {
	t.Helper()
	require.Empty(t, host.outputAccounts)
	require.Empty(t, host.output)
	require.Empty(t, host.logs)
}

func TestQualTransitionR02Fanout(t *testing.T) {
	t.Run("three shards should receive explicit transfers and cloned persisted balances", func(t *testing.T) {
		_, host, _ := qualTransitionContract(t, true)
		_, _, db, _, _, _ := qualNativeRegistration(t)
		persisted := make(map[string]vmcommon.UserAccountHandler)
		for shard := byte(0); shard < 3; shard++ {
			addr := bytes.Clone(core.SystemAccountAddress)
			addr[31] = shard
			acc, err := db.LoadAccount(addr)
			require.NoError(t, err)
			require.NoError(t, acc.(state.UserAccountHandler).AddToBalance(big.NewInt(100+int64(shard))))
			require.NoError(t, db.SaveAccount(acc))
			persisted[string(addr)] = acc.(vmcommon.UserAccountHandler)
		}
		root, err := db.Commit()
		require.NoError(t, err)
		require.NoError(t, db.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
		for key := range persisted {
			a, err := db.GetExistingAccount([]byte(key))
			require.NoError(t, err)
			persisted[key] = a.(vmcommon.UserAccountHandler)
		}
		host.blockChainHook.(*mock.BlockChainHookStub).GetUserAccountCalled = func(addr []byte) (vmcommon.UserAccountHandler, error) { return persisted[string(addr)], nil }
		data := []byte("ESDTPause@544f4b454e2d303030303031")
		host.SendGlobalSettingToAll(core.ESDTSCAddress, data)
		require.Len(t, host.outputAccounts, 3)
		for shard := byte(0); shard < 3; shard++ {
			addr := bytes.Clone(core.SystemAccountAddress)
			addr[31] = shard
			out := host.outputAccounts[string(addr)]
			require.NotNil(t, out)
			require.Equal(t, addr, out.Address)
			require.Equal(t, big.NewInt(100+int64(shard)), out.Balance)
			require.Zero(t, out.BalanceDelta.Sign())
			require.Len(t, out.OutputTransfers, 1)
			x := out.OutputTransfers[0]
			require.Equal(t, uint32(shard)+1, x.Index)
			require.Equal(t, data, x.Data)
			require.Empty(t, x.SenderAddress)
			require.Zero(t, x.Value.Sign())
			require.Zero(t, x.GasLimit)
			require.Zero(t, x.GasLocked)
			require.Equal(t, vmData.DirectCall, x.CallType)
			out.Balance.SetInt64(999)
			require.Equal(t, big.NewInt(100+int64(shard)), persisted[string(addr)].GetBalance())
		}
		qualTransitionReceivingPause(t, host, data)
		require.Equal(t, uint32(4), host.GetCrtTransferIndex())
		require.Equal(t, uint64(1000), host.gasRemaining)
		require.Empty(t, host.storageUpdate)
		require.Empty(t, host.output)
		require.Empty(t, host.logs)
	})
	t.Run("regulated public pause should deny before fanout", func(t *testing.T) {
		e, host, _ := qualTransitionContract(t, true)
		host.drwaClassifierConfigured = true
		classifier := &publicClassifier{regulated: true}
		host.drwaClassifier = classifier
		in := qualTransitionInput("pause", [][]byte{[]byte("TOKEN-000001")}, false)
		require.Equal(t, vmcommon.UserError, e.Execute(in))
		require.Equal(t, "DRWA public operation denied", host.returnMessage)
		require.Equal(t, 1, classifier.calls)
		qualTransitionNoOutput(t, host)
		require.Empty(t, host.storageUpdate)
		require.Equal(t, uint64(1000), host.gasRemaining)
	})
}

func qualTransitionCreation(t *testing.T, method string) {
	t.Helper()
	for _, fix := range []bool{false, true} {
		for _, width := range []uint{0, 32, 64} {
			t.Run(fmt.Sprintf("fix %t width %d should preserve source defined creation effects", fix, width), func(t *testing.T) {
				e, host, _ := qualTransitionContract(t, fix)
				decimal := big.NewInt(18)
				if width > 0 {
					decimal.Add(decimal, new(big.Int).Lsh(big.NewInt(1), width))
				}
				args := [][]byte{[]byte("TokenName"), []byte("TOKEN")}
				family := core.FungibleESDT
				supply := int64(0)
				switch method {
				case "issue":
					args = append(args, []byte{7}, decimal.Bytes())
					supply = 7
				case "registerMetaESDT":
					args = append(args, decimal.Bytes())
					family = core.MetaESDT
				case "registerAndSetAllRoles":
					args = append(args, []byte("FNG"), decimal.Bytes())
				}
				in := qualTransitionInput(method, args, true)
				code := e.Execute(in)
				require.Equal(t, uint64(990), host.gasRemaining)
				if fix && width > 0 {
					require.Equal(t, vmcommon.UserError, code)
					require.Contains(t, host.returnMessage, "provided: "+decimal.String())
					qualTransitionNoOutput(t, host)
					for _, stores := range host.storageUpdate {
						for _, value := range stores {
							require.Empty(t, value, "no definition save")
						}
					}
					return
				}
				require.Equal(t, vmcommon.Ok, code, host.returnMessage)
				require.Empty(t, host.returnMessage)
				require.Len(t, host.logs, 2)
				id := host.logs[1].Topics[0]
				require.Equal(t, &vmcommon.LogEntry{Identifier: []byte(upgradeProperties), Address: in.CallerAddr, Topics: [][]byte{id, {}, []byte(upgradable), []byte("true"), []byte(canAddSpecialRoles), []byte("true")}}, host.logs[0])
				require.Equal(t, &vmcommon.LogEntry{Identifier: []byte(method), Address: in.CallerAddr, Topics: [][]byte{id, []byte("TokenName"), []byte("TOKEN"), []byte(family), {18}}}, host.logs[1])
				token := &ESDTDataV2{}
				require.NoError(t, e.marshalizer.Unmarshal(token, host.storageUpdate[string(core.ESDTSCAddress)][string(id)]))
				require.Equal(t, in.CallerAddr, token.OwnerAddress)
				require.Equal(t, []byte(family), token.TokenType)
				require.Equal(t, uint32(18), token.NumDecimals)
				require.Equal(t, big.NewInt(supply), token.MintedValue)
				require.Zero(t, token.BurntValue.Sign())
				qualTransitionPersist(t, host, id)
				if method == "registerMetaESDT" {
					require.Equal(t, [][]byte{id}, host.output)
					require.Empty(t, host.outputAccounts)
					return
				}
				require.Len(t, host.outputAccounts, 2)
				sender := host.outputAccounts[string(core.ESDTSCAddress)]
				require.NotNil(t, sender)
				require.Empty(t, sender.OutputTransfers)
				require.Zero(t, sender.BalanceDelta.Sign())
				out := host.outputAccounts[string(in.CallerAddr)]
				require.NotNil(t, out)
				require.Len(t, out.OutputTransfers, 1)
				x := out.OutputTransfers[0]
				want := core.BuiltInFunctionESDTTransfer + "@" + hex.EncodeToString(id) + "@07"
				if method == "registerAndSetAllRoles" {
					want = core.BuiltInFunctionSetESDTRole + "@" + hex.EncodeToString(id) + "@" + hex.EncodeToString([]byte(core.ESDTRoleLocalMint)) + "@" + hex.EncodeToString([]byte(core.ESDTRoleLocalBurn))
					require.Equal(t, [][]byte{id}, host.output)
					require.Len(t, token.SpecialRoles, 1)
					require.Equal(t, in.CallerAddr, token.SpecialRoles[0].Address)
					require.Equal(t, [][]byte{[]byte(core.ESDTRoleLocalMint), []byte(core.ESDTRoleLocalBurn)}, token.SpecialRoles[0].Roles)
				} else {
					require.Empty(t, host.output)
				}
				require.Equal(t, []byte(want), x.Data)
				require.Equal(t, uint32(1), x.Index)
				require.Zero(t, x.Value.Sign())
				require.Zero(t, x.GasLimit)
				require.Zero(t, x.GasLocked)
				require.Equal(t, vmData.DirectCall, x.CallType)
			})
		}
	}
}

func TestQualTransitionR03Issue(t *testing.T) { qualTransitionCreation(t, "issue") }
func TestQualTransitionR04Meta(t *testing.T) {
	qualTransitionCreation(t, "registerMetaESDT")
	qualTransitionOrdering(t, "registerMetaESDT")
}
func TestQualTransitionR05Roles(t *testing.T) {
	qualTransitionCreation(t, "registerAndSetAllRoles")
	qualTransitionOrdering(t, "registerAndSetAllRoles")
	qualTransitionLateRoles(t)
}

func TestQualTransitionR06Conversion(t *testing.T) {
	qualTransitionConversionActivation(t)
	for _, fix := range []bool{false, true} {
		for _, width := range []uint{0, 32, 64} {
			for _, regulated := range []bool{false, true} {
				t.Run(fmt.Sprintf("fix %t width %d regulated %t should enforce conversion before effects", fix, width, regulated), func(t *testing.T) {
					e, host, flags := qualTransitionContract(t, fix)
					owner := bytes.Repeat([]byte{1}, 32)
					id, _, err := e.createNewToken(owner, []byte("TokenName"), []byte("TOKEN"), big.NewInt(0), 0, nil, []byte(core.SemiFungibleESDT))
					require.NoError(t, err)
					before := bytes.Clone(host.GetStorage(id))
					qualTransitionReset(host)
					flags.AddActiveFlags(common.DynamicESDTFlag)
					d := big.NewInt(18)
					if width > 0 {
						d.Add(d, new(big.Int).Lsh(big.NewInt(1), width))
					}
					if regulated {
						host.drwaClassifierConfigured = true
						host.drwaClassifier = &publicClassifier{regulated: true}
					}
					in := qualTransitionInput("changeSFTToMetaESDT", [][]byte{id, d.Bytes()}, false)
					code := e.Execute(in)
					if regulated || (fix && width > 0) {
						require.Equal(t, vmcommon.UserError, code)
						if regulated {
							require.Equal(t, "DRWA public operation denied", host.returnMessage)
						} else {
							require.Contains(t, host.returnMessage, "provided: "+d.String())
						}
						require.Equal(t, before, host.GetStorage(id))
						require.Equal(t, uint64(1000), host.gasRemaining)
						qualTransitionNoOutput(t, host)
						return
					}
					require.Equal(t, vmcommon.Ok, code, host.returnMessage)
					token, err := e.getExistingToken(id)
					require.NoError(t, err)
					require.Equal(t, []byte(core.MetaESDT), token.TokenType)
					require.Equal(t, uint32(18), token.NumDecimals)
					require.Equal(t, uint64(993), host.gasRemaining)
					require.Equal(t, []*vmcommon.LogEntry{{Identifier: []byte(in.Function), Address: owner, Topics: [][]byte{id, []byte("TokenName"), []byte("TOKEN"), []byte(core.MetaESDT), d.Bytes()}}, {Identifier: []byte(core.ESDTSetTokenType), Address: owner, Topics: [][]byte{id, []byte(core.MetaESDT)}}}, host.logs)
					require.Empty(t, host.output)
					qualTransitionTypeFanout(t, host, id, core.MetaESDT, 1)
					qualTransitionPersist(t, host, id)
				})
			}
		}
	}
}

func qualTransitionTypeFanout(t *testing.T, host *vmContext, id []byte, family string, count int) {
	t.Helper()
	require.Len(t, host.outputAccounts, 3)
	for shard := byte(0); shard < 3; shard++ {
		addr := bytes.Clone(core.SystemAccountAddress)
		addr[31] = shard
		out := host.outputAccounts[string(addr)]
		require.NotNil(t, out)
		require.Len(t, out.OutputTransfers, count)
		for n, x := range out.OutputTransfers {
			require.Equal(t, []byte(core.ESDTSetTokenType+"@"+hex.EncodeToString(id)+"@"+hex.EncodeToString([]byte(family))), x.Data)
			require.Equal(t, uint32(1+n*3+int(shard)), x.Index)
			require.Zero(t, x.Value.Sign())
			require.Zero(t, x.GasLimit)
			require.Zero(t, x.GasLocked)
			require.Equal(t, vmData.DirectCall, x.CallType)
		}
	}
}

func TestQualTransitionR07Update(t *testing.T) {
	for _, fix := range []bool{false, true} {
		for _, dynamic := range []bool{false, true} {
			for _, family := range []string{core.NonFungibleESDT, core.NonFungibleESDTv2, core.FungibleESDT, core.SemiFungibleESDT, core.MetaESDT} {
				for _, regulated := range []bool{false, true} {
					t.Run(fmt.Sprintf("fix %t dynamic %t type %s regulated %t should preserve one time update semantics", fix, dynamic, family, regulated), func(t *testing.T) {
						e, host, flags := qualTransitionContract(t, fix)
						id, _, err := e.createNewToken(bytes.Repeat([]byte{1}, 32), []byte("TokenName"), []byte("TOKEN"), big.NewInt(0), 0, nil, []byte(family))
						require.NoError(t, err)
						before := bytes.Clone(host.GetStorage(id))
						qualTransitionReset(host)
						if dynamic {
							flags.AddActiveFlags(common.DynamicESDTFlag)
						}
						if regulated {
							host.drwaClassifierConfigured = true
							host.drwaClassifier = &publicClassifier{regulated: true}
						}
						in := qualTransitionInput("updateTokenID", [][]byte{id}, false)
						in.CallerAddr = bytes.Repeat([]byte{2}, 32) // Native crawler is not restricted to the token owner.
						for n := 0; n < 2; n++ {
							gas := host.gasRemaining
							stateBefore := bytes.Clone(host.GetStorage(id))
							logsBefore := len(host.logs)
							messageBefore := host.returnMessage
							message := func(next string) string {
								if messageBefore == "" {
									return next
								}
								return messageBefore + "@" + next
							}
							code := e.Execute(in)
							if regulated || !dynamic {
								if regulated {
									require.Equal(t, vmcommon.UserError, code)
									require.Equal(t, message("DRWA public operation denied"), host.returnMessage)
								} else {
									require.Equal(t, vmcommon.FunctionNotFound, code)
									require.Equal(t, message("invalid method to call"), host.returnMessage)
								}
								require.Equal(t, gas, host.gasRemaining)
								require.Equal(t, before, host.GetStorage(id))
								qualTransitionNoOutput(t, host)
								continue
							}
							require.Equal(t, gas-7, host.gasRemaining)
							if fix && (family != core.NonFungibleESDT || n == 1) {
								require.Equal(t, vmcommon.UserError, code)
								require.Equal(t, message("token was already updated or not non-fungible"), host.returnMessage)
								require.Len(t, host.logs, logsBefore)
								require.Equal(t, stateBefore, host.GetStorage(id))
								if n == 0 || family != core.NonFungibleESDT {
									require.Empty(t, host.outputAccounts)
									require.Equal(t, before, host.GetStorage(id))
								} else {
									qualTransitionTypeFanout(t, host, id, core.NonFungibleESDTv2, 1)
								}
							} else {
								require.Equal(t, vmcommon.Ok, code, host.returnMessage)
								want := family
								if family == core.NonFungibleESDT {
									want = core.NonFungibleESDTv2
								}
								token, err := e.getExistingToken(id)
								require.NoError(t, err)
								require.Equal(t, []byte(want), token.TokenType)
								if family != core.NonFungibleESDT {
									require.Equal(t, before, host.GetStorage(id))
								}
								qualTransitionTypeFanout(t, host, id, want, n+1)
								require.Len(t, host.logs, logsBefore+1)
								require.Equal(t, &vmcommon.LogEntry{Identifier: []byte(core.ESDTSetTokenType), Address: in.CallerAddr, Topics: [][]byte{id, []byte(want)}}, host.logs[logsBefore])
							}
							require.Empty(t, host.output)
							qualTransitionPersist(t, host, id)
						}
					})
				}
			}
		}
	}
}

// Reuse the existing real AccountsDB fixture; no test-owned storage applier or
// rollback policy substitutes for the production V2 consumer/ProcessIfError.
func qualTransitionPersist(t *testing.T, host *vmContext, id []byte) {
	t.Helper()
	_, _, db, _, _, _ := qualNativeRegistration(t)
	expected := bytes.Clone(host.GetStorage(id))
	out := host.CreateVMOutput()
	flags := enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
	flags.AddActiveFlags(common.FixCorrectSmallIntAndGasLimitsFlag)
	args := scrCommon.ArgsNewSmartContractProcessor{
		VmContainer: &processMock.VMContainerMock{}, ArgsParser: smartContract.NewArgumentParser(),
		Hasher: blake2b.NewBlake2b(), Marshalizer: &marshal.GogoProtoMarshalizer{}, AccountsDB: db,
		BlockChainHook: &testscommon.BlockChainHookStub{}, PubkeyConv: testscommon.NewPubkeyConverterMock(32),
		ShardCoordinator: &testscommon.ShardsCoordinatorMock{SelfIDCalled: func() uint32 { return 0 }, ComputeIdCalled: func([]byte) uint32 { return 0 }},
		ScrForwarder:     &processMock.IntermediateTransactionHandlerMock{}, BadTxForwarder: &processMock.IntermediateTransactionHandlerMock{},
		TxFeeHandler: &processMock.FeeAccumulatorStub{}, TxLogsProcessor: &processMock.TxLogsProcessorStub{},
		EconomicsFee: &economicsmocks.EconomicsHandlerMock{}, TxTypeHandler: &testscommon.TxTypeHandlerMock{},
		GasHandler: &testscommon.GasHandlerStub{}, EnableEpochsHandler: flags,
		GasSchedule:        testscommon.NewGasScheduleNotifierMock(map[string]map[string]uint64{}),
		WasmVMChangeLocker: &sync.RWMutex{}, VMOutputCacher: txcache.NewDisabledCache(), BuiltInFunctions: builtInFunctions.NewBuiltInFunctionContainer(),
	}
	sc, err := processorV2.NewSmartContractProcessorV2(args)
	require.NoError(t, err)
	tx := &transaction.Transaction{SndAddr: bytes.Repeat([]byte{1}, 32), RcvAddr: core.ESDTSCAddress, Value: big.NewInt(0)}
	_, _, err = processorV2.NewVMOutputAccountsProcessor(sc, &vmcommon.VMInput{CallType: vmData.DirectCall}, out, tx, []byte("hash")).Run()
	require.NoError(t, err)
	root, err := db.Commit()
	require.NoError(t, err)
	require.NoError(t, db.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
	require.Equal(t, expected, qualNativeRegistrationValue(t, db, core.ESDTSCAddress, id))
	require.Equal(t, make([]byte, 8), qualNativeRegistrationValue(t, db, core.SystemAccountAddress, []byte(core.ProtectedKeyPrefix+"DRWA@registry@count")))
	require.Empty(t, qualNativeRegistrationValue(t, db, core.SystemAccountAddress, append([]byte(core.ProtectedKeyPrefix+"DRWA@registry@member@"), id...)))
	// A deliberately inconsistent total is detected only after account saves.
	// It exercises the owning rollback entrypoint without changing production.
	snapshot := db.JournalLen()
	account := out.OutputAccounts[string(core.ESDTSCAddress)]
	require.NotNil(t, account)
	account.BalanceDelta = big.NewInt(1)
	_, _, err = processorV2.NewVMOutputAccountsProcessor(sc, &vmcommon.VMInput{CallType: vmData.DirectCall}, out, tx, []byte("hash")).Run()
	require.ErrorIs(t, err, process.ErrOverallBalanceChangeFromSC)
	require.NoError(t, sc.ProcessIfError(nil, []byte("hash"), tx, err.Error(), nil, snapshot, 0))
	after, err := db.RootHash()
	require.NoError(t, err)
	require.Equal(t, root, after)
	require.Equal(t, expected, qualNativeRegistrationValue(t, db, core.ESDTSCAddress, id))
	require.Equal(t, make([]byte, 8), qualNativeRegistrationValue(t, db, core.SystemAccountAddress, []byte(core.ProtectedKeyPrefix+"DRWA@registry@count")))
	require.Empty(t, qualNativeRegistrationValue(t, db, core.SystemAccountAddress, append([]byte(core.ProtectedKeyPrefix+"DRWA@registry@member@"), id...)))
}

func qualTransitionOrdering(t *testing.T, method string) {
	t.Helper()
	for _, fix := range []bool{false, true} {
		for _, variant := range []string{"inactive", "arity", "type", "NFT", "SFT", "META"} {
			if method == "registerMetaESDT" && variant != "inactive" && variant != "arity" {
				continue
			}
			t.Run(fmt.Sprintf("fix %t %s should retain activation arity type decimal ordering", fix, variant), func(t *testing.T) {
				e, host, flags := qualTransitionContract(t, fix)
				args := [][]byte{[]byte("TokenName"), []byte("TOKEN"), []byte("FNG"), new(big.Int).Lsh(big.NewInt(1), 80).Bytes()}
				flag := common.ESDTRegisterAndSetAllRolesFlag
				if method == "registerMetaESDT" {
					flag = common.MetaESDTSetFlag
					args = [][]byte{[]byte("TokenName"), []byte("TOKEN"), {18}}
				}
				if variant == "inactive" {
					flags.RemoveActiveFlags(flag)
				}
				if variant == "arity" {
					args = args[:2]
				}
				if variant == "type" {
					args[2] = []byte("BAD")
				}
				if variant == "NFT" || variant == "SFT" || variant == "META" {
					args[2] = []byte(variant)
				}
				code := e.Execute(qualTransitionInput(method, args, true))
				gas := uint64(990)
				switch variant {
				case "inactive":
					gas = 1000
					want := vmcommon.FunctionNotFound
					if method == "registerMetaESDT" {
						want = vmcommon.UserError
					}
					require.Equal(t, want, code)
					require.Equal(t, "invalid method to call", host.returnMessage)
				case "arity":
					require.Equal(t, vmcommon.UserError, code)
					msg := "arguments length mismatch"
					if method == "registerMetaESDT" {
						msg = "not enough arguments"
					}
					require.Equal(t, msg, host.returnMessage)
				case "type":
					require.Equal(t, vmcommon.UserError, code)
					require.Equal(t, vm.ErrInvalidArgument.Error(), host.returnMessage)
				default:
					if variant == "META" && fix {
						require.Equal(t, vmcommon.UserError, code)
						require.Contains(t, host.returnMessage, "provided: ")
					} else {
						require.Equal(t, vmcommon.Ok, code, host.returnMessage)
						require.Len(t, host.output, 1)
						token, err := e.getExistingToken(host.output[0])
						require.NoError(t, err)
						require.Zero(t, token.NumDecimals)
						want := core.NonFungibleESDT
						if variant == "SFT" {
							want = core.SemiFungibleESDT
						}
						if variant == "META" {
							want = core.MetaESDT
						}
						require.Equal(t, []byte(want), token.TokenType)
						qualTransitionPersist(t, host, host.output[0])
					}
				}
				require.Equal(t, gas, host.gasRemaining)
				if code != vmcommon.Ok {
					qualTransitionNoOutput(t, host)
					require.Empty(t, host.storageUpdate)
				}
			})
		}
	}
}

type qualTransitionMarshalFault struct {
	marshal.Marshalizer
	tokenWrites int
	fault       error
}

func (m *qualTransitionMarshalFault) Marshal(obj interface{}) ([]byte, error) {
	switch obj.(type) {
	case *ESDTDataV1, *ESDTDataV2:
		m.tokenWrites++
		if m.tokenWrites == 2 {
			return nil, m.fault
		}
	}
	return m.Marshalizer.Marshal(obj)
}

func qualTransitionLateRoles(t *testing.T) {
	t.Run("late role save failure should discard staged definition transfer and logs at SystemVM boundary", func(t *testing.T) {
		e, host, _ := qualTransitionContract(t, true)
		_, _, db, _, _, _ := qualNativeRegistration(t)
		root, err := db.RootHash()
		require.NoError(t, err)
		host.userAccountsDB = db
		fault := errors.New("late token serialization")
		mar := &qualTransitionMarshalFault{Marshalizer: e.marshalizer, fault: fault}
		e.marshalizer = mar
		container := &mock.SystemSCContainerStub{GetCalled: func([]byte) (vm.SystemSmartContract, error) { return e, nil }}
		require.NoError(t, host.SetSystemSCContainer(container))
		machine, err := vmProcess.NewSystemVM(vmProcess.ArgsNewSystemVM{SystemEI: host, SystemContracts: container, VmType: []byte{0}, GasSchedule: testscommon.NewGasScheduleNotifierMock(map[string]map[string]uint64{common.BaseOpsAPICost: {common.AsyncCallStepField: 1, common.AsyncCallbackGasLockField: 1}})})
		require.NoError(t, err)
		in := qualTransitionInput("registerAndSetAllRoles", [][]byte{[]byte("TokenName"), []byte("TOKEN"), []byte("FNG"), {18}}, true)
		in.GasProvided = 1000
		out, err := machine.RunSmartContractCall(in)
		require.NoError(t, err)
		require.Equal(t, 2, mar.tokenWrites)
		require.Equal(t, vmcommon.UserError, out.ReturnCode)
		require.Equal(t, fault.Error(), out.ReturnMessage)
		require.Empty(t, out.OutputAccounts)
		require.Empty(t, out.ReturnData)
		require.Empty(t, out.Logs)
		require.Zero(t, out.GasRemaining)
		require.Zero(t, out.GasRefund.Sign())
		// Prove this was a late failure, not rejection before native effects.
		require.NotEmpty(t, host.storageUpdate[string(core.ESDTSCAddress)])
		require.Len(t, host.logs, 1)
		require.Len(t, host.outputAccounts[string(in.CallerAddr)].OutputTransfers, 1)
		after, err := db.RootHash()
		require.NoError(t, err)
		require.Equal(t, root, after)
		require.Zero(t, db.JournalLen())
		committed, err := db.Commit()
		require.NoError(t, err)
		require.Equal(t, root, committed)
		require.Equal(t, []byte{1}, qualNativeRegistrationValue(t, db, core.ESDTSCAddress, []byte("fixture/sentinel")))
	})
}

func qualTransitionReceivingPause(t *testing.T, host *vmContext, data []byte) {
	t.Helper()
	for shard := byte(0); shard < 3; shard++ {
		_, _, db, _, _, _ := qualNativeRegistration(t)
		token := []byte("TOKEN-000001")
		fn, err := builtInFunctions.NewESDTGlobalSettingsFunc(db, &marshal.GogoProtoMarshalizer{}, true, core.BuiltInFunctionESDTPause, func() bool { return true })
		require.NoError(t, err)
		addr := bytes.Clone(core.SystemAccountAddress)
		addr[31] = shard
		transfer := host.outputAccounts[string(addr)].OutputTransfers[0]
		require.Equal(t, data, transfer.Data)
		input := &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: core.ESDTSCAddress, CallValue: new(big.Int).Set(transfer.Value), CallType: transfer.CallType, Arguments: [][]byte{token}}, RecipientAddr: addr}
		root, err := db.RootHash()
		require.NoError(t, err)
		snapshot := db.JournalLen()
		out, err := fn.ProcessBuiltinFunction(nil, nil, input)
		require.NoError(t, err)
		require.Equal(t, vmcommon.Ok, out.ReturnCode)
		key := append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), token...)
		require.True(t, fn.IsPaused(key))
		require.NoError(t, db.RevertToSnapshot(snapshot))
		after, err := db.RootHash()
		require.NoError(t, err)
		require.Equal(t, root, after)
		require.False(t, fn.IsPaused(key))
		out, err = fn.ProcessBuiltinFunction(nil, nil, input)
		require.NoError(t, err)
		require.Equal(t, vmcommon.Ok, out.ReturnCode)
		root, err = db.Commit()
		require.NoError(t, err)
		require.NoError(t, db.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
		require.True(t, fn.IsPaused(key))
		require.Equal(t, []byte{1}, qualNativeRegistrationValue(t, db, core.ESDTSCAddress, []byte("fixture/sentinel")))
	}
}

func qualTransitionConversionActivation(t *testing.T) {
	for _, active := range []bool{false, true} {
		t.Run(fmt.Sprintf("meta active %t dynamic disabled should gate before effects or convert without fanout", active), func(t *testing.T) {
			e, host, flags := qualTransitionContract(t, true)
			owner := bytes.Repeat([]byte{1}, 32)
			id, _, err := e.createNewToken(owner, []byte("TokenName"), []byte("TOKEN"), big.NewInt(0), 0, nil, []byte(core.SemiFungibleESDT))
			require.NoError(t, err)
			before := bytes.Clone(host.GetStorage(id))
			qualTransitionReset(host)
			if !active {
				flags.RemoveActiveFlags(common.MetaESDTSetFlag)
			}
			in := qualTransitionInput("changeSFTToMetaESDT", [][]byte{id, {18}}, false)
			code := e.Execute(in)
			if !active {
				require.Equal(t, vmcommon.UserError, code)
				require.Equal(t, "invalid method to call", host.returnMessage)
				require.Equal(t, uint64(1000), host.gasRemaining)
				require.Equal(t, before, host.GetStorage(id))
				qualTransitionNoOutput(t, host)
				return
			}
			require.Equal(t, vmcommon.Ok, code, host.returnMessage)
			require.Equal(t, uint64(993), host.gasRemaining)
			require.Equal(t, []*vmcommon.LogEntry{{Identifier: []byte(in.Function), Address: owner, Topics: [][]byte{id, []byte("TokenName"), []byte("TOKEN"), []byte(core.MetaESDT), {18}}}}, host.logs)
			require.Empty(t, host.outputAccounts)
			require.Empty(t, host.output)
			token, err := e.getExistingToken(id)
			require.NoError(t, err)
			require.Equal(t, []byte(core.MetaESDT), token.TokenType)
			require.Equal(t, uint32(18), token.NumDecimals)
			qualTransitionPersist(t, host, id)
		})
	}
}
