package processorV2

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/smartContract"
	"github.com/multiversx/mx-chain-go/state"
	stateDisabled "github.com/multiversx/mx-chain-go/state/disabled"
	"github.com/multiversx/mx-chain-go/state/factory"
	pruningDisabled "github.com/multiversx/mx-chain-go/state/storagePruningManager/disabled"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/storageManager"
	"github.com/multiversx/mx-chain-go/trie"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Local output consumer and journal checks are separate from network/finality.
func TestQualTransitionR01SCR(t *testing.T) {
	qualTransitionR01Persistence(t)
	for _, fix := range []bool{false, true} {
		name := "disabled"
		if fix {
			name = "enabled"
		}
		t.Run(name+" should suppress only the synthetic callback after staking", func(t *testing.T) {
			args := createMockSmartContractProcessorArguments()
			args.ShardCoordinator = &testscommon.ShardsCoordinatorMock{SelfIDCalled: func() uint32 { return 0 }, ComputeIdCalled: func([]byte) uint32 { return 0 }}
			args.ArgsParser = smartContract.NewArgumentParser()
			flags := enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
			if fix {
				flags.AddActiveFlags(common.FixCorrectSmallIntAndGasLimitsFlag)
			}
			args.EnableEpochsHandler = flags
			sc, err := NewSmartContractProcessorV2(args)
			require.NoError(t, err)
			tx := &transaction.Transaction{SndAddr: bytes.Repeat([]byte{1}, 32), RcvAddr: bytes.Repeat([]byte{2}, 32), Value: big.NewInt(0), GasPrice: 9}
			out := &vmcommon.OutputAccount{Address: tx.SndAddr, BalanceDelta: big.NewInt(0)}
			output := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, ReturnData: [][]byte{[]byte("result")}, OutputAccounts: map[string]*vmcommon.OutputAccount{string(out.Address): out}}
			callback, results := sc.createSmartContractResults(&vmcommon.VMInput{CallType: vmData.AsynchronousCall}, output, out, tx, []byte("hash"))
			require.Equal(t, !fix, callback)
			if fix {
				require.Empty(t, results)
			} else {
				require.Len(t, results, 1)
				scr := results[0].result.(*smartContractResult.SmartContractResult)
				require.Equal(t, vmData.AsynchronousCallBack, scr.CallType)
				require.Equal(t, tx.SndAddr, scr.RcvAddr)
			}
			out.Address = vm.StakingSCAddress
			callback, results = sc.createSmartContractResults(&vmcommon.VMInput{CallType: vmData.DirectCall}, output, out, tx, []byte("hash"))
			require.False(t, callback)
			require.Len(t, results, 1)
			require.Equal(t, vm.StakingSCAddress, results[0].result.GetRcvAddr())
			out.Address = tx.SndAddr
			out.OutputTransfers = []vmcommon.OutputTransfer{{Index: 17, Value: big.NewInt(3), GasLimit: 41, GasLocked: 5, Data: []byte("payload"), CallType: vmData.DirectCall}}
			callback, results = sc.createSmartContractResults(&vmcommon.VMInput{CallType: vmData.DirectCall}, output, out, tx, []byte("hash"))
			require.False(t, callback)
			require.Len(t, results, 1)
			require.Equal(t, uint32(17), results[0].index)
			scr := results[0].result.(*smartContractResult.SmartContractResult)
			require.Equal(t, tx.RcvAddr, scr.SndAddr)
			require.Equal(t, tx.SndAddr, scr.RcvAddr)
			require.Equal(t, tx.SndAddr, scr.OriginalSender)
			require.Equal(t, []byte("hash"), scr.PrevTxHash)
			require.Equal(t, []byte("hash"), scr.OriginalTxHash)
			require.Equal(t, big.NewInt(3), scr.Value)
			require.Equal(t, uint64(41), scr.GasLimit)
			require.Equal(t, uint64(9), scr.GasPrice)
			require.Equal(t, vmData.DirectCall, scr.CallType)
			require.Equal(t, []byte("payload"), scr.Data)
			out.OutputTransfers[0].SenderAddress = tx.SndAddr
			callback, results = sc.createSmartContractResults(&vmcommon.VMInput{CallType: vmData.DirectCall}, output, out, tx, []byte("hash"))
			require.False(t, callback)
			require.Len(t, results, 1)
			require.Equal(t, tx.SndAddr, results[0].result.GetSndAddr())
		})
	}
}

func qualTransitionR01Persistence(t *testing.T) {
	for _, fix := range []bool{false, true} {
		t.Run(fmt.Sprintf("fix %t should persist independent effects and revert a late imbalance", fix), func(t *testing.T) {
			db := testscommon.NewMemDbMock()
			codec, hash := &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b()
			flags := enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
			if fix {
				flags.AddActiveFlags(common.FixCorrectSmallIntAndGasLimitsFlag)
			}
			storage := &storageManager.StorageManagerStub{GetCalled: db.Get, PutCalled: db.Put, GetFromCurrentEpochCalled: db.Get, GetIdentifierCalled: db.GetIdentifier, GetStateStatsHandlerCalled: db.GetStateStatsHandler}
			tr, err := trie.NewTrie(storage, codec, hash, flags, 5)
			require.NoError(t, err)
			collector := stateDisabled.NewDisabledStateAccessesCollector()
			creator, err := factory.NewAccountCreator(factory.ArgsAccountCreator{Hasher: hash, Marshaller: codec, EnableEpochsHandler: flags, StateAccessesCollector: collector})
			require.NoError(t, err)
			adb, err := state.NewAccountsDB(state.ArgsAccountsDB{Trie: tr, Hasher: hash, Marshaller: codec, AccountFactory: creator, StateAccessesCollector: collector, StoragePruningManager: pruningDisabled.NewDisabledStoragePruningManager(), SnapshotsManager: stateDisabled.NewDisabledSnapshotsManager(), AddressConverter: testscommon.NewPubkeyConverterMock(32)})
			require.NoError(t, err)
			args := createMockSmartContractProcessorArguments()
			args.AccountsDB, args.EnableEpochsHandler = adb, flags
			args.ArgsParser = smartContract.NewArgumentParser()
			args.BlockChainHook = &testscommon.BlockChainHookStub{FilterCodeMetadataForUpgradeCalled: func(b []byte) ([]byte, error) { return b, nil }}
			args.ShardCoordinator = &testscommon.ShardsCoordinatorMock{SelfIDCalled: func() uint32 { return 0 }, ComputeIdCalled: func([]byte) uint32 { return 0 }}
			sc, err := NewSmartContractProcessorV2(args)
			require.NoError(t, err)
			addr := make([]byte, 32)
			addr[9] = 5
			owner := bytes.Repeat([]byte{1}, 32)
			a, err := adb.LoadAccount(addr)
			require.NoError(t, err)
			require.NoError(t, a.(state.UserAccountHandler).AddToBalance(big.NewInt(100)))
			require.NoError(t, a.(state.UserAccountHandler).SaveKeyValue([]byte("sentinel"), []byte("before")))
			require.NoError(t, adb.SaveAccount(a))
			_, err = adb.Commit()
			require.NoError(t, err)
			for _, late := range []bool{false, true} {
				tx := &transaction.Transaction{SndAddr: owner, RcvAddr: addr, Value: big.NewInt(3)}
				if late {
					tx.Value.SetInt64(0)
				}
				root, err := adb.RootHash()
				require.NoError(t, err)
				snapshot := adb.JournalLen()
				code := []byte("first-code")
				if late {
					code = []byte("changed-code")
				}
				out := &vmcommon.OutputAccount{Address: addr, BalanceDelta: big.NewInt(3), Nonce: 2, Code: code, CodeMetadata: (&vmcommon.CodeMetadata{Upgradeable: true}).ToBytes(), CodeDeployerAddress: owner, StorageUpdates: map[string]*vmcommon.StorageUpdate{"sentinel": {Offset: []byte("sentinel"), Data: []byte("after")}}}
				if late {
					out.Nonce = 3
					out.StorageUpdates["sentinel"].Data = []byte("late")
				}
				output := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, OutputAccounts: map[string]*vmcommon.OutputAccount{string(addr): out}}
				callback, results, err := NewVMOutputAccountsProcessor(sc, &vmcommon.VMInput{CallType: vmData.DirectCall}, output, tx, []byte("hash")).Run()
				if late {
					require.ErrorIs(t, err, process.ErrOverallBalanceChangeFromSC)
					require.NoError(t, sc.ProcessIfError(nil, []byte("hash"), tx, err.Error(), nil, snapshot, 0))
					after, e := adb.RootHash()
					require.NoError(t, e)
					require.Equal(t, root, after)
				} else {
					require.NoError(t, err)
					require.False(t, callback)
					if fix {
						require.Empty(t, results)
					}
					root, err = adb.Commit()
					require.NoError(t, err)
					require.NoError(t, adb.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
				}
				a, err = adb.GetExistingAccount(addr)
				require.NoError(t, err)
				user := a.(state.UserAccountHandler)
				require.Equal(t, big.NewInt(103), user.GetBalance())
				require.Equal(t, uint64(2), user.GetNonce())
				require.Equal(t, []byte("first-code"), adb.GetCode(user.GetCodeHash()))
				v, _, err := user.RetrieveValue([]byte("sentinel"))
				require.NoError(t, err)
				require.Equal(t, []byte("after"), v)
				require.Equal(t, owner, user.GetOwnerAddress())
				require.True(t, core.IsSmartContractAddress(addr))
			}
		})
	}
}
