package systemSmartContracts

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	esdtData "github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/enablers"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/process/drwa"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/state"
	stateDisabled "github.com/multiversx/mx-chain-go/state/disabled"
	"github.com/multiversx/mx-chain-go/state/factory"
	pruningDisabled "github.com/multiversx/mx-chain-go/state/storagePruningManager/disabled"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/epochNotifier"
	"github.com/multiversx/mx-chain-go/testscommon/processMocks"
	"github.com/multiversx/mx-chain-go/testscommon/storageManager"
	"github.com/multiversx/mx-chain-go/trie"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/multiversx/mx-chain-vm-common-go/parsers"
	"github.com/stretchr/testify/require"
)

// E10 expected model SHA 4117ff54d390452ec650bcdea0165d546ee7f550043fbce718d020a14a152801.
// Three execution shards, epoch5/7, address02*32, record4096 and proof budgets
// below are explicit fixture inputs, never admitted configuration/identity.
func qualE10Args() drwa.ArgsResultAccountReader {
	db := testscommon.NewMemDbMock()
	return drwa.ArgsResultAccountReader{StorageManager: &storageManager.StorageManagerStub{
		GetCalled: db.Get, GetFromCurrentEpochCalled: db.Get, PutCalled: db.Put, GetStateStatsHandlerCalled: db.GetStateStatsHandler, GetIdentifierCalled: db.GetIdentifier},
		Marshaller: &marshal.GogoProtoMarshalizer{}, Hasher: blake2b.NewBlake2b(), EnableEpochsHandler: enableEpochsHandlerMock.NewEnableEpochsHandlerStub(), MaxTrieLevelInMemory: 5}
}
func qualE10DB(t *testing.T, a drwa.ArgsResultAccountReader, provision bool) *state.AccountsDB {
	t.Helper()
	tr, e := trie.NewTrie(a.StorageManager, a.Marshaller, a.Hasher, a.EnableEpochsHandler, 5)
	require.NoError(t, e)
	collector := stateDisabled.NewDisabledStateAccessesCollector()
	f, e := factory.NewAccountCreator(factory.ArgsAccountCreator{Hasher: a.Hasher, Marshaller: a.Marshaller, EnableEpochsHandler: a.EnableEpochsHandler, StateAccessesCollector: collector})
	require.NoError(t, e)
	db, e := state.NewAccountsDB(state.ArgsAccountsDB{Trie: tr, Hasher: a.Hasher, Marshaller: a.Marshaller, AccountFactory: f, StateAccessesCollector: collector,
		StoragePruningManager: pruningDisabled.NewDisabledStoragePruningManager(), SnapshotsManager: stateDisabled.NewDisabledSnapshotsManager(), AddressConverter: testscommon.NewPubkeyConverterMock(32)})
	require.NoError(t, e)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	if provision {
		u, e := db.LoadAccount(core.SystemAccountAddress)
		require.NoError(t, e)
		for k, v := range map[string][]byte{"ELRONDDRWA@registry@count": make([]byte, 8), "ELRONDDRWA@membershipIndex@count": make([]byte, 8)} {
			require.NoError(t, u.(state.UserAccountHandler).SaveKeyValue([]byte(k), v))
		}
		require.NoError(t, db.SaveAccount(u))
		_, e = db.Commit()
		require.NoError(t, e)
	}
	return db
}
func qualE10Proof(t *testing.T, s *qualDRWARegistrationStore, root, key []byte) drwa.AccountItemWitness {
	t.Helper()
	tr, e := s.AccountsAdapter.(*state.AccountsDB).GetTrie(root)
	require.NoError(t, e)
	p, _, e := tr.GetProof(core.SystemAccountAddress)
	require.NoError(t, e)
	u, e := s.GetExistingAccount(core.SystemAccountAddress)
	require.NoError(t, e)
	d, _, e := u.(state.UserAccountHandler).DataTrie().(common.Trie).GetProof(key)
	require.NoError(t, e)
	return drwa.AccountItemWitness{AccountProof: p, DataProof: d}
}
func qualE10Value(t *testing.T, s state.AccountsAdapter, id []byte) []byte {
	t.Helper()
	u, e := s.GetExistingAccount(core.SystemAccountAddress)
	require.NoError(t, e)
	v, _, e := u.(state.UserAccountHandler).RetrieveValue(append([]byte("ELRONDesdt"), id...))
	require.NoError(t, e)
	return v
}
func qualE10Input(id []byte, function string, shard byte) *vmcommon.ContractCallInput {
	dest := bytes.Clone(core.SystemAccountAddress)
	dest[31] = shard
	return &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: bytes.Clone(core.ESDTSCAddress), CallValue: big.NewInt(0), Arguments: [][]byte{bytes.Clone(id)}, GasProvided: 100}, RecipientAddr: dest, Function: function}
}
func qualE10Owner(t *testing.T, db state.AccountsAdapter, root []byte, shard uint32, flags common.EnableEpochsHandler, budget int) drwa.ArgsBurnForAllAbsence {
	t.Helper()
	a := qualE10Args()
	reader, e := drwa.NewResultAccountReader(a)
	require.NoError(t, e)
	// No reference ancestry is exercised here. Reject unexpected validation;
	// the process/drwa fixtures exercise the actual native header validator.
	v := &processMocks.HeaderValidatorMock{IsHeaderConstructionValidCalled: func(data.HeaderHandler, data.HeaderHandler) error {
		t.Fatal("unexpected reference ancestry in no-reference fixture")
		return errors.New("unexpected reference ancestry")
	}}
	// A retained native meta execution result selected from an owning predecessor,
	// with no new references. Native canonical finality is NOT established here.
	p := &block.MetaBlockV3{Nonce: 10, Round: 30, Epoch: 2, LastExecutionResult: &block.MetaExecutionResultInfo{ExecutionResult: &block.BaseMetaExecutionResult{BaseExecutionResult: &block.BaseExecutionResult{HeaderHash: []byte("fixture-executed-meta"), HeaderNonce: 9, HeaderRound: 29, HeaderEpoch: 2, RootHash: root}}}}
	pb, e := a.Marshaller.Marshal(p)
	require.NoError(t, e)
	c := &block.HeaderV3{ShardID: shard, Nonce: 20, Round: 50, Epoch: 2}
	cb, e := a.Marshaller.Marshal(c)
	require.NoError(t, e)
	return drwa.ArgsBurnForAllAbsence{Accounts: db, Reader: reader, Marshaller: a.Marshaller, Hasher: a.Hasher, Validator: v, EnableEpochsHandler: flags,
		CandidateHash: a.Hasher.Compute(string(cb)), Candidate: cb, PredecessorHash: a.Hasher.Compute(string(pb)), Predecessor: pb, MaxEver: 1, ProofByteLimit: budget, RecordByteLimit: 4096}
}

func TestQualDRWANativeRegistrationBurnForAllAllShards(t *testing.T) {
	families := []string{core.FungibleESDT, core.NonFungibleESDTv2, core.SemiFungibleESDT, core.MetaESDT, core.DynamicNFTESDT, core.DynamicSFTESDT, core.DynamicMetaESDT}
	for _, family := range families {
		for _, producerEpoch := range []uint32{4, 5, 6, 7} {
			t.Run(fmt.Sprintf("%s/epoch_%d", family, producerEpoch), func(t *testing.T) {
				e, ctx, s, _, _, request := qualNativeRegistration(t)
				request.family = []byte(family)
				request.properties = nil
				flags, err := enablers.NewEnableEpochsHandler(config.EnableEpochs{ESDTMetadataContinuousCleanupEnableEpoch: 5, DynamicESDTEnableEpoch: 7}, &epochNotifier.EpochNotifierStub{})
				require.NoError(t, err)
				flags.EpochConfirmed(producerEpoch, 0)
				e.enableEpochsHandler = flags
				require.Equal(t, producerEpoch >= 5, flags.IsFlagEnabled(common.ESDTMetadataContinuousCleanupFlag))
				require.Equal(t, producerEpoch >= 7, flags.IsFlagEnabled(common.DynamicESDTFlag))
				f := qualCommittedIntent(t, s, request)
				require.NoError(t, e.registerDRWACommittedToken(f.owner, request, f.profile, f.bodyDigest))
				id := bytes.Clone(ctx.output[0])
				roots, out, err := f.boundary.Commit()
				require.NoError(t, err)
				require.Len(t, out, 1)
				require.NoError(t, s.RecreateTrie(holders.NewDefaultRootHashesHolder(roots[0])))
				native := &ESDTDataV2{}
				require.NoError(t, e.marshalizer.Unmarshal(native, qualNativeRegistrationValue(t, s, core.ESDTSCAddress, id)))
				require.Equal(t, request.family, native.TokenType)
				require.Equal(t, request.manager, native.OwnerAddress)
				require.Empty(t, native.SpecialRoles, "actual persisted metachain poststate, not unset return")
				w := drwa.BurnForAllRegistrationWitness{Association: qualE10Proof(t, s, roots[0], append([]byte("ELRONDDRWA@registration@token@"), id...)),
					Intent: qualE10Proof(t, s, roots[0], append([]byte("ELRONDDRWA@registration@intent@"), f.id...)), Activation: qualE10Proof(t, s, roots[0], append([]byte("ELRONDDRWA@registration@activation@"), id...)), Profile: f.profile, Name: request.name, Ticker: request.ticker, Decimals: request.decimals}
				count := qualE10Proof(t, s, roots[0], []byte("ELRONDDRWA@registry@count"))
				members := []drwa.BurnForAllMemberWitness{{TokenID: id, Proof: qualE10Proof(t, s, roots[0], append([]byte("ELRONDDRWA@registry@member@"), id...))}}
				budget := 0
				for _, p := range []drwa.AccountItemWitness{count, members[0].Proof, w.Association, w.Intent, w.Activation} {
					for _, nodes := range [][][]byte{p.AccountProof, p.DataProof} {
						for _, n := range nodes {
							budget += len(n)
						}
					}
				}
				observed := 0
				normalized := []bool{false, false, false}
				for shard := byte(0); shard < 3; shard++ {
					a := qualE10Args()
					db := qualE10DB(t, a, true)
					adapter := &qualDRWARegistrationStore{AccountsAdapter: db}
					args := qualE10Owner(t, adapter, roots[0], uint32(shard), flags, budget)
					b, err := drwa.NewBurnForAllAbsence(args)
					require.NoError(t, err)
					require.NoError(t, b.Prepare(context.Background(), count, members))
					dest := bytes.Clone(core.SystemAccountAddress)
					dest[31] = shard
					transfers := []vmcommon.OutputTransfer{}
					if output := out[0].OutputAccounts[string(dest)]; output != nil {
						transfers = output.OutputTransfers
					}
					want := 0
					if producerEpoch >= 5 {
						want += 2
					}
					if producerEpoch >= 7 {
						want++
					}
					require.Len(t, transfers, want)
					settings, err := builtInFunctions.NewESDTGlobalSettingsFunc(db, a.Marshaller, false, vmcommon.BuiltInFunctionESDTUnSetBurnRoleForAll, func() bool { return flags.IsFlagEnabled(common.SendAlwaysFlag) })
					require.NoError(t, err)
					parser := parsers.NewCallArgsParser()
					// Original and reversed delivery: raw effects never authorize registered
					// toggles. Type fan-out uses its unchanged native implementation.
					for _, transfer := range transfers {
						require.Empty(t, transfer.SenderAddress)
						fn, arguments, err := parser.ParseData(string(transfer.Data))
						require.NoError(t, err)
						require.Equal(t, id, arguments[0])
						input := qualE10Input(id, fn, shard)
						input.Arguments = arguments
						if fn == core.ESDTSetTokenType {
							require.Equal(t, request.family, arguments[1])
							typeFn, err := builtInFunctions.NewESDTSetTokenTypeFunc(db, settings, a.Marshaller, func() bool { return flags.IsFlagEnabled(common.DynamicESDTFlag) })
							require.NoError(t, err)
							_, err = typeFn.ProcessBuiltinFunction(nil, nil, input)
							require.NoError(t, err)
						} else {
							require.Contains(t, []string{vmcommon.BuiltInFunctionESDTSetBurnRoleForAll, vmcommon.BuiltInFunctionESDTUnSetBurnRoleForAll}, fn)
							_, err = b.ProcessBuiltinFunction(input)
							require.Error(t, err)
						}
					}
					if shard == 2 {
						require.Equal(t, []bool{true, true, false}, normalized, "partial fan-out is not all-shard absence")
						prior := qualE10Value(t, db, id)
						before, err := db.RootHash()
						require.NoError(t, err)
						fault := errors.New("third shard false save after mutation")
						adapter.failAt, adapter.saveFault = adapter.saves+1, fault
						require.ErrorIs(t, b.Normalize(id, w), fault)
						after, err := db.RootHash()
						require.NoError(t, err)
						require.Equal(t, before, after)
						require.Equal(t, prior, qualE10Value(t, db, id))
						require.Equal(t, []bool{true, true, false}, normalized)
						adapter.failAt, adapter.saveFault = 0, nil
					}
					require.NoError(t, b.Normalize(id, w))
					expected := []byte{0, 0}
					if producerEpoch >= 7 {
						expected[1] = map[string]byte{core.FungibleESDT: 1, core.NonFungibleESDTv2: 3, core.SemiFungibleESDT: 5, core.MetaESDT: 4, core.DynamicNFTESDT: 6, core.DynamicSFTESDT: 7, core.DynamicMetaESDT: 8}[family]
					}
					require.Equal(t, expected, qualE10Value(t, db, id))
					require.False(t, settings.IsBurnForAll(append([]byte("ELRONDesdt"), id...)))
					for _, deliveryEpoch := range []uint32{4, 5, 6, 7} {
						flags.EpochConfirmed(deliveryEpoch, 0)
						for _, fn := range []string{vmcommon.BuiltInFunctionESDTUnSetBurnRoleForAll, vmcommon.BuiltInFunctionESDTSetBurnRoleForAll, vmcommon.BuiltInFunctionESDTSetBurnRoleForAll, vmcommon.BuiltInFunctionESDTUnSetBurnRoleForAll} {
							for _, forged := range []bool{false, true} {
								input := qualE10Input(id, fn, shard)
								if forged {
									input.CallerAddr = []byte("forged")
									input.RecipientAddr = []byte("wrong-shard")
								}
								_, err = b.ProcessBuiltinFunction(input)
								require.Error(t, err)
								require.Equal(t, expected, qualE10Value(t, db, id))
							}
						}
					}
					localRoots, _, err := b.Commit()
					require.NoError(t, err)
					_, err = b.ProcessBuiltinFunction(qualE10Input(id, vmcommon.BuiltInFunctionESDTSetBurnRoleForAll, shard))
					require.Error(t, err)
					reopened := qualE10DB(t, a, false)
					require.NoError(t, reopened.RecreateTrie(holders.NewDefaultRootHashesHolder(localRoots[0])))
					args.Accounts = reopened
					b, err = drwa.NewBurnForAllAbsence(args)
					require.NoError(t, err)
					require.NoError(t, b.Prepare(context.Background(), count, members))
					require.NoError(t, b.Normalize(id, w))
					_, err = b.ProcessBuiltinFunction(qualE10Input(id, vmcommon.BuiltInFunctionESDTSetBurnRoleForAll, shard))
					require.Error(t, err)
					require.Equal(t, expected, qualE10Value(t, reopened, id))
					normalized[shard] = true
					observed++
				}
				require.Equal(t, []bool{true, true, true}, normalized)
				require.Equal(t, 3, observed, "every explicit execution shard observed, no successful-unset oracle")
			})
		}
	}
}

func TestQualDRWANativeRegistrationBurnForAllGuardAndProofDenial(t *testing.T) {
	for _, fault := range []string{"partial", "profile", "name", "ticker", "decimals", "forged-association", "missing-intent", "activation", "malformed-metadata", "wrong-type", "save", "rollback"} {
		t.Run(fault, func(t *testing.T) {
			e, ctx, s, _, _, request := qualNativeRegistration(t)
			request.properties = nil
			f := qualCommittedIntent(t, s, request)
			require.NoError(t, e.registerDRWACommittedToken(f.owner, request, f.profile, f.bodyDigest))
			id := bytes.Clone(ctx.output[0])
			roots, _, err := f.boundary.Commit()
			require.NoError(t, err)
			w := drwa.BurnForAllRegistrationWitness{Association: qualE10Proof(t, s, roots[0], append([]byte("ELRONDDRWA@registration@token@"), id...)), Intent: qualE10Proof(t, s, roots[0], append([]byte("ELRONDDRWA@registration@intent@"), f.id...)), Activation: qualE10Proof(t, s, roots[0], append([]byte("ELRONDDRWA@registration@activation@"), id...)), Profile: bytes.Clone(f.profile), Name: request.name, Ticker: request.ticker}
			count := qualE10Proof(t, s, roots[0], []byte("ELRONDDRWA@registry@count"))
			members := []drwa.BurnForAllMemberWitness{{TokenID: id, Proof: qualE10Proof(t, s, roots[0], append([]byte("ELRONDDRWA@registry@member@"), id...))}}
			budget := 0
			for _, p := range []drwa.AccountItemWitness{count, members[0].Proof, w.Association, w.Intent, w.Activation} {
				for _, nodes := range [][][]byte{p.AccountProof, p.DataProof} {
					for _, n := range nodes {
						budget += len(n)
					}
				}
			}
			a := qualE10Args()
			db := qualE10DB(t, a, true)
			var prior []byte
			if fault == "malformed-metadata" {
				prior = []byte{4}
			}
			if fault == "wrong-type" {
				prior = []byte{4, 8}
			}
			if prior != nil {
				u, e := db.GetExistingAccount(core.SystemAccountAddress)
				require.NoError(t, e)
				require.NoError(t, u.(state.UserAccountHandler).SaveKeyValue(append([]byte("ELRONDesdt"), id...), prior))
				require.NoError(t, db.SaveAccount(u))
				_, e = db.Commit()
				require.NoError(t, e)
			}
			adapter := &qualDRWARegistrationStore{AccountsAdapter: db}
			b, err := drwa.NewBurnForAllAbsence(qualE10Owner(t, adapter, roots[0], 1, e.enableEpochsHandler, budget))
			require.NoError(t, err)
			if fault == "partial" {
				require.Error(t, b.Prepare(context.Background(), count, nil))
				require.Error(t, b.Normalize(id, w))
				return
			}
			require.NoError(t, b.Prepare(context.Background(), count, members))
			before, err := db.RootHash()
			require.NoError(t, err)
			switch fault {
			case "profile":
				w.Profile[0] ^= 1
			case "name":
				w.Name = []byte("WrongName")
			case "ticker":
				w.Ticker = []byte("WRONG")
			case "decimals":
				w.Decimals = 1
			case "forged-association":
				w.Association.AccountProof[0][0] ^= 1
			case "missing-intent":
				w.Intent.DataProof = nil
			case "activation":
				w.Activation.DataProof = w.Association.DataProof
			case "save", "rollback":
				adapter.failAt = adapter.saves + 1
				adapter.saveFault = errors.New("false save after mutation")
				if fault == "rollback" {
					adapter.rollbackFault = errors.New("false undo failed")
				}
			}
			require.Error(t, b.Normalize(id, w))
			if fault == "rollback" {
				_, _, err = b.Commit()
				require.Error(t, err)
				require.Error(t, b.Normalize(id, w))
				return
			}
			after, err := db.RootHash()
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.Equal(t, prior, qualE10Value(t, db, id), "invalid or absent false-return never credited positive false")
		})
	}
}

// Actual native readers, roles handler, account serialization and NFT storage.
// No-role denial is an independent E10 control, NOT T44 all-route supply proof.
func TestQualDRWANativeRegistrationBurnForAllRawBurnControls(t *testing.T) {
	for _, family := range []string{core.FungibleESDT, core.NonFungibleESDTv2, core.SemiFungibleESDT, core.MetaESDT, core.DynamicNFTESDT, core.DynamicSFTESDT, core.DynamicMetaESDT} {
		for _, enabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/global_%t", family, enabled), func(t *testing.T) {
				a := qualE10Args()
				db := qualE10DB(t, a, true)
				id := []byte("TOKEN-abcdef")
				key := append([]byte("ELRONDesdt"), id...)
				settings, err := builtInFunctions.NewESDTGlobalSettingsFunc(db, a.Marshaller, enabled, vmcommon.BuiltInFunctionESDTSetBurnRoleForAll, func() bool { return true })
				require.NoError(t, err)
				_, err = settings.ProcessBuiltinFunction(nil, nil, qualE10Input(id, vmcommon.BuiltInFunctionESDTSetBurnRoleForAll, 1))
				require.NoError(t, err)
				roles, err := builtInFunctions.NewESDTRolesFunc(a.Marshaller, true)
				require.NoError(t, err)
				address := bytes.Repeat([]byte{9}, 32)
				account, err := db.LoadAccount(address)
				require.NoError(t, err)
				user := account.(vmcommon.UserAccountHandler)
				typeID, err := core.ConvertESDTTypeToUint32(family)
				require.NoError(t, err)
				nonce := byte(1)
				if family == core.FungibleESDT {
					nonce = 0
				}
				data := &esdtData.ESDigitalToken{Type: typeID, Value: big.NewInt(9), Properties: []byte{0, 0}, TokenMetaData: &esdtData.MetaData{Nonce: uint64(nonce)}}
				raw, err := a.Marshaller.Marshal(data)
				require.NoError(t, err)
				storageKey := bytes.Clone(key)
				if nonce != 0 {
					storageKey = append(storageKey, nonce)
				}
				require.NoError(t, user.AccountDataHandler().SaveKeyValue(storageKey, raw))
				require.NoError(t, user.AccountDataHandler().SaveKeyValue([]byte("sentinel"), []byte{1}))
				require.NoError(t, db.SaveAccount(user))
				input := &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: address, CallValue: big.NewInt(0), GasProvided: 100, Arguments: [][]byte{id, {1}}}, RecipientAddr: address}
				var burn vmcommon.BuiltinFunction
				if family == core.FungibleESDT {
					burn, err = builtInFunctions.NewESDTLocalBurnFunc(1, a.Marshaller, settings, roles, a.EnableEpochsHandler)
				} else {
					coordinator, e := sharding.NewMultiShardCoordinator(3, 1)
					require.NoError(t, e)
					storage, e := builtInFunctions.NewESDTDataStorage(builtInFunctions.ArgsNewESDTDataStorage{Accounts: db, GlobalSettingsHandler: settings, Marshalizer: a.Marshaller, EnableEpochsHandler: a.EnableEpochsHandler, ShardCoordinator: coordinator})
					require.NoError(t, e)
					burn, err = builtInFunctions.NewESDTNFTBurnFunc(1, storage, settings, roles)
					input.Arguments = [][]byte{id, {1}, {1}}
				}
				require.NoError(t, err)
				out, err := burn.ProcessBuiltinFunction(user, nil, input)
				if enabled {
					require.NoError(t, err)
					require.Equal(t, vmcommon.Ok, out.ReturnCode)
					require.Equal(t, uint64(99), out.GasRemaining)
				} else {
					require.ErrorIs(t, err, builtInFunctions.ErrActionNotAllowed)
					require.Nil(t, out)
				}
				stored, _, err := user.AccountDataHandler().RetrieveValue(storageKey)
				require.NoError(t, err)
				got := &esdtData.ESDigitalToken{}
				require.NoError(t, a.Marshaller.Unmarshal(got, stored))
				want := int64(9)
				if enabled {
					want = 8
				}
				require.Equal(t, big.NewInt(want), got.Value)
			})
		}
	}
}

// Native createNewToken saves first, then T19 unsetBurnRoleGlobally saves
// second (esdt.go L709-712/L1206-1227; drwaRegistration.go L147-162).
// The native mutation precedes the injected save error. Exact prestate root,
// OPEN intent and tentative outputs are independent rollback observations.
func TestQualDRWANativeRegistrationBurnForAllMetachainUnsetRollback(t *testing.T) {
	for _, family := range []string{core.FungibleESDT, core.NonFungibleESDTv2, core.SemiFungibleESDT, core.MetaESDT, core.DynamicNFTESDT, core.DynamicSFTESDT, core.DynamicMetaESDT} {
		t.Run(family, func(t *testing.T) {
			e, ctx, s, _, _, request := qualNativeRegistration(t)
			request.family, request.properties = []byte(family), nil
			flags, err := enablers.NewEnableEpochsHandler(config.EnableEpochs{ESDTMetadataContinuousCleanupEnableEpoch: 5, DynamicESDTEnableEpoch: 7}, &epochNotifier.EpochNotifierStub{})
			require.NoError(t, err)
			flags.EpochConfirmed(5, 0)
			e.enableEpochsHandler = flags
			f := qualCommittedIntent(t, s, request)
			before, err := s.RootHash()
			require.NoError(t, err)
			fault := errors.New("native metachain unset save after mutation")
			s.failAt, s.saveFault = 2, fault
			require.ErrorIs(t, e.registerDRWACommittedToken(f.owner, request, f.profile, f.bodyDigest), fault)
			require.Equal(t, 2, s.saves)
			after, err := s.RootHash()
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.Zero(t, s.JournalLen())
			require.Equal(t, qualNativeIntentFrame(f.intent, []byte("OPEN"), nil), qualNativeRegistrationValue(t, s, core.SystemAccountAddress, append([]byte("ELRONDDRWA@registration@intent@"), f.id...)))
			require.Empty(t, ctx.output)
			require.Empty(t, ctx.outputAccounts)
			require.Empty(t, ctx.logs)
			require.Empty(t, ctx.storageUpdate)
			_, outputs, err := f.boundary.Commit()
			require.NoError(t, err)
			require.Empty(t, outputs)
		})
	}
}
