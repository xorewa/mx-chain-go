package drwa

import (
	"bytes"
	"math"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/state/factory"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/trie"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	nativeBuiltins "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
)

// Native stores, native builtin effects and rollback. Header, CEB and
// authorization providers here are qualification fixtures only.
type qualOwnedSupplyWriter struct {
	setup         *qualLifecycleFixture
	reader        *setupLocalStateReader
	host          *qualLocalSetupHost
	db            *state.AccountsDB
	owner         *RollbackContainment
	args          nativeBuiltins.ArgsCreateBuiltInFunctionContainer
	origin, token []byte
	leafVersion   core.TrieNodeVersion
}

func qualOwnedSupplyNew(t *testing.T, family core.ESDTType) *qualOwnedSupplyWriter {
	t.Helper()
	lifecycle, setup, _ := qualSetupNew(t, uint32(family), true, true)
	require.NoError(t, qualSetupExecute(lifecycle, setup))
	roots, _, err := lifecycle.x.f.boundary.Commit()
	require.NoError(t, err)
	db := qualReopenSupplyAccounts(t, lifecycle, roots[0], nil)
	origin := bytes.Clone(lifecycle.h.fields.supplyOrigin)
	coord := lifecycle.r.coordinator
	args := routeBuiltinArgs(db, coord, origin)
	if nonceFamily(family) {
		args.EnableEpochsHandler = enableEpochsHandlerMock.NewEnableEpochsHandlerStub(
			nativeBuiltins.SaveToSystemAccountFlag, nativeBuiltins.SendAlwaysFlag, nativeBuiltins.ESDTNFTImprovementV1Flag,
			nativeBuiltins.EGLDInESDTMultiTransferFlag, nativeBuiltins.CheckTransferFlag, nativeBuiltins.CheckCorrectTokenIDForTransferRoleFlag,
			nativeBuiltins.DynamicEsdtFlag, nativeBuiltins.ValueLengthCheckFlag)
	}
	w := &qualOwnedSupplyWriter{setup: lifecycle, db: db, args: args, origin: origin,
		token: []byte("TOKEN-abcdef"), leafVersion: core.NotSpecified}
	account, err := db.GetExistingAccount(origin)
	require.NoError(t, err)
	roles := [][]byte{[]byte(core.ESDTRoleLocalMint), []byte(core.ESDTRoleLocalBurn)}
	if nonceFamily(family) {
		roles = [][]byte{[]byte(core.ESDTRoleNFTCreate), []byte(core.ESDTRoleNFTBurn), []byte(core.ESDTRoleNFTAddQuantity)}
	}
	raw, err := args.Marshalizer.Marshal(&esdt.ESDTRoles{Roles: roles})
	require.NoError(t, err)
	require.NoError(t, account.(vmcommon.UserAccountHandler).AccountDataHandler().SaveKeyValue(
		append([]byte(core.ProtectedKeyPrefix+core.ESDTRoleIdentifier+core.ESDTKeyIdentifier), w.token...), raw))
	require.NoError(t, db.SaveAccount(account))
	if nonceFamily(family) {
		creator, err := nativeBuiltins.NewBuiltInFunctionsCreator(args)
		require.NoError(t, err)
		require.NoError(t, creator.CreateBuiltInFunctionContainer())
		meta := creator.ESDTGlobalSettingsHandler().(vmcommon.GlobalMetadataHandler)
		require.NoError(t, meta.SetTokenType(append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), w.token...), uint32(family)))
	}
	return w
}

func qualReopenSupplyAccounts(t *testing.T, lifecycle *qualLifecycleFixture, root []byte, flags common.EnableEpochsHandler) *state.AccountsDB {
	t.Helper()
	cfg, _ := qualContainmentArgs(t, lifecycle.x.f.store.backing)
	var err error
	if flags != nil {
		cfg.Trie, err = trie.NewTrie(cfg.Trie.GetStorageManager(), cfg.Marshaller, cfg.Hasher, flags, 5)
		require.NoError(t, err)
		cfg.AccountFactory, err = factory.NewAccountCreator(factory.ArgsAccountCreator{
			Hasher: cfg.Hasher, Marshaller: cfg.Marshaller, EnableEpochsHandler: flags,
			StateAccessesCollector: cfg.StateAccessesCollector,
		})
		require.NoError(t, err)
	}
	cfg.ProtectedChildRoot, err = NewSupplyPositionRootDecoder(cfg.Marshaller, cfg.Hasher, 4096, 32)
	require.NoError(t, err)
	db, err := state.NewAccountsDB(cfg)
	require.NoError(t, err)
	require.NoError(t, db.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
	return db
}

func (w *qualOwnedSupplyWriter) begin(t *testing.T) {
	t.Helper()
	_, err := w.db.Commit()
	require.NoError(t, err)
	w.owner, err = NewRollbackContainment(w.db)
	require.NoError(t, err)
	hook, _ := qualT42Hook(t, w.db, w.args.ShardCoordinator.SelfId(), true)
	_, end := qualT42Install(t, hook, w.args.ShardCoordinator.SelfId(), 1)
	t.Cleanup(end)
	w.setup.context, err = hook.EvaluatedHeaderTimeContext()
	require.NoError(t, err)
	current, err := newCurrentLocalDependencies(w.db, w.args.Marshalizer, w.setup.r.current.codec.hasher, 4096, 10, w.setup.h)
	require.NoError(t, err)
	lifecycle, err := newCurrentLifecycleReader(current, w.owner, hook, w.args.ShardCoordinator)
	require.NoError(t, err)
	w.host = &qualLocalSetupHost{t: t, f: w.setup}
	w.reader, err = newSetupLocalStateReader(lifecycle, w.host, 32)
	require.NoError(t, err)
	w.refresh(t)
}

func (w *qualOwnedSupplyWriter) read(t *testing.T, key []byte) []byte {
	t.Helper()
	a, err := w.db.GetExistingAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	raw, _, err := a.(vmcommon.UserAccountHandler).AccountDataHandler().RetrieveValue(key)
	require.NoError(t, err)
	return bytes.Clone(raw)
}

func (w *qualOwnedSupplyWriter) refresh(t *testing.T) {
	t.Helper()
	sk, pk := qualSetupKeys()
	w.host.supply, w.host.positions = w.read(t, sk), w.read(t, pk)
}

func (w *qualOwnedSupplyWriter) input(name string, from, to []byte, args ...[]byte) *vmcommon.ContractCallInput {
	return &vmcommon.ContractCallInput{Function: name, RecipientAddr: to,
		VMInput: vmcommon.VMInput{CallerAddr: from, CallValue: big.NewInt(0), GasProvided: 20000, Arguments: args}}
}

func (w *qualOwnedSupplyWriter) supply(t *testing.T, input *vmcommon.ContractCallInput, nonce uint64, cap *big.Int) error {
	t.Helper()
	return w.owner.executeOwned(func(owner *rollbackOperation) ([]*vmcommon.VMOutput, error) {
		output, err := w.applySupply(t, owner, input, nonce, cap, nil)
		if err != nil {
			return nil, err
		}
		return []*vmcommon.VMOutput{output}, nil
	})
}

func (w *qualOwnedSupplyWriter) applySupply(t *testing.T, owner *rollbackOperation, input *vmcommon.ContractCallInput,
	nonce uint64, cap, nonceCap *big.Int) (*vmcommon.VMOutput, error) {
	t.Helper()
	op, err := newSupplyNativeOperation(w.args, input.Function)
	require.NoError(t, err)
	resolver := &routeOperationTestFixture{args: w.args}
	policy := &qualSupplyOperationPolicy{classify: func(string, []byte) (bool, error) { return true, nil },
		check: func(_ string, effect vmcommon.DRWASupplyEffect, _ *vmcommon.ContractCallInput) error {
			require.Equal(t, w.origin, effect.RoleAddress)
			if nonce == 0 {
				require.Zero(t, w.recordsSupply(t).accounting.nextSupplyNonce)
			}
			return nil
		}}
	output, err := op.executeOwned(owner, w.reader, w.setup.context, input, policy, resolver.resolve,
		supplyWriteBinding{token: w.token, cebHash: w.setup.hash, epoch: 1, actionNonce: nonce,
			cumulativeCap: cap, nonceCap: nonceCap, leafVersion: &w.leafVersion})
	if err != nil {
		require.Nil(t, output)
		return nil, err
	}
	require.Equal(t, vmcommon.Ok, output.ReturnCode)
	return output, nil
}

func (w *qualOwnedSupplyWriter) recordsSupply(t *testing.T) *initializedSupplyState {
	t.Helper()
	key, _ := qualSetupKeys()
	value, err := w.reader.records.decodeSupplyRecord(w.read(t, key))
	require.NoError(t, err)
	return value
}

func (w *qualOwnedSupplyWriter) positions(t *testing.T, version, total uint64) []byte {
	t.Helper()
	_, key := qualSetupKeys()
	raw := w.read(t, key)
	record, err := w.reader.records.decodePositionRecord(raw)
	require.NoError(t, err)
	require.Equal(t, version, record.version)
	require.Equal(t, total, record.quantity.Uint64())
	return raw
}

func TestQualDRWAP02NativeSupplyWaitsForLocalSetup(t *testing.T) {
	supplyKey, positionKey := qualSetupKeys()
	for _, tc := range []struct {
		name string
		key  []byte
	}{
		{name: "missing supply record", key: supplyKey},
		{name: "missing position record", key: positionKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := qualOwnedSupplyNew(t, core.SemiFungible)
			w.begin(t)
			exact := w.read(t, tc.key)
			require.NotEmpty(t, exact)
			store := &qualNativeStore{AccountsAdapter: w.db}
			qualRecordPut(t, store, tc.key, nil)
			require.Empty(t, w.read(t, tc.key))
			before, err := w.db.RootHash()
			require.NoError(t, err)
			before = bytes.Clone(before)
			journal := w.db.JournalLen()
			mint := w.input(core.BuiltInFunctionESDTNFTCreate, w.origin, w.origin, w.token,
				[]byte{5}, []byte("name"), nil, nil, nil, []byte("uri"))
			require.ErrorIs(t, w.supply(t, mint, 0, nil), errCurrentLocalDependency)
			after, err := w.db.RootHash()
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.Equal(t, journal, w.db.JournalLen())
			require.Zero(t, w.host.calls, "the local proof provider must not substitute for the missing record")
			require.Empty(t, w.owner.outputs)

			qualRecordPut(t, store, tc.key, exact)
			w.refresh(t)
			require.NoError(t, w.supply(t, mint, 0, nil))
			require.Equal(t, 1, w.host.calls)
			require.Len(t, w.owner.outputs, 1)
			require.Equal(t, [][]byte{{1}}, w.owner.outputs[0].ReturnData)
			supply := w.recordsSupply(t)
			require.Equal(t, uint64(1), supply.accounting.nextSupplyNonce)
			require.Equal(t, big.NewInt(5), supply.accounting.liveSupply)
			w.positions(t, 1, 5)
		})
	}
}

func TestQualDRWAOwnedSupplyWriteNativeNonceFamilies(t *testing.T) {
	frozen := qualStructuralV1Data(t)
	for _, family := range []core.ESDTType{core.NonFungibleV2, core.DynamicNFT, core.SemiFungible, core.MetaFungible, core.DynamicSFT, core.DynamicMeta} {
		t.Run(family.String(), func(t *testing.T) {
			w := qualOwnedSupplyNew(t, family)
			w.begin(t)
			supplyBefore, positionBefore := bytes.Clone(w.host.supply), bytes.Clone(w.host.positions)
			q, live, burned := byte(5), "quantity_live5", "quantity_burned5"
			if uniqueNonceFamily(family) {
				q, live, burned = 1, "unique_live", "unique_burned"
			}
			mint := w.input(core.BuiltInFunctionESDTNFTCreate, w.origin, w.origin, w.token, []byte{q}, []byte("name"), nil, nil, nil, []byte("uri"))
			require.NoError(t, w.supply(t, mint, 0, big.NewInt(int64(q))))
			w.refresh(t)
			issued := w.recordsSupply(t)
			require.Equal(t, uint64(1), issued.accounting.nextSupplyNonce)
			require.Equal(t, uint64(q), issued.accounting.cumulativeIssued.Uint64())
			require.Equal(t, uint64(q), issued.accounting.liveSupply.Uint64())
			require.Equal(t, qualA19Bytes(t, frozen.NativeNodes[live].Root), issued.nonceRoot)
			w.positions(t, 1, uint64(q))
			if !uniqueNonceFamily(family) {
				add := w.input(core.BuiltInFunctionESDTNFTAddQuantity, w.origin, w.origin, w.token, []byte{1}, []byte{2})
				require.ErrorIs(t, w.owner.executeOwned(func(owner *rollbackOperation) ([]*vmcommon.VMOutput, error) {
					_, err := w.applySupply(t, owner, add, 1, nil, big.NewInt(5))
					return nil, err
				}), errSupplyAccounting)
				sk, _ := qualSetupKeys()
				require.Equal(t, w.host.supply, w.read(t, sk))
				w.positions(t, 1, uint64(q))
			}
			burn := w.input(core.BuiltInFunctionESDTNFTBurn, w.origin, w.origin, w.token, []byte{1}, []byte{q})
			require.NoError(t, w.supply(t, burn, 1, big.NewInt(int64(q))))
			w.refresh(t)
			retained := w.recordsSupply(t)
			require.Equal(t, uint64(2), retained.accounting.nextSupplyNonce)
			require.Equal(t, uint64(q), retained.accounting.cumulativeIssued.Uint64())
			require.Zero(t, retained.accounting.liveSupply.Sign())
			require.Equal(t, qualA19Bytes(t, frozen.NativeNodes[burned].Root), retained.nonceRoot)
			w.positions(t, 2, 0)
			sk, _ := qualSetupKeys()
			liveRaw := w.read(t, sk)
			leaves, err := w.db.ReadProtectedChildLeaves(core.SystemAccountAddress, sk, liveRaw,
				[][]byte{qualA19Bytes(t, frozen.NativeNodes[burned].Key)})
			require.NoError(t, err)
			require.Equal(t, qualA19Bytes(t, frozen.NativeNodes[burned].Value), leaves[0].Value)
			require.NoError(t, w.owner.Abort())
			w.refresh(t)
			require.Equal(t, supplyBefore, w.host.supply)
			require.Equal(t, positionBefore, w.host.positions)
		})
	}
}

func TestQualDRWAOwnedSupplyWriteBurnDoesNotRefillNonceCap(t *testing.T) {
	nonceKey := qualA19Bytes(t, qualStructuralV1Data(t).NativeNodes["quantity_live5"].Key)
	for _, family := range []core.ESDTType{core.SemiFungible, core.MetaFungible, core.DynamicSFT, core.DynamicMeta} {
		t.Run(family.String(), func(t *testing.T) {
			w := qualOwnedSupplyNew(t, family)
			w.begin(t)
			mint := w.input(core.BuiltInFunctionESDTNFTCreate, w.origin, w.origin, w.token, []byte{5}, []byte("name"), nil, nil, nil, []byte("uri"))
			require.NoError(t, w.supply(t, mint, 0, nil))
			w.refresh(t)
			burn := w.input(core.BuiltInFunctionESDTNFTBurn, w.origin, w.origin, w.token, []byte{1}, []byte{2})
			require.NoError(t, w.supply(t, burn, 1, nil))
			w.refresh(t)

			supplyKey, positionKey := qualSetupKeys()
			check := func(action, issued, live uint64, expectedLeaf []byte) {
				t.Helper()
				record := w.recordsSupply(t)
				require.Equal(t, action, record.accounting.nextSupplyNonce)
				require.Equal(t, new(big.Int).SetUint64(issued), record.accounting.cumulativeIssued)
				require.Equal(t, new(big.Int).SetUint64(live), record.accounting.liveSupply)
				w.positions(t, action, live)
				leaves, err := w.db.ReadProtectedChildLeaves(core.SystemAccountAddress, supplyKey, w.host.supply, [][]byte{nonceKey})
				require.NoError(t, err)
				require.Len(t, leaves, 1)
				require.Equal(t, nonceKey, leaves[0].Key)
				require.Equal(t, expectedLeaf, leaves[0].Value)
			}
			check(2, 5, 3, []byte{0x0a, 1, 5, 0x0a, 1, 3})
			root, err := w.db.RootHash()
			require.NoError(t, err)
			root = bytes.Clone(root)
			journal, outputs := w.db.JournalLen(), len(w.owner.outputs)

			add := w.input(core.BuiltInFunctionESDTNFTAddQuantity, w.origin, w.origin, w.token, []byte{1}, []byte{2})
			apply := func(nonceCap int64) error {
				return w.owner.executeOwned(func(owner *rollbackOperation) ([]*vmcommon.VMOutput, error) {
					output, err := w.applySupply(t, owner, add, 2, nil, big.NewInt(nonceCap))
					if err != nil {
						return nil, err
					}
					return []*vmcommon.VMOutput{output}, nil
				})
			}
			require.ErrorIs(t, apply(5), errSupplyAccounting)
			require.Equal(t, journal, w.db.JournalLen())
			require.Len(t, w.owner.outputs, outputs)
			require.Equal(t, w.host.supply, w.read(t, supplyKey))
			require.Equal(t, w.host.positions, w.read(t, positionKey))
			actual, err := w.db.RootHash()
			require.NoError(t, err)
			require.Equal(t, root, actual)

			// The same native call and action nonce with a sufficient fixture cap
			// succeed, so neither the native checks nor the earlier refusal explain it.
			require.NoError(t, apply(7))
			w.refresh(t)
			check(3, 7, 5, []byte{0x0a, 1, 7, 0x0a, 1, 5})
		})
	}
}

func TestQualDRWAP19SupplyNoncesShareCurrentTokenState(t *testing.T) {
	// Use the two literal keys from the independent A19 multi-leaf case.
	keys := [][]byte{
		qualA19Bytes(t, "0a0c544f4b454e2d6162636465660a080000000000000001"),
		qualA19Bytes(t, "0a0c544f4b454e2d6162636465660a080000000000000002"),
	}
	for _, family := range []core.ESDTType{core.NonFungibleV2, core.DynamicNFT, core.SemiFungible, core.MetaFungible, core.DynamicSFT, core.DynamicMeta} {
		t.Run(family.String(), func(t *testing.T) {
			w := qualOwnedSupplyNew(t, family)
			w.begin(t)
			quantity := byte(5)
			expectedValues := [][]byte{{0x0a, 1, 5, 0x0a, 0}, {0x0a, 1, 5, 0x0a, 1, 5}}
			if uniqueNonceFamily(family) {
				quantity = 1
				expectedValues = [][]byte{{0}, {1}}
			}
			create := func(name string) *vmcommon.ContractCallInput {
				return w.input(core.BuiltInFunctionESDTNFTCreate, w.origin, w.origin,
					w.token, []byte{quantity}, []byte(name), nil, nil, nil, []byte("uri"))
			}
			require.NoError(t, w.supply(t, create("first"), 0, nil))
			w.refresh(t)
			supplyKey, positionKey := qualSetupKeys()
			assertUnchangedOn := func(want error, invoke func() error) {
				t.Helper()
				before, err := w.db.RootHash()
				require.NoError(t, err)
				before = bytes.Clone(before)
				journal, outputs := w.db.JournalLen(), len(w.owner.outputs)
				require.ErrorIs(t, invoke(), want)
				require.Equal(t, journal, w.db.JournalLen())
				require.Len(t, w.owner.outputs, outputs)
				require.Equal(t, w.host.supply, w.read(t, supplyKey))
				require.Equal(t, w.host.positions, w.read(t, positionKey))
				after, err := w.db.RootHash()
				require.NoError(t, err)
				require.Equal(t, before, after)
			}
			second := create("second")
			assertUnchangedOn(errCurrentLocalDependency, func() error {
				current := w.setup.hash
				w.setup.hash = bytes.Clone(current)
				w.setup.hash[0] ^= 1
				defer func() { w.setup.hash = current }()
				return w.supply(t, second, 1, nil)
			})
			require.NoError(t, w.supply(t, second, 1, nil))
			w.refresh(t)
			w.positions(t, 2, 2*uint64(quantity))

			burnFirst := w.input(core.BuiltInFunctionESDTNFTBurn, w.origin, w.origin, w.token, []byte{1}, []byte{quantity})
			assertUnchangedOn(errSupplyAccounting, func() error { return w.supply(t, burnFirst, 1, nil) })
			require.NoError(t, w.supply(t, burnFirst, 2, nil))
			w.refresh(t)
			supply := w.recordsSupply(t)
			require.Equal(t, uint64(3), supply.accounting.nextSupplyNonce)
			require.Equal(t, uint64(2)*uint64(quantity), supply.accounting.cumulativeIssued.Uint64())
			require.Equal(t, uint64(quantity), supply.accounting.liveSupply.Uint64())
			w.positions(t, 3, uint64(quantity))
			leaves, err := w.db.ReadProtectedChildLeaves(core.SystemAccountAddress, supplyKey, w.host.supply, keys)
			require.NoError(t, err)
			require.Len(t, leaves, len(keys))
			for i, leaf := range leaves {
				require.Equal(t, keys[i], leaf.Key)
				require.Equal(t, expectedValues[i], leaf.Value)
			}
			if !uniqueNonceFamily(family) {
				require.Equal(t, qualA19Bytes(t, "d971616d9149f9e2f1f57738616ea53224f3e3019fc500b35fe87c3c8f1d1999"), supply.nonceRoot)
			}
		})
	}
}

func TestQualDRWAP20SupplyAndPositionsSurviveNativeDataTrieMigration(t *testing.T) {
	w := qualOwnedSupplyNew(t, core.SemiFungible)
	ordinaryKey, ordinaryValue := []byte("ordinary-existing-leaf"), []byte("untouched")
	account, err := w.db.GetExistingAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	require.NoError(t, account.(state.UserAccountHandler).SaveKeyValue(ordinaryKey, ordinaryValue))
	require.NoError(t, w.db.SaveAccount(account))
	w.begin(t)

	mint := w.input(core.BuiltInFunctionESDTNFTCreate, w.origin, w.origin, w.token, []byte{5}, []byte("name"), nil, nil, nil, []byte("uri"))
	burn := w.input(core.BuiltInFunctionESDTNFTBurn, w.origin, w.origin, w.token, []byte{1}, []byte{2})
	require.NoError(t, w.supply(t, mint, 0, nil))
	w.refresh(t)
	require.NoError(t, w.supply(t, burn, 1, nil))
	roots, outputs, err := w.owner.Commit()
	require.NoError(t, err)
	require.Len(t, roots, 1)
	require.Len(t, outputs, 2)
	for _, output := range outputs {
		require.Equal(t, vmcommon.Ok, output.ReturnCode)
	}

	flags := w.args.EnableEpochsHandler.(*enableEpochsHandlerMock.EnableEpochsHandlerStub)
	flags.AddActiveFlags(common.AutoBalanceDataTriesFlag, nativeBuiltins.MigrateDataTrieFlag)
	old := qualReopenSupplyAccounts(t, w.setup, roots[0], flags)
	account, err = old.GetExistingAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	system := account.(state.UserAccountHandler)
	oldDataRoot, err := system.DataTrie().(common.Trie).RootHash()
	require.NoError(t, err)
	oldDataRoot = bytes.Clone(oldDataRoot)
	migrate, err := nativeBuiltins.NewMigrateDataTrieFunc(
		vmcommon.BuiltInCost{TrieLoadPerNode: 1, TrieStorePerNode: 1}, w.args.EnableEpochsHandler, old)
	require.NoError(t, err)
	require.True(t, migrate.IsActive())
	input := w.input(core.BuiltInFunctionMigrateDataTrie, core.SystemAccountAddress, core.SystemAccountAddress)
	out, err := migrate.ProcessBuiltinFunction(nil, account.(vmcommon.UserAccountHandler), input)
	require.NoError(t, err)
	require.Equal(t, vmcommon.Ok, out.ReturnCode)
	require.Less(t, out.GasRemaining, input.GasProvided, "migration must perform work")
	require.NoError(t, old.SaveAccount(system))
	migratedRoot, err := old.Commit()
	require.NoError(t, err)
	require.NotEqual(t, roots[0], migratedRoot)

	// Reopen both checkpoints from native backing bytes. Only the enclosing
	// account data trie changes representation, so both children keep their exact data.
	supplyKey, positionKey := qualSetupKeys()
	nonceKey := qualA19Bytes(t, qualStructuralV1Data(t).NativeNodes["quantity_live5"].Key)
	holderKey := qualRecordFrame(w.token, []byte{0, 0, 0, 0, 0, 0, 0, 1}, w.origin)
	var priorRecords [][]byte
	for i, root := range [][]byte{roots[0], migratedRoot} {
		w.db = qualReopenSupplyAccounts(t, w.setup, root, flags)
		account, err = w.db.GetExistingAccount(core.SystemAccountAddress)
		require.NoError(t, err)
		dataRoot, err := account.(state.UserAccountHandler).DataTrie().(common.Trie).RootHash()
		require.NoError(t, err)
		if i == 0 {
			require.Equal(t, oldDataRoot, dataRoot)
		} else {
			require.NotEqual(t, oldDataRoot, dataRoot)
		}
		supplyRaw, positionsRaw := w.read(t, supplyKey), w.positions(t, 2, 3)
		if i == 0 {
			priorRecords = [][]byte{supplyRaw, positionsRaw}
		} else {
			require.Equal(t, priorRecords, [][]byte{supplyRaw, positionsRaw})
		}
		supply := w.recordsSupply(t)
		require.Equal(t, uint64(2), supply.accounting.nextSupplyNonce)
		require.Equal(t, big.NewInt(5), supply.accounting.cumulativeIssued)
		require.Equal(t, big.NewInt(3), supply.accounting.liveSupply)
		require.Equal(t, ordinaryValue, w.read(t, ordinaryKey))
		nonce, err := w.db.ReadProtectedChildLeaves(core.SystemAccountAddress, supplyKey, supplyRaw, [][]byte{nonceKey})
		require.NoError(t, err)
		require.Equal(t, []core.TrieData{{Key: nonceKey, Value: []byte{0x0a, 1, 5, 0x0a, 1, 3}, Version: core.NotSpecified}}, nonce)
		position, err := w.db.ReadProtectedChildLeaves(core.SystemAccountAddress, positionKey, positionsRaw, [][]byte{holderKey})
		require.NoError(t, err)
		require.Equal(t, []core.TrieData{{Key: holderKey, Value: []byte{3}, Version: core.NotSpecified}}, position)
	}

	w.args.Accounts = w.db
	w.begin(t)
	require.ErrorIs(t, w.supply(t, burn, 1, nil), errSupplyAccounting)
	require.Zero(t, w.db.JournalLen())
	require.Empty(t, w.owner.outputs)
	require.Equal(t, priorRecords[0], w.read(t, supplyKey))
	require.Equal(t, priorRecords[1], w.read(t, positionKey))
	require.NoError(t, w.supply(t, burn, 2, nil), "native balance can still fund the same call with the current nonce")
	w.positions(t, 3, 1)
}

func TestQualDRWAOwnedSupplyWriteRollsBackPositionFailure(t *testing.T) {
	w := qualOwnedSupplyNew(t, core.Fungible)
	a, err := w.db.GetExistingAccount(w.origin)
	require.NoError(t, err)
	key := append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), w.token...)
	initial, err := w.args.Marshalizer.Marshal(&esdt.ESDigitalToken{Type: uint32(core.Fungible), Value: big.NewInt(5)})
	require.NoError(t, err)
	require.NoError(t, a.(vmcommon.UserAccountHandler).AccountDataHandler().SaveKeyValue(key, initial))
	require.NoError(t, w.db.SaveAccount(a))
	w.begin(t)
	priorSupply, priorPosition := bytes.Clone(w.host.supply), bytes.Clone(w.host.positions)
	root, err := w.db.RootHash()
	require.NoError(t, err)
	root = bytes.Clone(root)
	mint := w.input(core.BuiltInFunctionESDTLocalMint, w.origin, w.origin, w.token, []byte{5})
	require.ErrorIs(t, w.supply(t, mint, 0, nil), errSetupLocalState)
	actual, err := w.db.RootHash()
	require.NoError(t, err)
	require.Equal(t, root, actual)
	w.refresh(t)
	require.Equal(t, priorSupply, w.host.supply)
	require.Equal(t, priorPosition, w.host.positions)
	require.Empty(t, w.owner.outputs)
}

func TestQualDRWAOwnedSupplyWriteRollsBackStagedNonceChild(t *testing.T) {
	w := qualOwnedSupplyNew(t, core.SemiFungible)
	_, pk := qualSetupKeys()
	system, err := w.db.GetExistingAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	raw := w.read(t, pk)
	records := qualRootLeafCodec(t)
	position, err := records.decodePositionRecord(raw)
	require.NoError(t, err)
	position.version = math.MaxUint64
	raw, err = records.encodePositionRecord(position)
	require.NoError(t, err)
	require.NoError(t, system.(vmcommon.UserAccountHandler).AccountDataHandler().SaveKeyValue(pk, raw))
	require.NoError(t, w.db.SaveAccount(system))
	w.begin(t)
	before, err := w.db.RootHash()
	require.NoError(t, err)
	before = bytes.Clone(before)
	input := w.input(core.BuiltInFunctionESDTNFTCreate, w.origin, w.origin, w.token, []byte{5}, []byte("name"), nil, nil, nil, []byte("uri"))
	require.ErrorIs(t, w.supply(t, input, 0, nil), errSetupLocalState)
	after, err := w.db.RootHash()
	require.NoError(t, err)
	require.Equal(t, before, after)
	require.Zero(t, w.db.JournalLen())
	require.Empty(t, w.owner.outputs)
	sk, _ := qualSetupKeys()
	require.Equal(t, w.host.supply, w.read(t, sk))
	require.Equal(t, w.host.positions, w.read(t, pk))
	leaves, err := w.db.ReadProtectedChildLeaves(core.SystemAccountAddress, sk, w.host.supply,
		[][]byte{qualA19Bytes(t, qualStructuralV1Data(t).NativeNodes["quantity_live5"].Key)})
	require.NoError(t, err)
	require.Empty(t, leaves[0].Value)
}

func TestQualDRWAOwnedSupplyWriteRejectsSecondPositionJoin(t *testing.T) {
	w := qualOwnedSupplyNew(t, core.Fungible)
	w.begin(t)
	before, err := w.db.RootHash()
	require.NoError(t, err)
	before = bytes.Clone(before)
	input := w.input(core.BuiltInFunctionESDTLocalMint, w.origin, w.origin, w.token, []byte{5})
	err = w.owner.executeOwned(func(owner *rollbackOperation) ([]*vmcommon.VMOutput, error) {
		first, err := w.applySupply(t, owner, input, 0, nil, nil)
		require.NoError(t, err)
		w.refresh(t)
		second, err := w.applySupply(t, owner, input, 1, nil, nil)
		require.ErrorIs(t, err, errSetupLocalState)
		require.Nil(t, second)
		return []*vmcommon.VMOutput{first}, nil // A swallowed denial must still prevent publication.
	})
	require.ErrorIs(t, err, errSetupLocalState)
	after, err := w.db.RootHash()
	require.NoError(t, err)
	require.Equal(t, before, after)
	require.Empty(t, w.owner.outputs)
}

func TestQualP08NativeEffectsCannotStartAfterTerminalSeal(t *testing.T) {
	for _, scenario := range []string{"open-control", "terminal-seal", "lagging-open-replica"} {
		t.Run(scenario, func(t *testing.T) {
			w := qualOwnedSupplyNew(t, core.Fungible)
			other := bytes.Repeat([]byte{0x22}, len(w.origin))
			other[len(other)-1] = w.origin[len(w.origin)-1]
			account, err := w.db.LoadAccount(other)
			require.NoError(t, err)
			require.NoError(t, w.db.SaveAccount(account))
			w.begin(t)
			mint := w.input(core.BuiltInFunctionESDTLocalMint, w.origin, w.origin, w.token, []byte{5})
			require.NoError(t, w.supply(t, mint, 0, big.NewInt(5)))
			w.refresh(t)

			// Set independently framed local replica bytes. The actual frozen
			// canonical seal producer and all-shard ACK are separate inputs.
			lrc := append([]byte(lifecycleRecordPrefix), qualRecordFrame(w.token)...)
			local := &qualNativeStore{AccountsAdapter: w.db}
			phase := "OPEN"
			wantSupply, wantRoute := error(nil), error(nil)
			if scenario == "terminal-seal" {
				phase = "WIND_DOWN_SEALED"
				qualRecordPut(t, local, append([]byte(registrationActivationPrefix), w.token...),
					qualLifecycleParent(w.token, w.setup.x.f.owner.id, "WindDownDeny"))
				wantSupply, wantRoute = errSupplyAccounting, errSetupLocalState
			} else if scenario == "lagging-open-replica" {
				w.setup.h.faults["lifecycle"] = errLifecycleClosed
				wantSupply, wantRoute = errLifecycleClosed, errLifecycleClosed
			}
			qualRecordPut(t, local, lrc, qualRecordFrame(w.token, []byte{0, 0, 0, 0, 0, 0, 0, 1}, []byte(phase)))
			before, err := w.db.RootHash()
			require.NoError(t, err)
			before = bytes.Clone(before)
			journal, outputs := w.db.JournalLen(), len(w.owner.outputs)
			supply, positions := bytes.Clone(w.host.supply), bytes.Clone(w.host.positions)
			burn := w.input(core.BuiltInFunctionESDTLocalBurn, w.origin, w.origin, w.token, []byte{1})
			require.ErrorIs(t, w.supply(t, burn, 1, nil), wantSupply)
			w.refresh(t)

			input := w.input(core.BuiltInFunctionESDTTransfer, w.origin, other, w.token, []byte{1})
			op, err := newRouteNativeOperation(w.args, input.Function, func(vmcommon.AccountsAdapter) (vmcommon.PayableHandler, error) {
				return &routeOperationTestPayable{}, nil
			})
			require.NoError(t, err)
			resolver := &routeOperationTestFixture{args: w.args}
			err = w.owner.executeOwned(func(owner *rollbackOperation) ([]*vmcommon.VMOutput, error) {
				out, parsed, err := op.executeOwnedPositions(owner, w.reader, w.setup.context, input, &routeOperationTestGate{}, resolver.resolve,
					positionTransferBinding{token: w.token, cebHash: w.setup.hash, epoch: 1, maxLegs: 1, maxKeys: 2, leafVersion: &w.leafVersion})
				if err != nil {
					require.Nil(t, out)
					require.Nil(t, parsed)
					return nil, err
				}
				require.Equal(t, vmcommon.Ok, out.ReturnCode)
				return []*vmcommon.VMOutput{out}, nil
			})
			require.ErrorIs(t, err, wantRoute)
			after, err := w.db.RootHash()
			require.NoError(t, err)
			if scenario == "open-control" {
				require.NotEqual(t, before, after)
				require.Len(t, w.owner.outputs, outputs+2)
				require.Equal(t, uint64(4), w.recordsSupply(t).accounting.liveSupply.Uint64())
				return
			}
			require.Equal(t, before, after)
			require.Equal(t, journal, w.db.JournalLen())
			require.Len(t, w.owner.outputs, outputs)
			sk, pk := qualSetupKeys()
			require.Equal(t, supply, w.read(t, sk))
			require.Equal(t, positions, w.read(t, pk))
		})
	}
}

func TestQualDRWAOwnedPositionWriteRepeatedLegsAndNoOp(t *testing.T) {
	w := qualOwnedSupplyNew(t, core.Fungible)
	other := bytes.Repeat([]byte{0x22}, len(w.origin))
	other[len(other)-1] = w.origin[len(w.origin)-1]
	ac, err := w.db.LoadAccount(other)
	require.NoError(t, err)
	require.NoError(t, w.db.SaveAccount(ac))
	system, err := w.db.GetExistingAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	lrc := append([]byte(lifecycleRecordPrefix), qualRecordFrame(w.token)...)
	require.NoError(t, system.(vmcommon.UserAccountHandler).AccountDataHandler().SaveKeyValue(lrc, qualRecordFrame(w.token, []byte{0, 0, 0, 0, 0, 0, 0, 1}, []byte("OPEN"))))
	require.NoError(t, w.db.SaveAccount(system))
	w.begin(t)
	mint := w.input(core.BuiltInFunctionESDTLocalMint, w.origin, w.origin, w.token, []byte{5})
	require.NoError(t, w.supply(t, mint, 0, big.NewInt(5)))
	w.refresh(t)
	supplyRaw := bytes.Clone(w.host.supply)
	transfer := func(input *vmcommon.ContractCallInput, legs int) {
		t.Helper()
		op, err := newRouteNativeOperation(w.args, input.Function, func(vmcommon.AccountsAdapter) (vmcommon.PayableHandler, error) {
			return &routeOperationTestPayable{}, nil
		})
		require.NoError(t, err)
		resolver := &routeOperationTestFixture{args: w.args}
		err = w.owner.executeOwned(func(owner *rollbackOperation) ([]*vmcommon.VMOutput, error) {
			out, parsed, e := op.executeOwnedPositions(owner, w.reader, w.setup.context, input, &routeOperationTestGate{}, resolver.resolve,
				positionTransferBinding{token: w.token, cebHash: w.setup.hash, epoch: 1, maxLegs: 2, maxKeys: 2, leafVersion: &w.leafVersion})
			if e != nil {
				return nil, e
			}
			require.Len(t, parsed.ESDTTransfers, legs)
			return []*vmcommon.VMOutput{out}, nil
		})
		require.NoError(t, err)
		w.refresh(t)
		require.Equal(t, supplyRaw, w.host.supply)
	}
	transfer(w.input(core.BuiltInFunctionMultiESDTNFTTransfer, w.origin, w.origin,
		other, []byte{2}, w.token, nil, []byte{2}, w.token, nil, []byte{3}), 2)
	pos := w.positions(t, 2, 5)
	committedPosition, err := w.reader.records.decodePositionRecord(pos)
	require.NoError(t, err)
	positionKey, err := w.reader.records.positionKey(w.token, core.Fungible, 0, other)
	require.NoError(t, err)
	journal := w.db.JournalLen()
	require.NoError(t, w.owner.executeOwned(func(owner *rollbackOperation) ([]*vmcommon.VMOutput, error) {
		return nil, owner.withWrite(w.owner, w.db, func() error {
			return w.reader.records.writePositionMap(w.db, localSetupState{positions: committedPosition, positionRaw: pos},
				[]positionLeafChange{{key: positionKey, before: []byte{5}, final: []byte{5}}}, 1, &w.leafVersion)
		})
	}))
	require.Equal(t, journal, w.db.JournalLen())
	transfer(w.input(core.BuiltInFunctionESDTTransfer, other, other, w.token, []byte{2}), 1)
	require.Equal(t, pos, w.positions(t, 2, 5))
	transfer(w.input(core.BuiltInFunctionESDTTransfer, other, w.origin, w.token, []byte{2}), 1)
	w.positions(t, 3, 5)
}

func TestQualDRWAP15LocalMultiNonceBatchPreservesOrderAndPositions(t *testing.T) {
	w := qualOwnedSupplyNew(t, core.SemiFungible)
	other := bytes.Repeat([]byte{0x22}, len(w.origin))
	other[len(other)-1] = w.origin[len(w.origin)-1]
	recipient, err := w.db.LoadAccount(other)
	require.NoError(t, err)
	require.NoError(t, w.db.SaveAccount(recipient))
	lrc := append([]byte(lifecycleRecordPrefix), qualRecordFrame(w.token)...)
	qualRecordPut(t, &qualNativeStore{AccountsAdapter: w.db}, lrc,
		qualRecordFrame(w.token, []byte{0, 0, 0, 0, 0, 0, 0, 1}, []byte("OPEN")))
	w.begin(t)
	mint := w.input(core.BuiltInFunctionESDTNFTCreate, w.origin, w.origin, w.token, []byte{5}, []byte("name"), nil, nil, nil, []byte("uri"))
	require.NoError(t, w.supply(t, mint, 0, nil))
	w.refresh(t)
	require.NoError(t, w.supply(t, mint, 1, nil))
	w.refresh(t)
	supplyKey, positionKey := qualSetupKeys()
	supplyBefore := w.read(t, supplyKey)
	positionBefore := w.positions(t, 2, 10)
	root, err := w.db.RootHash()
	require.NoError(t, err)
	root = bytes.Clone(root)
	journal, outputs := w.db.JournalLen(), len(w.owner.outputs)
	transfer := func(lastQuantity byte) (*vmcommon.VMOutput, *vmcommon.ParsedESDTTransfers, error) {
		t.Helper()
		input := w.input(core.BuiltInFunctionMultiESDTNFTTransfer, w.origin, w.origin,
			other, []byte{2}, w.token, []byte{2}, []byte{2}, w.token, []byte{1}, []byte{lastQuantity})
		op, err := newRouteNativeOperation(w.args, input.Function, func(vmcommon.AccountsAdapter) (vmcommon.PayableHandler, error) {
			return &routeOperationTestPayable{}, nil
		})
		require.NoError(t, err)
		resolver := &routeOperationTestFixture{args: w.args}
		var output *vmcommon.VMOutput
		var parsed *vmcommon.ParsedESDTTransfers
		err = w.owner.executeOwned(func(owner *rollbackOperation) ([]*vmcommon.VMOutput, error) {
			var runErr error
			output, parsed, runErr = op.executeOwnedPositions(owner, w.reader, w.setup.context, input, &routeOperationTestGate{}, resolver.resolve,
				positionTransferBinding{token: w.token, cebHash: w.setup.hash, epoch: 1, maxLegs: 2, maxKeys: 4, leafVersion: &w.leafVersion})
			if runErr != nil {
				return nil, runErr
			}
			return []*vmcommon.VMOutput{output}, nil
		})
		return output, parsed, err
	}

	out, parsed, err := transfer(6)
	require.ErrorIs(t, err, errSetupLocalState)
	require.Nil(t, out)
	require.Nil(t, parsed)
	after, err := w.db.RootHash()
	require.NoError(t, err)
	require.Equal(t, root, after)
	require.Equal(t, journal, w.db.JournalLen())
	require.Len(t, w.owner.outputs, outputs)
	require.Equal(t, positionBefore, w.read(t, positionKey))
	require.Equal(t, supplyBefore, w.read(t, supplyKey))

	out, parsed, err = transfer(3)
	require.NoError(t, err)
	require.Equal(t, []*vmcommon.ESDTTransfer{
		{ESDTTokenName: w.token, ESDTTokenNonce: 2, ESDTTokenType: uint32(core.SemiFungible), ESDTValue: big.NewInt(2)},
		{ESDTTokenName: w.token, ESDTTokenNonce: 1, ESDTTokenType: uint32(core.SemiFungible), ESDTValue: big.NewInt(3)},
	}, parsed.ESDTTransfers)
	require.Equal(t, vmcommon.Ok, out.ReturnCode)
	require.Equal(t, uint64(19986), out.GasRemaining)
	require.Empty(t, out.OutputAccounts)
	require.Len(t, out.Logs, 2)
	require.Equal(t, [][]byte{w.token, {2}, {2}, other}, out.Logs[0].Topics)
	require.Equal(t, [][]byte{w.token, {1}, {3}, other}, out.Logs[1].Topics)
	require.Equal(t, supplyBefore, w.read(t, supplyKey))
	positions := w.positions(t, 3, 10)
	keys := [][]byte{
		qualRecordFrame(w.token, []byte{0, 0, 0, 0, 0, 0, 0, 1}, w.origin),
		qualRecordFrame(w.token, []byte{0, 0, 0, 0, 0, 0, 0, 1}, other),
		qualRecordFrame(w.token, []byte{0, 0, 0, 0, 0, 0, 0, 2}, w.origin),
		qualRecordFrame(w.token, []byte{0, 0, 0, 0, 0, 0, 0, 2}, other),
	}
	leaves, err := w.db.ReadProtectedChildLeaves(core.SystemAccountAddress, positionKey, positions, keys)
	require.NoError(t, err)
	require.Equal(t, []core.TrieData{
		{Key: keys[0], Value: []byte{2}, Version: core.NotSpecified},
		{Key: keys[1], Value: []byte{3}, Version: core.NotSpecified},
		{Key: keys[2], Value: []byte{3}, Version: core.NotSpecified},
		{Key: keys[3], Value: []byte{2}, Version: core.NotSpecified},
	}, leaves)
}

func TestQualDRWAP21LocalSFTAttributesFollowNativeSystemAccount(t *testing.T) {
	w := qualOwnedSupplyNew(t, core.SemiFungible)
	other := bytes.Repeat([]byte{0x22}, len(w.origin))
	other[len(other)-1] = w.origin[len(w.origin)-1]
	recipient, err := w.db.LoadAccount(other)
	require.NoError(t, err)
	require.NoError(t, w.db.SaveAccount(recipient))
	origin, err := w.db.GetExistingAccount(w.origin)
	require.NoError(t, err)
	roleKey := append([]byte(core.ProtectedKeyPrefix+core.ESDTRoleIdentifier+core.ESDTKeyIdentifier), w.token...)
	originData := origin.(vmcommon.UserAccountHandler).AccountDataHandler()
	roleRaw, _, err := originData.RetrieveValue(roleKey)
	require.NoError(t, err)
	roles := &esdt.ESDTRoles{}
	require.NoError(t, w.args.Marshalizer.Unmarshal(roles, roleRaw))
	roles.Roles = append(roles.Roles, []byte(core.ESDTRoleNFTUpdateAttributes))
	roleRaw, err = w.args.Marshalizer.Marshal(roles)
	require.NoError(t, err)
	require.NoError(t, originData.SaveKeyValue(roleKey, roleRaw))
	require.NoError(t, w.db.SaveAccount(origin))
	lrc := append([]byte(lifecycleRecordPrefix), qualRecordFrame(w.token)...)
	qualRecordPut(t, &qualNativeStore{AccountsAdapter: w.db}, lrc,
		qualRecordFrame(w.token, []byte{0, 0, 0, 0, 0, 0, 0, 1}, []byte("OPEN")))
	w.begin(t)

	initial, sibling := []byte("initial"), []byte("sibling")
	for i, attributes := range [][]byte{initial, sibling} {
		mint := w.input(core.BuiltInFunctionESDTNFTCreate, w.origin, w.origin,
			w.token, []byte{5}, []byte("name"), nil, nil, attributes, []byte("uri"))
		require.NoError(t, w.supply(t, mint, uint64(i), nil))
		w.refresh(t)
	}
	transfer := w.input(core.BuiltInFunctionMultiESDTNFTTransfer, w.origin, w.origin, other, []byte{1}, w.token, []byte{1}, []byte{2})
	op, err := newRouteNativeOperation(w.args, transfer.Function, func(vmcommon.AccountsAdapter) (vmcommon.PayableHandler, error) {
		return &routeOperationTestPayable{}, nil
	})
	require.NoError(t, err)
	resolver := &routeOperationTestFixture{args: w.args}
	require.NoError(t, w.owner.executeOwned(func(owner *rollbackOperation) ([]*vmcommon.VMOutput, error) {
		out, _, runErr := op.executeOwnedPositions(owner, w.reader, w.setup.context, transfer, &routeOperationTestGate{}, resolver.resolve,
			positionTransferBinding{token: w.token, cebHash: w.setup.hash, epoch: 1, maxLegs: 1, maxKeys: 2, leafVersion: &w.leafVersion})
		if runErr != nil {
			return nil, runErr
		}
		require.Equal(t, vmcommon.Ok, out.ReturnCode)
		return []*vmcommon.VMOutput{out}, nil
	}))
	_, _, err = w.owner.Commit()
	require.NoError(t, err)

	// Exercise the pinned native role and read path in one shard. This fixture
	// provisions no production DRWA metadata authority or cross-shard propagation.
	creator, err := nativeBuiltins.NewBuiltInFunctionsCreator(w.args)
	require.NoError(t, err)
	require.NoError(t, creator.CreateBuiltInFunctionContainer())
	storage := creator.NFTStorageHandler()
	tokenKey := append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), w.token...)
	firstKey, secondKey := append(bytes.Clone(tokenKey), 1), append(bytes.Clone(tokenKey), 2)
	readHolder := func(address []byte, quantity int64, wantAttributes []byte) []byte {
		t.Helper()
		account, err := w.db.GetExistingAccount(address)
		require.NoError(t, err)
		holder := account.(vmcommon.UserAccountHandler)
		raw, _, err := holder.AccountDataHandler().RetrieveValue(firstKey)
		require.NoError(t, err)
		var local esdt.ESDigitalToken
		require.NoError(t, w.args.Marshalizer.Unmarshal(&local, raw))
		require.Equal(t, big.NewInt(quantity), local.Value)
		require.Nil(t, local.TokenMetaData)
		current, missing, err := storage.GetESDTNFTTokenOnDestination(holder, tokenKey, 1)
		require.NoError(t, err)
		require.False(t, missing)
		require.Equal(t, big.NewInt(quantity), current.Value)
		require.NotNil(t, current.TokenMetaData)
		require.Equal(t, wantAttributes, current.TokenMetaData.Attributes)
		return bytes.Clone(raw)
	}
	originBefore := readHolder(w.origin, 3, initial)
	recipientBefore := readHolder(other, 2, initial)
	firstBefore, siblingBefore := w.read(t, firstKey), w.read(t, secondKey)
	var second esdt.ESDigitalToken
	require.NoError(t, w.args.Marshalizer.Unmarshal(&second, siblingBefore))
	require.NotNil(t, second.TokenMetaData)
	require.Equal(t, sibling, second.TokenMetaData.Attributes)
	supplyKey, positionKey := qualSetupKeys()
	supplyBefore, positionsBefore := w.read(t, supplyKey), w.positions(t, 3, 10)

	updated := []byte("updated")
	input := w.input(core.BuiltInFunctionESDTNFTUpdateAttributes, w.origin, w.origin, w.token, []byte{1}, updated)
	builtin, err := creator.BuiltInFunctionContainer().Get(input.Function)
	require.NoError(t, err)
	hook, _ := qualT42Hook(t, w.db, w.args.ShardCoordinator.SelfId(), false)
	require.NoError(t, hook.GetBuiltinFunctionsContainer().Add(input.Function, builtin))
	out, err := hook.ProcessBuiltInFunction(input)
	require.NoError(t, err)
	require.Equal(t, vmcommon.Ok, out.ReturnCode)
	require.Equal(t, uint64(19944), out.GasRemaining)
	var first esdt.ESDigitalToken
	firstAfter := w.read(t, firstKey)
	require.NotEqual(t, firstBefore, firstAfter)
	require.NoError(t, w.args.Marshalizer.Unmarshal(&first, firstAfter))
	require.NotNil(t, first.TokenMetaData)
	require.Equal(t, updated, first.TokenMetaData.Attributes)
	require.Equal(t, originBefore, readHolder(w.origin, 3, updated))
	require.Equal(t, recipientBefore, readHolder(other, 2, updated))
	require.Equal(t, siblingBefore, w.read(t, secondKey))
	require.Equal(t, supplyBefore, w.read(t, supplyKey))
	require.Equal(t, positionsBefore, w.read(t, positionKey))
}
