package block

import (
	"bytes"
	"fmt"
	"testing"

	coreBlock "github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/state/accounts"
	stateDisabled "github.com/multiversx/mx-chain-go/state/disabled"
	"github.com/multiversx/mx-chain-go/state/factory"
	pruningDisabled "github.com/multiversx/mx-chain-go/state/storagePruningManager/disabled"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/stretchr/testify/require"
)

// NON-NORMATIVE AR-01/G3 main-trie -> account -> data-trie item reader.
// Account address, ACK key, byte budget and epoch mode are fixture inputs, not
// a DRWA namespace, profile, canonical codec, system-account selection or finality
// design. Native AccountsDB/factory/trackable-data-trie interpret committed bytes.
// The backing store is MemDbMock; fresh readers prove memory-store reconstruction,
// not disk restart, crash durability, pruning, consensus or canonical reorg.
type qualAccountItemWitness struct {
	main        qualDomainItemWitness
	itemKey     []byte
	dataNodes   [][]byte
	autoBalance bool
}

func qualAccountDB(t *testing.T, db *testscommon.MemDbMock, autoBalance bool) (*state.AccountsDB, common.Trie) {
	t.Helper()
	tr := qualItemTrie(t, db)
	flags := enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
	if autoBalance {
		flags.AddActiveFlags(common.AutoBalanceDataTriesFlag)
	}
	collector := stateDisabled.NewDisabledStateAccessesCollector()
	f, err := factory.NewAccountCreator(factory.ArgsAccountCreator{
		Hasher: blake2b.NewBlake2b(), Marshaller: &marshal.GogoProtoMarshalizer{},
		EnableEpochsHandler: flags, StateAccessesCollector: collector,
	})
	require.NoError(t, err)
	adb, err := state.NewAccountsDB(state.ArgsAccountsDB{
		Trie: tr, Hasher: blake2b.NewBlake2b(), Marshaller: &marshal.GogoProtoMarshalizer{},
		AccountFactory: f, StateAccessesCollector: collector,
		StoragePruningManager: pruningDisabled.NewDisabledStoragePruningManager(),
		SnapshotsManager:      stateDisabled.NewDisabledSnapshotsManager(),
		AddressConverter:      &testscommon.PubkeyConverterMock{},
	})
	require.NoError(t, err)
	return adb, tr
}

func qualReadAccountItem(t *testing.T, w qualAccountItemWitness) ([]byte, error) {
	t.Helper()
	accountBytes, err := qualImportResultItem(t, w.main.hHash, w.main.h, w.main.s,
		w.main.key, w.main.nodes, w.main.shard, w.main.limit)
	if err != nil {
		return nil, err
	}
	account := &accounts.UserAccountData{}
	if (&marshal.GogoProtoMarshalizer{}).Unmarshal(account, accountBytes) != nil ||
		!bytes.Equal(account.Address, w.main.key) || len(account.RootHash) == 0 {
		return nil, errQualAckRejected
	}
	used := 0
	for _, nodes := range [][][]byte{w.main.nodes, w.dataNodes} {
		if len(nodes) == 0 {
			return nil, errQualAckRejected
		}
		for _, node := range nodes {
			if len(node) == 0 || used > w.main.limit || len(node) > w.main.limit-used {
				return nil, errQualAckRejected
			}
			used += len(node)
		}
	}
	db := testscommon.NewMemDbMock()
	adb, tr := qualAccountDB(t, db, w.autoBalance)
	valid, err := tr.VerifyProof(account.RootHash, w.itemKey, w.dataNodes)
	if err != nil || !valid {
		return nil, errQualAckRejected
	}
	// Only proof-node bytes enter this fresh content-addressed store. The API's
	// parallel value or caller-supplied hash-to-node mapping is never trusted.
	for _, nodes := range [][][]byte{w.main.nodes, w.dataNodes} {
		for _, node := range nodes {
			if err = db.Put(blake2b.NewBlake2b().Compute(string(node)), bytes.Clone(node)); err != nil {
				return nil, err
			}
		}
	}
	h := &coreBlock.HeaderV3{}
	if (&marshal.GogoProtoMarshalizer{}).Unmarshal(h, w.main.h) != nil || len(h.ExecutionResults) != 1 {
		return nil, errQualAckRejected
	}
	if err = adb.RecreateTrie(holders.NewDefaultRootHashesHolder(h.ExecutionResults[0].BaseExecutionResult.RootHash)); err != nil {
		return nil, err
	}
	a, err := adb.GetExistingAccount(w.main.key)
	if err != nil {
		return nil, err
	}
	user, ok := a.(state.UserAccountHandler)
	if !ok {
		return nil, errQualAckRejected
	}
	value, _, err := user.RetrieveValue(w.itemKey)
	if err != nil || len(value) == 0 {
		return nil, errQualAckRejected
	}
	return value, nil
}

func qualObserveAccountItem(t *testing.T, m *qualConvergenceModel, e qualApplicationEvidence,
	expectedAccount, domain, body []byte, w qualAccountItemWitness) error {
	t.Helper()
	// Expected authoritative locus is a fixture dependency, never an address
	// inferred from a submitted proof. Native result and existing G3/domain
	// predicates precede the model's only progress writer.
	if !bytes.Equal(w.main.key, expectedAccount) || !bytes.Equal(w.itemKey, qualDomainAckKey(e.ack)) || !qualNativeResultMatches(e, w.main) {
		return errQualAckRejected
	}
	value, err := qualReadAccountItem(t, w)
	if err != nil {
		return err
	}
	if !qualDomainValueMatches(m, e, domain, body, value, w.main.shard) {
		return errQualAckRejected
	}
	return m.observe(e)
}

func qualAccountItemFixture(t *testing.T, value []byte, shard uint32, key []byte, autoBalance bool,
	address []byte) (qualAccountItemWitness, *state.AccountsDB, common.Trie, *testscommon.MemDbMock) {
	t.Helper()
	db := testscommon.NewMemDbMock()
	adb, tr := qualAccountDB(t, db, autoBalance)
	for _, addr := range [][]byte{address, bytes.Repeat([]byte{2}, 32)} {
		a, err := adb.LoadAccount(addr)
		require.NoError(t, err)
		user := a.(state.UserAccountHandler)
		require.NoError(t, user.SaveKeyValue(bytes.Clone(key), bytes.Clone(value)))
		require.NoError(t, user.SaveKeyValue([]byte("fixture/unrelated"), []byte("preserved")))
		require.NoError(t, adb.SaveAccount(user))
	}
	root, err := adb.Commit()
	require.NoError(t, err)
	w := qualDomainItemProof(t, value, shard, address)
	h := &coreBlock.HeaderV3{}
	mar := &marshal.GogoProtoMarshalizer{}
	require.NoError(t, mar.Unmarshal(h, w.h))
	h.ExecutionResults[0].BaseExecutionResult.RootHash = root
	w.h, err = mar.Marshal(h)
	require.NoError(t, err)
	w.hHash = blake2b.NewBlake2b().Compute(string(w.h))
	w.nodes, _, err = tr.GetProof(address)
	require.NoError(t, err)
	a, err := adb.GetExistingAccount(address)
	require.NoError(t, err)
	physicalKey := bytes.Clone(key)
	if autoBalance {
		physicalKey = blake2b.NewBlake2b().Compute(string(key))
	}
	dataProof, _, err := a.(state.UserAccountHandler).DataTrie().(common.Trie).GetProof(physicalKey)
	require.NoError(t, err)
	w.limit = 0
	for _, nodes := range [][][]byte{w.nodes, dataProof} {
		for _, node := range nodes {
			w.limit += len(node)
		}
	}
	return qualAccountItemWitness{main: w, itemKey: key, dataNodes: dataProof, autoBalance: autoBalance}, adb, tr, db
}

func TestQualDRWAAccountItemImport(t *testing.T) {
	address := bytes.Repeat([]byte{1}, 32)
	for _, auto := range []bool{false, true} {
		for shard := uint32(0); shard < 3; shard++ {
			for _, name := range []string{"valid", "other_account_same_item", "other_data_root", "missing_account_proof", "missing_data_proof",
				"corrupt_account_proof", "corrupt_data_proof", "reordered_data_proof", "wrong_item_key", "wrong_ack_context",
				"foreign_domain", "wrong_action_id", "wrong_digest", "over_budget", "malformed_account", "account_address_mismatch", "empty_data_root"} {
				t.Run(fmt.Sprintf("auto_%t/shard_%d/%s", auto, shard, name), func(t *testing.T) {
					m, evidence := qualDomainConvergenceFixture(t)
					other := (shard + 1) % 3
					require.NoError(t, m.observe(evidence[other]))
					e := evidence[shard]
					domain, body := qualDomainHex(t, qualDomainKAT), qualDomainHex(t, qualDomainBodyHex)
					value := append(bytes.Clone(domain), qualDomainHex(t, qualDomainActionKAT)...)
					value = append(value, []byte(e.ack.actionDigest)...)
					itemKey := qualDomainAckKey(e.ack)
					switch name {
					case "foreign_domain":
						value[0] ^= 1
					case "wrong_action_id":
						value[32] ^= 1
					case "wrong_digest":
						value[len(value)-1] ^= 1
					case "wrong_ack_context":
						ack := e.ack
						ack.binding.phase = "OTHER_PHASE"
						itemKey = qualDomainAckKey(ack)
					}
					w, adb, tr, _ := qualAccountItemFixture(t, value, shard, itemKey, auto, address)
					setBudget := func() {
						w.main.limit = 0
						for _, nodes := range [][][]byte{w.main.nodes, w.dataNodes} {
							for _, node := range nodes {
								w.main.limit += len(node)
							}
						}
					}
					replaceAccountProof := func() {
						var err error
						w.main.nodes, _, err = tr.GetProof(w.main.key)
						require.NoError(t, err)
						root, err := tr.RootHash()
						require.NoError(t, err)
						h := &coreBlock.HeaderV3{}
						mar := &marshal.GogoProtoMarshalizer{}
						require.NoError(t, mar.Unmarshal(h, w.main.h))
						h.ExecutionResults[0].BaseExecutionResult.RootHash = root
						w.main.h, err = mar.Marshal(h)
						require.NoError(t, err)
						w.main.hHash = blake2b.NewBlake2b().Compute(string(w.main.h))
						setBudget()
					}
					switch name {
					case "other_account_same_item", "other_data_root":
						a, err := adb.GetExistingAccount(bytes.Repeat([]byte{2}, 32))
						require.NoError(t, err)
						physicalKey := bytes.Clone(w.itemKey)
						if auto {
							physicalKey = blake2b.NewBlake2b().Compute(string(w.itemKey))
						}
						w.dataNodes, _, err = a.(state.UserAccountHandler).DataTrie().(common.Trie).GetProof(physicalKey)
						require.NoError(t, err)
						if name == "other_account_same_item" {
							w.main.key = bytes.Repeat([]byte{2}, 32)
							replaceAccountProof()
						}
						setBudget()
					case "missing_account_proof":
						w.main.nodes = nil
					case "missing_data_proof":
						w.dataNodes = nil
					case "corrupt_account_proof":
						w.main.nodes[0][0] ^= 1
					case "corrupt_data_proof":
						w.dataNodes[0][0] ^= 1
					case "reordered_data_proof":
						require.Greater(t, len(w.dataNodes), 1)
						w.dataNodes[0], w.dataNodes[len(w.dataNodes)-1] = w.dataNodes[len(w.dataNodes)-1], w.dataNodes[0]
					case "wrong_item_key":
						w.itemKey = []byte("another-item")
					case "over_budget":
						w.main.limit--
					case "malformed_account", "account_address_mismatch", "empty_data_root":
						raw, _, err := tr.Get(address)
						require.NoError(t, err)
						if name == "malformed_account" {
							raw = []byte{0xff}
						} else {
							data := &accounts.UserAccountData{}
							mar := &marshal.GogoProtoMarshalizer{}
							require.NoError(t, mar.Unmarshal(data, raw))
							if name == "account_address_mismatch" {
								data.Address = bytes.Repeat([]byte{2}, 32)
							} else {
								data.RootHash = nil
							}
							raw, err = mar.Marshal(data)
							require.NoError(t, err)
						}
						require.NoError(t, tr.Update(address, raw))
						replaceAccountProof()
					}
					// Candidate native result identities are trusted fixture inputs. This
					// prevents the new guards from being masked by a stale model root/H.
					e = qualBindDomainResultFixture(t, m, e, w.main)
					if name == "other_account_same_item" || name == "wrong_ack_context" || name == "foreign_domain" || name == "wrong_action_id" || name == "wrong_digest" {
						actual, err := qualReadAccountItem(t, w)
						require.NoError(t, err)
						require.Equal(t, value, actual)
					}
					err := qualObserveAccountItem(t, m, e, address, domain, body, w)
					if name == "valid" {
						require.NoError(t, err)
						require.NoError(t, qualObserveAccountItem(t, m, e, address, domain, body, w))
					} else {
						require.Error(t, err)
						require.Equal(t, map[uint32]bool{other: true}, m.acknowledged)
						// A denial leaves progress available to a fresh valid proof. This is
						// a retry control, not native durable bitmap persistence.
						good := append(bytes.Clone(domain), qualDomainHex(t, qualDomainActionKAT)...)
						good = append(good, []byte(e.ack.actionDigest)...)
						valid, _, _, _ := qualAccountItemFixture(t, good, shard, qualDomainAckKey(e.ack), auto, address)
						e = qualBindDomainResultFixture(t, m, e, valid.main)
						require.NoError(t, qualObserveAccountItem(t, m, e, address, domain, body, valid))
					}
					require.Equal(t, map[uint32]bool{other: true, shard: true}, m.acknowledged)
					require.False(t, m.complete())
				})
			}
		}
	}
}

func TestQualDRWAAccountItemRootSelection(t *testing.T) {
	// Explicit native root selection only; no branch/finality authority or disk
	// lifecycle is supplied by this test. Old and new committed roots coexist.
	for _, auto := range []bool{false, true} {
		t.Run(fmt.Sprintf("auto_%t", auto), func(t *testing.T) {
			address, key := bytes.Repeat([]byte{1}, 32), []byte("fixture/root-selection")
			oldValue, newValue := []byte("literal committed predecessor"), []byte("literal proposed successor")
			_, adb, _, db := qualAccountItemFixture(t, oldValue, 1, key, auto, address)
			oldRoot, err := adb.RootHash()
			require.NoError(t, err)
			write := func(value []byte) {
				a, err := adb.GetExistingAccount(address)
				require.NoError(t, err)
				u := a.(state.UserAccountHandler)
				require.NoError(t, u.SaveKeyValue(bytes.Clone(key), bytes.Clone(value)))
				require.NoError(t, adb.SaveAccount(u))
			}
			readFresh := func(root, expected []byte) {
				fresh, _ := qualAccountDB(t, db, auto)
				require.NoError(t, fresh.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
				a, err := fresh.GetExistingAccount(address)
				require.NoError(t, err)
				got, _, err := a.(state.UserAccountHandler).RetrieveValue(key)
				require.NoError(t, err)
				require.Equal(t, expected, got)
			}
			write(newValue)
			dirtyRoot, err := adb.RootHash()
			require.NoError(t, err)
			require.NotEqual(t, oldRoot, dirtyRoot)
			readFresh(oldRoot, oldValue)
			fresh, _ := qualAccountDB(t, db, auto)
			require.Error(t, fresh.RecreateTrie(holders.NewDefaultRootHashesHolder(dirtyRoot)), "uncommitted root cannot be recreated from the backing memory store")
			require.Greater(t, adb.JournalLen(), 0)
			require.NoError(t, adb.RevertToSnapshot(0))
			require.Zero(t, adb.JournalLen())
			restored, err := adb.RootHash()
			require.NoError(t, err)
			require.Equal(t, oldRoot, restored)
			a, err := adb.GetExistingAccount(address)
			require.NoError(t, err)
			got, _, err := a.(state.UserAccountHandler).RetrieveValue(key)
			require.NoError(t, err)
			require.Equal(t, oldValue, got)
			write(newValue)
			newRoot, err := adb.Commit()
			require.NoError(t, err)
			require.NotEqual(t, oldRoot, newRoot)
			readFresh(oldRoot, oldValue)
			readFresh(newRoot, newValue)
			require.NoError(t, adb.RecreateTrie(holders.NewDefaultRootHashesHolder(oldRoot)))
			a, err = adb.GetExistingAccount(address)
			require.NoError(t, err)
			got, _, err = a.(state.UserAccountHandler).RetrieveValue(key)
			require.NoError(t, err)
			require.Equal(t, oldValue, got, "root change resets cached data tries")
		})
	}
}
