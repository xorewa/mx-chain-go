package drwa

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/state/accounts"
	stateDisabled "github.com/multiversx/mx-chain-go/state/disabled"
	"github.com/multiversx/mx-chain-go/state/factory"
	pruningDisabled "github.com/multiversx/mx-chain-go/state/storagePruningManager/disabled"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/storageManager"
	"github.com/multiversx/mx-chain-go/trie"
	"github.com/stretchr/testify/require"
)

// All native calls use concrete AccountsDB, factory, trie, codec and hash.
// The only callbacks are the proof-cache StorageManagerStub, explicitly bound
// below, and healthy epoch flags. No account/data semantics are mocked.
func qualReaderArgs(auto bool) ArgsResultAccountReader {
	db := testscommon.NewMemDbMock()
	flags := enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
	if auto {
		flags.AddActiveFlags(common.AutoBalanceDataTriesFlag)
	}
	return ArgsResultAccountReader{
		StorageManager: &storageManager.StorageManagerStub{
			GetCalled: db.Get, GetFromCurrentEpochCalled: db.Get, PutCalled: db.Put,
			GetIdentifierCalled: db.GetIdentifier, GetStateStatsHandlerCalled: db.GetStateStatsHandler,
		},
		Marshaller: &marshal.GogoProtoMarshalizer{}, Hasher: blake2b.NewBlake2b(),
		EnableEpochsHandler: flags, MaxTrieLevelInMemory: 5,
	}
}

type qualReaderFixture struct {
	args                           ArgsResultAccountReader
	adb                            *state.AccountsDB
	tr                             common.Trie
	w                              AccountItemWitness
	anchor, address, key, expected []byte
	budget                         int
}

func qualNativeReaderFixture(t *testing.T, auto bool, shard uint32) *qualReaderFixture {
	t.Helper()
	f := &qualReaderFixture{args: qualReaderArgs(auto), address: bytes.Repeat([]byte{1}, 32),
		key: []byte("fixture/owned-item"), expected: []byte("literal authenticated native value")}
	var err error
	f.tr, err = trie.NewTrie(f.args.StorageManager, f.args.Marshaller, f.args.Hasher, f.args.EnableEpochsHandler, 5)
	require.NoError(t, err)
	collector := stateDisabled.NewDisabledStateAccessesCollector()
	af, err := factory.NewAccountCreator(factory.ArgsAccountCreator{Hasher: f.args.Hasher,
		Marshaller: f.args.Marshaller, EnableEpochsHandler: f.args.EnableEpochsHandler, StateAccessesCollector: collector})
	require.NoError(t, err)
	f.adb, err = state.NewAccountsDB(state.ArgsAccountsDB{Trie: f.tr, Hasher: f.args.Hasher,
		Marshaller: f.args.Marshaller, AccountFactory: af, StateAccessesCollector: collector,
		StoragePruningManager: pruningDisabled.NewDisabledStoragePruningManager(),
		SnapshotsManager:      stateDisabled.NewDisabledSnapshotsManager(), AddressConverter: &testscommon.PubkeyConverterMock{}})
	require.NoError(t, err)
	for _, address := range [][]byte{f.address, bytes.Repeat([]byte{2}, 32)} {
		a, loadErr := f.adb.LoadAccount(address)
		require.NoError(t, loadErr)
		u := a.(state.UserAccountHandler)
		require.NoError(t, u.SaveKeyValue(bytes.Clone(f.key), bytes.Clone(f.expected)))
		require.NoError(t, u.SaveKeyValue([]byte("unrelated"), []byte("retained")))
		require.NoError(t, f.adb.SaveAccount(u))
	}
	root, err := f.adb.Commit()
	require.NoError(t, err)
	s := &block.HeaderV3{Nonce: 11, Round: 21, Epoch: 3, ShardID: shard}
	f.w.ExecutedHeader, err = f.args.Marshaller.Marshal(s)
	require.NoError(t, err)
	h := &block.HeaderV3{Nonce: 15, Round: 25, Epoch: 4, ShardID: shard,
		ExecutionResults: []*block.ExecutionResult{{BaseExecutionResult: &block.BaseExecutionResult{
			HeaderHash: f.args.Hasher.Compute(string(f.w.ExecutedHeader)), HeaderNonce: 11,
			HeaderRound: 21, HeaderEpoch: 3, RootHash: root}}}}
	f.w.Header, err = f.args.Marshaller.Marshal(h)
	require.NoError(t, err)
	f.anchor = f.args.Hasher.Compute(string(f.w.Header))
	f.w.AccountProof, _, err = f.tr.GetProof(f.address)
	require.NoError(t, err)
	a, err := f.adb.GetExistingAccount(f.address)
	require.NoError(t, err)
	key := f.key
	if auto {
		key = f.args.Hasher.Compute(string(key))
	}
	f.w.DataProof, _, err = a.(state.UserAccountHandler).DataTrie().(common.Trie).GetProof(key)
	require.NoError(t, err)
	f.rebudget()
	return f
}

func (f *qualReaderFixture) rebudget() {
	f.budget = 0
	for _, nodes := range [][][]byte{f.w.AccountProof, f.w.DataProof} {
		for _, node := range nodes {
			f.budget += len(node)
		}
	}
}

func (f *qualReaderFixture) changeH(t *testing.T, change func(*block.HeaderV3)) {
	t.Helper()
	h := &block.HeaderV3{}
	require.NoError(t, f.args.Marshaller.Unmarshal(h, f.w.Header))
	change(h)
	var err error
	f.w.Header, err = f.args.Marshaller.Marshal(h)
	require.NoError(t, err)
	f.anchor = f.args.Hasher.Compute(string(f.w.Header))
}

func TestQualDRWAResultAccountReader(t *testing.T) {
	cases := []string{"valid", "multi_result", "wrong_H", "wrong_S", "malformed_H", "malformed_S",
		"wrong_H_shard", "wrong_S_shard", "missing_result", "duplicate_result", "empty_result",
		"wrong_nonce", "wrong_round", "wrong_epoch", "wrong_root", "wrong_account", "wrong_key",
		"empty_anchor", "empty_address", "empty_key", "missing_account_proof", "missing_data_proof",
		"empty_account_node", "empty_data_node", "corrupt_account_proof", "corrupt_data_proof",
		"reordered_account_proof", "reordered_data_proof", "over_budget", "negative_budget",
		"account_address_mismatch", "empty_data_root", "malformed_account", "wrong_data_root"}
	for _, auto := range []bool{false, true} {
		for shard := uint32(0); shard < 3; shard++ {
			for _, name := range cases {
				t.Run(fmt.Sprintf("auto_%t/shard_%d/%s", auto, shard, name), func(t *testing.T) {
					f := qualNativeReaderFixture(t, auto, shard)
					good := qualNativeReaderFixture(t, auto, shard)
					switch name {
					case "wrong_H":
						f.anchor[0] ^= 1
					case "wrong_S":
						// Same coordinates isolate S's full byte identity from nonce,
						// round, epoch and shard guards (GJ-01 prevention).
						s := &block.HeaderV3{Nonce: 11, Round: 21, Epoch: 3, ShardID: shard, PrevHash: []byte("different executed header")}
						var err error
						f.w.ExecutedHeader, err = f.args.Marshaller.Marshal(s)
						require.NoError(t, err)
					case "malformed_H":
						f.w.Header = []byte{0xff}
						f.anchor = f.args.Hasher.Compute(string(f.w.Header))
					case "malformed_S":
						f.w.ExecutedHeader = []byte{0xff}
					case "wrong_H_shard":
						f.changeH(t, func(h *block.HeaderV3) { h.ShardID++ })
					case "wrong_S_shard":
						s := &block.HeaderV3{}
						require.NoError(t, f.args.Marshaller.Unmarshal(s, f.w.ExecutedHeader))
						s.ShardID++
						var err error
						f.w.ExecutedHeader, err = f.args.Marshaller.Marshal(s)
						require.NoError(t, err)
						f.changeH(t, func(h *block.HeaderV3) {
							h.ExecutionResults[0].BaseExecutionResult.HeaderHash = f.args.Hasher.Compute(string(f.w.ExecutedHeader))
						})
					case "missing_result":
						f.changeH(t, func(h *block.HeaderV3) { h.ExecutionResults = nil })
					case "duplicate_result":
						f.changeH(t, func(h *block.HeaderV3) { h.ExecutionResults = append(h.ExecutionResults, h.ExecutionResults[0]) })
					case "empty_result":
						f.changeH(t, func(h *block.HeaderV3) { h.ExecutionResults = append(h.ExecutionResults, &block.ExecutionResult{}) })
					case "multi_result":
						f.changeH(t, func(h *block.HeaderV3) {
							h.ExecutionResults = append([]*block.ExecutionResult{{BaseExecutionResult: &block.BaseExecutionResult{HeaderHash: []byte("unrelated")}}}, h.ExecutionResults...)
						})
					case "wrong_nonce":
						f.changeH(t, func(h *block.HeaderV3) { h.ExecutionResults[0].BaseExecutionResult.HeaderNonce++ })
					case "wrong_round":
						f.changeH(t, func(h *block.HeaderV3) { h.ExecutionResults[0].BaseExecutionResult.HeaderRound++ })
					case "wrong_epoch":
						f.changeH(t, func(h *block.HeaderV3) { h.ExecutionResults[0].BaseExecutionResult.HeaderEpoch++ })
					case "wrong_root":
						f.changeH(t, func(h *block.HeaderV3) {
							h.ExecutionResults[0].BaseExecutionResult.RootHash = bytes.Repeat([]byte{7}, 32)
						})
					case "wrong_account":
						f.address = bytes.Repeat([]byte{2}, 32)
					case "wrong_key":
						f.key = []byte("other item")
					case "empty_anchor":
						f.anchor = nil
					case "empty_address":
						f.address = nil
					case "empty_key":
						f.key = nil
					case "missing_account_proof":
						f.w.AccountProof = nil
					case "missing_data_proof":
						f.w.DataProof = nil
					case "empty_account_node":
						f.w.AccountProof[0] = nil
					case "empty_data_node":
						f.w.DataProof[0] = nil
					case "corrupt_account_proof":
						f.w.AccountProof[0][0] ^= 1
					case "corrupt_data_proof":
						f.w.DataProof[0][0] ^= 1
					case "reordered_account_proof":
						n := f.w.AccountProof
						require.Greater(t, len(n), 1)
						n[0], n[len(n)-1] = n[len(n)-1], n[0]
					case "reordered_data_proof":
						n := f.w.DataProof
						require.Greater(t, len(n), 1)
						n[0], n[len(n)-1] = n[len(n)-1], n[0]
					case "over_budget":
						f.budget--
					case "negative_budget":
						f.budget = -1
					case "account_address_mismatch", "empty_data_root", "malformed_account", "wrong_data_root":
						raw, _, err := f.tr.Get(f.address)
						require.NoError(t, err)
						a := &accounts.UserAccountData{}
						require.NoError(t, f.args.Marshaller.Unmarshal(a, raw))
						if name == "account_address_mismatch" {
							a.Address = bytes.Repeat([]byte{2}, 32)
						}
						if name == "empty_data_root" {
							a.RootHash = nil
						}
						if name == "wrong_data_root" {
							a.RootHash = bytes.Repeat([]byte{7}, 32)
						}
						raw, err = f.args.Marshaller.Marshal(a)
						require.NoError(t, err)
						if name == "malformed_account" {
							raw = []byte{0xff}
						}
						require.NoError(t, f.tr.Update(f.address, raw))
						root, err := f.tr.RootHash()
						require.NoError(t, err)
						f.w.AccountProof, _, err = f.tr.GetProof(f.address)
						require.NoError(t, err)
						f.changeH(t, func(h *block.HeaderV3) { h.ExecutionResults[0].BaseExecutionResult.RootHash = root })
						f.rebudget()
						// This challenge is internally re-anchored: neither H's hash nor
						// main membership can mask the account/data guard under test.
					}
					r, err := NewResultAccountReader(qualReaderArgs(auto))
					require.NoError(t, err)
					v, err := r.Read(f.anchor, shard, f.address, f.key, f.w, f.budget)
					if name == "valid" || name == "multi_result" {
						require.NoError(t, err)
						require.Equal(t, f.expected, v)
					} else {
						require.Error(t, err)
						require.Nil(t, v)
					}
					// Every denial is followed by a healthy read on the same production
					// reader; partial cache writes cannot publish progress or poison it.
					v, err = r.Read(good.anchor, shard, good.address, good.key, good.w, good.budget)
					require.NoError(t, err)
					require.Equal(t, good.expected, v)
					a, err := good.adb.GetExistingAccount(good.address)
					require.NoError(t, err)
					native, _, err := a.(state.UserAccountHandler).RetrieveValue(good.key)
					require.NoError(t, err)
					require.Equal(t, native, v, "same native AccountsDB value, including metadata removal")
					require.Zero(t, good.adb.JournalLen())
					v[0] ^= 1
					again, err := r.Read(good.anchor, shard, good.address, good.key, good.w, good.budget)
					require.NoError(t, err)
					require.Equal(t, good.expected, again)
				})
			}
		}
	}
}

func TestQualDRWAResultAccountReaderDependencies(t *testing.T) {
	for _, name := range []string{"storage", "marshaller", "hasher", "epochs", "depth"} {
		t.Run(name, func(t *testing.T) {
			a := qualReaderArgs(false)
			switch name {
			case "storage":
				a.StorageManager = nil
			case "marshaller":
				a.Marshaller = nil
			case "hasher":
				a.Hasher = nil
			case "epochs":
				a.EnableEpochsHandler = nil
			case "depth":
				a.MaxTrieLevelInMemory = 0
			}
			r, err := NewResultAccountReader(a)
			require.Error(t, err)
			require.Nil(t, r)
		})
	}
	for _, boundary := range []string{"account_put", "data_put", "get"} {
		t.Run(boundary, func(t *testing.T) {
			f := qualNativeReaderFixture(t, false, 1)
			args := qualReaderArgs(false)
			s := args.StorageManager.(*storageManager.StorageManagerStub)
			originalPut, originalGet := s.PutCalled, s.GetCalled
			fault := errors.New("cache fault")
			calls := 0
			if boundary == "get" {
				s.GetCalled = func([]byte) ([]byte, error) { return nil, fault }
				s.GetFromCurrentEpochCalled = s.GetCalled
			} else {
				s.PutCalled = func(k, v []byte) error {
					calls++
					if boundary == "account_put" || calls > len(f.w.AccountProof) {
						return fault
					}
					return originalPut(k, v)
				}
			}
			r, err := NewResultAccountReader(args)
			require.NoError(t, err)
			v, err := r.Read(f.anchor, 1, f.address, f.key, f.w, f.budget)
			if boundary == "get" {
				// Native trie/node.go:130 wraps with the core key-bearing error,
				// whose v1.5.1 implementation has no Unwrap. Preserve that exact
				// native type, text and root key; do not invent error identity.
				h := &block.HeaderV3{}
				require.NoError(t, f.args.Marshaller.Unmarshal(h, f.w.Header))
				root := h.ExecutionResults[0].BaseExecutionResult.RootHash
				want := core.NewGetNodeFromDBErrWithKey(root, fault, s.GetIdentifier())
				require.IsType(t, want, err)
				require.EqualError(t, err, want.Error())
				require.Equal(t, root, err.(interface{ GetKey() []byte }).GetKey())
			} else {
				require.Same(t, fault, err)
			}
			require.Nil(t, v)
			s.PutCalled, s.GetCalled, s.GetFromCurrentEpochCalled = originalPut, originalGet, originalGet
			v, err = r.Read(f.anchor, 1, f.address, f.key, f.w, f.budget)
			require.NoError(t, err)
			require.Equal(t, f.expected, v)
		})
	}
}

func TestQualDRWAResultAccountReaderConcurrent(t *testing.T) {
	f := qualNativeReaderFixture(t, true, 1)
	r, err := NewResultAccountReader(qualReaderArgs(true))
	require.NoError(t, err)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, e := r.Read(f.anchor, 1, f.address, f.key, f.w, f.budget)
			require.NoError(t, e)
			require.Equal(t, f.expected, v)
		}()
	}
	wg.Wait()
}
