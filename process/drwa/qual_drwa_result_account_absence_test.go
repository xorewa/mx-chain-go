package drwa

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/state"
	statemock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/testscommon/storageManager"
	"github.com/stretchr/testify/require"
)

// The historical positive-only entry remains the before-change oracle when
// the absence entry is absent. Native lookup, not this bridge, chooses absence.
func qualReadNativeAbsence(r *ResultAccountReader, committedH []byte, shard uint32,
	address, key []byte, w AccountItemWitness, limit int) error {
	if reader, present := interface{}(r).(interface {
		readAbsent([]byte, uint32, []byte, []byte, AccountItemWitness, int) error
	}); present {
		return reader.readAbsent(committedH, shard, address, key, w, limit)
	}
	_, err := r.Read(committedH, shard, address, key, w, limit)
	if err == nil {
		return ErrInvalidAccountWitness // a positive-only read cannot authenticate absence
	}
	return err
}

// The literal source map has accounts 0x01/0x02 and exactly two data keys.
// Native proof production supplies bytes; it does not choose expected absence.
// Both profiles are synthetic fixtures, not admitted historical configurations.
func qualAbsenceFixture(t *testing.T, auto bool) *qualReaderFixture {
	t.Helper()
	f := qualNativeReaderFixture(t, auto, 1)
	account, err := f.adb.GetExistingAccount(f.address)
	require.NoError(t, err)
	key := []byte("unrelated")
	if auto {
		key = f.args.Hasher.Compute(string(key))
	}
	proof, _, err := account.(state.UserAccountHandler).DataTrie().(common.Trie).GetProof(key)
	require.NoError(t, err)
	f.w.DataProof = append(f.w.DataProof, proof...)
	f.rebudget()
	return f
}

func qualAbsenceReader(t *testing.T, auto, warm bool, w AccountItemWitness) (*ResultAccountReader, *[2]int) {
	t.Helper()
	args := qualReaderArgs(auto)
	store := args.StorageManager.(*storageManager.StorageManagerStub)
	get, put := store.GetCalled, store.PutCalled
	if warm {
		for _, proof := range [][][]byte{w.AccountProof, w.DataProof} {
			for _, node := range proof {
				require.NoError(t, put(args.Hasher.Compute(string(node)), bytes.Clone(node)))
			}
		}
	}
	calls := new([2]int)
	store.GetCalled = func(key []byte) ([]byte, error) {
		calls[0]++
		return get(key)
	}
	store.GetFromCurrentEpochCalled = store.GetCalled
	store.PutCalled = func(key, value []byte) error {
		calls[1]++
		return put(key, value)
	}
	reader, err := NewResultAccountReader(args)
	require.NoError(t, err)
	return reader, calls
}

func TestQualDRWAResultAccountAbsence(t *testing.T) {
	for _, auto := range []bool{false, true} {
		t.Run(fmt.Sprintf("native_profile_auto_%t", auto), func(t *testing.T) {
			f := qualAbsenceFixture(t, auto)
			missing := []byte("fixture/missing-origin")
			before, err := f.adb.RootHash()
			require.NoError(t, err)

			t.Run("positive_api_remains_positive_only", func(t *testing.T) {
				reader, _ := qualAbsenceReader(t, auto, false, f.w)
				value, readErr := reader.Read(f.anchor, 1, f.address, missing, f.w, f.budget)
				require.Error(t, readErr)
				require.Nil(t, value)
				value, readErr = reader.Read(f.anchor, 1, f.address, f.key, f.w, f.budget)
				require.NoError(t, readErr)
				require.Equal(t, f.expected, value)
			})

			t.Run("missing_item_replay_has_no_cache_publication", func(t *testing.T) {
				reader, calls := qualAbsenceReader(t, auto, false, f.w)
				for i := 0; i < 3; i++ {
					require.NoError(t, qualReadNativeAbsence(reader, f.anchor, 1, f.address, missing, f.w, f.budget))
				}
				require.Equal(t, [2]int{}, *calls)
				require.ErrorIs(t, qualReadNativeAbsence(reader, f.anchor, 1, f.address, f.key, f.w, f.budget), ErrInvalidAccountWitness)
			})

			t.Run("partial_path_stays_unavailable_then_restores", func(t *testing.T) {
				for _, warm := range []bool{false, true} {
					t.Run(fmt.Sprintf("external_cache_warm_%t", warm), func(t *testing.T) {
						reader, calls := qualAbsenceReader(t, auto, warm, f.w)
						partial := f.w
						partial.DataProof = nil
						require.Error(t, qualReadNativeAbsence(reader, f.anchor, 1, f.address, missing, partial, f.budget))
						partial = f.w
						partial.AccountProof = nil
						require.Error(t, qualReadNativeAbsence(reader, f.anchor, 1, f.address, missing, partial, f.budget))
						require.NoError(t, qualReadNativeAbsence(reader, f.anchor, 1, f.address, missing, f.w, f.budget))
						require.Equal(t, [2]int{}, *calls)
					})
				}
			})

			t.Run("witness_order_does_not_select_absence", func(t *testing.T) {
				reader, calls := qualAbsenceReader(t, auto, false, f.w)
				w := f.w
				w.AccountProof = append([][]byte(nil), w.AccountProof...)
				w.DataProof = append([][]byte(nil), w.DataProof...)
				for i, j := 0, len(w.AccountProof)-1; i < j; i, j = i+1, j-1 {
					w.AccountProof[i], w.AccountProof[j] = w.AccountProof[j], w.AccountProof[i]
				}
				for i, j := 0, len(w.DataProof)-1; i < j; i, j = i+1, j-1 {
					w.DataProof[i], w.DataProof[j] = w.DataProof[j], w.DataProof[i]
				}
				require.NoError(t, qualReadNativeAbsence(reader, f.anchor, 1, f.address, missing, w, f.budget))
				require.Equal(t, [2]int{}, *calls)
			})

			t.Run("locus_identity_and_bound_refuse", func(t *testing.T) {
				reader, calls := qualAbsenceReader(t, auto, false, f.w)
				wrongH := bytes.Clone(f.anchor)
				wrongH[0] ^= 1
				require.Error(t, qualReadNativeAbsence(reader, wrongH, 1, f.address, missing, f.w, f.budget))
				require.Error(t, qualReadNativeAbsence(reader, f.anchor, 2, f.address, missing, f.w, f.budget))
				w := f.w
				w.ExecutedHeader = bytes.Clone(w.ExecutedHeader)
				w.ExecutedHeader[0] ^= 1
				require.Error(t, qualReadNativeAbsence(reader, f.anchor, 1, f.address, missing, w, f.budget))
				require.Error(t, qualReadNativeAbsence(reader, f.anchor, 1, f.address, missing, f.w, f.budget-1))
				w = f.w
				w.AccountProof = append([][]byte(nil), w.AccountProof...)
				w.AccountProof[0] = bytes.Clone(w.AccountProof[0])
				w.AccountProof[0][0] ^= 1
				require.Error(t, qualReadNativeAbsence(reader, f.anchor, 1, f.address, missing, w, f.budget))
				require.Equal(t, [2]int{}, *calls)
			})

			t.Run("absent_account_requires_its_available_path", func(t *testing.T) {
				reader, calls := qualAbsenceReader(t, auto, true, f.w)
				w := f.w
				w.DataProof = nil
				require.NoError(t, qualReadNativeAbsence(reader, f.anchor, 1, bytes.Repeat([]byte{3}, 32), missing, w, f.budget))
				w.AccountProof = nil
				require.Error(t, qualReadNativeAbsence(reader, f.anchor, 1, bytes.Repeat([]byte{3}, 32), missing, w, f.budget))
				require.Equal(t, [2]int{}, *calls)
			})

			t.Run("bare_empty_main_root_is_not_a_negative", func(t *testing.T) {
				reader, _ := qualAbsenceReader(t, auto, false, f.w)
				h := &block.HeaderV3{}
				require.NoError(t, f.args.Marshaller.Unmarshal(h, f.w.Header))
				h.ExecutionResults[0].BaseExecutionResult.RootHash = nil
				w := f.w
				w.Header, err = f.args.Marshaller.Marshal(h)
				require.NoError(t, err)
				anchor := f.args.Hasher.Compute(string(w.Header))
				require.ErrorIs(t, qualReadNativeAbsence(reader, anchor, 1, f.address, missing, w, f.budget), ErrInvalidAccountWitness)
			})

			t.Run("shared_reader_never_borrows_other_call_nodes", func(t *testing.T) {
				reader, calls := qualAbsenceReader(t, auto, true, f.w)
				type outcome struct {
					wantError bool
					err       error
				}
				results := make(chan outcome, 8)
				var wg sync.WaitGroup
				for i := 0; i < 8; i++ {
					w := f.w
					wantError := i%2 == 0
					if wantError {
						w.DataProof = nil
					}
					wg.Add(1)
					go func(w AccountItemWitness, wantError bool) {
						defer wg.Done()
						results <- outcome{wantError, qualReadNativeAbsence(reader, f.anchor, 1, f.address, missing, w, f.budget)}
					}(w, wantError)
				}
				wg.Wait()
				close(results)
				for result := range results {
					if result.wantError {
						require.Error(t, result.err)
					} else {
						require.NoError(t, result.err)
					}
				}
				require.Equal(t, [2]int{}, *calls)
			})

			t.Run("native_missing_query_discards_its_proof_path", func(t *testing.T) {
				account, loadErr := f.adb.GetExistingAccount(f.address)
				require.NoError(t, loadErr)
				key := missing
				if auto {
					key = f.args.Hasher.Compute(string(key))
				}
				proof, value, queryErr := account.(state.UserAccountHandler).DataTrie().(common.Trie).GetProof(key)
				require.Error(t, queryErr)
				require.Nil(t, proof)
				require.Nil(t, value)
			})

			after, err := f.adb.RootHash()
			require.NoError(t, err)
			require.Equal(t, before, after)
		})
	}
}

// TestQualDRWAResultAccountAbsence_NativeQuery composes the actual native query
// prefix with the isolated byte reader. Synthetic headers/profiles confer no
// canonical finality, class no-work, funding or receiving-application authority.
func TestQualDRWAResultAccountAbsence_NativeQuery(t *testing.T) {
	for _, auto := range []bool{false, true} {
		t.Run(fmt.Sprintf("native_query_auto_%t", auto), func(t *testing.T) {
			f := qualNativeReaderFixture(t, auto, 1)
			before, err := f.adb.RootHash()
			require.NoError(t, err)
			account, err := f.adb.GetExistingAccount(f.address)
			require.NoError(t, err)
			data := account.(state.UserAccountHandler).DataTrie().(common.Trie)
			query, available := data.(interface {
				GetProofForQuery([]byte) ([][]byte, []byte, error)
			})
			require.True(t, available, "actual native query primitive required")
			missing := []byte("fixture/native-missing-origin")
			physical := missing
			if auto {
				physical = f.args.Hasher.Compute(string(physical))
			}
			nativeValue, _, err := data.Get(physical)
			require.NoError(t, err)
			require.Nil(t, nativeValue)
			proof, value, queryErr := query.GetProofForQuery(physical)
			require.Error(t, queryErr)
			require.Nil(t, value)
			require.NotEmpty(t, proof)
			w := f.w
			w.DataProof = proof
			full := *f
			full.w = w
			full.rebudget()
			for _, warm := range []bool{false, true} {
				t.Run(fmt.Sprintf("data_warm_%t", warm), func(t *testing.T) {
					reader, calls := qualAbsenceReader(t, auto, warm, w)
					for replay := 0; replay < 3; replay++ {
						require.NoError(t, qualReadNativeAbsence(reader, f.anchor, 1, f.address, missing, w, full.budget))
					}
					partial := w
					partial.DataProof = w.DataProof[:len(w.DataProof)-1]
					require.Error(t, qualReadNativeAbsence(reader, f.anchor, 1, f.address, missing, partial, full.budget))
					require.NoError(t, qualReadNativeAbsence(reader, f.anchor, 1, f.address, missing, w, full.budget))
					require.Equal(t, [2]int{}, *calls, "unavailable proof cannot borrow warm local cache")
				})
			}

			presentPhysical := f.key
			if auto {
				presentPhysical = f.args.Hasher.Compute(string(presentPhysical))
			}
			oldProof, oldValue, oldErr := data.GetProof(presentPhysical)
			require.NoError(t, oldErr)
			presentProof, presentValue, presentErr := query.GetProofForQuery(presentPhysical)
			require.NoError(t, presentErr)
			require.Equal(t, oldProof, presentProof)
			require.Equal(t, oldValue, presentValue)
			present := f.w
			present.DataProof = presentProof
			presentFixture := *f
			presentFixture.w = present
			presentFixture.rebudget()
			reader, _ := qualAbsenceReader(t, auto, false, present)
			require.ErrorIs(t, qualReadNativeAbsence(reader, f.anchor, 1, f.address, f.key, present, presentFixture.budget), ErrInvalidAccountWitness)
			got, err := reader.Read(f.anchor, 1, f.address, f.key, present, presentFixture.budget)
			require.NoError(t, err)
			require.Equal(t, f.expected, got)

			main, err := f.adb.GetTrie(before)
			require.NoError(t, err)
			mainQuery, available := main.(interface {
				GetProofForQuery([]byte) ([][]byte, []byte, error)
			})
			require.True(t, available)
			absentAddress := bytes.Repeat([]byte{3}, 32)
			nativeValue, _, err = main.Get(absentAddress)
			require.NoError(t, err)
			require.Nil(t, nativeValue)
			accountProof, accountValue, accountErr := mainQuery.GetProofForQuery(absentAddress)
			require.Error(t, accountErr)
			require.Nil(t, accountValue)
			require.NotEmpty(t, accountProof)
			absent := f.w
			absent.AccountProof = accountProof
			absent.DataProof = nil
			absentFixture := *f
			absentFixture.w = absent
			absentFixture.rebudget()
			for _, warm := range []bool{false, true} {
				t.Run(fmt.Sprintf("account_warm_%t", warm), func(t *testing.T) {
					reader, calls := qualAbsenceReader(t, auto, warm, absent)
					require.NoError(t, qualReadNativeAbsence(reader, f.anchor, 1, absentAddress, missing, absent, absentFixture.budget))
					partial := absent
					partial.AccountProof = absent.AccountProof[:len(absent.AccountProof)-1]
					require.Error(t, qualReadNativeAbsence(reader, f.anchor, 1, absentAddress, missing, partial, absentFixture.budget))
					require.NoError(t, qualReadNativeAbsence(reader, f.anchor, 1, absentAddress, missing, absent, absentFixture.budget))
					require.Equal(t, [2]int{}, *calls)
				})
			}
			after, err := f.adb.RootHash()
			require.NoError(t, err)
			require.Equal(t, before, after, "source state is not a proof cache")
		})
	}
}

type qualNativeWitnessSource struct {
	state.AccountsAdapter
	unavailable  bool
	overrideRoot []byte
	roots        [][]byte
}

func (s *qualNativeWitnessSource) GetTrie(root []byte) (common.Trie, error) {
	s.roots = append(s.roots, bytes.Clone(root))
	if s.unavailable {
		return nil, state.ErrFunctionalityNotImplemented
	}
	if s.overrideRoot != nil {
		return s.AccountsAdapter.GetTrie(s.overrideRoot)
	}
	return s.AccountsAdapter.GetTrie(root)
}

type qualWitnessQueryResponse struct {
	common.Trie
	prefix    [][]byte
	value     []byte
	err       error
	queries   int
	recreates int
}

func (q *qualWitnessQueryResponse) GetProofForQuery([]byte) ([][]byte, []byte, error) {
	q.queries++
	return q.prefix, q.value, q.err
}

func (q *qualWitnessQueryResponse) Recreate(root common.RootHashHolder) (common.Trie, error) {
	q.recreates++
	return q.Trie.Recreate(root)
}

type qualWitnessRecreateReturnsMainTrie struct {
	common.Trie
}

func (q *qualWitnessRecreateReturnsMainTrie) GetProofForQuery(key []byte) ([][]byte, []byte, error) {
	return q.Trie.(interface {
		GetProofForQuery([]byte) ([][]byte, []byte, error)
	}).GetProofForQuery(key)
}

func (q *qualWitnessRecreateReturnsMainTrie) Recreate(common.RootHashHolder) (common.Trie, error) {
	return q.Trie, nil
}

// These source-side fixtures exercise bytes and historical-root selection.
// They grant no canonical/class permission, source-era pricing or paid service.
func TestQualDRWAResultAccountAbsence_NativeSource(t *testing.T) {
	for _, auto := range []bool{false, true} {
		t.Run(fmt.Sprintf("native_source_auto_%t", auto), func(t *testing.T) {
			f := qualNativeReaderFixture(t, auto, 1)
			template := AccountItemWitness{
				Header: bytes.Clone(f.w.Header), ExecutedHeader: bytes.Clone(f.w.ExecutedHeader),
				AccountProof: [][]byte{[]byte("ignored-account-hint")},
				DataProof:    [][]byte{[]byte("ignored-data-hint")},
			}
			physical := bytes.Clone(f.key)
			if auto {
				physical = f.args.Hasher.Compute(string(physical))
			}
			rootBefore, err := f.adb.RootHash()
			require.NoError(t, err)
			t.Run("positive_original_carrier_and_input_copy", func(t *testing.T) {
				r, calls := qualAbsenceReader(t, auto, false, template)
				w, err := r.BuildNativeWitness(f.adb, f.anchor, 1, f.address, physical, template, f.budget)
				require.NoError(t, err)
				require.Equal(t, [2]int{}, *calls)
				require.Equal(t, f.w.AccountProof, w.AccountProof)
				require.Equal(t, f.w.DataProof, w.DataProof)
				value, err := r.Read(f.anchor, 1, f.address, f.key, w, f.budget)
				require.NoError(t, err)
				require.Equal(t, f.expected, value)
				w.Header[0] ^= 1
				require.Equal(t, f.w.Header, template.Header)
				require.Equal(t, []byte("ignored-account-hint"), template.AccountProof[0])
			})

			t.Run("query_unavailability_preserves_error_and_owned_prefix", func(t *testing.T) {
				r, _ := qualAbsenceReader(t, auto, false, template)
				sentinel := errors.New("fixture account query unavailable")
				query := &qualWitnessQueryResponse{Trie: f.tr, prefix: f.w.AccountProof[:1], err: sentinel}
				source := &statemock.AccountsStub{GetTrieCalled: func(root []byte) (common.Trie, error) {
					require.Equal(t, rootBefore, root)
					return query, nil
				}}
				witness, err := r.BuildNativeWitness(source, f.anchor, 1, f.address, physical, template, f.budget)
				require.ErrorIs(t, err, sentinel)
				require.Equal(t, query.prefix, witness.AccountProof)
				require.Empty(t, witness.DataProof)
				originalFirstByte := query.prefix[0][0]
				witness.AccountProof[0][0] ^= 1
				require.Equal(t, originalFirstByte, query.prefix[0][0])
			})

			t.Run("query_of_second_ordinary_account_stops_before_data_trie", func(t *testing.T) {
				r, _ := qualAbsenceReader(t, auto, false, template)
				otherAddress := bytes.Repeat([]byte{2}, len(f.address))
				require.NotEqual(t, f.address, otherAddress)
				native := f.tr.(interface {
					GetProofForQuery([]byte) ([][]byte, []byte, error)
				})
				proof, value, err := native.GetProofForQuery(otherAddress)
				require.NoError(t, err)
				require.NotEmpty(t, proof)
				require.NotEmpty(t, value)
				// Model a misrouted internal query response using the untouched
				// bytes from a second already-existing native account.
				query := &qualWitnessQueryResponse{Trie: f.tr, prefix: proof, value: value}
				source := &statemock.AccountsStub{GetTrieCalled: func(root []byte) (common.Trie, error) {
					require.Equal(t, rootBefore, root)
					return query, nil
				}}
				_, err = r.BuildNativeWitness(source, f.anchor, 1, f.address, physical, template, f.budget)
				require.Error(t, err)
				require.Equal(t, 1, query.queries)
				require.Zero(t, query.recreates)
			})

			t.Run("recreated_data_trie_must_have_the_account_root", func(t *testing.T) {
				r, _ := qualAbsenceReader(t, auto, false, template)
				account, err := f.adb.GetExistingAccount(f.address)
				require.NoError(t, err)
				require.NotEqual(t, rootBefore, account.(state.UserAccountHandler).GetRootHash())
				source := &statemock.AccountsStub{GetTrieCalled: func(root []byte) (common.Trie, error) {
					require.Equal(t, rootBefore, root)
					return &qualWitnessRecreateReturnsMainTrie{Trie: f.tr}, nil
				}}
				witness, err := r.BuildNativeWitness(source, f.anchor, 1, f.address, physical, template, f.budget)
				require.ErrorIs(t, err, ErrInvalidAccountWitness)
				require.Equal(t, f.w.AccountProof, witness.AccountProof)
				require.Empty(t, witness.DataProof)
			})

			t.Run("invalid_source_context_and_byte_bound", func(t *testing.T) {
				source := &qualNativeWitnessSource{AccountsAdapter: f.adb}
				r, calls := qualAbsenceReader(t, auto, false, template)
				w, err := r.BuildNativeWitness(nil, f.anchor, 1, f.address, physical, template, f.budget)
				require.Error(t, err)
				require.Empty(t, w.AccountProof)
				_, err = r.BuildNativeWitness(source, nil, 1, f.address, physical, template, f.budget)
				require.Error(t, err)
				_, err = r.BuildNativeWitness(source, f.anchor, 1, f.address, nil, template, f.budget)
				require.Error(t, err)
				_, err = r.BuildNativeWitness(source, f.anchor, 2, f.address, physical, template, f.budget)
				require.Error(t, err)
				malformed := template
				malformed.Header = []byte("fixture/malformed-native-H")
				hash := f.args.Hasher.Compute(string(malformed.Header))
				_, err = r.BuildNativeWitness(source, hash, 1, f.address, physical, malformed, f.budget)
				require.Error(t, err)
				require.Empty(t, source.roots)
				limit := len(template.Header)
				for _, input := range [][]byte{template.ExecutedHeader, f.address, physical} {
					if len(input) > limit {
						limit = len(input)
					}
				}
				proofBytes := 0
				for _, proof := range [][][]byte{f.w.AccountProof, f.w.DataProof} {
					for _, node := range proof {
						proofBytes += len(node)
					}
				}
				require.Greater(t, proofBytes, limit, "fixture must exceed this independent admission bound")
				_, err = r.BuildNativeWitness(source, f.anchor, 1, f.address, physical, template, limit)
				require.ErrorIs(t, err, ErrInvalidAccountWitness)
				require.Equal(t, [2]int{}, *calls)
			})

			t.Run("concurrent_source_witnesses_are_independent", func(t *testing.T) {
				r, calls := qualAbsenceReader(t, auto, false, template)
				type result struct {
					witness AccountItemWitness
					err     error
				}
				output := make(chan result, 4)
				for i := 0; i < 4; i++ {
					go func() {
						w, err := r.BuildNativeWitness(f.adb, f.anchor, 1, f.address, physical, template, f.budget)
						output <- result{witness: w, err: err}
					}()
				}
				collected := make([]result, 0, 4)
				for i := 0; i < 4; i++ {
					collected = append(collected, <-output)
				}
				witnesses := make([]AccountItemWitness, 0, 4)
				for _, res := range collected {
					require.NoError(t, res.err)
					require.Equal(t, f.w.AccountProof, res.witness.AccountProof)
					require.Equal(t, f.w.DataProof, res.witness.DataProof)
					witnesses = append(witnesses, res.witness)
				}
				require.Equal(t, [2]int{}, *calls)
				for _, w := range witnesses {
					value, err := r.Read(f.anchor, 1, f.address, f.key, w, f.budget)
					require.NoError(t, err)
					require.Equal(t, f.expected, value)
				}
				witnesses[0].AccountProof[0][0] ^= 1
				require.NotEqual(t, f.w.AccountProof, witnesses[0].AccountProof)
				require.Equal(t, f.w.AccountProof, witnesses[1].AccountProof)
				require.Equal(t, f.w.Header, template.Header)
			})
			missing := []byte("fixture/native-source-missing-origin")
			missingPhysical := bytes.Clone(missing)
			if auto {
				missingPhysical = f.args.Hasher.Compute(string(missingPhysical))
			}
			t.Run("missing_data_preserves_native_error_and_proof", func(t *testing.T) {
				account, err := f.adb.GetExistingAccount(f.address)
				require.NoError(t, err)
				data := account.(state.UserAccountHandler).DataTrie().(common.Trie)
				value, _, err := data.Get(missingPhysical)
				require.NoError(t, err)
				require.Nil(t, value)
				r, calls := qualAbsenceReader(t, auto, false, template)
				w, queryErr := r.BuildNativeWitness(f.adb, f.anchor, 1, f.address, missingPhysical, template, f.budget)
				require.Error(t, queryErr)
				require.NotEmpty(t, w.AccountProof)
				require.NotEmpty(t, w.DataProof)
				full := *f
				full.w = w
				full.rebudget()
				require.NoError(t, qualReadNativeAbsence(r, f.anchor, 1, f.address, missing, w, full.budget))
				partial := w
				partial.DataProof = nil
				require.ErrorIs(t, qualReadNativeAbsence(r, f.anchor, 1, f.address, missing, partial, full.budget), ErrInvalidAccountWitness)
				require.NoError(t, qualReadNativeAbsence(r, f.anchor, 1, f.address, missing, w, full.budget))
				require.NoError(t, qualReadNativeAbsence(r, f.anchor, 1, f.address, missing, w, full.budget))
				require.Equal(t, [2]int{}, *calls)
			})
			t.Run("missing_account_preserves_native_error_and_proof", func(t *testing.T) {
				address := bytes.Repeat([]byte{3}, len(f.address))
				value, _, err := f.tr.Get(address)
				require.NoError(t, err)
				require.Nil(t, value)
				r, calls := qualAbsenceReader(t, auto, false, template)
				w, queryErr := r.BuildNativeWitness(f.adb, f.anchor, 1, address, physical, template, f.budget)
				require.Error(t, queryErr)
				require.NotEmpty(t, w.AccountProof)
				require.Empty(t, w.DataProof)
				require.NoError(t, qualReadNativeAbsence(r, f.anchor, 1, address, f.key, w, f.budget))
				require.Equal(t, [2]int{}, *calls)
			})
			t.Run("unavailable_restored_replay", func(t *testing.T) {
				source := &qualNativeWitnessSource{AccountsAdapter: f.adb, unavailable: true}
				r, calls := qualAbsenceReader(t, auto, false, template)
				unavailable, err := r.BuildNativeWitness(source, f.anchor, 1, f.address, missingPhysical, template, f.budget)
				require.ErrorIs(t, err, state.ErrFunctionalityNotImplemented)
				require.Empty(t, unavailable.AccountProof)
				require.ErrorIs(t, qualReadNativeAbsence(r, f.anchor, 1, f.address, missing, unavailable, f.budget), ErrInvalidAccountWitness)
				source.unavailable = false
				restored, err := r.BuildNativeWitness(source, f.anchor, 1, f.address, missingPhysical, template, f.budget)
				require.Error(t, err)
				require.NotEmpty(t, restored.DataProof)
				full := *f
				full.w = restored
				full.rebudget()
				require.NoError(t, qualReadNativeAbsence(r, f.anchor, 1, f.address, missing, restored, full.budget))
				replay, err := r.BuildNativeWitness(source, f.anchor, 1, f.address, missingPhysical, template, f.budget)
				require.Error(t, err)
				require.Equal(t, restored, replay)
				require.NoError(t, qualReadNativeAbsence(r, f.anchor, 1, f.address, missing, replay, full.budget))
				require.Equal(t, [2]int{}, *calls)
			})
			after, err := f.adb.RootHash()
			require.NoError(t, err)
			require.Equal(t, rootBefore, after)
			t.Run("historical_root_and_pre_query_refusals", func(t *testing.T) {
				source := &qualNativeWitnessSource{AccountsAdapter: f.adb}
				r, calls := qualAbsenceReader(t, auto, false, template)
				_, err := r.BuildNativeWitness(source, []byte("different-H"), 1, f.address, physical, template, f.budget)
				require.ErrorIs(t, err, ErrInvalidAccountWitness)
				_, err = r.BuildNativeWitness(source, f.anchor, 1, f.address, physical, template, 0)
				require.ErrorIs(t, err, ErrInvalidAccountWitness)
				require.Empty(t, source.roots)
				account, err := f.adb.GetExistingAccount(f.address)
				require.NoError(t, err)
				account.IncreaseNonce(1)
				require.NoError(t, f.adb.SaveAccount(account))
				current, err := f.adb.Commit()
				require.NoError(t, err)
				require.NotEqual(t, rootBefore, current)
				w, err := r.BuildNativeWitness(source, f.anchor, 1, f.address, physical, template, f.budget)
				require.NoError(t, err)
				require.Equal(t, [][]byte{rootBefore}, source.roots)
				require.Equal(t, f.w.AccountProof, w.AccountProof)
				require.Equal(t, f.w.DataProof, w.DataProof)
				require.Equal(t, [2]int{}, *calls)
				source.overrideRoot = current
				corrupt, err := r.BuildNativeWitness(source, f.anchor, 1, f.address, physical, template, f.budget)
				require.ErrorIs(t, err, ErrInvalidAccountWitness)
				require.Empty(t, corrupt.AccountProof)
				source.overrideRoot = nil
				value, err := r.Read(f.anchor, 1, f.address, f.key, w, f.budget)
				require.NoError(t, err)
				require.Equal(t, f.expected, value)
				after, err := f.adb.RootHash()
				require.NoError(t, err)
				require.Equal(t, current, after)
			})
		})
	}
}
