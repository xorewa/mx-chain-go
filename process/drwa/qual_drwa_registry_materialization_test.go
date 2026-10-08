package drwa

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Fault decorators keep native persistence and rollback. No nullable callbacks
// or mock account semantics are introduced.
type qualRegistryMaterializationFault struct {
	state.AccountsAdapter
	saveAt, saves            int
	saveError, rollbackError error
	readError                error
}

func (s *qualRegistryMaterializationFault) GetExistingAccount(address []byte) (vmcommon.AccountHandler, error) {
	if s.readError != nil {
		return nil, s.readError
	}
	return s.AccountsAdapter.GetExistingAccount(address)
}

func (s *qualRegistryMaterializationFault) SaveAccount(a vmcommon.AccountHandler) error {
	s.saves++
	err := s.AccountsAdapter.SaveAccount(a)
	if err == nil && s.saveAt == s.saves {
		return s.saveError
	}
	return err
}

func (s *qualRegistryMaterializationFault) RevertToSnapshot(n int) error {
	if err := s.AccountsAdapter.RevertToSnapshot(n); err != nil {
		return err
	}
	return s.rollbackError
}

func qualRegistryMaterialization(t *testing.T, auto bool) (*registryMaterialization, *registryProjection, *state.AccountsDB, *qualRegistryMaterializationFault) {
	t.Helper()
	f := qualRegistryTransport(t, auto, []byte{0, 0, 0, 0, 0, 0, 0, 2}, []byte{1})
	transport, err := newRegistryTransport(f.reader, 2, f.limit)
	require.NoError(t, err)
	view, err := transport.reconstruct(f.anchor, f.count, f.members)
	require.NoError(t, err)
	db := qualGenesisAccounts(t, auto)
	s, err := newProtectedState(db)
	require.NoError(t, err)
	require.NoError(t, s.provisionGenesis())
	_, err = db.Commit()
	require.NoError(t, err)
	adapter := &qualRegistryMaterializationFault{AccountsAdapter: db}
	m, err := newRegistryMaterialization(adapter, f.anchor)
	require.NoError(t, err)
	return m, view, db, adapter
}

func TestQualDRWARegistryMaterialization(t *testing.T) {
	for _, auto := range []bool{false, true} {
		t.Run(fmt.Sprintf("auto_%t", auto), func(t *testing.T) {
			for _, name := range []string{"valid", "unprepared", "nil_view", "nil_members", "candidate", "meta", "executed", "root", "nonce", "round", "epoch", "different_candidate", "duplicate_prepare", "save", "rollback", "abort", "abort_failure", "commit", "alias"} {
				t.Run(name, func(t *testing.T) {
					m, view, db, adapter := qualRegistryMaterialization(t, auto)
					if name == "duplicate_prepare" {
						for _, id := range []string{"AAA-abcdef", "BBB-123456"} {
							require.NoError(t, m.state.materializeMembership([]byte(id)))
						}
						_, err := db.Commit()
						require.NoError(t, err)
						m, err = newRegistryMaterialization(adapter, &view.anchor)
						require.NoError(t, err)
					}
					candidate := bytes.Clone(view.anchor.candidateHash)
					before, err := db.RootHash()
					require.NoError(t, err)
					fault := errors.New("native materialization failed")
					switch name {
					case "unprepared":
						_, err = m.classify(candidate, []byte("AAA-abcdef"))
						require.Error(t, err)
						return
					case "nil_view":
						view = nil
					case "nil_members":
						view.members = nil
					case "candidate":
						view.anchor.candidateHash[0] ^= 1
					case "meta":
						view.anchor.metaHash[0] ^= 1
					case "executed":
						view.anchor.executedHash[0] ^= 1
					case "root":
						view.anchor.root[0] ^= 1
					case "nonce":
						view.anchor.nonce++
					case "round":
						view.anchor.round++
					case "epoch":
						view.anchor.epoch++
					case "save", "rollback":
						adapter.saveAt, adapter.saveError = 2, fault
						if name == "rollback" {
							adapter.rollbackError = errors.New("native rollback failed after undo")
						}
					}
					err = m.prepare(context.Background(), view)
					invalid := map[string]bool{"nil_view": true, "nil_members": true, "candidate": true, "meta": true, "executed": true, "root": true, "nonce": true, "round": true, "epoch": true, "save": true, "rollback": true}
					if invalid[name] {
						require.Error(t, err)
						_, err = m.classify(candidate, []byte("AAA-abcdef"))
						require.Error(t, err)
						after, e := db.RootHash()
						require.NoError(t, e)
						require.Equal(t, before, after)
						if name == "rollback" {
							_, _, e = m.owner.Commit()
							require.ErrorIs(t, e, fault)
							require.ErrorIs(t, e, adapter.rollbackError)
						}
						return
					}
					require.NoError(t, err)
					for _, id := range []string{"AAA-abcdef", "BBB-123456"} {
						a, e := db.GetExistingAccount(core.SystemAccountAddress)
						require.NoError(t, e)
						marker, _, e := a.(state.UserAccountHandler).RetrieveValue(append([]byte("ELRONDDRWA@membership@"), []byte(id)...))
						require.NoError(t, e)
						require.Equal(t, []byte{1}, marker)
					}
					if name == "duplicate_prepare" {
						require.Error(t, m.prepare(context.Background(), view))
					}
					if name == "alias" {
						delete(view.members, "AAA-abcdef")
						view.anchor.candidateHash[0] ^= 1
					}
					if name == "different_candidate" {
						candidate[0] ^= 1
					}
					closed := name == "abort" || name == "abort_failure" || name == "commit"
					if name == "abort_failure" {
						adapter.rollbackError = fault
						require.ErrorIs(t, m.abort(), fault)
					}
					if name == "abort" {
						require.NoError(t, m.abort())
					}
					if name == "commit" {
						_, _, err = m.owner.Commit()
						require.NoError(t, err)
					}
					present, e := m.classify(candidate, []byte("AAA-abcdef"))
					if closed || name == "different_candidate" {
						require.Error(t, e)
						require.False(t, present)
					} else {
						require.NoError(t, e)
						require.True(t, present)
						present, e = m.classify(candidate, []byte("CCC-abcdef"))
						require.NoError(t, e)
						require.False(t, present)
					}
					if name == "abort" || name == "abort_failure" {
						after, e := db.RootHash()
						require.NoError(t, e)
						require.Equal(t, before, after)
					}
				})
			}
		})
	}
}

func TestQualDRWARegistryMaterializationLocalIntegrity(t *testing.T) {
	for _, auto := range []bool{false, true} {
		for _, name := range []string{"existing", "stale", "malformed", "invalid_id", "cancelled", "nil_context", "account_read"} {
			t.Run(fmt.Sprintf("auto_%t/%s", auto, name), func(t *testing.T) {
				m, view, db, adapter := qualRegistryMaterialization(t, auto)
				ctx := context.Background()
				if name == "cancelled" {
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(ctx)
					cancel()
				}
				if name == "nil_context" {
					ctx = nil
				}
				if name == "account_read" {
					adapter.readError = errors.New("native existing account read failed")
				}
				if name == "existing" || name == "stale" || name == "malformed" || name == "invalid_id" {
					id, value := []byte("AAA-abcdef"), []byte{1}
					if name == "stale" {
						id = []byte("CCC-abcdef")
					}
					if name == "malformed" {
						value = []byte{2}
					}
					if name == "invalid_id" {
						id = []byte("bad")
						view.members[string(id)] = struct{}{}
					}
					u, err := db.GetExistingAccount(core.SystemAccountAddress)
					require.NoError(t, err)
					require.NoError(t, u.(state.UserAccountHandler).SaveKeyValue(append([]byte("ELRONDDRWA@membership@"), id...), value))
					// Independent literal local index, matching the marker fixture.
					require.NoError(t, u.(state.UserAccountHandler).SaveKeyValue([]byte("ELRONDDRWA@membershipIndex@count"), []byte{0, 0, 0, 0, 0, 0, 0, 1}))
					require.NoError(t, u.(state.UserAccountHandler).SaveKeyValue(append([]byte("ELRONDDRWA@membershipIndex@entry@"), make([]byte, 8)...), id))
					require.NoError(t, db.SaveAccount(u))
					_, err = db.Commit()
					require.NoError(t, err)
					m, err = newRegistryMaterialization(adapter, &view.anchor)
					require.NoError(t, err)
				}
				before, err := db.RootHash()
				require.NoError(t, err)
				integrityError := m.checkLocalMembership(ctx, view)
				if name == "existing" {
					require.NoError(t, integrityError)
				} else {
					require.Error(t, integrityError)
				}
				err = m.prepare(ctx, view)
				if name == "existing" {
					require.NoError(t, err)
					return
				}
				require.Error(t, err)
				_, err = m.classify(view.anchor.candidateHash, []byte("CCC-abcdef"))
				require.Error(t, err)
				after, err := db.RootHash()
				require.NoError(t, err)
				require.Equal(t, before, after)
			})
		}
	}
}

// Cancellation is triggered by a successful native ordinal read, not elapsed
// time or a goroutine. Count and marker reads remain native (T08-R2).
type qualRegistryOrdinalCancellation struct {
	state.UserAccountHandler
	cancel       context.CancelFunc
	ordinalsRead int
}

func (a *qualRegistryOrdinalCancellation) RetrieveValue(key []byte) ([]byte, uint32, error) {
	value, depth, err := a.UserAccountHandler.RetrieveValue(key)
	if err == nil && bytes.HasPrefix(key, []byte("ELRONDDRWA@membershipIndex@entry@")) {
		a.ordinalsRead++
		if a.ordinalsRead == 1 && a.cancel != nil {
			a.cancel()
		}
	}
	return value, depth, err
}

func TestQualDRWARegistryMaterializationOrdinalCancellation(t *testing.T) {
	for _, auto := range []bool{false, true} {
		for _, prepare := range []bool{false, true} {
			for _, cancelled := range []bool{false, true} {
				t.Run(fmt.Sprintf("auto_%t/prepare_%t/cancelled_%t", auto, prepare, cancelled), func(t *testing.T) {
					m, view, db, _ := qualRegistryMaterialization(t, auto)
					a, err := db.GetExistingAccount(core.SystemAccountAddress)
					require.NoError(t, err)
					u := a.(state.UserAccountHandler)
					// Independently seed two valid ordinal/marker pairs. The next
					// iteration must observe cancellation after reading the first.
					require.NoError(t, u.SaveKeyValue([]byte("ELRONDDRWA@membershipIndex@count"), []byte{0, 0, 0, 0, 0, 0, 0, 2}))
					for i, id := range []string{"AAA-abcdef", "BBB-123456"} {
						require.NoError(t, u.SaveKeyValue(qualIndexLiteralEntry(byte(i)), []byte(id)))
						require.NoError(t, u.SaveKeyValue(append([]byte("ELRONDDRWA@membership@"), []byte(id)...), []byte{1}))
					}
					require.NoError(t, db.SaveAccount(u))
					_, err = db.Commit()
					require.NoError(t, err)
					m, err = newRegistryMaterialization(db, &view.anchor)
					require.NoError(t, err)
					a, err = db.GetExistingAccount(core.SystemAccountAddress)
					require.NoError(t, err)
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					observed := &qualRegistryOrdinalCancellation{UserAccountHandler: a.(state.UserAccountHandler)}
					if cancelled {
						observed.cancel = cancel
					}
					m.state.accounts = &qualProtectedAccountSource{AccountsAdapter: db, account: observed}
					before, err := db.RootHash()
					require.NoError(t, err)
					require.NoError(t, ctx.Err(), "context starts active; cancellation occurs inside the read")
					if prepare {
						err = m.prepare(ctx, view)
					} else {
						err = m.checkLocalMembership(ctx, view)
					}
					if cancelled {
						require.ErrorIs(t, err, context.Canceled)
						require.Equal(t, 1, observed.ordinalsRead, "second ordinal must not be read")
					} else {
						require.NoError(t, err)
						require.Equal(t, 2, observed.ordinalsRead)
					}
					present, classifyErr := m.classify(view.anchor.candidateHash, []byte("AAA-abcdef"))
					if prepare && !cancelled {
						require.NoError(t, classifyErr)
						require.True(t, present)
					} else {
						require.Error(t, classifyErr)
						require.False(t, present, "failed or absent prepare publishes no usable view")
					}
					after, err := db.RootHash()
					require.NoError(t, err)
					require.Equal(t, before, after)
					require.Zero(t, db.JournalLen())
				})
			}
		}
	}
}

func TestQualDRWARegistryMaterializationConcurrent(t *testing.T) {
	m, view, _, _ := qualRegistryMaterialization(t, true)
	require.NoError(t, m.prepare(context.Background(), view))
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			present, err := m.classify(view.anchor.candidateHash, []byte("AAA-abcdef"))
			require.NoError(t, err)
			require.True(t, present)
		}()
	}
	wg.Wait()
	require.NoError(t, m.abort())
	_, err := m.classify(view.anchor.candidateHash, []byte("AAA-abcdef"))
	require.Error(t, err)
}

func TestQualDRWARegistryMaterializationDependencies(t *testing.T) {
	for _, name := range []string{"nil_anchor", "candidate", "meta", "executed", "root", "nil_accounts", "missing_system", "empty_data", "dirty"} {
		t.Run(name, func(t *testing.T) {
			m, _, _, adapter := qualRegistryMaterialization(t, false)
			a := &m.required
			var store state.AccountsAdapter = adapter
			switch name {
			case "nil_anchor":
				a = nil
			case "candidate":
				a.candidateHash = nil
			case "meta":
				a.metaHash = nil
			case "executed":
				a.executedHash = nil
			case "root":
				a.root = nil
			case "nil_accounts":
				store = nil
			case "missing_system":
				store = qualGenesisAccounts(t, false)
			case "empty_data":
				db := qualGenesisAccounts(t, false)
				u, err := db.LoadAccount(core.SystemAccountAddress)
				require.NoError(t, err)
				require.NoError(t, db.SaveAccount(u))
				_, err = db.Commit()
				require.NoError(t, err)
				store = db
			case "dirty":
				u, err := store.LoadAccount(bytes.Repeat([]byte{7}, 32))
				require.NoError(t, err)
				require.NoError(t, store.SaveAccount(u))
			}
			got, err := newRegistryMaterialization(store, a)
			require.Error(t, err)
			require.Nil(t, got)
		})
	}
}
