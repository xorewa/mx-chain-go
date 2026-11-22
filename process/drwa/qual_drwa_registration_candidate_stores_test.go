package drwa

import (
	"bytes"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/state/factory"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// All selected coordinates below are experimental development fixtures under
// register XV-T41-S5-12; none selects production configuration or authority.
// Native user and peer databases have different account factories. Only the
// named fault boundaries are replaced; trie persistence and journals are real.
// The retained roots here are fixture prestates, not canonical admission.
type qualRegistrationPeerStore struct {
	*qualNativeStore
	rootErr error
}

func (s *qualRegistrationPeerStore) RootHash() ([]byte, error) {
	if s.rootErr != nil {
		return nil, s.rootErr
	}
	return s.qualNativeStore.RootHash()
}

func qualRegistrationPeer(t *testing.T) *qualRegistrationPeerStore {
	t.Helper()
	args, db := qualContainmentArgs(t)
	args.AccountFactory = factory.NewPeerAccountCreator()
	adb, err := state.NewPeerAccountsDB(args)
	require.NoError(t, err)
	s := &qualRegistrationPeerStore{qualNativeStore: &qualNativeStore{AccountsAdapter: adb, backing: db}}
	qualRegistrationPeerRating(t, s, 100)
	_, err = adb.Commit()
	require.NoError(t, err)
	return s
}

func qualRegistrationPeerRating(t *testing.T, s *qualRegistrationPeerStore, rating uint32) {
	t.Helper()
	a, err := s.LoadAccount(qualContainmentAddress)
	require.NoError(t, err)
	a.(state.PeerAccountHandler).SetRating(rating)
	require.NoError(t, s.SaveAccount(a))
}

func qualAssertRegistrationPeer(t *testing.T, s *qualRegistrationPeerStore, rating uint32) {
	t.Helper()
	a, err := s.GetExistingAccount(qualContainmentAddress)
	require.NoError(t, err)
	require.Equal(t, rating, a.(state.PeerAccountHandler).GetRating())
}

func qualRegistrationWithPeer(t *testing.T, next bool, peer *qualRegistrationPeerStore) (*registrationCandidate, *qualRegistrationCandidateStore, *registryProjection) {
	t.Helper()
	r, s, projection := qualRegistrationCandidate(t, false, false, peer)
	if next {
		require.NoError(t, r.abort())
		parent, err := r.discard()
		require.NoError(t, err)
		r, err = parent.beginRegistration(s, qualRegistrationCoordinator(), 2, &projection.anchor, &projection.anchor, peer)
		require.NoError(t, err)
	}
	return r, s, projection
}

func qualRegistrationCreatorWithPeer(t *testing.T, peer *qualRegistrationPeerStore, id string, rating uint32) func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
	t.Helper()
	create := qualRegistrationCreator(t, id)
	return func(accounts state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
		qualRegistrationPeerRating(t, peer, rating)
		return create(accounts)
	}
}

// P-05 and DS02 M6/M7: operation errors preserve the prior candidate on healthy
// undo; failed undo/persistence exposes neither partial receipts nor outputs.
// Recover must reconstruct BOTH roots, including an already-persisted user
// store or an equal-root peer journal, before any fresh handle is issued.
func TestQualDRWARegistrationCandidateNativeStores(t *testing.T) {
	for _, path := range []string{"reconstruct", "begin"} {
		for _, fault := range []string{"healthy-rollback", "rollback-user", "rollback-peer", "rollback-both", "abort", "abort-user", "abort-peer", "abort-both", "commit-peer", "recover-peer", "missing-peer-root", "equal-peer-root"} {
			t.Run(path+"/"+fault, func(t *testing.T) {
				peer := qualRegistrationPeer(t)
				r, user, projection := qualRegistrationWithPeer(t, path == "begin", peer)
				user.reverts, peer.reverts = 0, 0
				peerRoot, err := peer.RootHash()
				require.NoError(t, err)
				peerRoot = bytes.Clone(peerRoot)
				node, err := peer.backing.Get(peerRoot)
				require.NoError(t, err)
				require.Same(t, r.writer.boundary, r.view.material.owner)
				require.Len(t, r.writer.boundary.stores, 2)
				require.NoError(t, r.RegisterToken(qualRegistrationCreatorWithPeer(t, peer, "TOKEN-abcdef", 90)))
				userBefore, err := user.RootHash()
				require.NoError(t, err)
				peerBefore, err := peer.RootHash()
				require.NoError(t, err)
				userJournal, peerJournal := user.JournalLen(), peer.JournalLen()
				original, userFault, peerFault := errors.New("native operation fault"), errors.New("user undo fault"), errors.New("peer undo fault")
				if fault == "rollback-user" || fault == "rollback-both" || fault == "abort-user" || fault == "abort-both" {
					user.revertErr = userFault
				}
				if fault == "rollback-peer" || fault == "rollback-both" || fault == "abort-peer" || fault == "abort-both" {
					peer.revertErr = peerFault
				}
				switch fault {
				case "abort", "abort-user", "abort-peer", "abort-both":
					err = r.abort()
					if fault == "abort" {
						require.NoError(t, err)
					} else {
						require.Error(t, err)
					}
				case "commit-peer", "missing-peer-root":
					peer.commitErr = peerFault
					roots, out, commitErr := r.commit()
					require.ErrorIs(t, commitErr, peerFault)
					require.Nil(t, roots)
					require.Nil(t, out)
					require.False(t, r.nativeCommitted)
					require.Equal(t, 1, user.commits)
					require.Equal(t, 1, peer.commits)
					require.Zero(t, user.JournalLen())
					require.Positive(t, peer.JournalLen())
					actual, e := user.RootHash()
					require.NoError(t, e)
					require.NotEqual(t, projection.anchor.root, actual)
				default:
					if fault == "recover-peer" || fault == "equal-peer-root" {
						peer.revertErr = peerFault
					}
					err = r.RegisterToken(func(accounts state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
						rating := uint32(70)
						if fault == "equal-peer-root" {
							rating = 100
						}
						_, _, e := qualRegistrationCreatorWithPeer(t, peer, "TOKEN-abcdee", rating)(accounts)
						require.NoError(t, e)
						return nil, nil, original
					})
					require.ErrorIs(t, err, original)
				}
				if user.revertErr != nil {
					require.ErrorIs(t, err, userFault)
				}
				if peer.revertErr != nil {
					require.ErrorIs(t, err, peerFault)
				}
				if fault == "healthy-rollback" {
					require.Same(t, original, err)
					for i, s := range []state.AccountsAdapter{user, peer} {
						actual, e := s.RootHash()
						require.NoError(t, e)
						require.Equal(t, [][]byte{userBefore, peerBefore}[i], actual)
						require.Equal(t, []int{userJournal, peerJournal}[i], s.JournalLen())
					}
					qualAssertRegistrationPeer(t, peer, 90)
					qualAssertRegistrationClassification(t, r, projection.anchor.candidateHash, "TOKEN-abcdef", true)
					qualAssertRegistrationClassification(t, r, projection.anchor.candidateHash, "TOKEN-abcdee", false)
					roots, out, e := r.commit()
					require.NoError(t, e)
					require.Equal(t, [][]byte{userBefore, peerBefore}, roots)
					require.Len(t, out, 1)
					require.Equal(t, []byte("TOKEN-abcdef"), out[0].ReturnData[0])
					return
				}
				_, e := r.classify(projection.anchor.candidateHash, []byte("TOKEN-abcdee"))
				require.Error(t, e)
				roots, out, e := r.commit()
				require.Error(t, e)
				require.Nil(t, roots)
				require.Nil(t, out)
				if fault != "commit-peer" && fault != "missing-peer-root" {
					require.Equal(t, 1, user.reverts)
					require.Equal(t, 1, peer.reverts, "abort/undo must attempt every participating store")
				}
				if fault == "recover-peer" {
					peer.recreateErr = peerFault
					require.ErrorIs(t, r.recover(), peerFault)
					require.Equal(t, 1, user.recreates)
					require.Equal(t, 1, peer.recreates)
					_, e = r.discard()
					require.ErrorIs(t, e, peerFault)
					peer.recreateErr = nil
				}
				if fault == "missing-peer-root" {
					require.NoError(t, peer.backing.Remove(peerRoot))
					require.ErrorIs(t, r.recover(), peerFault)
					_, e = r.discard()
					require.ErrorIs(t, e, peerFault)
					require.NoError(t, peer.backing.Put(peerRoot, node))
				}
				if fault == "equal-peer-root" {
					actual, e := peer.RootHash()
					require.NoError(t, e)
					require.Equal(t, peerRoot, actual)
					require.Positive(t, peer.JournalLen())
				}
				if fault != "abort" {
					require.NoError(t, r.recover())
					require.Positive(t, user.recreates)
					require.Positive(t, peer.recreates)
				}
				for i, s := range []state.AccountsAdapter{user, peer} {
					actual, e := s.RootHash()
					require.NoError(t, e)
					require.Equal(t, [][]byte{projection.anchor.root, peerRoot}[i], actual)
					require.Zero(t, s.JournalLen())
				}
				qualAssertRegistrationPeer(t, peer, 100)
				require.Empty(t, qualRegistryValue(t, user.qualNativeStore, registryMemberKeyPrefix+"TOKEN-abcdef"))
				require.ErrorIs(t, r.DRWAExecutionError(), ErrExecutionClosed)
				parent, e := r.discard()
				require.NoError(t, e)
				fresh, e := parent.beginRegistration(user, qualRegistrationCoordinator(), 2, &projection.anchor, &projection.anchor, peer)
				require.NoError(t, e)
				qualAssertRegistrationClassification(t, fresh, projection.anchor.candidateHash, "TOKEN-abcdef", false)
				peer.revertErr, peer.commitErr, user.revertErr = nil, nil, nil
				require.NoError(t, fresh.RegisterToken(qualRegistrationCreatorWithPeer(t, peer, "TOKEN-abcdef", 80)))
				roots, out, e = fresh.commit()
				require.NoError(t, e)
				require.Len(t, roots, 2)
				require.Len(t, out, 1)
				qualAssertRegistrationPeer(t, peer, 80)
			})
		}
	}
}

func TestQualDRWARegistrationCandidateStoreGuards(t *testing.T) {
	for _, path := range []string{"reconstruct", "begin"} {
		for _, fault := range []string{"nil", "typed-nil", "dirty", "root-error"} {
			t.Run(path+"/"+fault, func(t *testing.T) {
				peer := qualRegistrationPeer(t)
				r, user, projection := qualRegistrationCandidate(t, false, false)
				require.NoError(t, r.abort())
				parent, err := r.discard()
				require.NoError(t, err)
				var store state.AccountsAdapter = peer
				switch fault {
				case "nil":
					store = nil
				case "typed-nil":
					store = (*state.PeerAccountsDB)(nil)
				case "dirty":
					qualRegistrationPeerRating(t, peer, 99)
				case "root-error":
					peer.rootErr = errors.New("peer root fault")
				}
				if path == "begin" {
					r, err = parent.beginRegistration(user, qualRegistrationCoordinator(), 2, &projection.anchor, &projection.anchor, store)
				} else {
					r, err = reconstructRegistrationCandidate(user, qualRegistrationCoordinator(), 2, projection, store)
				}
				require.Error(t, err)
				require.Nil(t, r)
				require.Nil(t, parent.active)
				require.Zero(t, user.JournalLen())
			})
		}
	}
}

func TestQualDRWARegistrationCandidateDiscardStores(t *testing.T) {
	for _, fault := range []string{"root-error", "different-root", "equal-root-dirty"} {
		t.Run(fault, func(t *testing.T) {
			peer := qualRegistrationPeer(t)
			r, _, projection := qualRegistrationWithPeer(t, false, peer)
			require.NoError(t, r.abort())
			if fault == "root-error" {
				peer.rootErr = errors.New("peer root fault")
			} else {
				rating := uint32(70)
				if fault == "equal-root-dirty" {
					rating = 100
				}
				qualRegistrationPeerRating(t, peer, rating)
				if fault == "different-root" {
					_, err := peer.AccountsAdapter.Commit()
					require.NoError(t, err)
				}
			}
			parent, err := r.discard()
			require.Error(t, err)
			require.Nil(t, parent)
			require.Same(t, r.view, r.view.parent.active)
			require.Equal(t, projection.anchor.root, r.view.parent.anchor.root)
		})
	}
}
