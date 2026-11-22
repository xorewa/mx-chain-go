package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

type qualRegistrationCandidateStore struct {
	*qualNativeStore
	reads int
}

func (s *qualRegistrationCandidateStore) GetExistingAccount(address []byte) (vmcommon.AccountHandler, error) {
	s.reads++
	return s.qualNativeStore.GetExistingAccount(address)
}

func qualRegistrationCoordinator() sharding.Coordinator {
	return &testscommon.ShardsCoordinatorMock{SelfIDCalled: func() uint32 { return core.MetachainShardId }}
}

// Reuse the real T08 proof producer/independent proof reader, not a test-supplied
// membership map. The executing store is the very native store at the proved
// root. These fixtures establish component semantics, not canonical finality.
func qualRegistrationCandidate(t *testing.T, auto, existing bool, participating ...state.AccountsAdapter) (*registrationCandidate, *qualRegistrationCandidateStore, *registryProjection) {
	t.Helper()
	count := make([]byte, 8)
	if existing {
		count[7] = 2
	}
	f := qualRegistryTransport(t, auto, count, []byte{1})
	transport, err := newRegistryTransport(f.reader, 2, f.limit)
	require.NoError(t, err)
	projection, err := transport.reconstruct(f.anchor, f.count, f.members)
	require.NoError(t, err)
	s := &qualRegistrationCandidateStore{qualNativeStore: &qualNativeStore{AccountsAdapter: f.source}}
	r, err := reconstructRegistrationCandidate(s, qualRegistrationCoordinator(), 2, projection, participating...)
	require.NoError(t, err)
	return r, s, projection
}

func qualAssertRegistrationClassification(t *testing.T, r *registrationCandidate, candidate []byte, id string, expected bool) {
	t.Helper()
	got, err := r.classify(candidate, []byte(id))
	require.NoError(t, err)
	require.Equal(t, expected, got)
}

func TestQualDRWARegistrationCandidateVisibility(t *testing.T) {
	for _, auto := range []bool{false, true} {
		for _, existing := range []bool{false, true} {
			t.Run(fmt.Sprintf("auto_%t/existing_%t", auto, existing), func(t *testing.T) {
				r, s, projection := qualRegistrationCandidate(t, auto, existing)
				candidate := bytes.Clone(projection.anchor.candidateHash)
				root := bytes.Clone(projection.anchor.root)
				reads := s.reads
				qualAssertRegistrationClassification(t, r, candidate, "AAA-abcdef", existing)
				qualAssertRegistrationClassification(t, r, candidate, "BBB-123456", existing)
				qualAssertRegistrationClassification(t, r, candidate, "TOKEN-abcddd", false)
				require.Equal(t, reads, s.reads, "classification must not read native accounts")
				if !existing {
					id := []byte("TOKEN-abcdef")
					creator := qualRegistrationCreator(t, string(id))
					require.NoError(t, r.RegisterToken(func(accounts state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
						_, out, err := creator(accounts)
						return id, out, err
					}))
					id[0] ^= 1
					qualAssertRegistrationClassification(t, r, candidate, "TOKEN-abcdef", true)
					require.Empty(t, projection.members, "input proof projection must not acquire tentative members")
					require.NoError(t, r.RegisterToken(qualRegistrationCreator(t, "TOKEN-abcdee")))
					qualAssertRegistrationClassification(t, r, candidate, "TOKEN-abcdee", true)
					require.Equal(t, []byte{1}, qualRegistryValue(t, s.qualNativeStore, registryMemberKeyPrefix+"TOKEN-abcdef"))
				}
				// Neither the caller's map nor anchor aliases the admitted view.
				projection.members["TOKEN-abcddd"] = struct{}{}
				projection.anchor.candidateHash[0] ^= 1
				qualAssertRegistrationClassification(t, r, candidate, "TOKEN-abcddd", false)
				_, err := r.classify(projection.anchor.candidateHash, []byte("TOKEN-abcddd"))
				require.ErrorIs(t, err, errInvalidMetaContext)
				called := false
				require.ErrorIs(t, r.RegisterToken(func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
					called = true
					return nil, nil, nil
				}), ErrInvalidRegistryRegistration)
				require.False(t, called)
				roots, outputs, err := r.commit()
				require.NoError(t, err)
				require.Len(t, roots, 1)
				if existing {
					require.Empty(t, outputs)
					require.Equal(t, root, roots[0])
				} else {
					require.Len(t, outputs, 2)
					require.Equal(t, []byte("TOKEN-abcdef"), outputs[0].ReturnData[0])
					require.Equal(t, []byte("TOKEN-abcdee"), outputs[1].ReturnData[0])
				}
				_, err = r.classify(candidate, []byte("TOKEN-abcddd"))
				require.ErrorIs(t, err, ErrExecutionClosed)
				require.ErrorIs(t, r.RegisterToken(qualRegistrationCreator(t, "TOKEN-abcddd")), ErrExecutionClosed)
			})
		}
	}
}

func TestQualDRWARegistrationCandidateRollback(t *testing.T) {
	for _, fault := range []string{"creator", "save", "invalid-id", "nil-output", "failed-output", "duplicate", "count-tamper"} {
		t.Run(fault, func(t *testing.T) {
			r, s, projection := qualRegistrationCandidate(t, false, false)
			candidate := projection.anchor.candidateHash
			require.NoError(t, r.RegisterToken(qualRegistrationCreator(t, "TOKEN-abcdef")))
			before, err := s.RootHash()
			require.NoError(t, err)
			journal := s.JournalLen()
			original := errors.New("creator fault")
			creator := qualRegistrationCreator(t, "TOKEN-abcdee")
			err = r.RegisterToken(func(accounts state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
				id, out, err := creator(accounts)
				if err != nil {
					return nil, nil, err
				}
				switch fault {
				case "creator":
					return nil, nil, original
				case "save":
					s.saveErr = original
				case "invalid-id":
					id = []byte("invalid")
				case "nil-output":
					out = nil
				case "failed-output":
					out.ReturnCode = vmcommon.UserError
				case "duplicate":
					id = []byte("TOKEN-abcdef")
				case "count-tamper":
					a, e := accounts.GetExistingAccount(core.SystemAccountAddress)
					require.NoError(t, e)
					require.NoError(t, a.(state.UserAccountHandler).SaveKeyValue([]byte(registryCountKey), []byte{0, 0, 0, 0, 0, 0, 0, 2}))
					require.NoError(t, accounts.SaveAccount(a))
				}
				return id, out, nil
			})
			require.Error(t, err)
			s.saveErr = nil
			after, err := s.RootHash()
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.Equal(t, journal, s.JournalLen())
			require.Equal(t, uint64(1), binary.BigEndian.Uint64(qualRegistryValue(t, s.qualNativeStore, registryCountKey)))
			qualAssertRegistrationClassification(t, r, candidate, "TOKEN-abcdef", true)
			qualAssertRegistrationClassification(t, r, candidate, "TOKEN-abcdee", false)
			require.NoError(t, r.RegisterToken(creator))
			_, outputs, err := r.commit()
			require.NoError(t, err)
			require.Len(t, outputs, 2, "failed operation must not leak a pending output")
		})
	}
}

func TestQualDRWARegistrationCandidateContainment(t *testing.T) {
	for _, fault := range []string{"rollback", "commit", "abort", "abort-rollback", "panic"} {
		t.Run(fault, func(t *testing.T) {
			r, s, projection := qualRegistrationCandidate(t, false, false)
			candidate := projection.anchor.candidateHash
			require.NoError(t, r.RegisterToken(qualRegistrationCreator(t, "TOKEN-abcdef")))
			original, boundary := errors.New("creator fault"), errors.New("native boundary fault")
			switch fault {
			case "rollback":
				s.revertErr = boundary
				err := r.RegisterToken(func(accounts state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
					_, _, err := qualRegistrationCreator(t, "TOKEN-abcdee")(accounts)
					require.NoError(t, err)
					return nil, nil, original
				})
				require.ErrorIs(t, err, original)
				require.ErrorIs(t, err, boundary)
			case "commit":
				s.commitErr = boundary
				roots, outputs, err := r.commit()
				require.ErrorIs(t, err, boundary)
				require.Nil(t, roots)
				require.Nil(t, outputs)
			case "abort":
				require.NoError(t, r.abort())
			case "abort-rollback":
				s.revertErr = boundary
				require.ErrorIs(t, r.abort(), boundary)
			case "panic":
				require.PanicsWithValue(t, "native panic", func() {
					_ = r.RegisterToken(func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) { panic("native panic") })
				})
			}
			_, err := r.classify(candidate, []byte("TOKEN-abcdef"))
			require.Error(t, err, "unusable candidate must not yield ordinary absence")
			_, outputs, err := r.commit()
			require.Error(t, err)
			require.Nil(t, outputs)
			require.Error(t, r.RegisterToken(qualRegistrationCreator(t, "TOKEN-abcddd")))
			if fault != "abort" {
				s.recreateErr = boundary
				require.ErrorIs(t, r.recover(), boundary)
				_, err = r.classify(candidate, []byte("TOKEN-abcddd"))
				require.Error(t, err)
				s.recreateErr = nil
				require.NoError(t, r.recover())
			}
			after, err := s.RootHash()
			require.NoError(t, err)
			require.Equal(t, projection.anchor.root, after)
			require.Zero(t, s.JournalLen())
			require.Equal(t, uint64(0), binary.BigEndian.Uint64(qualRegistryValue(t, s.qualNativeStore, registryCountKey)))
			require.Empty(t, qualRegistryValue(t, s.qualNativeStore, registryMemberKeyPrefix+"TOKEN-abcdef"))
			_, err = r.classify(candidate, []byte("TOKEN-abcdef"))
			require.ErrorIs(t, err, ErrExecutionClosed)
			fresh, err := reconstructRegistrationCandidate(s, qualRegistrationCoordinator(), 2, projection)
			require.NoError(t, err)
			qualAssertRegistrationClassification(t, fresh, candidate, "TOKEN-abcdef", false)
			require.NoError(t, fresh.RegisterToken(qualRegistrationCreator(t, "TOKEN-abcdef")))
			qualAssertRegistrationClassification(t, fresh, candidate, "TOKEN-abcdef", true)
		})
	}
}

func TestQualDRWARegistrationCandidateBusy(t *testing.T) {
	r, _, projection := qualRegistrationCandidate(t, false, false)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	checkBusy := func() {
		_, err := r.classify(projection.anchor.candidateHash, []byte("TOKEN-abcddd"))
		require.ErrorIs(t, err, ErrExecutionBusy)
		require.ErrorIs(t, r.RegisterToken(qualRegistrationCreator(t, "TOKEN-abcdee")), ErrExecutionBusy)
		_, _, err = r.commit()
		require.ErrorIs(t, err, ErrExecutionBusy)
		require.ErrorIs(t, r.abort(), ErrExecutionBusy)
		require.ErrorIs(t, r.recover(), ErrExecutionBusy)
	}
	go func() {
		done <- r.RegisterToken(func(accounts state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
			checkBusy() // Reentry on the native creator's own goroutine.
			close(entered)
			<-release
			return qualRegistrationCreator(t, "TOKEN-abcdef")(accounts)
		})
	}()
	<-entered
	checkBusy() // Concurrent calls cannot read a half-published registration.
	close(release)
	require.NoError(t, <-done)
	qualAssertRegistrationClassification(t, r, projection.anchor.candidateHash, "TOKEN-abcdef", true)
}

func TestQualDRWARegistrationCandidateGuards(t *testing.T) {
	for _, fault := range []string{"nil", "members", "candidate", "meta", "executed", "root", "wrong-root", "cap", "shard", "nil-accounts", "uncommitted"} {
		t.Run(fault, func(t *testing.T) {
			_, s, projection := qualRegistrationCandidate(t, false, true)
			var accounts state.AccountsAdapter = s
			coordinator, cap := qualRegistrationCoordinator(), uint64(2)
			switch fault {
			case "nil":
				projection = nil
			case "members":
				projection.members = nil
			case "candidate":
				projection.anchor.candidateHash = nil
			case "meta":
				projection.anchor.metaHash = nil
			case "executed":
				projection.anchor.executedHash = nil
			case "root":
				projection.anchor.root = nil
			case "wrong-root":
				projection.anchor.root[0] ^= 1
			case "cap":
				cap = 1
			case "shard":
				coordinator = &testscommon.ShardsCoordinatorMock{SelfIDCalled: func() uint32 { return 0 }}
			case "nil-accounts":
				accounts = nil
			case "uncommitted":
				_, _, err := qualRegistrationCreator(t, "TOKEN-abcdef")(s)
				require.NoError(t, err)
			}
			root, err := s.RootHash()
			require.NoError(t, err)
			journal := s.JournalLen()
			r, err := reconstructRegistrationCandidate(accounts, coordinator, cap, projection)
			require.Error(t, err)
			require.Nil(t, r)
			after, err := s.RootHash()
			require.NoError(t, err)
			require.Equal(t, root, after)
			require.Equal(t, journal, s.JournalLen())
		})
	}
}
