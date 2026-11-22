package drwa

import (
	"bytes"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// The existing native context fixture supplies independently hashed metadata
// around the actual native root. Its ancestry validation is not canonical
// finality/admission; these tests exercise private projection bookkeeping only.
func qualRegistrationProjectionAnchor(t *testing.T, root []byte) *metaRegistryAnchor {
	t.Helper()
	f := qualNativeMetaContext(t)
	f.references[1].LastExecutionResult.ExecutionResult.BaseExecutionResult.RootHash = bytes.Clone(root)
	f.encode(t)
	a, err := f.read()
	require.NoError(t, err)
	return a
}

func TestQualDRWARegistrationProjectionIncremental(t *testing.T) {
	r, s, proof := qualRegistrationCandidate(t, false, false)
	_, err := r.commitProjection(&proof.anchor)
	require.Error(t, err)
	require.NoError(t, r.RegisterToken(qualRegistrationCreator(t, "TOKEN-abcdef")))
	roots, outputs, err := r.commit()
	require.NoError(t, err)
	require.Len(t, outputs, 1)
	a := qualRegistrationProjectionAnchor(t, roots[0])
	c, err := r.commitProjection(a)
	require.NoError(t, err)
	require.Same(t, r.view.parent, c)
	require.Empty(t, proof.members)
	require.Equal(t, map[string]struct{}{"TOKEN-abcdef": {}}, c.members)
	_, err = r.commitProjection(a)
	require.Error(t, err)
	before := copyRegistryAnchor(a)
	// The returned native root and input anchor buffers cannot retag the cache.
	roots[0][0] ^= 1
	a.root[0] ^= 1
	nextAnchor := qualRegistrationProjectionAnchor(t, before.root)
	next, err := c.beginRegistration(s, qualRegistrationCoordinator(), 2, &before, nextAnchor)
	require.NoError(t, err)
	require.Same(t, c, next.view.parent)
	qualAssertRegistrationClassification(t, next, nextAnchor.candidateHash, "TOKEN-abcdef", true)
	qualAssertRegistrationClassification(t, next, nextAnchor.candidateHash, "TOKEN-abcdee", false)
	_, err = r.classify(before.candidateHash, []byte("TOKEN-abcdef"))
	require.Error(t, err)
	root, err := s.RootHash()
	require.NoError(t, err)
	err = next.RegisterToken(func(accounts state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
		_, _, err := qualRegistrationCreator(t, "TOKEN-abcdee")(accounts)
		require.NoError(t, err)
		return nil, nil, errors.New("next candidate creation fault")
	})
	require.Error(t, err)
	after, err := s.RootHash()
	require.NoError(t, err)
	require.Equal(t, root, after)
	qualAssertRegistrationClassification(t, next, nextAnchor.candidateHash, "TOKEN-abcdef", true)
	qualAssertRegistrationClassification(t, next, nextAnchor.candidateHash, "TOKEN-abcdee", false)
	require.NoError(t, next.RegisterToken(qualRegistrationCreator(t, "TOKEN-abcdee")))
	roots, outputs, err = next.commit()
	require.NoError(t, err)
	require.Len(t, outputs, 1)
	c2, err := next.commitProjection(qualRegistrationProjectionAnchor(t, roots[0]))
	require.NoError(t, err)
	require.Same(t, c, c2)
	require.Equal(t, map[string]struct{}{"TOKEN-abcdef": {}, "TOKEN-abcdee": {}}, c.members)
}

func TestQualDRWARegistrationProjectionHandoffGuards(t *testing.T) {
	for _, fault := range []string{"uncommitted", "commit-fault", "abort", "nil", "candidate", "meta", "executed", "root", "wrong-root"} {
		t.Run(fault, func(t *testing.T) {
			r, s, p := qualRegistrationCandidate(t, false, false)
			require.NoError(t, r.RegisterToken(qualRegistrationCreator(t, "TOKEN-abcdef")))
			a := qualRegistrationProjectionAnchor(t, p.anchor.root)
			if fault == "commit-fault" {
				s.commitErr = errors.New("native commit fault")
			}
			if fault == "abort" {
				require.NoError(t, r.abort())
			} else if fault != "uncommitted" {
				roots, _, err := r.commit()
				if fault == "commit-fault" {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
					a = qualRegistrationProjectionAnchor(t, roots[0])
				}
			}
			switch fault {
			case "nil":
				a = nil
			case "candidate":
				a.candidateHash = nil
			case "meta":
				a.metaHash = nil
			case "executed":
				a.executedHash = nil
			case "root":
				a.root = nil
			case "wrong-root":
				a.root[0] ^= 1
			}
			_, err := r.commitProjection(a)
			require.Error(t, err)
			require.Empty(t, r.view.parent.members)
			require.Same(t, r.view, r.view.parent.active)
		})
	}
}

func TestQualDRWARegistrationProjectionDiscard(t *testing.T) {
	for _, fault := range []string{"abort", "recovery", "commit", "open"} {
		t.Run(fault, func(t *testing.T) {
			r, s, p := qualRegistrationCandidate(t, false, false)
			require.NoError(t, r.RegisterToken(qualRegistrationCreator(t, "TOKEN-abcdef")))
			switch fault {
			case "abort":
				require.NoError(t, r.abort())
			case "recovery":
				s.revertErr = errors.New("native rollback fault")
				require.Error(t, r.RegisterToken(func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
					return nil, nil, errors.New("operation fault")
				}))
				_, err := r.discard()
				require.Error(t, err)
				require.NoError(t, r.recover())
			case "commit":
				_, _, err := r.commit()
				require.NoError(t, err)
			}
			c, err := r.discard()
			if fault == "commit" || fault == "open" {
				require.Error(t, err)
				require.Nil(t, c)
				return
			}
			require.NoError(t, err)
			require.Empty(t, c.members)
			require.Empty(t, r.view.added)
			require.True(t, sameRegistryAnchor(&c.anchor, &p.anchor))
			next, err := c.beginRegistration(s, qualRegistrationCoordinator(), 2, &p.anchor, &p.anchor)
			require.NoError(t, err)
			qualAssertRegistrationClassification(t, next, p.anchor.candidateHash, "TOKEN-abcdef", false)
		})
	}
}

func TestQualDRWARegistrationProjectionBeginGuards(t *testing.T) {
	for _, fault := range []string{"before", "candidate", "meta", "executed", "root", "nonce", "round", "epoch", "cap", "active", "nil-store"} {
		t.Run(fault, func(t *testing.T) {
			r, s, _ := qualRegistrationCandidate(t, false, true)
			roots, _, err := r.commit()
			require.NoError(t, err)
			a := qualRegistrationProjectionAnchor(t, roots[0])
			c, err := r.commitProjection(a)
			require.NoError(t, err)
			before, selected := copyRegistryAnchor(a), copyRegistryAnchor(a)
			cap := uint64(2)
			var accounts state.AccountsAdapter = s
			switch fault {
			case "before":
				before.metaHash[0] ^= 1
			case "candidate":
				selected.candidateHash = nil
			case "meta":
				selected.metaHash = nil
			case "executed":
				selected.executedHash[0] ^= 1
			case "root":
				selected.root[0] ^= 1
			case "nonce":
				selected.nonce++
			case "round":
				selected.round++
			case "epoch":
				selected.epoch++
			case "cap":
				cap = 1
			case "active":
				_, err = c.beginRegistration(s, qualRegistrationCoordinator(), 2, &before, &selected)
				require.NoError(t, err)
			case "nil-store":
				accounts = nil
			}
			_, err = c.beginRegistration(accounts, qualRegistrationCoordinator(), cap, &before, &selected)
			require.Error(t, err)
			require.Equal(t, map[string]struct{}{"AAA-abcdef": {}, "BBB-123456": {}}, c.members)
		})
	}
}

func TestQualDRWARegistrationProjectionBusy(t *testing.T) {
	r, _, p := qualRegistrationCandidate(t, false, false)
	c := r.view.parent
	c.mut.Lock()
	defer c.mut.Unlock()
	_, err := r.commitProjection(&p.anchor)
	require.ErrorIs(t, err, ErrExecutionBusy)
	_, err = r.discard()
	require.ErrorIs(t, err, ErrExecutionBusy)
	_, err = c.beginRegistration(nil, qualRegistrationCoordinator(), 2, &p.anchor, &p.anchor)
	require.ErrorIs(t, err, ErrExecutionBusy)
	var absent *committedRegistry
	_, err = absent.beginRegistration(nil, nil, 2, nil, nil)
	require.Error(t, err)
}
