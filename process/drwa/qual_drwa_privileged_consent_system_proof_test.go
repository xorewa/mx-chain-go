package drwa

import (
	"bytes"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func qualConsentWitnessBytes(w PrivilegedConsentWitness) int {
	used := 0
	for _, nodes := range [][][]byte{w.AccountProof, w.DataProof, w.EOAProof} {
		for _, node := range nodes {
			used += len(node)
		}
	}
	return used
}

type qualConsentEOAProofBoundary struct {
	common.Trie
	calls    int
	boundary func() (bool, error)
}

func (p *qualConsentEOAProofBoundary) VerifyProof(root, address []byte, nodes [][]byte) (bool, error) {
	p.calls++
	if p.calls == 3 {
		return p.boundary()
	}
	return p.Trie.VerifyProof(root, address, nodes)
}

type qualConsentEOACacheBoundary struct {
	common.StorageManager
	calls, at int
	failure   error
}

func (s *qualConsentEOACacheBoundary) Put(key, value []byte) error {
	s.calls++
	if s.calls == s.at {
		return s.failure
	}
	return s.StorageManager.Put(key, value)
}

type qualConsentEmptyEOATrie struct{ common.Trie }

func (tr *qualConsentEmptyEOATrie) Get(_ []byte) ([]byte, uint32, error) {
	return nil, 0, nil
}

func TestQualDRWAPrivilegedConsentSystemProofGuards(t *testing.T) {
	for _, name := range []string{"no_EOA_proof", "empty_EOA_node", "aggregate_limit", "verify_false", "verify_error", "cache_error", "empty_EOA_account", "wrong_EOA_account_address"} {
		t.Run(name, func(t *testing.T) {
			ctx := qualConsentContext(t)
			c, owner := qualConsentInstall(t, ctx, 0)
			s := qualConsentScope()
			qualConsentProcess(t, ctx, qualConsentData(s), nil)
			_, _, err := owner.Commit()
			require.NoError(t, err)
			h, w, budget := qualConsentWitness(t, ctx, 0)
			r := qualConsentReader(t, ctx)
			// Prime the REAL native proof cache before injecting a dependency
			// failure. This prevents downstream cache absence from hiding a guard.
			require.NoError(t, c.ReadEvidence(r, h, 1, s, w, budget))
			failure := errors.New("qualification EOA proof boundary")
			expected := error(ErrInvalidAccountWitness)
			switch name {
			case "no_EOA_proof":
				w.EOAProof = nil
			case "empty_EOA_node":
				// Native membership verification stops at a valid leaf and
				// ignores trailing nodes. The resource shape must still reject
				// an empty trailing node, even with an otherwise valid proof.
				w.EOAProof = append(w.EOAProof, nil)
			case "aggregate_limit":
				budget-- // both system proofs fit; all three together do not
			case "verify_false":
				r.proofTrie = &qualConsentEOAProofBoundary{Trie: r.proofTrie, boundary: func() (bool, error) { return false, nil }}
			case "verify_error":
				r.proofTrie = &qualConsentEOAProofBoundary{Trie: r.proofTrie, boundary: func() (bool, error) { return true, failure }}
			case "cache_error":
				expected = failure
				r.args.StorageManager = &qualConsentEOACacheBoundary{StorageManager: r.args.StorageManager, at: len(w.AccountProof) + len(w.DataProof) + 1, failure: failure}
			case "empty_EOA_account":
				expected = ErrPrivilegedConsent
				r.proofTrie = &qualConsentProofTrie{Trie: r.proofTrie, boundary: func(tr common.Trie) (common.Trie, error) { return &qualConsentEmptyEOATrie{tr}, nil }}
				saved, e := ctx.Accounts.GetExistingAccount(s.Address)
				require.NoError(t, e)
				r.accountFactory = &qualConsentProofFactory{AccountFactory: r.accountFactory, boundary: func(_ vmcommon.AccountHandler) (vmcommon.AccountHandler, error) { return saved, nil }}
				original := r.args.Marshaller
				r.args.Marshaller = &qualConsentReadMarshal{original, func(v interface{}, b []byte) error {
					if _, account := v.(state.UserAccountHandler); account && len(b) == 0 {
						return nil // explicit fail-open fault; not native evidence
					}
					return original.Unmarshal(v, b)
				}}
			case "wrong_EOA_account_address":
				expected = ErrPrivilegedConsent
				foreign, e := ctx.Accounts.LoadAccount(bytes.Repeat([]byte{0x33}, 32))
				require.NoError(t, e)
				foreign.IncreaseNonce(1)
				foreignRaw, e := ctx.Marshalizer.Marshal(foreign)
				require.NoError(t, e)
				original := r.args.Marshaller
				calls := 0
				r.args.Marshaller = &qualConsentReadMarshal{original, func(v interface{}, b []byte) error {
					if _, account := v.(state.UserAccountHandler); account {
						calls++
						if calls == 2 {
							return original.Unmarshal(v, foreignRaw)
						}
					}
					return original.Unmarshal(v, b)
				}}
			}
			require.NotPanics(t, func() { err = c.ReadEvidence(r, h, 1, s, w, budget) })
			require.ErrorIs(t, err, expected)
		})
	}
}

func TestQualDRWAPrivilegedConsentMixedRoots(t *testing.T) {
	ctx := qualConsentContext(t)
	c, owner := qualConsentInstall(t, ctx, 0)
	s := qualConsentScope()
	qualConsentProcess(t, ctx, qualConsentData(s), nil)
	_, _, err := owner.Commit()
	require.NoError(t, err)
	oldH, oldW, oldBudget := qualConsentWitness(t, ctx, 0)
	a, err := ctx.Accounts.GetExistingAccount(s.Address)
	require.NoError(t, err)
	a.IncreaseNonce(1)
	require.NoError(t, ctx.Accounts.SaveAccount(a))
	h, w, budget := qualConsentWitness(t, ctx, 0)
	r := qualConsentReader(t, ctx)
	require.ErrorIs(t, c.ReadEvidence(r, h, 1, s, w, budget), ErrPrivilegedConsent, "same-root current nonce makes old consent stale")
	mixed := w
	mixed.EOAProof = oldW.EOAProof
	require.ErrorIs(t, c.ReadEvidence(r, h, 1, s, mixed, qualConsentWitnessBytes(mixed)), ErrInvalidAccountWitness, "old EOA proof cannot satisfy new system-record root")
	mixed = oldW
	mixed.EOAProof = w.EOAProof
	require.ErrorIs(t, c.ReadEvidence(r, oldH, 1, s, mixed, qualConsentWitnessBytes(mixed)), ErrInvalidAccountWitness)
	require.NoError(t, c.ReadEvidence(r, oldH, 1, s, oldW, oldBudget))
}

func TestQualDRWAPrivilegedConsentLocusForgery(t *testing.T) {
	for _, name := range []string{"EOA_only", "system_family_only", "EOA_replacement"} {
		t.Run(name, func(t *testing.T) {
			ctx := qualConsentContext(t)
			c, owner := qualConsentInstall(t, ctx, 0)
			s := qualConsentScope()
			if name == "EOA_replacement" {
				qualConsentProcess(t, ctx, qualConsentData(s), nil)
				_, _, err := owner.Commit()
				require.NoError(t, err)
			}
			original := s
			s.Roles = []byte("forged alternate roles")
			address := s.Address
			if name == "system_family_only" {
				address = bytes.Clone(core.SystemAccountAddress)
				address[len(address)-1] = 0xfe
			}
			a, err := ctx.Accounts.LoadAccount(address)
			require.NoError(t, err)
			// Hostile imported-state fixture: a native user-account value is
			// never the system record, even if its bytes/nonce match exactly.
			require.NoError(t, a.(state.UserAccountHandler).SaveKeyValue(privilegedConsentRecordKey(s.Address, s.Token, s.Program), encodeExperimentalConsent(s, a.GetNonce(), 0)))
			require.NoError(t, ctx.Accounts.SaveAccount(a))
			h, w, budget := qualConsentWitnessScope(t, ctx, 0, s)
			r := qualConsentReader(t, ctx)
			require.Error(t, c.ReadEvidence(r, h, 1, s, w, budget))
			if name == "EOA_replacement" {
				require.NoError(t, c.ReadEvidence(r, h, 1, original, w, budget), "EOA data cannot replace the authenticated system record")
			}
		})
	}
}
