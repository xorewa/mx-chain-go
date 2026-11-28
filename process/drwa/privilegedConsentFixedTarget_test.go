package drwa

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/integrationtests"
	"github.com/multiversx/mx-chain-go/testscommon/storageManager"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// The oracle describes a fixed business identity as six independent categorical
// coordinates, of which the first four are also required by the consent scope.
// Different ordinary business choices model distinct identities; this does not
// construct or exercise any native ingress, call route, or operational scenario.
func TestSP230FixedTargetReferenceModel(t *testing.T) {
	mkFixed := func(v [6]string) privilegedFixedTargetIdentity {
		return privilegedFixedTargetIdentity{[]byte(v[0]), []byte(v[1]), []byte(v[2]), []byte(v[3]), []byte(v[4]), []byte(v[5])}
	}
	mkScope := func(v [4]string) PrivilegedConsentScope {
		return PrivilegedConsentScope{Domain: []byte(v[0]), Token: []byte(v[1]), Program: []byte(v[2]), Target: []byte(v[3])}
	}
	original := [6]string{"domain A", "token A", "programme A", "target A", "action A", "plan A"}
	alternate := [6]string{"domain B", "token B", "programme B", "target B", "action B", "plan B"}
	fixed := mkFixed(original)
	for selectedMask := 0; selectedMask < 1<<6; selectedMask++ {
		selected := original
		for i := range selected {
			if selectedMask&(1<<i) != 0 {
				selected[i] = alternate[i]
			}
		}
		for scopeMask := 0; scopeMask < 1<<4; scopeMask++ {
			var scope [4]string
			copy(scope[:], original[:4])
			for i := range scope {
				if scopeMask&(1<<i) != 0 {
					scope[i] = alternate[i]
				}
			}
			// By definition of a fixed action and target, all stage choices
			// must equal the original, as must the business context of consent.
			want := selectedMask == 0 && scopeMask == 0
			err := checkPrivilegedFixedTarget(fixed, mkFixed(selected), mkScope(scope))
			require.Equal(t, want, err == nil, "identity selection %d/%d", selectedMask, scopeMask)
		}
	}
	for i := range original {
		missing := original
		missing[i] = ""
		scope := [4]string{missing[0], missing[1], missing[2], missing[3]}
		require.ErrorIs(t, checkPrivilegedFixedTarget(mkFixed(missing), mkFixed(missing), mkScope(scope)), ErrPrivilegedConsent)
	}
	// A different selected business action is decided by the identity check
	// alone, before requesting any canonical account evidence.
	other := original
	other[4] = alternate[4]
	var c *PrivilegedConsentCandidate
	require.ErrorIs(t, c.readFixedTargetCanonicalEvidence(nil, fixed, mkFixed(other),
		privilegedAdmissionSelection{scope: mkScope([4]string{original[0], original[1], original[2], original[3]})},
		canonicalResultWitness{}, nil, 0), ErrPrivilegedConsent)
}

// Use a real disk AccountsDB with fresh caches on reopen, and the existing
// explicit unit canonical/header oracle. No native authorization, transaction,
// live finality, or profile selection is inferred from the fixture.
func TestSP230FixedTargetCanonicalDiskAdmission(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts")
	store, closeStore := qualConvergenceDiskOpen(t, path, false)
	protected, err := newProtectedState(store)
	require.NoError(t, err)
	require.NoError(t, protected.provisionGenesis())
	require.NoError(t, qualContainmentBalance(store, 100))
	// The data record is a synthetic already-admitted native consent. Both the
	// privileged and unrelated ordinary data are persisted by the real store.
	scope := qualConsentScope()
	scope.Address = bytes.Clone(qualContainmentAddress)
	account, err := store.GetExistingAccount(scope.Address)
	require.NoError(t, err)
	const epoch = uint32(3)
	consent := encodeExperimentalConsent(scope, account.GetNonce(), epoch)
	require.NoError(t, savePrivilegedConsent(store, scope.Address, scope.Token, scope.Program, consent))
	other := scope
	other.Token, other.Program = []byte("TOKEN-second"), []byte("fixture-second-program")
	otherConsent := encodeExperimentalConsent(other, account.GetNonce(), epoch)
	require.NoError(t, savePrivilegedConsent(store, other.Address, other.Token, other.Program, otherConsent))
	require.Equal(t, consent, qualConsentScopedValue(t, store, scope))
	require.Equal(t, otherConsent, qualConsentScopedValue(t, store, other))
	fixed := privilegedFixedTargetIdentity{scope.Domain, scope.Token, scope.Program, scope.Target, []byte("fixture-action"), []byte("fixture-plan")}

	f := newCanonicalTestFixture(t, 1, core.MetachainShardId)
	// The shared disk fixture uses the integration test hasher. Build both the
	// canonical header scaffold and fresh proof reader with that same hasher.
	f.r.codec.hasher = integrationtests.TestHasher
	newReader := func() *canonicalResultReader {
		args := f.reader.accounts.args
		args.Hasher = integrationtests.TestHasher
		cache := testscommon.NewMemDbMock()
		args.StorageManager = &storageManager.StorageManagerStub{GetCalled: cache.Get, GetFromCurrentEpochCalled: cache.Get,
			PutCalled: cache.Put, GetIdentifierCalled: cache.GetIdentifier, GetStateStatsHandlerCalled: cache.GetStateStatsHandler}
		accounts, readErr := NewResultAccountReader(args)
		require.NoError(t, readErr)
		exclusions, readErr := common.NewRoundExclusionHandler(nil)
		require.NoError(t, readErr)
		r, readErr := newCanonicalResultReader(accounts, &canonicalTestValidator{marshaller: args.Marshaller, hash: args.Hasher.Compute},
			&canonicalTestProofVerifier{}, &canonicalTestIntegrity{}, exclusions)
		require.NoError(t, readErr)
		return r
	}
	newCandidate := func(s *qualNativeStore) *PrivilegedConsentCandidate {
		owner, ownErr := NewRollbackContainment(s)
		require.NoError(t, ownErr)
		c, ownErr := NewPrivilegedConsentCandidate(s, owner, scope.Domain, 32, 256, nil,
			func() uint32 { return epoch }, 10, qualConsentReferenceFixture())
		require.NoError(t, ownErr)
		return c
	}
	witness := func(s *qualNativeStore, root []byte, advance bool) (privilegedAdmissionSelection, canonicalResultWitness, [][]byte) {
		t.Helper()
		var header, executed block.HeaderV3
		require.NoError(t, f.reader.accounts.args.Marshaller.Unmarshal(&header, f.w.Account.Header))
		require.NoError(t, f.reader.accounts.args.Marshaller.Unmarshal(&executed, f.w.Account.ExecutedHeader))
		if advance {
			executed.Nonce++
			executed.Round++
			header.Nonce++
			header.Round++
		}
		f.w.Account.ExecutedHeader = f.encode(t, &executed)
		result := header.ExecutionResults[0].BaseExecutionResult
		result.HeaderHash = f.hash(f.w.Account.ExecutedHeader)
		result.HeaderNonce, result.HeaderRound, result.RootHash = executed.Nonce, executed.Round, root
		f.w.Account.Header = f.encode(t, &header)
		f.w.HeaderProof = f.proof(t, &header, f.w.Account.Header)
		first := f.metas[0]
		first.ShardInfo[0].HeaderHash = result.HeaderHash
		first.ShardInfo[0].Nonce, first.ShardInfo[0].Round = executed.Nonce, executed.Round
		first.ShardInfoProposal[0].HeaderHash = f.hash(f.w.Account.Header)
		first.ShardInfoProposal[0].Nonce, first.ShardInfoProposal[0].Round = header.Nonce, header.Round
		main, trErr := s.GetTrie(root)
		require.NoError(t, trErr)
		proof, _, trErr := main.GetProof(scope.Address)
		require.NoError(t, trErr)
		f.w.Account.AccountProof, _, trErr = main.GetProof(core.SystemAccountAddress)
		require.NoError(t, trErr)
		system, trErr := s.GetExistingAccount(core.SystemAccountAddress)
		require.NoError(t, trErr)
		f.w.Account.DataProof, _, trErr = system.(state.UserAccountHandler).DataTrie().(common.Trie).GetProof(
			privilegedConsentRecordKey(scope.Address, scope.Token, scope.Program))
		require.NoError(t, trErr)
		f.rechain(t)
		return privilegedAdmissionSelection{committedB: bytes.Clone(f.bHash), origin: bytes.Clone(result.HeaderHash),
			consumer: core.MetachainShardId, producer: 1, scope: scope}, f.w, proof
	}
	assertRead := func(s *qualNativeStore, selection privilegedAdmissionSelection, w canonicalResultWitness, proof [][]byte) {
		t.Helper()
		root, readErr := s.RootHash()
		require.NoError(t, readErr)
		journal := s.JournalLen()
		budget := f.limit
		for _, node := range proof {
			budget += len(node)
		}
		require.NoError(t, newCandidate(s).readFixedTargetCanonicalEvidence(newReader(), fixed, fixed, selection, w, proof, budget))
		after, readErr := s.RootHash()
		require.NoError(t, readErr)
		require.Equal(t, root, after)
		require.Equal(t, journal, s.JournalLen())
		require.Equal(t, consent, qualConsentScopedValue(t, s, scope))
		require.Equal(t, otherConsent, qualConsentScopedValue(t, s, other))
		qualAssertContainmentBalance(t, s, 100)
	}

	root, err := store.Commit()
	require.NoError(t, err)
	selection, w, proof := witness(store, root, false)
	assertRead(store, selection, w, proof)

	// The guardian metadata is a suitability-neutral native account fact.
	// This test changes only the synthetic snapshot, not native authorization
	// or nonce; the existing conservative nonce/epoch profile is unchanged.
	setGuardianFact := func(s *qualNativeStore, guarded bool) []byte {
		t.Helper()
		a, setErr := s.GetExistingAccount(scope.Address)
		require.NoError(t, setErr)
		u := a.(state.UserAccountHandler)
		u.SetCodeMetadata((&vmcommon.CodeMetadata{Guarded: guarded}).ToBytes())
		require.NoError(t, s.SaveAccount(u))
		next, setErr := s.Commit()
		require.NoError(t, setErr)
		return next
	}
	guardedRoot := setGuardianFact(store, true)
	require.NotEqual(t, root, guardedRoot)
	guarded, w, proof := witness(store, guardedRoot, true)
	require.NotEqual(t, selection.committedB, guarded.committedB)
	assertRead(store, guarded, w, proof)

	// Reopen the persistent store with fresh native AccountsDB and read the
	// same committed state and admitted instant. No cached permit survives.
	closeStore()
	store, _ = qualConvergenceDiskOpen(t, path, false)
	require.NoError(t, store.RecreateTrie(holders.NewDefaultRootHashesHolder(guardedRoot)))
	reopened, w, proof := witness(store, guardedRoot, false)
	require.Equal(t, guarded.committedB, reopened.committedB)
	assertRead(store, reopened, w, proof)

	unguardedRoot := setGuardianFact(store, false)
	require.NotEqual(t, guardedRoot, unguardedRoot)
	unguarded, w, proof := witness(store, unguardedRoot, true)
	require.NotEqual(t, reopened.committedB, unguarded.committedB)
	assertRead(store, unguarded, w, proof)
}
