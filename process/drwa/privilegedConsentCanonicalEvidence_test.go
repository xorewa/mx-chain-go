package drwa

import (
	"bytes"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/stretchr/testify/require"
)

// The native store supplies the account and consent proofs; the existing
// canonical test fixture supplies an explicit unit proof/ancestry oracle.
// The fixture record is an already-admitted experimental consent, not a
// demonstration of production ingress, signatures or chain finality.
func TestSP230PrivilegedCanonicalEvidence(t *testing.T) {
	f := newCanonicalTestFixture(t, 1, core.MetachainShardId)
	scope := qualConsentScope()
	scope.Address = bytes.Clone(qualContainmentAddress)
	account, err := f.s.GetExistingAccount(scope.Address)
	require.NoError(t, err)
	consentEpoch := uint32(3)
	require.NoError(t, savePrivilegedConsent(f.s, scope.Address, scope.Token, scope.Program,
		encodeExperimentalConsent(scope, account.GetNonce(), consentEpoch)))
	c, err := NewPrivilegedConsentCandidate(f.s, f.owner, scope.Domain, 32, 256, nil,
		func() uint32 { return consentEpoch }, 10, qualConsentReferenceFixture())
	require.NoError(t, err)

	currentWitness := func(advance bool) (canonicalResultWitness, [][]byte, int) {
		t.Helper()
		root, commitErr := f.s.Commit()
		require.NoError(t, commitErr)
		var header block.HeaderV3
		require.NoError(t, f.reader.accounts.args.Marshaller.Unmarshal(&header, f.w.Account.Header))
		result := header.ExecutionResults[0].BaseExecutionResult
		if advance {
			var executed block.HeaderV3
			require.NoError(t, f.reader.accounts.args.Marshaller.Unmarshal(&executed, f.w.Account.ExecutedHeader))
			executed.Nonce++
			executed.Round++
			f.w.Account.ExecutedHeader = f.encode(t, &executed)
			result.HeaderHash = f.hash(f.w.Account.ExecutedHeader)
			result.HeaderNonce, result.HeaderRound = executed.Nonce, executed.Round
			header.Nonce++
			header.Round++
			f.metas[0].ShardInfo[0].HeaderHash = result.HeaderHash
			f.metas[0].ShardInfo[0].Nonce, f.metas[0].ShardInfo[0].Round = executed.Nonce, executed.Round
			f.metas[0].ShardInfoProposal[0].Nonce, f.metas[0].ShardInfoProposal[0].Round = header.Nonce, header.Round
		}
		result.RootHash = root
		f.w.Account.Header = f.encode(t, &header)
		f.w.HeaderProof = f.proof(t, &header, f.w.Account.Header)
		f.metas[0].ShardInfoProposal[0].HeaderHash = f.hash(f.w.Account.Header)
		main, trieErr := f.s.GetTrie(root)
		require.NoError(t, trieErr)
		var eoaProof [][]byte
		eoaProof, _, trieErr = main.GetProof(scope.Address)
		require.NoError(t, trieErr)
		f.w.Account.AccountProof, _, trieErr = main.GetProof(core.SystemAccountAddress)
		require.NoError(t, trieErr)
		system, loadErr := f.s.GetExistingAccount(core.SystemAccountAddress)
		require.NoError(t, loadErr)
		f.w.Account.DataProof, _, trieErr = system.(state.UserAccountHandler).DataTrie().(common.Trie).GetProof(
			privilegedConsentRecordKey(scope.Address, scope.Token, scope.Program))
		require.NoError(t, trieErr)
		f.rechain(t)
		remaining, budgetErr := canonicalWitnessRemaining(f.w, f.limit)
		require.NoError(t, budgetErr)
		limit := f.limit - remaining
		for _, node := range eoaProof {
			limit += len(node)
		}
		return f.w, eoaProof, limit
	}
	w, eoa, limit := currentWitness(false)
	origin := f.hash(w.Account.ExecutedHeader)
	read := func(reader *canonicalResultReader, producer uint32, evidence canonicalResultWitness, proof [][]byte, budget int) error {
		return c.readCanonicalEvidence(reader, f.bHash, core.MetachainShardId, producer, origin, scope, evidence, proof, budget)
	}
	rootBefore, err := f.s.RootHash()
	require.NoError(t, err)
	require.NoError(t, read(f.reader, 1, w, eoa, limit))
	require.ErrorIs(t, read(nil, 1, w, eoa, limit), ErrPrivilegedConsent)
	require.ErrorIs(t, read(f.reader, core.MetachainShardId, w, eoa, limit), ErrPrivilegedConsent)
	require.ErrorIs(t, read(f.reader, 1, w, eoa, 0), ErrInvalidAccountWitness)
	require.ErrorIs(t, read(f.reader, 1, w, eoa, limit-1), ErrInvalidAccountWitness)
	unavailable := errors.New("fixture proof verifier unavailable")
	f.oracle.failure = unavailable
	require.ErrorIs(t, read(f.reader, 1, w, eoa, limit), unavailable)
	f.oracle.failure = nil
	require.NoError(t, read(f.reader, 1, w, eoa, limit))
	rootAfter, err := f.s.RootHash()
	require.NoError(t, err)
	require.Equal(t, rootBefore, rootAfter, "evidence reading must not modify execution state")

	// A subsequently committed account-state change is observed at the next
	// independently selected result. No old observation can waive this check.
	account, err = f.s.GetExistingAccount(scope.Address)
	require.NoError(t, err)
	account.(state.UserAccountHandler).SetCode([]byte("fixture contract code"))
	require.NoError(t, f.s.SaveAccount(account))
	w, eoa, limit = currentWitness(true)
	previousOrigin := origin
	origin = f.hash(w.Account.ExecutedHeader)
	require.NotEqual(t, previousOrigin, origin)
	require.ErrorIs(t, read(f.reader, 1, w, eoa, limit), ErrPrivilegedConsent)
}
