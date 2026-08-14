package hooks

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/block"
	chainstate "github.com/multiversx/mx-chain-go/state"
	"github.com/stretchr/testify/require"
)

const drwaRecoveryProductionBoundaryToken = "RECOVERY-boundary"

// TestCharacterization_ProductionRecoveryGovernanceHasOneStableOuterCaller
// exercises the public hook and the production trie-backed AccountsDB adapter.
// It records
// the boundary that helper-level governance tests do not exercise: the native
// governance engine identifies approvals by immediate caller address, while
// the outer sync allowlist admits only the single address currently registered
// for recovery_admin.
func TestCharacterization_ProductionRecoveryGovernanceHasOneStableOuterCaller(t *testing.T) {
	hook, accounts, signers := newProductionRecoveryBoundaryFixture(t)

	proposalID := proposeRecoveryThroughProductionHook(t, hook, signers[0])
	requireProposalApprovals(t, accounts, proposalID, signers[0])

	approvePayload := buildRecoveryGovernanceOperationPayload(
		t,
		drwaSyncOpGovernanceApprove,
		proposalID,
	)

	// Signer 1 belongs to the native 3-of-5 configuration, but is not the
	// one address registered in the outer recovery_admin allowlist.
	err := hook.ApplyDRWASyncEnvelopeBytes(approvePayload, signers[1])
	require.EqualError(t, err, drwaSyncRejectUnauthorizedCaller)
	requireProposalApprovals(t, accounts, proposalID, signers[0])

	// The registered caller reaches the governance engine, but it is already
	// the proposer/first approver and therefore cannot create a second vote.
	err = hook.ApplyDRWASyncEnvelopeBytes(approvePayload, signers[0])
	require.ErrorIs(t, err, errDRWAGovernanceDuplicateApproval)
	requireProposalApprovals(t, accounts, proposalID, signers[0])
}

// TestCharacterization_ProductionRecoveryGovernanceCanAccumulateApprovalsOnlyAfterCallerRotation
// prevents the stable-caller result above from being overstated as an absolute
// reachability proof. The current auth_admin operation can rotate the one
// recovery_admin registry entry. Rotating it between calls lets different
// native governance signers pass the outer gate and accumulate approvals.
// This proves the BlockChainHook boundary only. The VM supplies a smart
// contract's context address to this hook, so an end-to-end deployment would
// additionally need each rotated signer address to be a hook-emitting contract
// (or another explicitly designed adapter); an EOA cannot invoke the managed
// hook directly.
// This is observable current behavior, not an endorsement of rotation as the
// permanent governance topology.
func TestCharacterization_ProductionRecoveryGovernanceCanAccumulateApprovalsOnlyAfterCallerRotation(t *testing.T) {
	hook, accounts, signers := newProductionRecoveryBoundaryFixture(t)
	authAdmin := testDRWACallerAddress(drwaSyncCallerAuthAdmin)
	require.NoError(t, ProvisionDRWAAuthorizedCaller(
		accounts,
		drwaSyncCallerAuthAdmin,
		authAdmin,
		1,
	))

	proposalID := proposeRecoveryThroughProductionHook(t, hook, signers[0])
	approvePayload := buildRecoveryGovernanceOperationPayload(
		t,
		drwaSyncOpGovernanceApprove,
		proposalID,
	)

	rotateRecoveryCallerThroughProductionHook(t, hook, authAdmin, signers[1], 2)
	require.NoError(t, hook.ApplyDRWASyncEnvelopeBytes(approvePayload, signers[1]))
	requireProposalApprovals(t, accounts, proposalID, signers[0], signers[1])

	rotateRecoveryCallerThroughProductionHook(t, hook, authAdmin, signers[2], 3)
	require.NoError(t, hook.ApplyDRWASyncEnvelopeBytes(approvePayload, signers[2]))
	requireProposalApprovals(t, accounts, proposalID, signers[0], signers[1], signers[2])

	executePayload := buildRecoveryGovernanceOperationPayload(
		t,
		drwaSyncOpGovernanceExecute,
		proposalID,
	)
	require.NoError(t, hook.ApplyDRWASyncEnvelopeBytes(executePayload, signers[2]))

	adapter, err := newDRWAHookStateAdapter(accounts)
	require.NoError(t, err)
	version, err := adapter.GetTokenPolicyVersion(drwaRecoveryProductionBoundaryToken)
	require.NoError(t, err)
	require.Equal(t, uint64(1), version)
}

func newProductionRecoveryBoundaryFixture(
	t *testing.T,
) (*BlockChainHookImpl, chainstate.AccountsAdapter, [][]byte) {
	t.Helper()

	accounts := createRealAccountsDBForDRWATest(t)

	signers := productionRecoveryBoundarySigners()
	require.NoError(t, ProvisionDRWAAuthorizedCaller(
		accounts,
		drwaSyncCallerRecoveryAdmin,
		signers[0],
		1,
	))
	require.NoError(t, ProvisionDRWARecoveryGovernance(
		accounts,
		drwaRecoveryProductionBoundaryToken,
		&DRWAGovernanceConfig{
			Threshold:   3,
			Signers:     signers,
			ProposalTTL: 2_400,
			MaxSigners:  5,
		},
	))

	hook := &BlockChainHookImpl{
		accounts:      accounts,
		currentHdr:    &block.Header{Nonce: 100},
		epochStartHdr: &block.Header{},
	}

	return hook, accounts, signers
}

func proposeRecoveryThroughProductionHook(
	t *testing.T,
	hook *BlockChainHookImpl,
	caller []byte,
) [32]byte {
	t.Helper()

	envelope := drwaSyncEnvelope{
		SchemaVersion: drwaSyncEnvelopeSchemaVersionWithRecovery,
		CallerDomain:  drwaSyncCallerRecoveryAdmin,
		RecoveryScope: []string{drwaRecoveryProductionBoundaryToken},
		Operations: []drwaSyncOperation{{
			OperationType: drwaSyncOpTokenPolicy,
			TokenID:       drwaRecoveryProductionBoundaryToken,
			Version:       1,
			Body:          []byte(`{"transferable":true}`),
		}},
	}
	adapter, err := newDRWAHookStateAdapter(hook.accounts)
	require.NoError(t, err)
	envelope.PreRecoveryStateHash, err = computeDRWARecoveryStateHash(
		adapter,
		&drwaRecoveryManifest{TokenID: drwaRecoveryProductionBoundaryToken},
	)
	require.NoError(t, err)
	payload := buildRecoveryV2Payload(t, &envelope)
	require.NoError(t, hook.ApplyDRWASyncEnvelopeBytes(payload, caller))

	envelopeHash, err := computeDRWASyncEnvelopeHash(&envelope)
	require.NoError(t, err)
	var fixedHash [32]byte
	copy(fixedHash[:], envelopeHash)

	return computeProposalID(fixedHash, hook.CurrentNonce())
}

func productionRecoveryBoundarySigners() [][]byte {
	signers := make([][]byte, 5)
	for idx := range signers {
		signers[idx] = make([]byte, drwaAuthorizedCallerAddressLen)
		signers[idx][0] = byte(idx + 1)
	}
	return signers
}

func rotateRecoveryCallerThroughProductionHook(
	t *testing.T,
	hook *BlockChainHookImpl,
	authAdmin []byte,
	newRecoveryCaller []byte,
	version uint64,
) {
	t.Helper()

	payload := buildBinaryEnvelope(t, drwaSyncCallerAuthAdmin, []drwaSyncOperation{{
		OperationType: drwaSyncOpAuthorizedCallerUpdate,
		TokenID:       drwaSyncCallerRecoveryAdmin,
		Version:       version,
		Body:          []byte(hex.EncodeToString(newRecoveryCaller)),
	}})
	require.NoError(t, hook.ApplyDRWASyncEnvelopeBytes(payload, authAdmin))
}

func buildRecoveryGovernanceOperationPayload(
	t *testing.T,
	operationType drwaSyncOperationType,
	proposalID [32]byte,
) []byte {
	t.Helper()

	envelope := &drwaSyncEnvelope{
		SchemaVersion:        drwaSyncEnvelopeSchemaVersionWithRecovery,
		CallerDomain:         drwaSyncCallerRecoveryAdmin,
		PreRecoveryStateHash: bytes.Repeat([]byte{0x55}, 32),
		RecoveryScope:        []string{drwaRecoveryProductionBoundaryToken},
		Operations: []drwaSyncOperation{{
			OperationType: operationType,
			Version:       1,
			Body:          append([]byte(nil), proposalID[:]...),
		}},
	}

	return buildRecoveryV2Payload(t, envelope)
}

func buildRecoveryV2Payload(t *testing.T, envelope *drwaSyncEnvelope) []byte {
	t.Helper()

	canonical, err := serializeDRWARecoverySyncEnvelopePayload(envelope)
	require.NoError(t, err)
	hash, err := computeDRWASyncEnvelopeHash(envelope)
	require.NoError(t, err)

	payload := make([]byte, 0, len(hash)+len(canonical))
	payload = append(payload, hash...)
	payload = append(payload, canonical...)
	return payload
}

func requireProposalApprovals(
	t *testing.T,
	accounts chainstate.AccountsAdapter,
	proposalID [32]byte,
	expected ...[]byte,
) {
	t.Helper()

	store, err := newDRWAGovernanceTrieStore(accounts)
	require.NoError(t, err)
	proposal, err := store.GetProposal(proposalID)
	require.NoError(t, err)
	require.NotNil(t, proposal)
	require.Equal(t, expected, proposal.Approvals)
}
