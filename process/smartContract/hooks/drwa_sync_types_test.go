package hooks

import (
	"bytes"
	"encoding/hex"
	"testing"

	builtInFunctions "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
)

// TestInitPrefixValidation_DidNotPanic verifies that the init() function in
// drwa_sync_types.go executed without panicking, which means all prefix
// constants between this module and mx-chain-vm-common-go are aligned.
// If the binary loaded and this test runs, init() succeeded.
func TestInitPrefixValidation_DidNotPanic(t *testing.T) {
	// Cross-check a representative pair to confirm the constants are in sync.
	if drwaSyncTokenPolicyPrefix != builtInFunctions.DRWATokenPolicyPrefix {
		t.Fatalf("token policy prefix mismatch: local=%q vm-common=%q",
			drwaSyncTokenPolicyPrefix, builtInFunctions.DRWATokenPolicyPrefix)
	}
	if drwaSyncHolderMirrorPrefix != builtInFunctions.DRWAHolderMirrorPrefix {
		t.Fatalf("holder mirror prefix mismatch: local=%q vm-common=%q",
			drwaSyncHolderMirrorPrefix, builtInFunctions.DRWAHolderMirrorPrefix)
	}
	if drwaSyncHolderProfilePrefix != builtInFunctions.DRWAHolderProfilePrefix {
		t.Fatalf("holder profile prefix mismatch: local=%q vm-common=%q",
			drwaSyncHolderProfilePrefix, builtInFunctions.DRWAHolderProfilePrefix)
	}
	if drwaSyncHolderAuditorAuthPrefix != builtInFunctions.DRWAHolderAuditorAuthPrefix {
		t.Fatalf("holder auditor auth prefix mismatch: local=%q vm-common=%q",
			drwaSyncHolderAuditorAuthPrefix, builtInFunctions.DRWAHolderAuditorAuthPrefix)
	}
	if drwaSyncAssetRecordPrefix != builtInFunctions.DRWAAssetRecordPrefix {
		t.Fatalf("asset record prefix mismatch: local=%q vm-common=%q",
			drwaSyncAssetRecordPrefix, builtInFunctions.DRWAAssetRecordPrefix)
	}
}

func TestDRWANativeStateKeyBuildersStayCanonical(t *testing.T) {
	tokenID := []byte("CARBON-ab12cd")
	holder := bytes.Repeat([]byte{0xAB}, 32)
	payloadHash := bytes.Repeat([]byte{0xCD}, 32)
	proposalID := [32]byte{0xEF}

	testCases := map[string][]byte{
		"token policy":        buildDRWATokenPolicyKey(tokenID),
		"asset record":        buildDRWAAssetRecordKey(tokenID),
		"active flag":         buildDRWAActiveKey(tokenID),
		"holder mirror":       buildDRWAHolderMirrorKey(tokenID, holder),
		"holder profile":      buildDRWAHolderProfileKey(holder),
		"holder auditor auth": buildDRWAHolderAuditorAuthorizationKey(tokenID, holder),
	}
	expected := map[string][]byte{
		"token policy":        builtInFunctions.BuildDRWATokenPolicyKey(tokenID),
		"asset record":        builtInFunctions.BuildDRWAAssetRecordKey(tokenID),
		"active flag":         builtInFunctions.BuildDRWAActiveKey(tokenID),
		"holder mirror":       builtInFunctions.BuildDRWAHolderMirrorKey(tokenID, holder),
		"holder profile":      builtInFunctions.BuildDRWAHolderProfileKey(holder),
		"holder auditor auth": builtInFunctions.BuildDRWAHolderAuditorAuthorizationKey(tokenID, holder),
	}

	for name, key := range testCases {
		if !bytes.Equal(expected[name], key) {
			t.Fatalf("%s key mismatch: local=%q vm-common=%q", name, key, expected[name])
		}
	}

	if got := string(buildDRWAAuthorizedCallerKey(drwaSyncCallerPolicyRegistry)); got != "drwa:auth:"+drwaSyncCallerPolicyRegistry {
		t.Fatalf("authorized caller key mismatch: %q", got)
	}
	if got := string(buildDRWARecoveryLastTimestampKey(string(tokenID))); got != "drwa:recovery:lastTimestamp:"+string(tokenID) {
		t.Fatalf("recovery last timestamp key mismatch: %q", got)
	}
	if got := string(buildDRWARecoveryEvidenceKey(tokenID)); got != "drwa:evidence:"+hex.EncodeToString(tokenID)+":recovery:latest" {
		t.Fatalf("recovery evidence key mismatch: %q", got)
	}
	if got := string(buildDRWARecoveryEvidenceHistoryKey(tokenID, payloadHash)); got != "drwa:evidence:"+hex.EncodeToString(tokenID)+":recovery:history:"+hex.EncodeToString(payloadHash) {
		t.Fatalf("recovery evidence history key mismatch: %q", got)
	}
	if got := string(buildDRWAGovernanceConfigKey(string(tokenID))); got != "DRWA_GOV_"+hex.EncodeToString(tokenID) {
		t.Fatalf("governance config key mismatch: %q", got)
	}
	if got := string(buildDRWAGovernanceProposalKey(proposalID)); got != "DRWA_PROPOSAL_"+hex.EncodeToString(proposalID[:]) {
		t.Fatalf("governance proposal key mismatch: %q", got)
	}
	if got := string(buildDRWAGovernanceAuditKey(proposalID)); got != "DRWA_GOV_AUDIT_"+hex.EncodeToString(proposalID[:]) {
		t.Fatalf("governance audit key mismatch: %q", got)
	}
}

func TestSyncLimits_ExpectedValues(t *testing.T) {
	if drwaSyncMaxOperations != 256 {
		t.Fatalf("expected drwaSyncMaxOperations=256, got %d", drwaSyncMaxOperations)
	}
	expectedPayloadBytes := 1 << 20 // 1 MB
	if drwaSyncMaxPayloadBytes != expectedPayloadBytes {
		t.Fatalf("expected drwaSyncMaxPayloadBytes=%d (1 MB), got %d",
			expectedPayloadBytes, drwaSyncMaxPayloadBytes)
	}
}

func TestOperationTypeConstants_NonEmpty(t *testing.T) {
	opTypes := []drwaSyncOperationType{
		drwaSyncOpTokenPolicy,
		drwaSyncOpAssetRecord,
		drwaSyncOpHolderMirror,
		drwaSyncOpHolderProfile,
		drwaSyncOpHolderAuditorAuth,
		drwaSyncOpHolderMirrorDelete,
	}
	for _, op := range opTypes {
		if op == "" {
			t.Error("found empty operation type constant")
		}
	}
}

func TestOperationTypeConstants_NoDuplicates(t *testing.T) {
	opTypes := []drwaSyncOperationType{
		drwaSyncOpTokenPolicy,
		drwaSyncOpAssetRecord,
		drwaSyncOpHolderMirror,
		drwaSyncOpHolderProfile,
		drwaSyncOpHolderAuditorAuth,
		drwaSyncOpHolderMirrorDelete,
	}
	seen := make(map[drwaSyncOperationType]bool)
	for _, op := range opTypes {
		if seen[op] {
			t.Errorf("duplicate operation type constant: %q", op)
		}
		seen[op] = true
	}
}

func TestCallerDomainConstants_NonEmpty(t *testing.T) {
	callers := []string{
		drwaSyncCallerPolicyRegistry,
		drwaSyncCallerAssetManager,
		drwaSyncCallerIdentityRegistry,
		drwaSyncCallerAttestation,
		drwaSyncCallerRecoveryAdmin,
	}
	for _, c := range callers {
		if c == "" {
			t.Error("found empty caller domain constant")
		}
	}
}

func TestCallerDomainConstants_NoDuplicates(t *testing.T) {
	callers := []string{
		drwaSyncCallerPolicyRegistry,
		drwaSyncCallerAssetManager,
		drwaSyncCallerIdentityRegistry,
		drwaSyncCallerAttestation,
		drwaSyncCallerRecoveryAdmin,
	}
	seen := make(map[string]bool)
	for _, c := range callers {
		if seen[c] {
			t.Errorf("duplicate caller domain constant: %q", c)
		}
		seen[c] = true
	}
}

func TestRejectReasonConstants_NonEmpty(t *testing.T) {
	reasons := []string{
		drwaSyncRejectUnauthorizedCaller,
		drwaSyncRejectPayloadTooLarge,
		drwaSyncRejectHashMismatch,
		drwaSyncRejectReplayStale,
		drwaSyncRejectReplayDuplicate,
		drwaSyncRejectVersionOverflow,
		drwaSyncRejectVersionGap,
		drwaSyncRejectBatchAtomicity,
	}
	for _, r := range reasons {
		if r == "" {
			t.Error("found empty reject reason constant")
		}
	}
}

func TestRejectReasonConstants_NoDuplicates(t *testing.T) {
	reasons := []string{
		drwaSyncRejectUnauthorizedCaller,
		drwaSyncRejectPayloadTooLarge,
		drwaSyncRejectHashMismatch,
		drwaSyncRejectReplayStale,
		drwaSyncRejectReplayDuplicate,
		drwaSyncRejectVersionOverflow,
		drwaSyncRejectVersionGap,
		drwaSyncRejectBatchAtomicity,
	}
	seen := make(map[string]bool)
	for _, r := range reasons {
		if seen[r] {
			t.Errorf("duplicate reject reason constant: %q", r)
		}
		seen[r] = true
	}
}
