package hooks

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/testscommon/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	builtInFunctions "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	vmmock "github.com/multiversx/mx-chain-vm-common-go/mock"
	"github.com/stretchr/testify/require"
)

func TestDecodeDRWASyncEnvelope_RustGeneratedFixtures(t *testing.T) {
	t.Parallel()

	holder := string(repeatByte(0xAA, 32))
	testCases := []struct {
		name           string
		fixture        string
		schemaVersion  uint16
		callerDomain   string
		operationTypes []drwaSyncOperationType
		versions       []uint64
		assertEnvelope func(*testing.T, *drwaSyncEnvelope)
	}{
		{
			name:           "schema v1 token policy",
			fixture:        "sync-envelope-v1.hex",
			schemaVersion:  drwaSyncEnvelopeSchemaVersion,
			callerDomain:   drwaSyncCallerPolicyRegistry,
			operationTypes: []drwaSyncOperationType{drwaSyncOpTokenPolicy},
			versions:       []uint64{7},
		},
		{
			name:           "schema v2 recovery governance",
			fixture:        "sync-envelope-v2-recovery.hex",
			schemaVersion:  drwaSyncEnvelopeSchemaVersionWithRecovery,
			callerDomain:   drwaSyncCallerRecoveryAdmin,
			operationTypes: []drwaSyncOperationType{drwaSyncOpGovernanceApprove, drwaSyncOpGovernanceExecute},
			versions:       []uint64{1, 2},
			assertEnvelope: func(t *testing.T, envelope *drwaSyncEnvelope) {
				require.Equal(t, repeatByte(0x06, 32), envelope.PreRecoveryStateHash)
				require.Equal(t, []string{"CARBON-ab12cd"}, envelope.RecoveryScope)
				expectedHash, err := computeDRWASyncEnvelopeHash(envelope)
				require.NoError(t, err)
				require.Equal(t, expectedHash, envelope.PayloadHash)
			},
		},
		{
			name:          "schema v1 all operation tags",
			fixture:       "sync-envelope-v1-all-op-tags.hex",
			schemaVersion: drwaSyncEnvelopeSchemaVersion,
			callerDomain:  drwaSyncCallerPolicyRegistry,
			operationTypes: []drwaSyncOperationType{
				drwaSyncOpTokenPolicy,
				drwaSyncOpAssetRecord,
				drwaSyncOpHolderMirror,
				drwaSyncOpHolderProfile,
				drwaSyncOpHolderAuditorAuth,
				drwaSyncOpHolderMirrorDelete,
				drwaSyncOpAuthorizedCallerUpdate,
				drwaSyncOpGovernanceApprove,
				drwaSyncOpGovernanceExecute,
			},
			versions: []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9},
			assertEnvelope: func(t *testing.T, envelope *drwaSyncEnvelope) {
				require.Equal(t, "CARBON-aa0000", envelope.Operations[0].TokenID)
				require.Empty(t, envelope.Operations[0].Holder)
				require.Equal(t, "CARBON-aa0001", envelope.Operations[1].TokenID)
				require.Empty(t, envelope.Operations[1].Holder)
				require.Equal(t, "CARBON-aa0002", envelope.Operations[2].TokenID)
				require.Equal(t, holder, envelope.Operations[2].Holder)
				require.Empty(t, envelope.Operations[3].TokenID)
				require.Equal(t, holder, envelope.Operations[3].Holder)
				require.Equal(t, "CARBON-aa0004", envelope.Operations[4].TokenID)
				require.Equal(t, holder, envelope.Operations[4].Holder)
				require.Equal(t, "CARBON-aa0005", envelope.Operations[5].TokenID)
				require.Equal(t, holder, envelope.Operations[5].Holder)
				require.Equal(t, "auth_admin", envelope.Operations[6].TokenID)
				require.Empty(t, envelope.Operations[6].Holder)
				require.Empty(t, envelope.Operations[7].TokenID)
				require.Empty(t, envelope.Operations[7].Holder)
				require.Empty(t, envelope.Operations[8].TokenID)
				require.Empty(t, envelope.Operations[8].Holder)
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			payload := readRustDRWASyncFixture(t, testCase.fixture)
			envelope, err := decodeDRWASyncEnvelope(payload)
			require.NoError(t, err)
			require.Equal(t, testCase.schemaVersion, envelope.SchemaVersion)
			require.Equal(t, testCase.callerDomain, envelope.CallerDomain)
			require.Len(t, envelope.Operations, len(testCase.operationTypes))
			for index, expectedType := range testCase.operationTypes {
				require.Equal(t, expectedType, envelope.Operations[index].OperationType)
				require.Equal(t, testCase.versions[index], envelope.Operations[index].Version)
			}
			if testCase.assertEnvelope != nil {
				testCase.assertEnvelope(t, envelope)
			}
		})
	}
}

func TestDecodeDRWASyncEnvelope_RustNearCapFixture(t *testing.T) {
	t.Parallel()

	payload := readRustDRWASyncFixture(t, "sync-envelope-v1-near-cap.hex")
	require.LessOrEqual(t, len(payload), drwaSyncMaxPayloadBytes)
	require.Greater(t, len(payload), drwaSyncMaxPayloadBytes-4096)

	envelope, err := decodeDRWASyncEnvelope(payload)
	require.NoError(t, err)
	require.Equal(t, drwaSyncCallerPolicyRegistry, envelope.CallerDomain)
	require.Len(t, envelope.Operations, drwaSyncMaxOperations)

	oversized := append(append([]byte(nil), payload...), bytes.Repeat([]byte{0}, drwaSyncMaxPayloadBytes-len(payload)+1)...)
	_, err = decodeDRWASyncEnvelope(oversized)
	require.Error(t, err)
	require.Contains(t, err.Error(), drwaSyncRejectPayloadTooLarge)
}

func TestRustGeneratedV1FixtureAppliesToCanonicalNativeTokenPolicyKey(t *testing.T) {
	payload := readRustDRWASyncFixture(t, "sync-envelope-v1.hex")
	envelope, err := decodeDRWASyncEnvelope(payload)
	require.NoError(t, err)
	require.Len(t, envelope.Operations, 1)

	// The fixture hash is a deterministic golden-test marker. Recompute the
	// production apply hash after decoding so this test can focus on the native
	// key written by a Rust-shaped envelope.
	envelope.PayloadHash, err = computeDRWASyncHash(envelope.CallerDomain, envelope.Operations)
	require.NoError(t, err)

	systemAccount := vmmock.NewAccountWrapMock(core.SystemAccountAddress)
	accountsStub := &state.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			require.Equal(t, core.SystemAccountAddress, address)
			return systemAccount, nil
		},
		SaveAccountCalled: func(account vmcommon.AccountHandler) error { return nil },
		JournalLenCalled:  func() int { return 1 },
	}
	adapter, err := newDRWAHookStateAdapter(accountsStub)
	require.NoError(t, err)
	require.NoError(t, adapter.SetAuthorizedCallerAddressVersioned(
		drwaSyncCallerPolicyRegistry,
		testDRWACallerAddress(drwaSyncCallerPolicyRegistry),
		1,
	))
	require.NoError(t, adapter.PutTokenPolicyBody("CARBON-ab12cd", 6, []byte(`{"previous":true}`)))

	result, err := applyDRWASyncEnvelope(adapter, envelope, drwaSyncMaxOperations, testDRWACallerAddress(drwaSyncCallerPolicyRegistry))
	require.NoError(t, err)
	require.Equal(t, 1, result.AppliedOperations)

	expectedKey := builtInFunctions.BuildDRWATokenPolicyKey([]byte("CARBON-ab12cd"))
	require.Equal(t, expectedKey, buildDRWATokenPolicyKey([]byte("CARBON-ab12cd")))

	rawStored, _, err := systemAccount.AccountDataHandler().RetrieveValue(expectedKey)
	require.NoError(t, err)
	stored, err := decodeDRWASyncStoredValue(rawStored)
	require.NoError(t, err)
	require.Equal(t, uint64(7), stored.Version)
	require.Equal(t, []byte(`{"drwa_enabled":true}`), stored.Body)
}

func readRustDRWASyncFixture(t *testing.T, fixtureName string) []byte {
	t.Helper()

	fixtureDir := os.Getenv("DRWA_SYNC_FIXTURE_DIR")
	if fixtureDir == "" {
		fixtureDir = filepath.Join(
			"..", "..", "..", "..",
			"mx-sdk-rs", "contracts", "drwa", "common", "testdata", "drwa-sync-fixtures",
		)
	}
	path := filepath.Join(fixtureDir, fixtureName)
	contents, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		t.Skipf("DRWA sync fixture %q not available at %s; set DRWA_SYNC_FIXTURE_DIR in split-repo CI", fixtureName, path)
	}
	require.NoError(t, err)

	payload, err := hex.DecodeString(strings.Join(strings.Fields(string(contents)), ""))
	require.NoError(t, err)
	return payload
}

func repeatByte(value byte, count int) []byte {
	result := make([]byte, count)
	for i := range result {
		result[i] = value
	}
	return result
}
