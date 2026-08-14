package hooks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// Characterizes the native allow-list boundary against the production state
// adapter. It accepts a stored 32-byte address for the appropriate domain; it
// has no Safe/member/quorum, code-hash, or code-metadata input at this layer.
func TestCharacterization_ProductionNativeAuthAdminAuthorizationIsAddressOnly(t *testing.T) {
	accounts := createRealAccountsDBForDRWATest(t)
	adapter, err := newDRWAHookStateAdapter(accounts)
	require.NoError(t, err)
	arbitraryAddress := testDRWACallerAddress("not-proven-contract")
	require.NoError(t, adapter.SetAuthorizedCallerAddressVersioned(
		drwaSyncCallerAuthAdmin,
		arbitraryAddress,
		1,
	))

	require.True(t, isDRWASyncCallerAuthorized(adapter, drwaSyncCallerAuthAdmin, []drwaSyncOperation{{
		OperationType: drwaSyncOpAuthorizedCallerUpdate,
		TokenID:       drwaSyncCallerPolicyRegistry,
		Version:       1,
		Body:          []byte("0x1111111111111111111111111111111111111111111111111111111111111111"),
	}}, arbitraryAddress))
}

func TestCharacterization_ProductionAuthorizationAcceptsAddressWithoutAccountOrContractCode(t *testing.T) {
	accounts := createRealAccountsDBForDRWATest(t)
	caller := bytes.Repeat([]byte{0x7a}, drwaAuthorizedCallerAddressLen)

	_, err := accounts.GetExistingAccount(caller)
	require.Error(t, err)
	require.NoError(t, ProvisionDRWAAuthorizedCaller(
		accounts,
		drwaSyncCallerPolicyRegistry,
		caller,
		1,
	))
	_, err = accounts.GetExistingAccount(caller)
	require.Error(t, err)

	adapter, err := newDRWAHookStateAdapter(accounts)
	require.NoError(t, err)
	require.True(t, isDRWASyncCallerAuthorized(adapter, drwaSyncCallerPolicyRegistry, []drwaSyncOperation{{
		OperationType: drwaSyncOpTokenPolicy,
		TokenID:       "RWA-root-cause",
		Version:       1,
		Body:          []byte(`{}`),
	}}, caller))
}

func TestCharacterization_EmptyNativeRegistryCannotBootstrapAuthAdmin(t *testing.T) {
	accounts := createRealAccountsDBForDRWATest(t)
	adapter, err := newDRWAHookStateAdapter(accounts)
	require.NoError(t, err)

	candidate := testDRWACallerAddress("candidate-auth-admin")
	require.False(t, isDRWASyncCallerAuthorized(adapter, drwaSyncCallerAuthAdmin, []drwaSyncOperation{{
		OperationType: drwaSyncOpAuthorizedCallerUpdate,
		TokenID:       drwaSyncCallerAuthAdmin,
		Version:       1,
		Body:          []byte("0x1111111111111111111111111111111111111111111111111111111111111111"),
	}}, candidate))
}

func TestCharacterization_MigrationCallerHelperDoesNotBootstrapAuthAdmin(t *testing.T) {
	accounts := createRealAccountsDBForDRWATest(t)
	adapter, err := newDRWAHookStateAdapter(accounts)
	require.NoError(t, err)
	hexAddress := func(octet string) string {
		value := ""
		for range 32 {
			value += octet
		}
		return value
	}
	manifest := &drwaMigrationManifest{
		TokenID:       "RWA-characterization",
		PolicyVersion: 1,
		PolicyBody:    []byte(`{"drwa_enabled":true}`),
		AuthorizedCallers: map[string]string{
			drwaSyncCallerAuthAdmin:        hexAddress("11"),
			drwaSyncCallerPolicyRegistry:   hexAddress("22"),
			drwaSyncCallerAssetManager:     hexAddress("33"),
			drwaSyncCallerIdentityRegistry: hexAddress("44"),
			drwaSyncCallerAttestation:      hexAddress("55"),
			drwaSyncCallerRecoveryAdmin:    hexAddress("66"),
		},
	}

	require.NoError(t, persistDRWAMigrationAuthorizedCallers(adapter, manifest))
	address, version, err := adapter.GetAuthorizedCallerAddressVersioned(drwaSyncCallerAuthAdmin)
	require.NoError(t, err)
	require.Empty(t, address)
	require.Zero(t, version)
}

// Characterizes the current JSON decoder boundary. json.Unmarshal ignores
// unknown fields, so this ingress is not a closed-schema equivalent of the
// binary parser and must not be reused for the future code-bound profile.
func TestCharacterization_JSONSyncIngressIgnoresUnknownFields(t *testing.T) {
	payload := []byte(`{
		"schema_version": 1,
		"caller_domain": "policy_registry",
		"operations": [],
		"unknown_security_field": "ignored"
	}`)

	envelope, err := decodeDRWASyncEnvelope(payload)
	require.NoError(t, err)
	require.Equal(t, uint16(1), envelope.SchemaVersion)
	require.Equal(t, drwaSyncCallerPolicyRegistry, envelope.CallerDomain)
}

// Characterizes the current inverse-schema gap. Recovery callers are required
// to use schema 2, but the apply path does not require schema 2 to have the
// recovery_admin domain; a policy_registry schema-2 envelope is accepted.
// Target code-bound admission must therefore define a new closed matrix rather
// than claiming current schema 2 is already recovery-only.
func TestCharacterization_Schema2IsAcceptedForNonRecoveryDomain(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	envelope := &drwaSyncEnvelope{
		SchemaVersion: drwaSyncEnvelopeSchemaVersionWithRecovery,
		CallerDomain:  drwaSyncCallerPolicyRegistry,
		Operations: []drwaSyncOperation{{
			OperationType: drwaSyncOpTokenPolicy,
			TokenID:       "RWA-schema-matrix",
			Version:       1,
			Body:          []byte(`{"drwa_enabled":true}`),
		}},
	}
	hash, err := computeDRWASyncEnvelopeHash(envelope)
	require.NoError(t, err)
	canonicalPayload, err := serializeDRWARecoverySyncEnvelopePayload(envelope)
	require.NoError(t, err)
	binaryPayload := make([]byte, 0, len(hash)+len(canonicalPayload))
	binaryPayload = append(binaryPayload, hash...)
	binaryPayload = append(binaryPayload, canonicalPayload...)
	decoded, err := decodeDRWASyncEnvelope(binaryPayload)
	require.NoError(t, err)
	require.Equal(t, drwaSyncCallerPolicyRegistry, decoded.CallerDomain)
	require.Equal(t, drwaSyncEnvelopeSchemaVersionWithRecovery, decoded.SchemaVersion)

	result, err := applyDRWASyncEnvelope(
		adapter,
		decoded,
		16,
		testDRWACallerAddress(drwaSyncCallerPolicyRegistry),
	)
	require.NoError(t, err)
	require.Equal(t, 1, result.AppliedOperations)
}

// Characterizes the current JSON schema-version boundary. The JSON decoder
// does not reject missing or otherwise unsupported non-recovery schema values,
// and hash selection treats every value other than schema 2 as schema 1.
// These legacy compatibility cells must not be mistaken for a closed target
// profile.
func TestCharacterization_JSONNonRecoveryIngressTreatsEveryNon2SchemaAsSchema1(t *testing.T) {
	for _, schemaVersion := range []uint16{0, 1, 3, 65_535} {
		t.Run(fmt.Sprintf("schema-%d", schemaVersion), func(t *testing.T) {
			accounts := createRealAccountsDBForDRWATest(t)
			caller := testDRWACallerAddress("json-schema-policy-registry")
			require.NoError(t, ProvisionDRWAAuthorizedCaller(
				accounts,
				drwaSyncCallerPolicyRegistry,
				caller,
				1,
			))
			envelope := &drwaSyncEnvelope{
				SchemaVersion: schemaVersion,
				CallerDomain:  drwaSyncCallerPolicyRegistry,
				Operations: []drwaSyncOperation{{
					OperationType: drwaSyncOpTokenPolicy,
					TokenID:       "RWA-json-schema-matrix",
					Version:       1,
					Body:          []byte(`{"drwa_enabled":true}`),
				}},
			}
			envelope.PayloadHash = requireDRWASyncEnvelopeHash(t, envelope)

			schema1 := *envelope
			schema1.SchemaVersion = drwaSyncEnvelopeSchemaVersion
			require.Equal(t, requireDRWASyncEnvelopeHash(t, &schema1), envelope.PayloadHash)

			payload, err := json.Marshal(envelope)
			require.NoError(t, err)
			decoded, err := decodeDRWASyncEnvelope(payload)
			require.NoError(t, err)
			require.Equal(t, schemaVersion, decoded.SchemaVersion)

			hook := &BlockChainHookImpl{accounts: accounts}
			require.NoError(t, hook.ApplyDRWASyncEnvelopeBytes(payload, caller))
			adapter, err := newDRWAHookStateAdapter(accounts)
			require.NoError(t, err)
			version, err := adapter.GetTokenPolicyVersion("RWA-json-schema-matrix")
			require.NoError(t, err)
			require.Equal(t, uint64(1), version)
		})
	}

	accounts := createRealAccountsDBForDRWATest(t)
	caller := testDRWACallerAddress("json-omitted-schema-policy-registry")
	require.NoError(t, ProvisionDRWAAuthorizedCaller(
		accounts,
		drwaSyncCallerPolicyRegistry,
		caller,
		1,
	))
	operations := []drwaSyncOperation{{
		OperationType: drwaSyncOpTokenPolicy,
		TokenID:       "RWA-json-schema-omitted",
		Version:       1,
		Body:          []byte(`{"drwa_enabled":true}`),
	}}
	hash, err := computeDRWASyncHash(drwaSyncCallerPolicyRegistry, operations)
	require.NoError(t, err)
	payload, err := json.Marshal(map[string]any{
		"caller_domain": drwaSyncCallerPolicyRegistry,
		"payload_hash":  hash,
		"operations":    operations,
	})
	require.NoError(t, err)
	decoded, err := decodeDRWASyncEnvelope(payload)
	require.NoError(t, err)
	require.Zero(t, decoded.SchemaVersion)
	hook := &BlockChainHookImpl{accounts: accounts}
	require.NoError(t, hook.ApplyDRWASyncEnvelopeBytes(payload, caller))
	adapter, err := newDRWAHookStateAdapter(accounts)
	require.NoError(t, err)
	version, err := adapter.GetTokenPolicyVersion("RWA-json-schema-omitted")
	require.NoError(t, err)
	require.Equal(t, uint64(1), version)
}

// Characterizes the current zero-operation ordering at the public production
// hook. The outer allow-list accepts a caller registered for any DRWA domain,
// then apply returns the valid implicit no-op before checking that the caller
// matches the envelope's declared domain. This performs no DRWA state write,
// but it proves the legacy admission grammar is not domain-closed.
func TestCharacterization_EmptyEnvelopeReturnsBeforeDomainSpecificAuthorization(t *testing.T) {
	accounts := createRealAccountsDBForDRWATest(t)
	policyRegistry := testDRWACallerAddress("noop-policy-registry")
	assetManager := testDRWACallerAddress("noop-asset-manager")
	require.NoError(t, ProvisionDRWAAuthorizedCaller(
		accounts,
		drwaSyncCallerPolicyRegistry,
		policyRegistry,
		1,
	))
	require.NoError(t, ProvisionDRWAAuthorizedCaller(
		accounts,
		drwaSyncCallerAssetManager,
		assetManager,
		1,
	))

	hook := &BlockChainHookImpl{accounts: accounts}
	adapter, err := newDRWAHookStateAdapter(accounts)
	require.NoError(t, err)
	require.False(t, isDRWASyncCallerAuthorized(
		adapter,
		drwaSyncCallerPolicyRegistry,
		nil,
		assetManager,
	))

	policyNoop := buildBinaryEnvelope(t, drwaSyncCallerPolicyRegistry, nil)
	require.NoError(t, hook.ApplyDRWASyncEnvelopeBytes(policyNoop, assetManager))
	require.EqualError(
		t,
		hook.ApplyDRWASyncEnvelopeBytes(policyNoop, testDRWACallerAddress("unregistered-noop-caller")),
		drwaSyncRejectUnauthorizedCaller,
	)
}

func TestCharacterization_JSONSchema2IsAcceptedForNonRecoveryDomain(t *testing.T) {
	accounts := createRealAccountsDBForDRWATest(t)
	caller := testDRWACallerAddress("json-schema2-policy-registry")
	require.NoError(t, ProvisionDRWAAuthorizedCaller(
		accounts,
		drwaSyncCallerPolicyRegistry,
		caller,
		1,
	))
	envelope := &drwaSyncEnvelope{
		SchemaVersion: drwaSyncEnvelopeSchemaVersionWithRecovery,
		CallerDomain:  drwaSyncCallerPolicyRegistry,
		Operations: []drwaSyncOperation{{
			OperationType: drwaSyncOpTokenPolicy,
			TokenID:       "RWA-json-schema2-policy",
			Version:       1,
			Body:          []byte(`{"drwa_enabled":true}`),
		}},
	}
	envelope.PayloadHash = requireDRWASyncEnvelopeHash(t, envelope)
	payload, err := json.Marshal(envelope)
	require.NoError(t, err)

	hook := &BlockChainHookImpl{accounts: accounts}
	require.NoError(t, hook.ApplyDRWASyncEnvelopeBytes(payload, caller))
	adapter, err := newDRWAHookStateAdapter(accounts)
	require.NoError(t, err)
	version, err := adapter.GetTokenPolicyVersion("RWA-json-schema2-policy")
	require.NoError(t, err)
	require.Equal(t, uint64(1), version)
}

func TestCharacterization_JSONDuplicateMembersUseLastValue(t *testing.T) {
	accounts := createRealAccountsDBForDRWATest(t)
	caller := testDRWACallerAddress("json-duplicate-policy-registry")
	require.NoError(t, ProvisionDRWAAuthorizedCaller(
		accounts,
		drwaSyncCallerPolicyRegistry,
		caller,
		1,
	))
	envelope := &drwaSyncEnvelope{
		SchemaVersion: 3,
		CallerDomain:  drwaSyncCallerPolicyRegistry,
		Operations: []drwaSyncOperation{{
			OperationType: drwaSyncOpTokenPolicy,
			TokenID:       "RWA-json-duplicate-schema",
			Version:       1,
			Body:          []byte(`{"drwa_enabled":true}`),
		}},
	}
	envelope.PayloadHash = requireDRWASyncEnvelopeHash(t, envelope)
	payload, err := json.Marshal(envelope)
	require.NoError(t, err)
	payload = bytes.Replace(
		payload,
		[]byte(`"schema_version":3`),
		[]byte(`"schema_version":1,"schema_version":3`),
		1,
	)
	decoded, err := decodeDRWASyncEnvelope(payload)
	require.NoError(t, err)
	require.Equal(t, uint16(3), decoded.SchemaVersion)

	hook := &BlockChainHookImpl{accounts: accounts}
	require.NoError(t, hook.ApplyDRWASyncEnvelopeBytes(payload, caller))
	adapter, err := newDRWAHookStateAdapter(accounts)
	require.NoError(t, err)
	version, err := adapter.GetTokenPolicyVersion("RWA-json-duplicate-schema")
	require.NoError(t, err)
	require.Equal(t, uint64(1), version)
}

func TestCharacterization_JSONFormatDetectionDoesNotTrimWhitespaceOrBOM(t *testing.T) {
	jsonPayload := []byte(`{"schema_version":1,"caller_domain":"policy_registry","operations":[]}`)

	_, whitespaceErr := decodeDRWASyncEnvelope(append([]byte(" \n"), jsonPayload...))
	require.Error(t, whitespaceErr)
	_, bomErr := decodeDRWASyncEnvelope(append([]byte{0xef, 0xbb, 0xbf}, jsonPayload...))
	require.Error(t, bomErr)
}

// Characterizes the inverse first-byte discriminator collision. The current
// ingress checks payload[0] before removing the 32-byte binary hash, so an
// otherwise canonical binary envelope whose hash starts with the JSON marker
// '{' is sent to json.Unmarshal and rejected.
func TestCharacterization_BinaryHashLeadingJSONMarkerIsMisrouted(t *testing.T) {
	var binaryPayload []byte
	for nonce := 0; nonce < 100_000; nonce++ {
		candidate := buildBinaryEnvelope(t, drwaSyncCallerPolicyRegistry, []drwaSyncOperation{{
			OperationType: drwaSyncOpTokenPolicy,
			TokenID:       fmt.Sprintf("RWA-binary-marker-%d", nonce),
			Version:       1,
			Body:          []byte(`{"drwa_enabled":true}`),
		}})
		if candidate[0] == '{' {
			binaryPayload = candidate
			break
		}
	}
	require.NotEmpty(t, binaryPayload)

	decodedBinary, err := decodeDRWASyncEnvelopeBinary(binaryPayload)
	require.NoError(t, err)
	require.Equal(t, drwaSyncCallerPolicyRegistry, decodedBinary.CallerDomain)

	_, err = decodeDRWASyncEnvelope(binaryPayload)
	require.Error(t, err)
}

func requireDRWASyncEnvelopeHash(t *testing.T, envelope *drwaSyncEnvelope) []byte {
	t.Helper()

	hash, err := computeDRWASyncEnvelopeHash(envelope)
	require.NoError(t, err)
	return hash
}
