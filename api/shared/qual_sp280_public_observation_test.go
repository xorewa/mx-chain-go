package shared

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core/pubkeyConverter"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/stretchr/testify/require"
)

func observationTestPtr[T any](value T) *T { return &value }

func observationTestReport(observations ...PublicObservation) ObservationReportV1 {
	if observations == nil {
		observations = []PublicObservation{}
	}
	return ObservationReportV1{SchemaVersion: ObservationVersionV1, Availability: ObservationAvailable, Observations: observations}
}

func TestQualSP280PublicObservationNullableAndExtension(t *testing.T) {
	for _, tc := range []struct {
		name   string
		report ObservationReportV1
		list   string
	}{
		{"unknown", observationLimitation(ObservationUnknown), "null"},
		{"known empty", observationTestReport(), "[]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := EncodeObservationReport(tc.report)
			require.NoError(t, err)
			var raw map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(wire, &raw))
			require.Len(t, raw, 5)
			require.Equal(t, tc.list, string(raw["observations"]))
			require.Equal(t, "null", string(raw["subject"]))
			require.Equal(t, "null", string(raw["reportedAtMs"]))
			raw["futureDisplayLabel"] = json.RawMessage(`"example"`)
			wire, err = json.Marshal(raw)
			require.NoError(t, err)
			decoded, err := DecodeObservationReport(wire)
			require.NoError(t, err)
			require.Equal(t, tc.report, decoded)
		})
	}
	legacy := GenericAPIResponse{Data: map[string]string{"label": "ordinary"}, Error: "", Code: ReturnCodeSuccess}
	wire, err := json.Marshal(legacy)
	require.NoError(t, err)
	require.JSONEq(t, `{"data":{"label":"ordinary"},"error":"","code":"successful"}`, string(wire))
}

func TestQualSP280PublicObservationKnownAndUnknownVersion(t *testing.T) {
	for _, tc := range []struct {
		name, wire   string
		want         error
		availability ObservationAvailability
	}{
		{"unknown version", `{"schemaVersion":"future-display"}`, ErrUnsupportedObservationVersion, ObservationUnsupported},
		{"missing version", `{}`, ErrMalformedObservation, ObservationMalformed},
		{"version absent", `{"schemaVersion":null}`, ErrMalformedObservation, ObservationMalformed},
		{"missing required key", `{"schemaVersion":"drwa-observation-v1","availability":"UNKNOWN","subject":null,"observations":null}`, ErrMalformedObservation, ObservationMalformed},
		{"non object", `[]`, ErrMalformedObservation, ObservationMalformed},
		{"unentered list", `{"schemaVersion":"drwa-observation-v1","availability":"AVAILABLE","subject":null,"observations":null,"reportedAtMs":null}`, ErrMalformedObservation, ObservationMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report, err := DecodeObservationReport([]byte(tc.wire))
			require.ErrorIs(t, err, tc.want)
			require.Equal(t, observationLimitation(tc.availability), report)
		})
	}
	_, err := EncodeObservationReport(ObservationReportV1{SchemaVersion: "future-display"})
	require.ErrorIs(t, err, ErrUnsupportedObservationVersion)
	_, err = EncodeObservationReport(ObservationReportV1{SchemaVersion: ObservationVersionV1, Availability: ObservationAvailable})
	require.ErrorIs(t, err, ErrMalformedObservation)
}

func TestQualSP280PublicObservationSuppliedPresentationValues(t *testing.T) {
	// These are invented display-only values, independent of native records.
	converter, err := pubkeyConverter.NewBech32PubkeyConverter(32, "erd")
	require.NoError(t, err)
	addr, err := converter.Encode(make([]byte, 32))
	require.NoError(t, err)
	hash := ObservationHash(strings.Repeat("a", 64))
	other := ObservationHash(strings.Repeat("b", 64))
	zero := uint32(0)
	nonce := ObservationUInt64("18446744073709551615")
	value := PublicObservationValue{TokenID: "DEMO-abcdef", TokenNonce: &nonce, QuantityAtomic: "1000000000000000000000000000000", Unit: "ASSET_ATOMIC"}
	subject := &PublicObservationSubject{TransactionHash: &hash, OriginalTransactionHash: &other, TokenID: observationTestPtr(ObservationTokenID("DEMO-abcdef")), TokenNonce: &nonce, HolderAddress: observationTestPtr(ObservationAddress(addr)), PolicyEpoch: &zero, RecordRef: observationTestPtr(ObservationOpaqueRef("example-label"))}
	provenance := &PublicObservationProvenance{ProducerID: observationTestPtr(ObservationPublicLabel("example")), ExecutionObjectHash: &hash, ExecutionShard: &zero, ObservedAtMs: observationTestPtr(ObservationUnixMs("1234"))}
	states := []PublicObservation{
		{Kind: "SUBMISSION", Availability: ObservationAvailable, State: "ACKNOWLEDGED", Subject: subject},
		{Kind: "PROVISIONAL_EXECUTION", Availability: ObservationAvailable, State: "OBSERVED", Subject: subject, Provenance: provenance},
		{Kind: "VALUE_SETTLEMENT", Availability: ObservationAvailable, State: "SETTLED", Values: []PublicObservationValue{value}},
		{Kind: "VALUE_RETURN", Availability: ObservationAvailable, State: "IN_TRANSIT", OriginalValues: []PublicObservationValue{value}},
		{Kind: "ECONOMIC_GAS_REFUND", Availability: ObservationAvailable, State: "REPORTED", GasRefund: &PublicObservationGasRefund{TokenID: observationTestPtr(ObservationTokenID("DEMO-abcdef")), AmountAtomic: observationTestPtr(ObservationUInt("0")), AmountUnit: observationTestPtr(ObservationUnit("ASSET_ATOMIC")), GasUnits: observationTestPtr(ObservationUInt("15")), GasUnit: observationTestPtr(ObservationUnit("GAS_UNIT")), PresentationClass: "INFORMATIONAL"}},
		{Kind: "SOURCE_COMPLETION", Availability: ObservationUnknown, State: "UNKNOWN"},
		{Kind: "PREFLIGHT_ADVISORY", Availability: ObservationAvailable, State: "INDETERMINATE"},
		{Kind: "CANONICAL_FINALITY", Availability: ObservationUnavailable, State: "UNAVAILABLE"},
	}
	report := observationTestReport(states...)
	report.Subject = subject
	report.ReportedAtMs = observationTestPtr(ObservationUnixMs("5678"))
	wire, err := EncodeObservationReport(report)
	require.NoError(t, err)
	decoded, err := DecodeObservationReport(wire)
	require.NoError(t, err)
	require.Equal(t, report, decoded)
	// The ordinary DTO adapter preserves explicit fields but does not create an outcome.
	fromSource, err := ObservationSubjectFromPublicTransaction(&transaction.ApiTransactionResult{Hash: string(hash), OriginalTransactionHash: string(other), Receiver: addr, Value: "12"})
	require.NoError(t, err)
	require.Equal(t, &PublicObservationSubject{TransactionHash: &hash, OriginalTransactionHash: &other}, fromSource)
	absent, err := ObservationSubjectFromPublicTransaction(nil)
	require.NoError(t, err)
	require.Nil(t, absent)
	empty, err := ObservationSubjectFromPublicTransaction(&transaction.ApiTransactionResult{})
	require.NoError(t, err)
	require.Nil(t, empty)
}

func TestQualSP280PublicObservationDisplaySemantics(t *testing.T) {
	for _, tc := range []struct {
		name string
		o    PublicObservation
	}{
		{"unknown kind", PublicObservation{Kind: "FUTURE_DISPLAY", Availability: ObservationAvailable, State: "ADVISORY"}},
		{"unknown state", PublicObservation{Kind: "SUBMISSION", Availability: ObservationAvailable, State: "FUTURE_DISPLAY"}},
		{"unknown availability", PublicObservation{Kind: "SUBMISSION", Availability: "FUTURE_DISPLAY", State: "UNKNOWN"}},
		{"unavailable list", PublicObservation{Kind: "VALUE_RETURN", Availability: ObservationUnavailable, State: "UNAVAILABLE", Values: []PublicObservationValue{}}},
		{"incomplete public basis", PublicObservation{Kind: "CANONICAL_FINALITY", Availability: ObservationAvailable, State: "FINALIZED"}},
		{"provisional without basis", PublicObservation{Kind: "PROVISIONAL_EXECUTION", Availability: ObservationAvailable, State: "OBSERVED"}},
		{"refund unit absent", PublicObservation{Kind: "ECONOMIC_GAS_REFUND", Availability: ObservationAvailable, State: "REPORTED", GasRefund: &PublicObservationGasRefund{AmountAtomic: observationTestPtr(ObservationUInt("20")), PresentationClass: "INFORMATIONAL"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := observationTestReport(tc.o)
			_, err := EncodeObservationReport(report)
			require.ErrorIs(t, err, ErrMalformedObservation)
			wire, err := json.Marshal(report)
			require.NoError(t, err)
			decoded, err := DecodeObservationReport(wire)
			require.ErrorIs(t, err, ErrMalformedObservation)
			require.Equal(t, observationLimitation(ObservationMalformed), decoded)
		})
	}
	for _, a := range []ObservationAvailability{ObservationUnknown, ObservationStale, ObservationMalformed, ObservationConflicting, ObservationUnsupported} {
		state := ObservationState("UNKNOWN")
		if a == ObservationUnsupported {
			state = "UNAVAILABLE"
		}
		report := observationTestReport(PublicObservation{Kind: "SUBMISSION", Availability: a, State: state})
		wire, err := EncodeObservationReport(report)
		require.NoError(t, err)
		decoded, err := DecodeObservationReport(wire)
		require.NoError(t, err)
		require.Equal(t, report, decoded)
	}
}

func TestQualSP280PublicObservationReferenceShapes(t *testing.T) {
	// Shape-only example: no report, source evidence, or finality assertion.
	hash := ObservationHash(strings.Repeat("a", 64))
	nonce := ObservationUInt64("1")
	shard := uint32(1)
	base := PublicObservationFinalityBasis{
		MembershipKind: "BLOCK_MINIBLOCK_TRANSACTION", BlockHash: &hash, BlockNonce: &nonce,
		BlockRound: &nonce, BlockShard: &shard, MiniblockHash: &hash, TransactionHash: &hash,
	}
	require.True(t, completePublicMembership(&base))
	base.MembershipKind = "EXECUTION_RESULT_MINIBLOCK_TRANSACTION"
	require.False(t, completePublicMembership(&base))
	base.ExecutionHeaderHash, base.ExecutionHeaderNonce = &hash, &nonce
	base.ExecutionHeaderRound, base.ExecutionHeaderEpoch = &nonce, &shard
	require.True(t, completePublicMembership(&base))
	base.MembershipKind = "UNKNOWN"
	require.False(t, completePublicMembership(&base))
	base.MembershipKind, base.TransactionHash, base.SubjectResultHash = "BLOCK_MINIBLOCK_TRANSACTION", nil, &hash
	require.True(t, completePublicMembership(&base))
}

func TestQualSP280PublicObservationBasicFormats(t *testing.T) {
	for _, v := range []ObservationHash{"", "example", ObservationHash(strings.Repeat("A", 64))} {
		require.False(t, validObservationHash(v))
	}
	for _, v := range []string{"", "01", "1.5", "18446744073709551616"} {
		require.False(t, validObservationDecimal(v, true))
	}
	require.True(t, validObservationDecimal("0", true))
	require.True(t, validObservationDecimal("18446744073709551616", false))
	require.False(t, validObservationAddress("Example"))
	require.False(t, validObservationAddress("example"))
	_, err := ObservationSubjectFromPublicTransaction(&transaction.ApiTransactionResult{Hash: "example"})
	require.ErrorIs(t, err, ErrMalformedObservation)
}

func TestQualSP280PublicObservationRequiredNestedFields(t *testing.T) {
	valid := observationTestReport(PublicObservation{Kind: "SUBMISSION", Availability: ObservationAvailable, State: "ACKNOWLEDGED"})
	wire, err := EncodeObservationReport(valid)
	require.NoError(t, err)
	var object map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(wire, &object))
	var children []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(object["observations"], &children))
	children[0]["futureLabel"] = json.RawMessage(`"test display"`)
	children[0]["State"] = json.RawMessage(`"future display"`)
	object["observations"], err = json.Marshal(children)
	require.NoError(t, err)
	wire, err = json.Marshal(object)
	require.NoError(t, err)
	decoded, err := DecodeObservationReport(wire)
	require.NoError(t, err)
	require.Equal(t, valid, decoded)
	for _, v := range []json.RawMessage{json.RawMessage(`"not an array"`), json.RawMessage(`[null]`), json.RawMessage(`[{"kind":"SUBMISSION"}]`)} {
		object["observations"] = v
		wire, err = json.Marshal(object)
		require.NoError(t, err)
		decoded, err = DecodeObservationReport(wire)
		require.ErrorIs(t, err, ErrMalformedObservation)
		require.Equal(t, observationLimitation(ObservationMalformed), decoded)
	}
	for _, raw := range []string{`{"schemaVersion":"drwa-observation-v1","schemaVersion":"drwa-observation-v1"}`, `{"schemaVersion":`, `{"schemaVersion":"drwa-observation-v1"} {}`} {
		decoded, err := DecodeObservationReport([]byte(raw))
		require.ErrorIs(t, err, ErrMalformedObservation)
		require.Equal(t, observationLimitation(ObservationMalformed), decoded)
	}
}
