package shared

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

// The independent field roster is taken from the adopted R86 v1 contract,
// sections 2.1–2.6. It is intentionally not generated from the DTO or codec.
func TestQualSP280PublicObservationSchemaContract(t *testing.T) {
	specs := []struct {
		dto    any
		fields map[string]string
	}{
		{ObservationReportV1{}, map[string]string{
			"schemaVersion": "string", "availability": "shared.ObservationAvailability",
			"subject": "*shared.PublicObservationSubject", "observations": "[]shared.PublicObservation",
			"reportedAtMs": "*shared.ObservationUnixMs",
		}},
		{PublicObservationSubject{}, map[string]string{
			"recordRef": "*shared.ObservationOpaqueRef", "effectRef": "*shared.ObservationOpaqueRef",
			"contextRef": "*shared.ObservationOpaqueRef", "transactionHash": "*shared.ObservationHash",
			"originalTransactionHash": "*shared.ObservationHash", "originalBatchId": "*shared.ObservationPublicLabel",
			"originalBatchRef": "*shared.ObservationOpaqueRef", "tokenId": "*shared.ObservationTokenID",
			"tokenNonce": "*shared.ObservationUInt64", "holderAddress": "*shared.ObservationAddress",
			"beneficiaryAddress": "*shared.ObservationAddress", "policyVersionRef": "*shared.ObservationPublicLabel",
			"policyEpoch": "*uint32",
		}},
		{PublicObservation{}, map[string]string{
			"observationRef": "*shared.ObservationOpaqueRef", "kind": "shared.ObservationKind",
			"availability": "shared.ObservationAvailability", "state": "shared.ObservationState",
			"subject": "*shared.PublicObservationSubject", "provenance": "*shared.PublicObservationProvenance",
			"finalityBasis": "*shared.PublicObservationFinalityBasis", "values": "[]shared.PublicObservationValue",
			"originalValues": "[]shared.PublicObservationValue", "gasRefund": "*shared.PublicObservationGasRefund",
		}},
		{PublicObservationProvenance{}, map[string]string{
			"producerId": "*shared.ObservationPublicLabel", "producerVersion": "*shared.ObservationPublicLabel",
			"producerCommitId": "*shared.ObservationPublicLabel", "basisRef": "*shared.ObservationOpaqueRef",
			"executionObjectHash": "*shared.ObservationHash", "executionShard": "*uint32",
			"asOfBlockHash": "*shared.ObservationHash", "asOfBlockNonce": "*shared.ObservationUInt64",
			"asOfBlockRound": "*shared.ObservationUInt64", "asOfShard": "*uint32",
			"observedAtMs": "*shared.ObservationUnixMs",
		}},
		{PublicObservationFinalityBasis{}, map[string]string{
			"membershipKind": "shared.ObservationMembershipKind", "blockHash": "*shared.ObservationHash",
			"blockNonce": "*shared.ObservationUInt64", "blockRound": "*shared.ObservationUInt64",
			"blockEpoch": "*uint32", "blockShard": "*uint32", "miniblockHash": "*shared.ObservationHash",
			"transactionHash": "*shared.ObservationHash", "subjectResultHash": "*shared.ObservationHash",
			"executionHeaderHash": "*shared.ObservationHash", "executionHeaderNonce": "*shared.ObservationUInt64",
			"executionHeaderRound": "*shared.ObservationUInt64", "executionHeaderEpoch": "*uint32",
			"finalityAtBlockHash": "*shared.ObservationHash",
		}},
		{PublicObservationValue{}, map[string]string{
			"tokenId": "shared.ObservationTokenID", "tokenNonce": "*shared.ObservationUInt64",
			"quantityAtomic": "shared.ObservationUInt", "unit": "shared.ObservationUnit",
		}},
		{PublicObservationGasRefund{}, map[string]string{
			"tokenId": "*shared.ObservationTokenID", "amountAtomic": "*shared.ObservationUInt",
			"amountUnit": "*shared.ObservationUnit", "gasUnits": "*shared.ObservationUInt",
			"gasUnit": "*shared.ObservationUnit", "presentationClass": "shared.ObservationRefundClass",
		}},
	}

	require.Equal(t, "drwa-observation-v1", ObservationVersionV1)
	count := 0
	for _, spec := range specs {
		count += len(spec.fields)
		typ := reflect.TypeOf(spec.dto)
		t.Run(typ.Name(), func(t *testing.T) {
			actual := make(map[string]string)
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				require.True(t, field.IsExported())
				tag, exists := field.Tag.Lookup("json")
				require.True(t, exists)
				require.NotContains(t, actual, tag)
				actual[tag] = field.Type.String()
			}
			require.Equal(t, spec.fields, actual)

			// Raw zero-value serialization checks only DTO shape and presence.
			// It is deliberately not an admitted or valid observation report.
			wire, err := json.Marshal(spec.dto)
			require.NoError(t, err)
			var object map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(wire, &object))
			require.Len(t, object, len(spec.fields))
			for key, typeName := range spec.fields {
				require.Contains(t, object, key)
				if typeName[0] == '*' || typeName[0] == '[' {
					require.Equal(t, "null", string(object[key]), key)
				}
			}
		})
	}
	require.Equal(t, 63, count)
}
