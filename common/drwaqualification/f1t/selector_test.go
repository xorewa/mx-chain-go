package f1t

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"sort"
	"strings"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/common"
	processMock "github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
)

func TestCanonicalSourceConstructorReproducesV17ProfileIdentities(t *testing.T) {
	constructor := DefaultCanonicalSourceConstructor()
	tests := []struct {
		profile Profile
		arm     string
		scr     string
		mini    string
		batch   string
	}{
		{ProfileLegacy, "SELECTED", "aeafa062494b64ac448af4668321ad33aef1b9f2e97bdba88f54d6634c611c53", "1d3e41a51d75ac68bbb2700c43d459f8abab3d2a5120c3bc11767794031f8a23", "5a8572f6afebc12464a27af400a3883153ba79c91e98e33ee2ccf029907a25c9"},
		{ProfileV2, "SELECTED", "282008087574fa2fbb58c5c9c056a875f972132d20ab9f33dd06b1d62d7dd5e3", "5258aa94c2b42728edee3b5ecd28daff89c3910be31aaf78eaa1a85124b049cf", "1312b939514c3d6ce9f0f374b156ced45f59d464be95496d8865bfe5b10e4b3c"},
		{ProfileLegacy, "SENTINEL_1", "9d195155ae9995ac7360aabb3f46873ad47acbaab577d749c8263b02910f996a", "d7c82c8cca4b685ebc3d40287e88dc9681d753737e650f39d095f700d44cdf75", "31104fcaf5cad66b358affebece21da291460796e1f753533549a4be2011a2ac"},
		{ProfileV2, "SENTINEL_1", "57b26fc5f96a4e1d57ed099d5b56957281487e2ea1afbec6ad1185029491a7ea", "28ed2e7978eb36217decceb1eb3e88262da982da513bedcc1156fb4a055ba632", "8e05e9bc703bfbc5fad4bc2888c7f1170ddee269e2543af6e49e44e6507be694"},
	}
	for _, test := range tests {
		t.Run(string(test.profile)+"/"+test.arm, func(t *testing.T) {
			_, fixture, err := BuildCalibrationFixture(constructor, test.profile, test.arm, 1, "fixture", "topic", "peer", test.arm == "SELECTED")
			require.NoError(t, err)
			require.Equal(t, test.scr, fixture.SCRHash)
			require.Equal(t, test.mini, fixture.MiniBlockHash)
			require.Equal(t, test.batch, fixture.BatchSHA256)
			require.NotEmpty(t, fixture.ArtifactChainSHA256)
		})
	}
}

func TestFixtureLabelsArtifactChainDigestWithoutClaimingSourceCodeProvenance(t *testing.T) {
	raw, _, err := BuildCalibrationFixture(DefaultCanonicalSourceConstructor(), ProfileV2, "SELECTED", 1, "fixture", "topic", "peer", true)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"artifact_chain_sha256"`)
	require.NotContains(t, string(raw), `"source_constructor_sha256"`)
}

func TestFixtureClassificationIsSemanticFirstThenRawIdentity(t *testing.T) {
	constructor := DefaultCanonicalSourceConstructor()
	selected, selectedFixture, err := BuildCalibrationFixture(constructor, ProfileV2, "SELECTED", 1, "fixture", "topic", "peer", true)
	require.NoError(t, err)
	sentinel, _, err := BuildCalibrationFixture(constructor, ProfileV2, "SENTINEL_1", 1, "fixture", "topic", "peer", false)
	require.NoError(t, err)
	selection, err := ClassifyFixture(selected, ProfileV2, "topic", "peer", [][]byte{selected, sentinel})
	require.NoError(t, err)
	require.Equal(t, "SELECTED", selection.ClassifiedArm)
	require.True(t, selection.Selected)
	require.Equal(t, "EXPECTED_SOURCE_ARM_ONLY_NOT_OBSERVED", selection.PredicateEvidenceStatus)
	require.Len(t, selection.ExpectedPredicateVector, 59)
	require.Equal(t, "N_A", selection.ExpectedPredicateVector["PR042_VM_INPUT_TRANSFORM"])
	require.Equal(t, "TRUE", selection.ExpectedPredicateVector["PR052_DESTINATION_CONVERSION_REACHED"])
	require.Equal(t, "TRUE", selection.ExpectedPredicateVector["PR059_MINIBLOCK_RESERVED_EMPTY"])
	selection.ExpectedPredicateVector["PR001_BATCH_DECODABLE"] = "MUTATED"
	reselection, err := ClassifyFixture(selected, ProfileV2, "topic", "peer", [][]byte{selected, sentinel})
	require.NoError(t, err)
	require.Equal(t, "TRUE", reselection.ExpectedPredicateVector["PR001_BATCH_DECODABLE"])

	_, err = EvaluateFixture(selected, ProfileLegacy, "topic", "peer")
	require.ErrorIs(t, err, ErrSelectorMismatch)

	// This candidate has selected semantics but a distinct source-constructed raw chain.
	otherRaw, _, err := BuildCalibrationFixture(constructor, ProfileV2, "SELECTED", 1, "different-kind", "topic", "peer", true)
	require.NoError(t, err)
	_, err = ClassifyFixture(otherRaw, ProfileV2, "topic", "peer", [][]byte{selected, sentinel})
	require.ErrorIs(t, err, ErrSelectorMismatch)

	_, err = ClassifyFixture(selected, ProfileV2, "topic", "peer", [][]byte{selected, selected})
	require.ErrorIs(t, err, ErrSelectorMismatch)

	calibration, _, err := BuildCalibrationFixture(constructor, ProfileV2, "CALIBRATION_1", 1, "fixture", "topic", "peer", false)
	require.NoError(t, err)
	_, err = ClassifyFixture(calibration, ProfileV2, "topic", "peer", [][]byte{selected, sentinel})
	require.ErrorIs(t, err, ErrSelectorMismatch)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(selected, &decoded))
	decoded["scr_hash"] = selectedFixture.MiniBlockHash
	mutated, err := json.Marshal(decoded)
	require.NoError(t, err)
	_, err = EvaluateFixture(mutated, ProfileV2, "topic", "peer")
	require.ErrorIs(t, err, ErrSelectorMismatch)
}

func TestV17PositivePredicateVectorUsesExactFrozenIdentifiers(t *testing.T) {
	vector := V17PositivePredicateVector()
	require.Len(t, vector, len(v17PredicateIDs))
	for _, id := range v17PredicateIDs {
		value, exists := vector[id]
		require.True(t, exists, id)
		require.Contains(t, []string{"TRUE", "N_A"}, value, id)
	}
	require.NotContains(t, vector, "PR001")
	require.NotContains(t, vector, "PR059")
	require.Len(t, v17PositiveNotApplicableIDs, 12)

	ids := make([]string, 0, len(vector))
	for id := range vector {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var canonical strings.Builder
	for _, id := range ids {
		canonical.WriteString(id)
		canonical.WriteByte('=')
		canonical.WriteString(vector[id])
		canonical.WriteByte('\n')
	}
	digest := sha256.Sum256([]byte(canonical.String()))
	require.Equal(t, "53657b9755908c1c665f2be485377a6e4eb6814b595588a7640aa5a27aa3e84a", hex.EncodeToString(digest[:]))
}

func TestFixtureRequiresSourceConstructor(t *testing.T) {
	_, _, err := BuildCalibrationFixture(nil, ProfileV2, "SELECTED", 1, "fixture", "topic", "peer", true)
	require.ErrorIs(t, err, ErrSourceConstructorUnavailable)

	constructor := DefaultCanonicalSourceConstructor()
	_, _, err = BuildCalibrationFixture(constructor, ProfileV2, "SELECTED", 1, "fixture", "topic", "peer", false)
	require.ErrorIs(t, err, ErrSourceConstructorUnavailable)
	_, _, err = BuildCalibrationFixture(constructor, ProfileV2, "CALIBRATION_01", 1, "fixture", "topic", "peer", false)
	require.ErrorIs(t, err, ErrSourceConstructorUnavailable)
}

func TestObservedFixtureProjectsAllFieldsAndEvaluatesStructuredResults(t *testing.T) {
	constructor := DefaultCanonicalSourceConstructor()
	selected, _, err := BuildCalibrationFixture(constructor, ProfileV2, "SELECTED", 1, "fixture", "topic", "peer", true)
	require.NoError(t, err)
	sentinel, _, err := BuildCalibrationFixture(constructor, ProfileV2, "SENTINEL_1", 1, "fixture", "topic", "peer", false)
	require.NoError(t, err)

	context := observedFixtureContext(constructor.NetworkDomain)
	selection, err := ClassifyObservedFixture(selected, ProfileV2, "topic", "peer", [][]byte{selected, sentinel}, context)
	require.NoError(t, err)
	require.Equal(t, "OBSERVED_STRUCTURED_SUCCESSOR", selection.PredicateEvidenceStatus)
	require.Len(t, selection.ObservedPredicates, 59)
	require.Equal(t, PredicateResult{State: "TRUE"}, selection.ObservedPredicates["PR041_VALIDATOR_PROJECTION"])
	require.Equal(t, PredicateResult{State: "FALSE"}, selection.ObservedPredicates["PR052_DESTINATION_CONVERSION_REACHED"])
	require.Equal(t, "N_A", selection.ObservedPredicates["PR042_VM_INPUT_TRANSFORM"].State)
	require.NotEmpty(t, selection.ObservedPredicates["PR042_VM_INPUT_TRANSFORM"].ReasonID)
	require.Equal(t, uint64(4_800_000), selection.SemanticCandidate.GasLimit)
	require.Equal(t, OptionalDecimal{State: "ABSENT"}, selection.SemanticCandidate.RelayedValue)
	require.Equal(t, hex.EncodeToString(constructor.NetworkDomain[:]), selection.SemanticCandidate.NetworkDomain)
	require.Equal(t, "445257415155414c2d616263646566", selection.SemanticCandidate.Intent.RegulatedTokenID)
	require.Equal(t, selection.SemanticCandidate.Intent, selection.SemanticCandidate.Envelope.Intent)
	require.NotContains(t, string(mustJSON(t, selection.SemanticCandidate)), "reserved_gas")

	selection.ObservedPredicates["PR001_BATCH_DECODABLE"] = PredicateResult{State: "FALSE"}
	reselection, err := ClassifyObservedFixture(selected, ProfileV2, "topic", "peer", [][]byte{selected, sentinel}, context)
	require.NoError(t, err)
	require.Equal(t, PredicateResult{State: "TRUE"}, reselection.ObservedPredicates["PR001_BATCH_DECODABLE"])
}

func TestObservedFixtureValidatesCapturedProductionInputWithoutReconstruction(t *testing.T) {
	constructor := DefaultCanonicalSourceConstructor()
	for _, profile := range []Profile{ProfileLegacy, ProfileV2} {
		t.Run(string(profile), func(t *testing.T) {
			selected, _, err := BuildCalibrationFixture(constructor, profile, "SELECTED", 1, "fixture", "topic", "peer", true)
			require.NoError(t, err)
			sentinel, _, err := BuildCalibrationFixture(constructor, profile, "SENTINEL_1", 1, "fixture", "topic", "peer", false)
			require.NoError(t, err)

			parsed, err := parseFixture(selected, profile, "topic", "peer")
			require.NoError(t, err)
			_, decoded, err := projectSemanticCandidate(parsed, constructor.NetworkDomain)
			require.NoError(t, err)
			input := expectedCapturedInput(profile, decoded.scr, decoded.envelopeBytes, parsed.artifacts.SCRHash)
			context := observedFixtureContext(constructor.NetworkDomain)
			context.Conversion = &DestinationConversionObservation{InvocationCount: 1, VMInput: input}

			selection, err := ClassifyObservedFixture(selected, profile, "topic", "peer", [][]byte{selected, sentinel}, context)
			require.NoError(t, err)
			require.Equal(t, PredicateResult{State: "TRUE"}, selection.ObservedPredicates["PR052_DESTINATION_CONVERSION_REACHED"])

			input.GasProvided--
			selection, err = ClassifyObservedFixture(selected, profile, "topic", "peer", [][]byte{selected, sentinel}, context)
			require.NoError(t, err)
			require.Equal(t, PredicateResult{State: "FALSE"}, selection.ObservedPredicates["PR052_DESTINATION_CONVERSION_REACHED"])
		})
	}
}

func TestObservedFixtureRejectsUnboundContextAndPredicateGraphDefects(t *testing.T) {
	constructor := DefaultCanonicalSourceConstructor()
	selected, _, err := BuildCalibrationFixture(constructor, ProfileV2, "SELECTED", 1, "fixture", "topic", "peer", true)
	require.NoError(t, err)
	sentinel, _, err := BuildCalibrationFixture(constructor, ProfileV2, "SENTINEL_1", 1, "fixture", "topic", "peer", false)
	require.NoError(t, err)
	_, err = ClassifyObservedFixture(selected, ProfileV2, "topic", "peer", [][]byte{selected, sentinel}, ObservationContext{})
	require.ErrorIs(t, err, ErrSelectorMismatch)

	complete := make(map[string]PredicateResult, len(v17PredicateIDs))
	for _, id := range v17PredicateIDs {
		complete[id] = PredicateResult{State: "TRUE"}
	}
	delete(complete, "PR059_MINIBLOCK_RESERVED_EMPTY")
	_, err = resolvePredicateDependencies(complete)
	require.ErrorIs(t, err, ErrSelectorMismatch)
	complete["PR059_MINIBLOCK_RESERVED_EMPTY"] = PredicateResult{State: "TRUE"}
	complete["EXTRA"] = PredicateResult{State: "TRUE"}
	_, err = resolvePredicateDependencies(complete)
	require.ErrorIs(t, err, ErrSelectorMismatch)
	delete(complete, "EXTRA")
	complete["PR046_RECORDER_EVENT"] = PredicateResult{State: "N_A"}
	_, err = resolvePredicateDependencies(complete)
	require.ErrorIs(t, err, ErrSelectorMismatch)
}

func TestObservedValidatorProjectionInvokesRealAdmissionAcrossOrderedRows(t *testing.T) {
	constructor := DefaultCanonicalSourceConstructor()
	raw, _, err := BuildCalibrationFixture(constructor, ProfileV2, "SELECTED", 1, "fixture", "topic", "peer", true)
	require.NoError(t, err)
	parsed, err := parseFixture(raw, ProfileV2, "topic", "peer")
	require.NoError(t, err)
	_, decoded, err := projectSemanticCandidate(parsed, constructor.NetworkDomain)
	require.NoError(t, err)
	active := enableEpochsHandlerMock.NewEnableEpochsHandlerStub(common.DRWAEnforcementFlag)
	inactive := enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
	localDestination := observedFixtureContext(constructor.NetworkDomain).Coordinator
	remoteDestination := &processMock.ShardCoordinatorStub{SelfIdCalled: func() uint32 { return 2 }, ComputeIdCalled: localDestination.ComputeId}
	localSource := &processMock.ShardCoordinatorStub{SelfIdCalled: func() uint32 { return 0 }, ComputeIdCalled: func([]byte) uint32 { return 0 }}

	tests := []struct {
		name        string
		row         string
		handler     common.EnableEpochsHandler
		coordinator sharding.Coordinator
		mutate      func(*smartContractResult.SmartContractResult)
	}{
		{name: "VP01", row: "VP01_KIND_NONE", handler: active, coordinator: localDestination, mutate: func(scr *smartContractResult.SmartContractResult) {
			scr.ProtocolMessageKind = vmData.ProtocolMessageKindNone
		}},
		{name: "VP02", row: "VP02_KIND_UNKNOWN", handler: active, coordinator: localDestination, mutate: func(scr *smartContractResult.SmartContractResult) {
			scr.ProtocolMessageKind = vmData.ProtocolMessageKind(255)
		}},
		{name: "VP03", row: "VP03_BEFORE_ACTIVATION", handler: inactive, coordinator: localDestination},
		{name: "VP04", row: "VP04_RELAYER_ADDR", handler: active, coordinator: localDestination, mutate: func(scr *smartContractResult.SmartContractResult) { scr.RelayerAddr = []byte{1} }},
		{name: "VP05", row: "VP05_RELAYED_VALUE", handler: active, coordinator: localDestination, mutate: func(scr *smartContractResult.SmartContractResult) { scr.RelayedValue = big.NewInt(0) }},
		{name: "VP06", row: "VP06_WRONG_FUNCTION", handler: active, coordinator: localDestination, mutate: func(scr *smartContractResult.SmartContractResult) { scr.Data = []byte("wrong@00") }},
		{name: "VP07", row: "VP07_BAD_GRAMMAR", handler: active, coordinator: localDestination, mutate: func(scr *smartContractResult.SmartContractResult) {
			scr.Data = []byte(vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope)
		}},
		{name: "VP08", row: "VP08_BAD_ENVELOPE", handler: active, coordinator: localDestination, mutate: func(scr *smartContractResult.SmartContractResult) {
			scr.Data = []byte(vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope + "@00")
		}},
		{name: "VP09", row: "VP09_DEST_REMOTE", handler: active, coordinator: remoteDestination},
		{name: "VP10", row: "VP10_SOURCE_LOCAL", handler: active, coordinator: localSource},
		{name: "VP11", row: "VP11_VALID_ROUTE", handler: active, coordinator: localDestination},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scr := decoded.scr
			if test.mutate != nil {
				test.mutate(&scr)
			}
			observation := observeProtocolAdmission(&scr, test.handler, test.coordinator)
			require.True(t, observation.matches)
			require.Equal(t, test.row, observation.projectionID)
			require.NotEqual(t, "UNEXPECTED_ERROR_CLASS", observation.errorClass)
		})
	}
}

func observedFixtureContext(networkDomain [32]byte) ObservationContext {
	return ObservationContext{
		NetworkDomain:       networkDomain,
		EnableEpochsHandler: enableEpochsHandlerMock.NewEnableEpochsHandlerStub(common.DRWAEnforcementFlag),
		Coordinator: &processMock.ShardCoordinatorStub{
			NumberOfShardsCalled: func() uint32 { return 3 },
			SelfIdCalled:         func() uint32 { return 1 },
			ComputeIdCalled: func(address []byte) uint32 {
				if len(address) == 32 && address[0] == 0x22 {
					return 1
				}
				return 0
			},
			SameShardCalled:               func(firstAddress, secondAddress []byte) bool { return bytes.Equal(firstAddress, secondAddress) },
			CommunicationIdentifierCalled: func(destShardID uint32) string { return string(rune(destShardID)) },
		},
	}
}

func expectedCapturedInput(profile Profile, scr smartContractResult.SmartContractResult, envelope []byte, currentHash [32]byte) *vmcommon.ContractCallInput {
	input := &vmcommon.ContractCallInput{RecipientAddr: append([]byte(nil), scr.RcvAddr...), Function: vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope}
	input.NativeCallOrigin = vmcommon.NativeCallOriginDRWAProtocolMessage
	input.CallerAddr = append([]byte(nil), scr.SndAddr...)
	input.Arguments = [][]byte{append([]byte(nil), envelope...)}
	input.CallValue = big.NewInt(0)
	input.CallType = vmData.DirectCall
	input.GasPrice = scr.GasPrice
	input.GasProvided = scr.GasLimit
	input.OriginalTxHash = append([]byte(nil), scr.OriginalTxHash...)
	input.CurrentTxHash = append([]byte(nil), currentHash[:]...)
	input.PrevTxHash = append([]byte(nil), scr.PrevTxHash...)
	if profile == ProfileV2 {
		input.AsyncArguments = &vmcommon.AsyncArguments{}
		input.OriginalCallerAddr = append([]byte(nil), scr.SndAddr...)
	}
	return input
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	return encoded
}

func TestFixtureMessageIdentityBindsArmKindAndIndex(t *testing.T) {
	constructor := DefaultCanonicalSourceConstructor()
	selected, selectedFixture, err := BuildCalibrationFixture(constructor, ProfileV2, "SELECTED", 1, "fixture", "topic", "peer", true)
	require.NoError(t, err)
	sentinel, sentinelFixture, err := BuildCalibrationFixture(constructor, ProfileV2, "SENTINEL_1", 1, "fixture", "topic", "peer", false)
	require.NoError(t, err)
	require.NotEqual(t, selectedFixture.MessageID, sentinelFixture.MessageID)
	_, err = EvaluateFixture(selected, ProfileV2, "topic", "peer")
	require.NoError(t, err)
	_, err = EvaluateFixture(sentinel, ProfileV2, "topic", "peer")
	require.NoError(t, err)
}
