package f1t

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/batch"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-core-go/marshal"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"golang.org/x/crypto/blake2b"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwa"
	"github.com/multiversx/mx-chain-go/process/smartContract/scrCommon"
	"github.com/multiversx/mx-chain-go/sharding"
)

type Profile string

const (
	ProfileLegacy Profile = "LEGACY_OFFLINE_COMPATIBILITY"
	ProfileV2     Profile = "V2_CURRENT_RUNTIME_CLASS"
)

var ErrSelectorMismatch = errors.New("F1-T selector mismatch")

type TransportFixture struct {
	Schema              string  `json:"schema"`
	ArmID               string  `json:"arm_id"`
	Profile             Profile `json:"profile"`
	FixtureKind         string  `json:"fixture_kind"`
	FixtureIndex        uint64  `json:"fixture_index"`
	Topic               string  `json:"topic"`
	OriginPeer          string  `json:"origin_peer"`
	MessageID           string  `json:"message_id"`
	Function            string  `json:"function"`
	ProtocolKind        uint32  `json:"protocol_kind"`
	Selected            bool    `json:"selected"`
	PayloadHex          string  `json:"payload_hex"`
	SCRHex              string  `json:"scr_canonical_hex"`
	MiniBlockHex        string  `json:"miniblock_canonical_hex"`
	SCRHash             string  `json:"scr_hash"`
	MiniBlockHash       string  `json:"miniblock_hash"`
	BatchSHA256         string  `json:"batch_sha256"`
	ArtifactChainSHA256 string  `json:"artifact_chain_sha256"`
}

type Selection struct {
	ArmID                   string
	MessageID               string
	Selected                bool
	Profile                 Profile
	ClassifiedArm           string
	ExpectedPredicateVector map[string]string
	PredicateEvidenceStatus string
	SemanticCandidate       *SemanticCandidate
	ObservedPredicates      map[string]PredicateResult
	ValidatorProjectionID   string
	ValidatorErrorClass     string
}

// PredicateResult is the closed successor representation for one observed
// predicate. N_A is valid only with a concrete reason identifier.
type PredicateResult struct {
	State    string `json:"state"`
	ReasonID string `json:"reason_id,omitempty"`
}

// OptionalDecimal preserves the consensus-significant distinction between a
// nil bigint and a present bigint whose value is zero.
type OptionalDecimal struct {
	State        string `json:"state"`
	ValueDecimal string `json:"value_decimal,omitempty"`
}

type SemanticEffectiveEpochs struct {
	SCDeployEnableEpoch        uint32 `json:"sc_deploy_enable_epoch"`
	SCProcessorV2EnableEpoch   uint32 `json:"sc_processor_v2_enable_epoch"`
	SupernovaEnableEpoch       uint32 `json:"supernova_enable_epoch"`
	DynamicESDTEnableEpoch     uint32 `json:"dynamic_esdt_enable_epoch"`
	DRWAEnforcementEnableEpoch uint32 `json:"drwa_enforcement_enable_epoch"`
}

type SemanticProfileFlags struct {
	SCDeployFlag        bool `json:"sc_deploy_flag"`
	SCProcessorV2Flag   bool `json:"sc_processor_v2_flag"`
	DRWAEnforcementFlag bool `json:"drwa_enforcement_flag"`
}

// SemanticProfileBinding is the externally supplied, hash-bound description
// of the runtime profile against which one observation is evaluated. The
// selector does not infer these values from a profile label.
type SemanticProfileBinding struct {
	ID              Profile                 `json:"id"`
	EvaluationEpoch uint32                  `json:"evaluation_epoch"`
	EffectiveEpochs SemanticEffectiveEpochs `json:"effective_epochs"`
	ExpectedFlags   SemanticProfileFlags    `json:"expected_flags"`
}

type SemanticProfileFields struct {
	ID              Profile                 `json:"id"`
	EvaluationEpoch uint32                  `json:"evaluation_epoch"`
	EffectiveEpochs SemanticEffectiveEpochs `json:"effective_epochs"`
	ExpectedFlags   SemanticProfileFlags    `json:"expected_flags"`
	Nonce           uint64                  `json:"nonce"`
	GasPrice        uint64                  `json:"gas_price"`
	CodeHex         string                  `json:"code_hex"`
	CodeMetadataHex string                  `json:"code_metadata_hex"`
	ReturnMessage   string                  `json:"return_message"`
	OriginalSender  string                  `json:"original_sender_hex"`
}

type SemanticIntent struct {
	RegulatedTokenID         string `json:"regulated_token_id_hex"`
	Quantity                 string `json:"quantity_hex"`
	SourceHolder             string `json:"source_holder_hex"`
	DestinationHolder        string `json:"destination_holder_hex"`
	CEBEpoch                 uint32 `json:"ceb_epoch"`
	SettlementExpiry         uint64 `json:"settlement_expiry"`
	GasScheduleIdentity      string `json:"gas_schedule_identity_hex"`
	DestinationGateGasLimit  uint64 `json:"destination_gate_gas_limit"`
	SuccessReceiptGasLimit   uint64 `json:"success_receipt_gas_limit"`
	RefundGenerationGasLimit uint64 `json:"refund_generation_gas_limit"`
	SourceCompletionGasLimit uint64 `json:"source_completion_gas_limit"`
}

type SemanticEnvelope struct {
	CanonicalHex            string         `json:"canonical_hex"`
	OriginalTransferPayload string         `json:"original_transfer_payload_hex"`
	EffectID                string         `json:"effect_id_hex"`
	EffectKind              uint32         `json:"effect_kind"`
	OriginExecutionIdentity string         `json:"origin_execution_identity_hex"`
	RegulatedTokenType      uint32         `json:"regulated_token_type"`
	TransferMode            uint32         `json:"transfer_mode"`
	Intent                  SemanticIntent `json:"intent"`
}

// SemanticCandidate is the exact, closed 18-field projection constructed only
// from authenticated decoded carrier objects and separately bound context.
type SemanticCandidate struct {
	ProtocolKind      uint32                `json:"protocol_kind"`
	CallType          uint32                `json:"call_type"`
	Value             string                `json:"value"`
	GasLimit          uint64                `json:"gas_limit"`
	RelayerAddr       string                `json:"relayer_addr"`
	RelayedValue      OptionalDecimal       `json:"relayed_value"`
	ProfileFields     SemanticProfileFields `json:"profile_fields"`
	Function          string                `json:"function"`
	Calldata          string                `json:"calldata"`
	Envelope          SemanticEnvelope      `json:"envelope"`
	SourceHolder      string                `json:"source_holder"`
	DestinationHolder string                `json:"destination_holder"`
	SenderShard       uint32                `json:"sender_shard"`
	ReceiverShard     uint32                `json:"receiver_shard"`
	TxHash            string                `json:"tx_hash"`
	NetworkDomain     string                `json:"network_domain"`
	Intent            SemanticIntent        `json:"intent"`
	ESDTPayload       string                `json:"esdt_payload"`
}

// DestinationConversionObservation is populated by a real processor-route
// test after its capturing built-in observes the production createVMCallInput
// output. The selector validates the captured value; it never reconstructs it.
type DestinationConversionObservation struct {
	InvocationCount uint64
	VMInput         *vmcommon.ContractCallInput
}

// ObservationContext contains facts that are not carried inside the Batch.
// None is an expected semantic arm or an expected predicate result.
type ObservationContext struct {
	NetworkDomain       [32]byte
	ProfileBinding      SemanticProfileBinding
	ProfileBindingHash  [32]byte
	EnableEpochsHandler common.EnableEpochsHandler
	Coordinator         sharding.Coordinator
	Conversion          *DestinationConversionObservation
}

func NewObservationContext(profile VerifiedProfile, constructor CanonicalSourceConstructor) (ObservationContext, error) {
	if profile.EnableEpochsHandler == nil || profile.EnableEpochsHandler.IsInterfaceNil() ||
		profile.Entry.ID != profile.Binding.ID || profile.Binding.ID == "" {
		return ObservationContext{}, ErrSelectorMismatch
	}
	bindingHash, err := SemanticProfileBindingHash(profile.Binding)
	if err != nil || hex.EncodeToString(bindingHash[:]) != profile.SelectorDigest {
		return ObservationContext{}, ErrSelectorMismatch
	}
	coordinator, err := sharding.NewMultiShardCoordinator(3, constructor.ReceiverShard)
	if err != nil || coordinator.ComputeId(constructor.Destination[:]) != constructor.ReceiverShard ||
		coordinator.ComputeId(constructor.SourceHolder[:]) != constructor.SenderShard {
		return ObservationContext{}, ErrSelectorMismatch
	}
	return ObservationContext{NetworkDomain: constructor.NetworkDomain, ProfileBinding: profile.Binding,
		ProfileBindingHash: bindingHash, EnableEpochsHandler: profile.EnableEpochsHandler, Coordinator: coordinator}, nil
}

const semanticProfileBindingDomain = "DRWA/F1T/SEMANTIC-PROFILE/v1"

// SemanticProfileBindingHash deterministically binds the complete profile
// artifact. Only closed, scalar structs are serialized, so callers cannot
// retain mutable aliases inside the binding.
func SemanticProfileBindingHash(binding SemanticProfileBinding) ([32]byte, error) {
	if binding.ID != ProfileLegacy && binding.ID != ProfileV2 {
		return [32]byte{}, fmt.Errorf("%w: unknown profile binding", ErrSelectorMismatch)
	}
	encoded, err := json.Marshal(binding)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: profile binding encoding", ErrSelectorMismatch)
	}
	preimage := make([]byte, 0, len(semanticProfileBindingDomain)+1+len(encoded))
	preimage = append(preimage, semanticProfileBindingDomain...)
	preimage = append(preimage, 0)
	preimage = append(preimage, encoded...)
	return sha256.Sum256(preimage), nil
}

type parsedFixture struct {
	fixture        TransportFixture
	artifacts      SourceArtifacts
	semanticDigest [32]byte
}

func EvaluateFixture(raw []byte, expectedProfile Profile, topic, origin string) (Selection, error) {
	parsed, err := parseFixture(raw, expectedProfile, topic, origin)
	if err != nil {
		return Selection{}, err
	}
	return Selection{ArmID: parsed.fixture.ArmID, MessageID: parsed.fixture.MessageID,
		Selected: parsed.fixture.Selected, Profile: parsed.fixture.Profile, ClassifiedArm: parsed.fixture.ArmID}, nil
}

func ClassifyFixture(raw []byte, expectedProfile Profile, topic, origin string, arms [][]byte) (Selection, error) {
	candidate, err := parseFixture(raw, expectedProfile, topic, origin)
	if err != nil || len(arms) < 2 {
		return Selection{}, ErrSelectorMismatch
	}
	var matched *parsedFixture
	for _, armRaw := range arms {
		arm, armErr := parseFixture(armRaw, expectedProfile, topic, origin)
		if armErr != nil {
			return Selection{}, armErr
		}
		if candidate.semanticDigest == arm.semanticDigest {
			if matched != nil {
				return Selection{}, fmt.Errorf("%w: multiple semantic arms", ErrSelectorMismatch)
			}
			copyArm := arm
			matched = &copyArm
		}
	}
	if matched == nil {
		return Selection{}, fmt.Errorf("%w: no semantic arm", ErrSelectorMismatch)
	}
	if candidate.artifacts.SCRHash != matched.artifacts.SCRHash || candidate.artifacts.MiniBlockHash != matched.artifacts.MiniBlockHash ||
		candidate.artifacts.BatchSHA256 != matched.artifacts.BatchSHA256 {
		return Selection{}, fmt.Errorf("%w: raw identity", ErrSelectorMismatch)
	}
	return Selection{ArmID: candidate.fixture.ArmID, MessageID: candidate.fixture.MessageID,
		Selected: matched.fixture.Selected, Profile: candidate.fixture.Profile, ClassifiedArm: matched.fixture.ArmID,
		ExpectedPredicateVector: V17PositivePredicateVector(), PredicateEvidenceStatus: "EXPECTED_SOURCE_ARM_ONLY_NOT_OBSERVED"}, nil
}

// ClassifyObservedFixture constructs the corrected semantic candidate before
// reading any expected arm, invokes the real protocol-message admission seam,
// and evaluates the closed PR001..PR059 result set. Expected arms are used only
// after evaluation, to establish unique semantic classification and raw identity.
func ClassifyObservedFixture(
	raw []byte,
	expectedProfile Profile,
	topic string,
	origin string,
	arms [][]byte,
	context ObservationContext,
) (Selection, error) {
	profileBindingHash, bindingErr := SemanticProfileBindingHash(context.ProfileBinding)
	if isZero32(context.NetworkDomain) || isZero32(context.ProfileBindingHash) || bindingErr != nil ||
		profileBindingHash != context.ProfileBindingHash || context.ProfileBinding.ID != expectedProfile ||
		context.EnableEpochsHandler == nil || context.EnableEpochsHandler.IsInterfaceNil() ||
		context.Coordinator == nil || context.Coordinator.IsInterfaceNil() {
		return Selection{}, fmt.Errorf("%w: unbound observation context", ErrSelectorMismatch)
	}
	candidate, err := parseFixture(raw, expectedProfile, topic, origin)
	if err != nil || len(arms) < 2 {
		return Selection{}, ErrSelectorMismatch
	}
	semanticCandidate, decoded, err := projectSemanticCandidate(candidate, context.NetworkDomain, context.ProfileBinding)
	if err != nil {
		return Selection{}, err
	}

	matchedCount := 0
	var matched *parsedFixture
	for _, armRaw := range arms {
		arm, armErr := parseFixture(armRaw, expectedProfile, topic, origin)
		if armErr != nil {
			return Selection{}, armErr
		}
		armSemantic, _, armErr := projectSemanticCandidate(arm, context.NetworkDomain, context.ProfileBinding)
		if armErr != nil {
			return Selection{}, armErr
		}
		if reflect.DeepEqual(semanticCandidate, armSemantic) {
			matchedCount++
			copyArm := arm
			matched = &copyArm
		}
	}
	if matchedCount != 1 || matched == nil {
		return Selection{}, fmt.Errorf("%w: semantic arm cardinality", ErrSelectorMismatch)
	}
	if candidate.artifacts.SCRHash != matched.artifacts.SCRHash || candidate.artifacts.MiniBlockHash != matched.artifacts.MiniBlockHash ||
		candidate.artifacts.BatchSHA256 != matched.artifacts.BatchSHA256 {
		return Selection{}, fmt.Errorf("%w: raw identity", ErrSelectorMismatch)
	}

	results, admission, err := evaluateObservedPredicates(candidate, decoded, semanticCandidate, matchedCount, topic, origin, context)
	if err != nil {
		return Selection{}, err
	}
	return Selection{
		ArmID: candidate.fixture.ArmID, MessageID: candidate.fixture.MessageID, Selected: matched.fixture.Selected,
		Profile: candidate.fixture.Profile, ClassifiedArm: matched.fixture.ArmID,
		ExpectedPredicateVector: V17PositivePredicateVector(), PredicateEvidenceStatus: "OBSERVED_STRUCTURED_SUCCESSOR",
		SemanticCandidate: semanticCandidate, ObservedPredicates: clonePredicateResults(results),
		ValidatorProjectionID: admission.projectionID, ValidatorErrorClass: admission.errorClass,
	}, nil
}

type decodedProjection struct {
	batch         batch.Batch
	miniBlock     block.MiniBlock
	scr           smartContractResult.SmartContractResult
	envelope      drwa.ValueEnvelope
	envelopeBytes []byte
}

func projectSemanticCandidate(
	parsed parsedFixture,
	networkDomain [32]byte,
	profileBinding SemanticProfileBinding,
) (*SemanticCandidate, decodedProjection, error) {
	marshaller := &marshal.GogoProtoMarshalizer{}
	decoded := decodedProjection{}
	if err := canonicalUnmarshal(marshaller, parsed.artifacts.BatchCanonical, &decoded.batch); err != nil {
		return nil, decodedProjection{}, err
	}
	if err := canonicalUnmarshal(marshaller, parsed.artifacts.MiniBlockCanonical, &decoded.miniBlock); err != nil {
		return nil, decodedProjection{}, err
	}
	if err := canonicalUnmarshal(marshaller, parsed.artifacts.SCRCanonical, &decoded.scr); err != nil {
		return nil, decodedProjection{}, err
	}
	parts := bytes.Split(decoded.scr.Data, []byte{'@'})
	if len(parts) != 2 || len(parts[1]) == 0 || !bytes.Equal(parts[1], []byte(hex.EncodeToString(mustDecodeCanonicalHex(parts[1])))) {
		return nil, decodedProjection{}, fmt.Errorf("%w: calldata projection", ErrSelectorMismatch)
	}
	decoded.envelopeBytes = mustDecodeCanonicalHex(parts[1])
	envelope, err := drwa.DecodeValueEnvelope(decoded.envelopeBytes)
	if err != nil {
		return nil, decodedProjection{}, fmt.Errorf("%w: envelope projection", ErrSelectorMismatch)
	}
	reencoded, err := drwa.EncodeValueEnvelope(*envelope)
	if err != nil || !bytes.Equal(reencoded, decoded.envelopeBytes) {
		return nil, decodedProjection{}, fmt.Errorf("%w: envelope canonical projection", ErrSelectorMismatch)
	}
	decoded.envelope = *envelope

	candidate, err := semanticCandidateFromDecoded(parsed.fixture.Profile, networkDomain, profileBinding, decoded)
	if err != nil {
		return nil, decodedProjection{}, err
	}
	return candidate, decoded, nil
}

func semanticCandidateFromDecoded(
	profile Profile,
	networkDomain [32]byte,
	profileBinding SemanticProfileBinding,
	decoded decodedProjection,
) (*SemanticCandidate, error) {
	parts := bytes.Split(decoded.scr.Data, []byte{'@'})
	if len(parts) != 2 {
		return nil, fmt.Errorf("%w: calldata projection", ErrSelectorMismatch)
	}
	profileFields, err := semanticProfile(profileBinding, profile, decoded.scr)
	if err != nil {
		return nil, err
	}
	relayedValue := OptionalDecimal{State: "ABSENT"}
	if decoded.scr.RelayedValue != nil {
		relayedValue = OptionalDecimal{State: "PRESENT", ValueDecimal: decoded.scr.RelayedValue.String()}
	}
	envelope := decoded.envelope
	intent := semanticIntent(envelope.Context)
	candidate := &SemanticCandidate{
		ProtocolKind: uint32(decoded.scr.ProtocolMessageKind), CallType: uint32(decoded.scr.CallType), Value: decoded.scr.Value.String(),
		GasLimit: decoded.scr.GasLimit, RelayerAddr: hex.EncodeToString(decoded.scr.RelayerAddr), RelayedValue: relayedValue,
		ProfileFields: profileFields, Function: string(parts[0]), Calldata: hex.EncodeToString(decoded.scr.Data),
		Envelope: SemanticEnvelope{CanonicalHex: hex.EncodeToString(decoded.envelopeBytes),
			OriginalTransferPayload: hex.EncodeToString(envelope.OriginalTransferPayload), EffectID: hex.EncodeToString(envelope.Context.EffectID[:]),
			EffectKind: uint32(envelope.Context.EffectKind), OriginExecutionIdentity: hex.EncodeToString(envelope.Context.OriginExecutionIdentity[:]),
			RegulatedTokenType: uint32(envelope.Context.RegulatedTokenType), TransferMode: uint32(envelope.Context.TransferMode), Intent: intent},
		SourceHolder: hex.EncodeToString(decoded.scr.SndAddr), DestinationHolder: hex.EncodeToString(decoded.scr.RcvAddr),
		SenderShard: decoded.miniBlock.SenderShardID, ReceiverShard: decoded.miniBlock.ReceiverShardID,
		TxHash: hex.EncodeToString(decoded.scr.PrevTxHash), NetworkDomain: hex.EncodeToString(networkDomain[:]), Intent: intent,
		ESDTPayload: hex.EncodeToString(envelope.OriginalTransferPayload),
	}
	return candidate, nil
}

func mustDecodeCanonicalHex(encoded []byte) []byte {
	decoded, err := hex.DecodeString(string(encoded))
	if err != nil || len(encoded)%2 != 0 {
		return nil
	}
	return decoded
}

func semanticProfile(
	binding SemanticProfileBinding,
	profile Profile,
	scr smartContractResult.SmartContractResult,
) (SemanticProfileFields, error) {
	if scr.Value == nil {
		return SemanticProfileFields{}, fmt.Errorf("%w: nil value", ErrSelectorMismatch)
	}
	if binding.ID != profile {
		return SemanticProfileFields{}, fmt.Errorf("%w: profile binding", ErrSelectorMismatch)
	}
	fields := SemanticProfileFields{ID: binding.ID, EvaluationEpoch: binding.EvaluationEpoch,
		EffectiveEpochs: binding.EffectiveEpochs, ExpectedFlags: binding.ExpectedFlags, Nonce: scr.Nonce,
		GasPrice: scr.GasPrice, CodeHex: hex.EncodeToString(scr.Code), CodeMetadataHex: hex.EncodeToString(scr.CodeMetadata),
		ReturnMessage: string(scr.ReturnMessage), OriginalSender: hex.EncodeToString(scr.OriginalSender)}
	return fields, nil
}

func semanticIntent(context drwa.ValueContext) SemanticIntent {
	return SemanticIntent{RegulatedTokenID: hex.EncodeToString(context.RegulatedTokenID), Quantity: hex.EncodeToString(context.Quantity),
		SourceHolder: hex.EncodeToString(context.SourceHolder[:]), DestinationHolder: hex.EncodeToString(context.DestinationHolder[:]),
		CEBEpoch: context.CEBEpoch, SettlementExpiry: context.SettlementExpiry, GasScheduleIdentity: hex.EncodeToString(context.GasScheduleIdentity[:]),
		DestinationGateGasLimit: context.DestinationGateGasLimit, SuccessReceiptGasLimit: context.SuccessReceiptGasLimit,
		RefundGenerationGasLimit: context.RefundGenerationGasLimit, SourceCompletionGasLimit: context.SourceCompletionGasLimit}
}

func checkedBudgetTotal(context drwa.ValueContext) (uint64, error) {
	return (drwa.WorkBudgets{
		DestinationGate: context.DestinationGateGasLimit, SuccessReceipt: context.SuccessReceiptGasLimit,
		RefundGeneration: context.RefundGenerationGasLimit, SourceCompletion: context.SourceCompletionGasLimit,
	}).Total()
}

func profileFieldsMatch(
	profile Profile,
	scr smartContractResult.SmartContractResult,
	fields SemanticProfileFields,
	binding SemanticProfileBinding,
) bool {
	expected, err := semanticProfile(binding, profile, scr)
	if err != nil || !reflect.DeepEqual(fields, expected) || scr.Nonce != 0 || scr.GasPrice == 0 || len(scr.Code) != 0 ||
		len(scr.CodeMetadata) != 0 || len(scr.ReturnMessage) != 0 {
		return false
	}
	if !binding.ExpectedFlags.SCProcessorV2Flag {
		return len(scr.OriginalSender) == 0
	}
	return bytes.Equal(scr.OriginalSender, scr.SndAddr)
}

func canonicalCallData(data []byte) bool {
	parts := bytes.Split(data, []byte{'@'})
	if len(parts) != 2 || len(parts[1]) == 0 || len(parts[1])%2 != 0 || bytes.IndexAny(parts[1], "ABCDEF") >= 0 {
		return false
	}
	decoded, err := hex.DecodeString(string(parts[1]))
	return err == nil && bytes.Equal(parts[1], []byte(hex.EncodeToString(decoded)))
}

func directArtifactsMatch(networkDomain [32]byte, decoded decodedProjection) bool {
	context := decoded.envelope.Context
	artifacts, err := drwa.BuildDirectValueArtifacts(networkDomain, context.OriginExecutionIdentity, drwa.DirectValueIntent{
		RegulatedTokenID: context.RegulatedTokenID, Quantity: context.Quantity, SourceHolder: context.SourceHolder,
		DestinationHolder: context.DestinationHolder, CEBEpoch: context.CEBEpoch, SettlementExpiry: context.SettlementExpiry,
		GasScheduleIdentity: context.GasScheduleIdentity, DestinationGateGasLimit: context.DestinationGateGasLimit,
		SuccessReceiptGasLimit: context.SuccessReceiptGasLimit, RefundGenerationGasLimit: context.RefundGenerationGasLimit,
		SourceCompletionGasLimit: context.SourceCompletionGasLimit,
	})
	if err != nil {
		return false
	}
	encoded, err := drwa.EncodeValueEnvelope(artifacts.Envelope)
	return err == nil && bytes.Equal(encoded, decoded.envelopeBytes)
}

func validateCapturedVMInput(
	input *vmcommon.ContractCallInput,
	profile Profile,
	scr smartContractResult.SmartContractResult,
	envelope []byte,
	currentHash [32]byte,
) bool {
	if input == nil || input.NativeCallOrigin != vmcommon.NativeCallOriginDRWAProtocolMessage ||
		!bytes.Equal(input.CallerAddr, scr.SndAddr) || !bytes.Equal(input.RecipientAddr, scr.RcvAddr) ||
		input.Function != vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope || input.AllowInitFunction || len(input.Arguments) != 1 ||
		!bytes.Equal(input.Arguments[0], envelope) || input.CallValue == nil || input.CallValue.Sign() != 0 ||
		input.CallType != vmData.DirectCall || input.GasPrice != scr.GasPrice || input.GasProvided != scr.GasLimit || input.GasLocked != 0 ||
		!bytes.Equal(input.OriginalTxHash, scr.OriginalTxHash) || !bytes.Equal(input.CurrentTxHash, currentHash[:]) ||
		!bytes.Equal(input.PrevTxHash, scr.PrevTxHash) || len(input.ESDTTransfers) != 0 || input.ReturnCallAfterError ||
		len(input.TxGuardian) != 0 || len(input.RelayerAddr) != 0 {
		return false
	}
	switch profile {
	case ProfileLegacy:
		return input.AsyncArguments == nil && len(input.OriginalCallerAddr) == 0
	case ProfileV2:
		return emptyAsyncArguments(input.AsyncArguments) && bytes.Equal(input.OriginalCallerAddr, scr.SndAddr)
	default:
		return false
	}
}

func emptyAsyncArguments(arguments *vmcommon.AsyncArguments) bool {
	return arguments != nil && len(arguments.CallID) == 0 && len(arguments.CallerCallID) == 0 &&
		len(arguments.CallbackAsyncInitiatorCallID) == 0 && arguments.GasAccumulated == 0
}

var predicateDependencies = map[string][]string{
	"PR002_BATCH_CANONICAL":                   {"PR001_BATCH_DECODABLE"},
	"PR003_MINIBLOCK_DECODABLE":               {"PR001_BATCH_DECODABLE"},
	"PR004_MINIBLOCK_CANONICAL":               {"PR003_MINIBLOCK_DECODABLE"},
	"PR006_SCR_CANONICAL":                     {"PR005_SCR_DECODABLE"},
	"PR007_BATCH_MATCH_COUNT_ONE":             {"PR001_BATCH_DECODABLE"},
	"PR008_MEMBER_HASH_BINDING":               {"PR003_MINIBLOCK_DECODABLE"},
	"PR009_MINIBLOCK_TYPE":                    {"PR003_MINIBLOCK_DECODABLE"},
	"PR010_SHARDS_DISTINCT":                   {"PR003_MINIBLOCK_DECODABLE", "PR005_SCR_DECODABLE"},
	"PR011_SCR_OCCURRENCE_ONE":                {"PR003_MINIBLOCK_DECODABLE"},
	"PR012_SIDECAR_IDENTITY":                  {"PR005_SCR_DECODABLE"},
	"PR013_PROTOCOL_KIND":                     {"PR005_SCR_DECODABLE"},
	"PR015_CALL_TYPE":                         {"PR005_SCR_DECODABLE"},
	"PR016_VALUE":                             {"PR005_SCR_DECODABLE"},
	"PR017_RESERVED_GAS":                      {"PR005_SCR_DECODABLE"},
	"PR018_RELAYER_ADDR_ABSENT":               {"PR005_SCR_DECODABLE"},
	"PR019_RELAYED_VALUE_ABSENT":              {"PR005_SCR_DECODABLE"},
	"PR020_REMAINING_PROFILE_FIELDS":          {"PR005_SCR_DECODABLE"},
	"PR021_FUNCTION":                          {"PR005_SCR_DECODABLE"},
	"PR022_CALLDATA_GRAMMAR":                  {"PR005_SCR_DECODABLE"},
	"PR023_ENVELOPE_DECODABLE":                {"PR022_CALLDATA_GRAMMAR"},
	"PR024_ENVELOPE_CANONICAL":                {"PR023_ENVELOPE_DECODABLE"},
	"PR025_SENDER_CORRELATION":                {"PR005_SCR_DECODABLE", "PR023_ENVELOPE_DECODABLE"},
	"PR026_RECEIVER_CORRELATION":              {"PR005_SCR_DECODABLE", "PR023_ENVELOPE_DECODABLE"},
	"PR027_MINIBLOCK_SHARD_CORRELATION":       {"PR003_MINIBLOCK_DECODABLE", "PR005_SCR_DECODABLE"},
	"PR028_SOURCE_LENGTH":                     {"PR005_SCR_DECODABLE"},
	"PR029_DESTINATION_LENGTH":                {"PR005_SCR_DECODABLE"},
	"PR030_SOURCE_EOA":                        {"PR028_SOURCE_LENGTH"},
	"PR031_DESTINATION_EOA":                   {"PR029_DESTINATION_LENGTH"},
	"PR032_SOURCE_REMOTE":                     {"PR005_SCR_DECODABLE"},
	"PR033_DESTINATION_LOCAL":                 {"PR005_SCR_DECODABLE"},
	"PR034_TX_HASH_EQUALITY":                  {"PR005_SCR_DECODABLE"},
	"PR035_CONTEXT_ORIGIN":                    {"PR023_ENVELOPE_DECODABLE"},
	"PR036_CURRENT_HASH":                      {"PR005_SCR_DECODABLE"},
	"PR037_NETWORK_DOMAIN":                    {"PR023_ENVELOPE_DECODABLE"},
	"PR038_NORMATIVE_ENUMS":                   {"PR023_ENVELOPE_DECODABLE"},
	"PR039_INTENT_FIELDS":                     {"PR023_ENVELOPE_DECODABLE"},
	"PR040_ESDT_PAYLOAD":                      {"PR023_ENVELOPE_DECODABLE"},
	"PR041_VALIDATOR_PROJECTION":              {"PR005_SCR_DECODABLE"},
	"PR042_VM_INPUT_TRANSFORM":                {"PR005_SCR_DECODABLE", "PR049_PROXY_PROFILE_SELECTION", "PR052_DESTINATION_CONVERSION_REACHED"},
	"PR043_TOPIC_BINDING":                     {"PR023_ENVELOPE_DECODABLE"},
	"PR044_ARM_IDENTITY":                      {"PR051_DUAL_CLASSIFICATION_UNIQUE"},
	"PR048_SOURCE_CONSTRUCTOR":                {"PR057_SOURCE_CASE_OUTCOME"},
	"PR050_OUTPUT_ASYNC_DATA_NIL":             {"PR048_SOURCE_CONSTRUCTOR"},
	"PR052_DESTINATION_CONVERSION_REACHED":    {"PR041_VALIDATOR_PROJECTION"},
	"PR053_SOURCE_OUTPUT_CONTRACT":            {"PR048_SOURCE_CONSTRUCTOR"},
	"PR055_SOURCE_ADMISSION_CONTRACT":         {"PR054_SOURCE_TRANSACTION_CONTRACT"},
	"PR056_SOURCE_PREMUTATION_CONTRACT":       {"PR055_SOURCE_ADMISSION_CONTRACT"},
	"PR058_BATCH_AUXILIARY_FIELDS_EMPTY_ZERO": {"PR001_BATCH_DECODABLE"},
	"PR059_MINIBLOCK_RESERVED_EMPTY":          {"PR003_MINIBLOCK_DECODABLE"},
}

func resolvePredicateDependencies(results map[string]PredicateResult) (map[string]PredicateResult, error) {
	known := make(map[string]struct{}, len(v17PredicateIDs))
	for _, id := range v17PredicateIDs {
		known[id] = struct{}{}
	}
	if len(results) != len(known) {
		return nil, fmt.Errorf("%w: predicate cardinality", ErrSelectorMismatch)
	}
	for id, result := range results {
		if _, ok := known[id]; !ok || (result.State != "TRUE" && result.State != "FALSE" && result.State != "N_A") ||
			(result.State == "N_A") != (result.ReasonID != "") {
			return nil, fmt.Errorf("%w: predicate result %s", ErrSelectorMismatch, id)
		}
	}
	visiting, resolved := make(map[string]bool), make(map[string]bool)
	var visit func(string) error
	visit = func(id string) error {
		if visiting[id] {
			return fmt.Errorf("%w: predicate cycle %s", ErrSelectorMismatch, id)
		}
		if resolved[id] {
			return nil
		}
		visiting[id] = true
		for _, dependency := range predicateDependencies[id] {
			if _, ok := known[dependency]; !ok {
				return fmt.Errorf("%w: unknown dependency %s", ErrSelectorMismatch, dependency)
			}
			if err := visit(dependency); err != nil {
				return err
			}
			if results[dependency].State != "TRUE" {
				results[id] = PredicateResult{State: "N_A", ReasonID: dependency}
				break
			}
		}
		visiting[id], resolved[id] = false, true
		return nil
	}
	for _, id := range v17PredicateIDs {
		if err := visit(id); err != nil {
			return nil, err
		}
	}
	return results, nil
}

func clonePredicateResults(source map[string]PredicateResult) map[string]PredicateResult {
	clone := make(map[string]PredicateResult, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func isZero32(value [32]byte) bool { return value == ([32]byte{}) }

type admissionObservation struct {
	projectionID string
	errorClass   string
	matches      bool
}

func observeProtocolAdmission(
	scr *smartContractResult.SmartContractResult,
	enableEpochsHandler common.EnableEpochsHandler,
	coordinator sharding.Coordinator,
) admissionObservation {
	projectionID, expected := expectedProtocolAdmission(scr, enableEpochsHandler, coordinator)
	actual := scrCommon.ValidateProtocolMessageAdmission(scr, enableEpochsHandler, coordinator)
	matches := (expected == nil && actual == nil) || (expected != nil && errors.Is(actual, expected))
	return admissionObservation{projectionID: projectionID, errorClass: protocolAdmissionErrorClass(actual), matches: matches}
}

func expectedProtocolAdmission(
	scr *smartContractResult.SmartContractResult,
	enableEpochsHandler common.EnableEpochsHandler,
	coordinator sharding.Coordinator,
) (string, error) {
	switch scr.ProtocolMessageKind {
	case vmData.ProtocolMessageKindNone:
		return "VP01_KIND_NONE", nil
	case vmData.ProtocolMessageKindDRWA:
	default:
		return "VP02_KIND_UNKNOWN", process.ErrUnknownProtocolMessageKind
	}
	if !enableEpochsHandler.IsFlagEnabled(common.DRWAEnforcementFlag) {
		return "VP03_BEFORE_ACTIVATION", process.ErrProtocolMessageBeforeActivation
	}
	if len(scr.RelayerAddr) != 0 {
		return "VP04_RELAYER_ADDR", process.ErrInvalidProtocolMessageRoute
	}
	if scr.RelayedValue != nil {
		return "VP05_RELAYED_VALUE", process.ErrInvalidProtocolMessageRoute
	}
	separator := bytes.IndexByte(scr.Data, '@')
	function := scr.Data
	if separator >= 0 {
		function = scr.Data[:separator]
	}
	isValue := bytes.Equal(function, []byte(vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope))
	isReceipt := bytes.Equal(function, []byte(scrCommon.DRWASettlementReceiptFunction))
	isRefund := bytes.Equal(function, []byte(scrCommon.DRWARefundEnvelopeFunction))
	if !isValue && !isReceipt && !isRefund {
		return "VP06_WRONG_FUNCTION", process.ErrInvalidProtocolMessageFunction
	}
	if separator < 0 {
		return "VP07_BAD_GRAMMAR", process.ErrInvalidProtocolMessageEnvelope
	}
	envelopeHex := scr.Data[separator+1:]
	if len(envelopeHex) == 0 || len(envelopeHex)%2 != 0 ||
		len(envelopeHex) > 2*drwa.DRWAValueEnvelopeMaximumLength() || bytes.IndexByte(envelopeHex, '@') >= 0 {
		return "VP07_BAD_GRAMMAR", process.ErrInvalidProtocolMessageEnvelope
	}
	envelopeBytes, err := hex.DecodeString(string(envelopeHex))
	if err != nil || !bytes.Equal(envelopeHex, []byte(hex.EncodeToString(envelopeBytes))) {
		return "VP07_BAD_GRAMMAR", process.ErrInvalidProtocolMessageEnvelope
	}
	switch {
	case isValue:
		_, err = drwa.DecodeValueEnvelope(envelopeBytes)
	case isReceipt:
		_, err = drwa.DecodeSettlementReceipt(envelopeBytes)
	case isRefund:
		_, err = drwa.DecodeRefundEnvelope(envelopeBytes)
	}
	if err != nil {
		return "VP08_BAD_ENVELOPE", process.ErrInvalidProtocolMessageEnvelope
	}
	if coordinator.ComputeId(scr.RcvAddr) != coordinator.SelfId() {
		return "VP09_DEST_REMOTE", process.ErrInvalidProtocolMessageRoute
	}
	if coordinator.ComputeId(scr.SndAddr) == coordinator.SelfId() {
		return "VP10_SOURCE_LOCAL", process.ErrInvalidProtocolMessageRoute
	}
	return "VP11_VALID_ROUTE", nil
}

func protocolAdmissionErrorClass(err error) string {
	switch {
	case err == nil:
		return "NIL"
	case errors.Is(err, process.ErrUnknownProtocolMessageKind):
		return "ErrUnknownProtocolMessageKind"
	case errors.Is(err, process.ErrProtocolMessageBeforeActivation):
		return "ErrProtocolMessageBeforeActivation"
	case errors.Is(err, process.ErrInvalidProtocolMessageRoute):
		return "ErrInvalidProtocolMessageRoute"
	case errors.Is(err, process.ErrInvalidProtocolMessageFunction):
		return "ErrInvalidProtocolMessageFunction"
	case errors.Is(err, process.ErrInvalidProtocolMessageEnvelope):
		return "ErrInvalidProtocolMessageEnvelope"
	default:
		return "UNEXPECTED_ERROR_CLASS"
	}
}

func evaluateObservedPredicates(
	parsed parsedFixture,
	decoded decodedProjection,
	candidate *SemanticCandidate,
	matchedCount int,
	topic string,
	origin string,
	context ObservationContext,
) (map[string]PredicateResult, admissionObservation, error) {
	results := make(map[string]PredicateResult, len(v17PredicateIDs))
	set := func(id string, value bool) {
		if value {
			results[id] = PredicateResult{State: "TRUE"}
		} else {
			results[id] = PredicateResult{State: "FALSE"}
		}
	}
	na := func(id, reason string) { results[id] = PredicateResult{State: "N_A", ReasonID: reason} }

	set("PR001_BATCH_DECODABLE", true)
	set("PR002_BATCH_CANONICAL", true)
	set("PR003_MINIBLOCK_DECODABLE", true)
	set("PR004_MINIBLOCK_CANONICAL", true)
	set("PR005_SCR_DECODABLE", true)
	set("PR006_SCR_CANONICAL", true)
	set("PR007_BATCH_MATCH_COUNT_ONE", len(decoded.batch.Data) == 1 && bytes.Equal(decoded.batch.Data[0], parsed.artifacts.MiniBlockCanonical))
	set("PR008_MEMBER_HASH_BINDING", blake2b.Sum256(parsed.artifacts.MiniBlockCanonical) == parsed.artifacts.MiniBlockHash)
	set("PR009_MINIBLOCK_TYPE", decoded.miniBlock.Type == block.SmartContractResultBlock)
	set("PR010_SHARDS_DISTINCT", context.Coordinator.ComputeId(decoded.scr.SndAddr) != context.Coordinator.ComputeId(decoded.scr.RcvAddr))
	occurrences := 0
	for _, hash := range decoded.miniBlock.TxHashes {
		if bytes.Equal(hash, parsed.artifacts.SCRHash[:]) {
			occurrences++
		}
	}
	set("PR011_SCR_OCCURRENCE_ONE", occurrences == 1)
	set("PR012_SIDECAR_IDENTITY", blake2b.Sum256(parsed.artifacts.SCRCanonical) == parsed.artifacts.SCRHash)
	set("PR013_PROTOCOL_KIND", decoded.scr.ProtocolMessageKind == vmData.ProtocolMessageKindDRWA)
	set("PR014_ACTIVATION", context.EnableEpochsHandler.IsFlagEnabled(common.DRWAEnforcementFlag))
	set("PR015_CALL_TYPE", decoded.scr.CallType == vmData.DirectCall)
	set("PR016_VALUE", decoded.scr.Value != nil && decoded.scr.Value.Sign() == 0)
	budgetTotal, budgetErr := checkedBudgetTotal(decoded.envelope.Context)
	set("PR017_RESERVED_GAS", budgetErr == nil && decoded.scr.GasLimit == budgetTotal)
	set("PR018_RELAYER_ADDR_ABSENT", len(decoded.scr.RelayerAddr) == 0)
	set("PR019_RELAYED_VALUE_ABSENT", decoded.scr.RelayedValue == nil && candidate.RelayedValue.State == "ABSENT")
	set("PR020_REMAINING_PROFILE_FIELDS", profileFieldsMatch(parsed.fixture.Profile, decoded.scr, candidate.ProfileFields, context.ProfileBinding))
	set("PR021_FUNCTION", candidate.Function == vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope)
	set("PR022_CALLDATA_GRAMMAR", canonicalCallData(decoded.scr.Data))
	set("PR023_ENVELOPE_DECODABLE", true)
	encodedEnvelope, envelopeErr := drwa.EncodeValueEnvelope(decoded.envelope)
	set("PR024_ENVELOPE_CANONICAL", envelopeErr == nil && bytes.Equal(encodedEnvelope, decoded.envelopeBytes))
	set("PR025_SENDER_CORRELATION", bytes.Equal(decoded.scr.SndAddr, decoded.envelope.Context.SourceHolder[:]))
	set("PR026_RECEIVER_CORRELATION", bytes.Equal(decoded.scr.RcvAddr, decoded.envelope.Context.DestinationHolder[:]))
	set("PR027_MINIBLOCK_SHARD_CORRELATION", decoded.miniBlock.SenderShardID == context.Coordinator.ComputeId(decoded.scr.SndAddr) &&
		decoded.miniBlock.ReceiverShardID == context.Coordinator.ComputeId(decoded.scr.RcvAddr))
	set("PR028_SOURCE_LENGTH", len(decoded.scr.SndAddr) == 32)
	set("PR029_DESTINATION_LENGTH", len(decoded.scr.RcvAddr) == 32)
	set("PR030_SOURCE_EOA", !core.IsSmartContractAddress(decoded.scr.SndAddr))
	set("PR031_DESTINATION_EOA", !core.IsSmartContractAddress(decoded.scr.RcvAddr))
	set("PR032_SOURCE_REMOTE", context.Coordinator.ComputeId(decoded.scr.SndAddr) != context.Coordinator.SelfId())
	set("PR033_DESTINATION_LOCAL", context.Coordinator.ComputeId(decoded.scr.RcvAddr) == context.Coordinator.SelfId())
	set("PR034_TX_HASH_EQUALITY", len(decoded.scr.PrevTxHash) == 32 && bytes.Equal(decoded.scr.PrevTxHash, decoded.scr.OriginalTxHash))
	set("PR035_CONTEXT_ORIGIN", bytes.Equal(decoded.envelope.Context.OriginExecutionIdentity[:], decoded.scr.PrevTxHash))
	set("PR036_CURRENT_HASH", blake2b.Sum256(parsed.artifacts.SCRCanonical) == parsed.artifacts.SCRHash)
	set("PR037_NETWORK_DOMAIN", directArtifactsMatch(context.NetworkDomain, decoded))
	set("PR038_NORMATIVE_ENUMS", decoded.envelope.Context.EffectKind == drwa.ValueEffectKindDirectTransfer &&
		decoded.envelope.Context.RegulatedTokenType == drwa.TokenTypeFungible && decoded.envelope.Context.TransferMode == drwa.TransferModeGatedDirect)
	set("PR039_INTENT_FIELDS", decoded.envelope.Context.CEBEpoch != 0 && reflect.DeepEqual(candidate.Intent, semanticIntent(decoded.envelope.Context)))
	tokenID, quantity, payloadErr := drwa.DecodeDirectValueTransferPayload(decoded.envelope.OriginalTransferPayload)
	set("PR040_ESDT_PAYLOAD", payloadErr == nil && bytes.Equal(tokenID, decoded.envelope.Context.RegulatedTokenID) && bytes.Equal(quantity, decoded.envelope.Context.Quantity))
	admission := observeProtocolAdmission(&decoded.scr, context.EnableEpochsHandler, context.Coordinator)
	set("PR041_VALIDATOR_PROJECTION", admission.matches)
	set("PR043_TOPIC_BINDING", topic != "" && parsed.fixture.Topic == topic)
	set("PR045_PEER_BINDING", origin != "" && parsed.fixture.OriginPeer == origin)
	na("PR046_RECORDER_EVENT", "NO_RECORDER_EVENT_IN_DESTINATION_PROJECTION")
	na("PR047_PRODUCTION_REGISTRATION", "SOURCE_ROUTE_ONLY")
	na("PR048_SOURCE_CONSTRUCTOR", "SOURCE_ROUTE_ONLY")
	na("PR049_PROXY_PROFILE_SELECTION", "SOURCE_ROUTE_ONLY")
	na("PR050_OUTPUT_ASYNC_DATA_NIL", "SOURCE_ROUTE_ONLY")
	set("PR051_DUAL_CLASSIFICATION_UNIQUE", matchedCount == 1)
	conversionEligible := admission.matches && (admission.projectionID == "VP11_VALID_ROUTE" || admission.projectionID == "VP12_NONVALIDATOR_EOA_CLASS")
	conversionValid := conversionEligible && context.Conversion != nil && context.Conversion.InvocationCount == 1 &&
		validateCapturedVMInput(context.Conversion.VMInput, parsed.fixture.Profile, decoded.scr, decoded.envelopeBytes, parsed.artifacts.SCRHash)
	set("PR052_DESTINATION_CONVERSION_REACHED", conversionValid)
	if conversionValid {
		set("PR042_VM_INPUT_TRANSFORM", true)
	} else {
		na("PR042_VM_INPUT_TRANSFORM", "PR052_DESTINATION_CONVERSION_REACHED")
	}
	na("PR053_SOURCE_OUTPUT_CONTRACT", "SOURCE_ROUTE_ONLY")
	na("PR054_SOURCE_TRANSACTION_CONTRACT", "SOURCE_ROUTE_ONLY")
	na("PR055_SOURCE_ADMISSION_CONTRACT", "SOURCE_ROUTE_ONLY")
	na("PR056_SOURCE_PREMUTATION_CONTRACT", "SOURCE_ROUTE_ONLY")
	na("PR057_SOURCE_CASE_OUTCOME", "SOURCE_ROUTE_ONLY")
	set("PR058_BATCH_AUXILIARY_FIELDS_EMPTY_ZERO", len(decoded.batch.Reference) == 0 && decoded.batch.ChunkIndex == 0 && decoded.batch.MaxChunks == 0)
	set("PR059_MINIBLOCK_RESERVED_EMPTY", len(decoded.miniBlock.Reserved) == 0)
	set("PR044_ARM_IDENTITY", results["PR051_DUAL_CLASSIFICATION_UNIQUE"].State == "TRUE" &&
		parsed.fixture.BatchSHA256 == hex.EncodeToString(parsed.artifacts.BatchSHA256[:]) &&
		parsed.fixture.MiniBlockHash == hex.EncodeToString(parsed.artifacts.MiniBlockHash[:]) &&
		parsed.fixture.SCRHash == hex.EncodeToString(parsed.artifacts.SCRHash[:]))

	resolved, err := resolvePredicateDependencies(results)
	return resolved, admission, err
}

// V17PositivePredicateVector returns a fresh copy of the frozen expected
// source-arm vector. It is not observed predicate evidence: in particular,
// ClassifyFixture does not execute destination conversion, recorder admission,
// production registration, or source-route predicates.
func V17PositivePredicateVector() map[string]string {
	vector := make(map[string]string, len(v17PredicateIDs))
	for _, id := range v17PredicateIDs {
		vector[id] = "TRUE"
	}
	for _, id := range v17PositiveNotApplicableIDs {
		vector[id] = "N_A"
	}
	return vector
}

// V17ExpectedPredicateResults converts the frozen comparison oracle to the
// structured event representation. These remain expected results, never
// observed evidence.
func V17ExpectedPredicateResults() map[string]PredicateResult {
	flat := V17PositivePredicateVector()
	results := make(map[string]PredicateResult, len(flat))
	for id, state := range flat {
		if state == "N_A" {
			results[id] = PredicateResult{State: state, ReasonID: "EXPECTED_SCOPE_NOT_APPLICABLE"}
		} else {
			results[id] = PredicateResult{State: state}
		}
	}
	return results
}

var v17PredicateIDs = [...]string{
	"PR001_BATCH_DECODABLE",
	"PR002_BATCH_CANONICAL",
	"PR003_MINIBLOCK_DECODABLE",
	"PR004_MINIBLOCK_CANONICAL",
	"PR005_SCR_DECODABLE",
	"PR006_SCR_CANONICAL",
	"PR007_BATCH_MATCH_COUNT_ONE",
	"PR008_MEMBER_HASH_BINDING",
	"PR009_MINIBLOCK_TYPE",
	"PR010_SHARDS_DISTINCT",
	"PR011_SCR_OCCURRENCE_ONE",
	"PR012_SIDECAR_IDENTITY",
	"PR013_PROTOCOL_KIND",
	"PR014_ACTIVATION",
	"PR015_CALL_TYPE",
	"PR016_VALUE",
	"PR017_RESERVED_GAS",
	"PR018_RELAYER_ADDR_ABSENT",
	"PR019_RELAYED_VALUE_ABSENT",
	"PR020_REMAINING_PROFILE_FIELDS",
	"PR021_FUNCTION",
	"PR022_CALLDATA_GRAMMAR",
	"PR023_ENVELOPE_DECODABLE",
	"PR024_ENVELOPE_CANONICAL",
	"PR025_SENDER_CORRELATION",
	"PR026_RECEIVER_CORRELATION",
	"PR027_MINIBLOCK_SHARD_CORRELATION",
	"PR028_SOURCE_LENGTH",
	"PR029_DESTINATION_LENGTH",
	"PR030_SOURCE_EOA",
	"PR031_DESTINATION_EOA",
	"PR032_SOURCE_REMOTE",
	"PR033_DESTINATION_LOCAL",
	"PR034_TX_HASH_EQUALITY",
	"PR035_CONTEXT_ORIGIN",
	"PR036_CURRENT_HASH",
	"PR037_NETWORK_DOMAIN",
	"PR038_NORMATIVE_ENUMS",
	"PR039_INTENT_FIELDS",
	"PR040_ESDT_PAYLOAD",
	"PR041_VALIDATOR_PROJECTION",
	"PR042_VM_INPUT_TRANSFORM",
	"PR043_TOPIC_BINDING",
	"PR044_ARM_IDENTITY",
	"PR045_PEER_BINDING",
	"PR046_RECORDER_EVENT",
	"PR047_PRODUCTION_REGISTRATION",
	"PR048_SOURCE_CONSTRUCTOR",
	"PR049_PROXY_PROFILE_SELECTION",
	"PR050_OUTPUT_ASYNC_DATA_NIL",
	"PR051_DUAL_CLASSIFICATION_UNIQUE",
	"PR052_DESTINATION_CONVERSION_REACHED",
	"PR053_SOURCE_OUTPUT_CONTRACT",
	"PR054_SOURCE_TRANSACTION_CONTRACT",
	"PR055_SOURCE_ADMISSION_CONTRACT",
	"PR056_SOURCE_PREMUTATION_CONTRACT",
	"PR057_SOURCE_CASE_OUTCOME",
	"PR058_BATCH_AUXILIARY_FIELDS_EMPTY_ZERO",
	"PR059_MINIBLOCK_RESERVED_EMPTY",
}

var v17PositiveNotApplicableIDs = [...]string{
	"PR042_VM_INPUT_TRANSFORM",
	"PR045_PEER_BINDING",
	"PR046_RECORDER_EVENT",
	"PR047_PRODUCTION_REGISTRATION",
	"PR048_SOURCE_CONSTRUCTOR",
	"PR049_PROXY_PROFILE_SELECTION",
	"PR050_OUTPUT_ASYNC_DATA_NIL",
	"PR053_SOURCE_OUTPUT_CONTRACT",
	"PR054_SOURCE_TRANSACTION_CONTRACT",
	"PR055_SOURCE_ADMISSION_CONTRACT",
	"PR056_SOURCE_PREMUTATION_CONTRACT",
	"PR057_SOURCE_CASE_OUTCOME",
}

func parseFixture(raw []byte, expectedProfile Profile, topic, origin string) (parsedFixture, error) {
	var fixture TransportFixture
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fixture); err != nil {
		return parsedFixture{}, fmt.Errorf("%w: decode", ErrSelectorMismatch)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return parsedFixture{}, fmt.Errorf("%w: trailing", ErrSelectorMismatch)
	}
	canonical, err := json.Marshal(fixture)
	if err != nil || !bytes.Equal(raw, canonical) {
		return parsedFixture{}, fmt.Errorf("%w: canonical", ErrSelectorMismatch)
	}
	if fixture.Schema != "DRWA_S1_F1T_TRANSPORT_FIXTURE_V1" || fixture.ArmID == "" || fixture.MessageID == "" ||
		!validFixtureArmID(fixture.ArmID) || fixture.FixtureKind == "" || strings.Contains(fixture.FixtureKind, "/") || fixture.FixtureIndex == 0 ||
		fixture.Profile != expectedProfile || fixture.Topic != topic || fixture.OriginPeer != origin ||
		fixture.Function != "DRWARegulatedValueEnvelope" ||
		fixture.ProtocolKind == 0 || !isHexDigest(fixture.ArtifactChainSHA256) || !isHexDigest(fixture.SCRHash) ||
		!isHexDigest(fixture.MiniBlockHash) || !isHexDigest(fixture.BatchSHA256) {
		return parsedFixture{}, ErrSelectorMismatch
	}
	expectedMessageID := fmt.Sprintf("%s/%s/%s/%d", fixture.Profile, fixture.ArmID, fixture.FixtureKind, fixture.FixtureIndex)
	if fixture.MessageID != expectedMessageID || fixture.Selected != (fixture.ArmID == "SELECTED") {
		return parsedFixture{}, ErrSelectorMismatch
	}
	batchRaw, err := hex.DecodeString(fixture.PayloadHex)
	if err != nil {
		return parsedFixture{}, ErrSelectorMismatch
	}
	scrRaw, err := hex.DecodeString(fixture.SCRHex)
	if err != nil {
		return parsedFixture{}, ErrSelectorMismatch
	}
	miniBlockRaw, err := hex.DecodeString(fixture.MiniBlockHex)
	if err != nil {
		return parsedFixture{}, ErrSelectorMismatch
	}
	artifacts := SourceArtifacts{SCRCanonical: scrRaw, MiniBlockCanonical: miniBlockRaw, BatchCanonical: batchRaw,
		ProtocolKind: fixture.ProtocolKind}
	if err = decodeDigest(fixture.SCRHash, artifacts.SCRHash[:]); err != nil {
		return parsedFixture{}, err
	}
	if err = decodeDigest(fixture.MiniBlockHash, artifacts.MiniBlockHash[:]); err != nil {
		return parsedFixture{}, err
	}
	if err = decodeDigest(fixture.BatchSHA256, artifacts.BatchSHA256[:]); err != nil {
		return parsedFixture{}, err
	}
	if err = decodeDigest(fixture.ArtifactChainSHA256, artifacts.ArtifactChainHash[:]); err != nil {
		return parsedFixture{}, err
	}
	if err = ValidateSourceArtifacts(artifacts, expectedProfile); err != nil {
		return parsedFixture{}, err
	}
	preimage := make([]byte, 0, len(sourceConstructorDomain)+len(scrRaw)+len(miniBlockRaw)+len(batchRaw))
	preimage = append(preimage, sourceConstructorDomain...)
	preimage = append(preimage, scrRaw...)
	preimage = append(preimage, miniBlockRaw...)
	preimage = append(preimage, batchRaw...)
	if sha256.Sum256(preimage) != artifacts.ArtifactChainHash {
		return parsedFixture{}, ErrSelectorMismatch
	}
	semanticDigest, err := fixtureSemanticDigest(scrRaw, expectedProfile)
	if err != nil {
		return parsedFixture{}, err
	}
	return parsedFixture{fixture: fixture, artifacts: artifacts, semanticDigest: semanticDigest}, nil
}

func validFixtureArmID(value string) bool {
	if value == "SELECTED" {
		return true
	}
	for _, prefix := range []string{"SENTINEL_", "CALIBRATION_"} {
		if strings.HasPrefix(value, prefix) {
			suffix := strings.TrimPrefix(value, prefix)
			parsed, err := strconv.ParseUint(suffix, 10, 64)
			return err == nil && parsed > 0 && strconv.FormatUint(parsed, 10) == suffix
		}
	}
	return false
}

func FixtureHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func decodeDigest(value string, destination []byte) error {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || len(destination) != sha256.Size {
		return ErrSelectorMismatch
	}
	copy(destination, decoded)
	return nil
}

func fixtureSemanticDigest(scrRaw []byte, profile Profile) ([32]byte, error) {
	var scr smartContractResult.SmartContractResult
	marshaller := &marshal.GogoProtoMarshalizer{}
	if err := canonicalUnmarshal(marshaller, scrRaw, &scr); err != nil {
		return [32]byte{}, err
	}
	parts := strings.Split(string(scr.Data), "@")
	if len(parts) != 2 {
		return [32]byte{}, ErrSelectorMismatch
	}
	envelopeRaw, err := hex.DecodeString(parts[1])
	if err != nil {
		return [32]byte{}, ErrSelectorMismatch
	}
	envelope, err := drwa.DecodeValueEnvelope(envelopeRaw)
	if err != nil {
		return [32]byte{}, ErrSelectorMismatch
	}
	semantic := struct {
		Profile      Profile `json:"profile"`
		Function     string  `json:"function"`
		ProtocolKind uint32  `json:"protocol_kind"`
		CallType     uint32  `json:"call_type"`
		Value        string  `json:"value"`
		Receiver     []byte  `json:"receiver"`
		Sender       []byte  `json:"sender"`
		GasLimit     uint64  `json:"gas_limit"`
		GasPrice     uint64  `json:"gas_price"`
		Envelope     any     `json:"envelope"`
	}{Profile: profile, Function: parts[0], ProtocolKind: uint32(scr.ProtocolMessageKind), CallType: uint32(scr.CallType),
		Value: scr.Value.String(), Receiver: scr.RcvAddr, Sender: scr.SndAddr, GasLimit: scr.GasLimit, GasPrice: scr.GasPrice, Envelope: envelope}
	encoded, err := json.Marshal(semantic)
	if err != nil {
		return [32]byte{}, ErrSelectorMismatch
	}
	return sha256.Sum256(encoded), nil
}
