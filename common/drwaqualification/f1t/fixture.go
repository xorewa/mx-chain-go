package f1t

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/multiversx/mx-chain-core-go/data/batch"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwa"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"golang.org/x/crypto/blake2b"
)

var ErrSourceConstructorUnavailable = errors.New("F1-T source constructor unavailable")

const sourceConstructorDomain = "DRWA/S1/F1T/SOURCE_CONSTRUCTOR/v1"

const FixtureCatalogSchema = "DRWA_S1_F1T_FIXTURE_CATALOG_V1"

type SourceArtifacts struct {
	SCRCanonical       []byte
	SCRHash            [32]byte
	MiniBlockCanonical []byte
	MiniBlockHash      [32]byte
	BatchCanonical     []byte
	BatchSHA256        [32]byte
	ProtocolKind       uint32
	ArtifactChainHash  [32]byte
}

// SourceConstructor produces the complete canonical transport chain. A caller
// cannot satisfy this interface with payload bytes alone: BuildCalibrationFixture
// independently decodes, remarshal-checks and rehashes every layer.
type SourceConstructor interface {
	Build(profile Profile, armID string, index uint64, kind string) (SourceArtifacts, error)
}

type CanonicalSourceConstructor struct {
	NetworkDomain [32]byte
	SourceHolder  [32]byte
	Destination   [32]byte
	GasIdentity   [32]byte
	SenderShard   uint32
	ReceiverShard uint32
	CEBEpoch      uint32
	Expiry        uint64
	GasPrice      uint64
	Budgets       drwa.WorkBudgets
}

type GasProfileBinding struct {
	ID               string           `json:"id"`
	Path             string           `json:"path"`
	SHA256           string           `json:"sha256"`
	ScheduleIdentity string           `json:"schedule_identity"`
	Budgets          drwa.WorkBudgets `json:"budgets"`
}

type FixtureCatalog struct {
	Schema                   string                     `json:"schema"`
	TrustedRoot              string                     `json:"trusted_workspace_realpath"`
	ControlMatrixPath        string                     `json:"control_matrix_path"`
	ControlMatrixSHA256      string                     `json:"control_matrix_sha256"`
	ActivationManifestPath   string                     `json:"activation_manifest_path"`
	ActivationManifestSHA256 string                     `json:"activation_manifest_sha256"`
	ConstructorSourceCommit  string                     `json:"constructor_source_commit"`
	Constructor              CanonicalSourceConstructor `json:"constructor"`
	GasProfiles              []GasProfileBinding        `json:"gas_profiles"`
	CanonicalFixtureSHA256   map[Profile]string         `json:"canonical_fixture_sha256"`
	RuntimeCredit            int                        `json:"authoritative_runtime_credit"`
	NumericRatification      bool                       `json:"numeric_ratification"`
}

func LoadAndVerifyFixtureCatalog(trustedRoot, catalogPath, catalogSHA256, expectedSourceCommit string) (CanonicalSourceConstructor, error) {
	bound, err := ReadBoundRegularFile(trustedRoot, catalogPath, catalogSHA256)
	if err != nil {
		return CanonicalSourceConstructor{}, err
	}
	var catalog FixtureCatalog
	if err = decodeExactPayload(bound.Bytes, &catalog); err != nil || catalog.Schema != FixtureCatalogSchema ||
		catalog.TrustedRoot != trustedRoot || catalog.ConstructorSourceCommit != expectedSourceCommit ||
		!isSourceCommit(expectedSourceCommit) ||
		catalog.RuntimeCredit != 0 || catalog.NumericRatification || len(catalog.GasProfiles) != 2 || len(catalog.CanonicalFixtureSHA256) != 2 {
		return CanonicalSourceConstructor{}, ErrPreflight
	}
	matrixBound, err := ReadBoundRegularFile(trustedRoot, catalog.ControlMatrixPath, catalog.ControlMatrixSHA256)
	if err != nil {
		return CanonicalSourceConstructor{}, err
	}
	manifestBound, err := ReadBoundRegularFile(trustedRoot, catalog.ActivationManifestPath, catalog.ActivationManifestSHA256)
	if err != nil {
		return CanonicalSourceConstructor{}, err
	}
	var matrix map[string]any
	var manifest map[string]any
	if json.Unmarshal(matrixBound.Bytes, &matrix) != nil || json.Unmarshal(manifestBound.Bytes, &manifest) != nil {
		return CanonicalSourceConstructor{}, ErrPreflight
	}
	if err = verifyConstructorAgainstControlMatrix(catalog.Constructor, matrix); err != nil {
		return CanonicalSourceConstructor{}, err
	}
	maximum := drwa.WorkBudgets{}
	for index, profile := range catalog.GasProfiles {
		expectedID := "A"
		if index == 1 {
			expectedID = "B"
		}
		if profile.ID != expectedID || !isHexDigest(profile.SHA256) || !isHexDigest(profile.ScheduleIdentity) {
			return CanonicalSourceConstructor{}, ErrPreflight
		}
		err = withBoundRegularFile(trustedRoot, profile.Path, profile.SHA256, func(fd int, _ string, _ []byte, _ string) error {
			loaded, loadErr := common.LoadGasScheduleConfig("/proc/self/fd/" + strconv.Itoa(fd))
			if loadErr != nil {
				return loadErr
			}
			costs, ok := loaded["DRWAPrototypeCost"]
			if !ok || len(costs) != 4 || costs["DestinationGate"] != profile.Budgets.DestinationGate ||
				costs["SuccessReceipt"] != profile.Budgets.SuccessReceipt || costs["RefundGeneration"] != profile.Budgets.RefundGeneration ||
				costs["SourceCompletion"] != profile.Budgets.SourceCompletion {
				return ErrPreflight
			}
			return nil
		})
		if err != nil {
			return CanonicalSourceConstructor{}, err
		}
		maximum.DestinationGate = max(maximum.DestinationGate, profile.Budgets.DestinationGate)
		maximum.SuccessReceipt = max(maximum.SuccessReceipt, profile.Budgets.SuccessReceipt)
		maximum.RefundGeneration = max(maximum.RefundGeneration, profile.Budgets.RefundGeneration)
		maximum.SourceCompletion = max(maximum.SourceCompletion, profile.Budgets.SourceCompletion)
	}
	if maximum != catalog.Constructor.Budgets || !manifestGasBindingsMatch(manifest, catalog.GasProfiles, maximum) {
		return CanonicalSourceConstructor{}, ErrPreflight
	}
	for _, profile := range []Profile{ProfileLegacy, ProfileV2} {
		raw, _, buildErr := BuildCalibrationFixture(catalog.Constructor, profile, "SELECTED", 1, "fixture", "/drwa/f1t", "peer-remote", true)
		if buildErr != nil || catalog.CanonicalFixtureSHA256[profile] != digestHex(raw) {
			return CanonicalSourceConstructor{}, ErrPreflight
		}
	}
	return catalog.Constructor, nil
}

func isSourceCommit(value string) bool {
	if len(value) != 40 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func verifyConstructorAgainstControlMatrix(constructor CanonicalSourceConstructor, document map[string]any) error {
	rawCatalog, ok := document["raw_identity_preimage_catalog"].(map[string]any)
	if !ok {
		return ErrPreflight
	}
	selected, ok := rawCatalog["SELECTED::V2_CURRENT_RUNTIME_CLASS"].(map[string]any)
	if !ok {
		return ErrPreflight
	}
	inputs, ok := selected["construction_inputs"].(map[string]any)
	if !ok {
		return ErrPreflight
	}
	semantic, ok := inputs["semantic_fields"].(map[string]any)
	if !ok {
		return ErrPreflight
	}
	value := func(name string) any {
		field, _ := semantic[name].(map[string]any)
		return field["value"]
	}
	fixtureValues, ok := document["fixture_value_catalog"].(map[string]any)
	if !ok {
		return ErrPreflight
	}
	budgetRecord, _ := fixtureValues["POSITIVE_CURRENT_WORK_BUDGET_PROVIDER_RESULT"].(map[string]any)
	budgetValue, _ := budgetRecord["value"].(map[string]any)
	gasPriceRecord, _ := fixtureValues["ARM_POSITIVE_GAS_PRICE"].(map[string]any)
	dependencies, ok := document["constructor_dependency_catalog"].(map[string]any)
	if !ok {
		return ErrPreflight
	}
	caseBound, _ := dependencies["CASE_BOUND_VALID_TEST_DOUBLES"].(map[string]any)
	rows, _ := caseBound["dependencies"].([]any)
	constructorValue := func(field string) any {
		for _, row := range rows {
			object, _ := row.(map[string]any)
			if object["field"] == field {
				if valueHex, exists := object["value_hex"]; exists {
					return valueHex
				}
				return object["value"]
			}
		}
		return nil
	}
	if value("network_domain") != hex.EncodeToString(constructor.NetworkDomain[:]) ||
		value("source_holder") != strings.Repeat("11", 32) || value("destination_holder") != strings.Repeat("22", 32) ||
		uint64FromJSON(value("sender_shard")) != uint64(constructor.SenderShard) ||
		uint64FromJSON(value("receiver_shard")) != uint64(constructor.ReceiverShard) ||
		value("tx_hash") != strings.Repeat("33", 32) || value("function") != vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope ||
		constructorValue("networkDomain") != hex.EncodeToString(constructor.NetworkDomain[:]) || uint64FromJSON(constructorValue("cebEpoch")) != uint64(constructor.CEBEpoch) ||
		uint64FromJSON(constructorValue("settlementLifetimeRounds")) != constructor.Expiry ||
		uint64FromJSON(gasPriceRecord["value"]) != constructor.GasPrice || budgetValue["gas_schedule_identity_hex"] != hex.EncodeToString(constructor.GasIdentity[:]) ||
		uint64FromJSON(budgetValue["DestinationGate"]) != constructor.Budgets.DestinationGate ||
		uint64FromJSON(budgetValue["SuccessReceipt"]) != constructor.Budgets.SuccessReceipt ||
		uint64FromJSON(budgetValue["RefundGeneration"]) != constructor.Budgets.RefundGeneration ||
		uint64FromJSON(budgetValue["SourceCompletion"]) != constructor.Budgets.SourceCompletion {
		return ErrPreflight
	}
	intentField, ok := semantic["intent"].(map[string]any)
	if !ok {
		return ErrPreflight
	}
	intent, ok := intentField["value"].(map[string]any)
	if !ok || intent["TokenID"] != "DRWAQUAL-abcdef" || intent["Quantity"] != "0a" ||
		intent["SourceSubject"] != strings.Repeat("11", 32) || intent["DestinationSubject"] != strings.Repeat("22", 32) {
		return ErrPreflight
	}
	return nil
}

func manifestGasBindingsMatch(manifest map[string]any, profiles []GasProfileBinding, maximum drwa.WorkBudgets) bool {
	gas, ok := manifest["gas_catalog"].(map[string]any)
	if !ok || gas["profile_a_identity"] != profiles[0].ScheduleIdentity || gas["profile_b_identity"] != profiles[1].ScheduleIdentity {
		return false
	}
	total, err := maximum.Total()
	return err == nil && uint64FromJSON(gas["maximum_reserved_total"]) == total
}

func uint64FromJSON(value any) uint64 {
	number, ok := value.(float64)
	if !ok || number < 0 || number > float64(^uint64(0)) || number != float64(uint64(number)) {
		return 0
	}
	return uint64(number)
}

func DefaultCanonicalSourceConstructor() CanonicalSourceConstructor {
	return CanonicalSourceConstructor{
		NetworkDomain: repeatedDigest(0x44), SourceHolder: repeatedDigest(0x55), Destination: repeatedDigest(0x66),
		GasIdentity: repeatedDigest(0x88), SenderShard: 1, ReceiverShard: 2, CEBEpoch: 2, Expiry: 4000,
		GasPrice: 1_000_000_000,
		Budgets: drwa.WorkBudgets{DestinationGate: 1_200_000, SuccessReceipt: 1_200_000,
			RefundGeneration: 1_200_000, SourceCompletion: 1_200_000},
	}
}

func (constructor CanonicalSourceConstructor) Build(profile Profile, armID string, index uint64, kind string) (SourceArtifacts, error) {
	if !knownProfile(profile) || !validFixtureArmID(armID) || index == 0 || kind == "" || strings.Contains(kind, "/") || constructor.NetworkDomain == ([32]byte{}) ||
		constructor.SourceHolder == ([32]byte{}) || constructor.Destination == ([32]byte{}) || constructor.GasIdentity == ([32]byte{}) ||
		constructor.SenderShard == constructor.ReceiverShard || constructor.CEBEpoch == 0 || constructor.Expiry == 0 || constructor.GasPrice == 0 {
		return SourceArtifacts{}, ErrSourceConstructorUnavailable
	}
	reserved, err := constructor.Budgets.Total()
	if err != nil || reserved == 0 {
		return SourceArtifacts{}, fmt.Errorf("%w: work budgets", ErrSourceConstructorUnavailable)
	}
	txHash := sha256.Sum256([]byte(fmt.Sprintf("%s/%s/%s/%d/%s", sourceConstructorDomain, profile, armID, index, kind)))
	sourceHolder := constructor.SourceHolder
	destination := constructor.Destination
	tokenID := []byte("DRWACAL-abcdef")
	quantity := new(big.Int).SetUint64(index).Bytes()
	switch armID {
	case "SELECTED":
		tokenID = []byte("DRWAQUAL-abcdef")
		if kind == "fixture" {
			txHash = repeatedDigest(0x33)
		}
		sourceHolder = repeatedDigest(0x11)
		destination = repeatedDigest(0x22)
		quantity = []byte{0x0a}
	case "SENTINEL_1":
		tokenID = []byte("DRWASENT-abcdef")
		if kind == "fixture" {
			txHash = repeatedDigest(0x77)
		}
		sourceHolder = repeatedDigest(0x55)
		destination = repeatedDigest(0x66)
		quantity = []byte{0x0b}
	}
	artifacts, err := drwa.BuildDirectValueArtifacts(constructor.NetworkDomain, txHash, drwa.DirectValueIntent{
		RegulatedTokenID: tokenID, Quantity: quantity, SourceHolder: sourceHolder,
		DestinationHolder: destination, CEBEpoch: constructor.CEBEpoch, SettlementExpiry: constructor.Expiry,
		GasScheduleIdentity: constructor.GasIdentity, DestinationGateGasLimit: constructor.Budgets.DestinationGate,
		SuccessReceiptGasLimit: constructor.Budgets.SuccessReceipt, RefundGenerationGasLimit: constructor.Budgets.RefundGeneration,
		SourceCompletionGasLimit: constructor.Budgets.SourceCompletion,
	})
	if err != nil {
		return SourceArtifacts{}, fmt.Errorf("%w: direct artifacts: %v", ErrSourceConstructorUnavailable, err)
	}
	envelope, err := drwa.EncodeValueEnvelope(artifacts.Envelope)
	if err != nil {
		return SourceArtifacts{}, fmt.Errorf("%w: envelope: %v", ErrSourceConstructorUnavailable, err)
	}
	callData := []byte(vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope + "@" + hex.EncodeToString(envelope))
	scr := &smartContractResult.SmartContractResult{
		Value: big.NewInt(0), RcvAddr: append([]byte(nil), destination[:]...),
		SndAddr: append([]byte(nil), sourceHolder[:]...), Data: callData,
		PrevTxHash: append([]byte(nil), txHash[:]...), OriginalTxHash: append([]byte(nil), txHash[:]...),
		GasLimit: reserved, GasPrice: constructor.GasPrice, CallType: vmData.DirectCall,
		ProtocolMessageKind: vmData.ProtocolMessageKindDRWA,
	}
	if profile == ProfileV2 {
		scr.OriginalSender = append([]byte(nil), sourceHolder[:]...)
	}
	marshaller := &marshal.GogoProtoMarshalizer{}
	scrBytes, err := marshaller.Marshal(scr)
	if err != nil {
		return SourceArtifacts{}, err
	}
	scrHash := blake2b.Sum256(scrBytes)
	miniBlock := &block.MiniBlock{TxHashes: [][]byte{append([]byte(nil), scrHash[:]...)}, SenderShardID: constructor.SenderShard,
		ReceiverShardID: constructor.ReceiverShard, Type: block.SmartContractResultBlock}
	miniBlockBytes, err := marshaller.Marshal(miniBlock)
	if err != nil {
		return SourceArtifacts{}, err
	}
	miniBlockHash := blake2b.Sum256(miniBlockBytes)
	batchBytes, err := marshaller.Marshal(&batch.Batch{Data: [][]byte{append([]byte(nil), miniBlockBytes...)}})
	if err != nil {
		return SourceArtifacts{}, err
	}
	batchHash := sha256.Sum256(batchBytes)
	preimage := make([]byte, 0, len(sourceConstructorDomain)+len(scrBytes)+len(miniBlockBytes)+len(batchBytes))
	preimage = append(preimage, sourceConstructorDomain...)
	preimage = append(preimage, scrBytes...)
	preimage = append(preimage, miniBlockBytes...)
	preimage = append(preimage, batchBytes...)
	return SourceArtifacts{SCRCanonical: scrBytes, SCRHash: scrHash, MiniBlockCanonical: miniBlockBytes,
		MiniBlockHash: miniBlockHash, BatchCanonical: batchBytes, BatchSHA256: batchHash,
		ProtocolKind: uint32(vmData.ProtocolMessageKindDRWA), ArtifactChainHash: sha256.Sum256(preimage)}, nil
}

func BuildCalibrationFixture(
	constructor SourceConstructor,
	profile Profile,
	armID string,
	index uint64,
	kind, topic, origin string,
	selected bool,
) ([]byte, TransportFixture, error) {
	if constructor == nil || topic == "" || origin == "" || !validFixtureArmID(armID) || strings.Contains(kind, "/") ||
		selected != (armID == "SELECTED") {
		return nil, TransportFixture{}, ErrSourceConstructorUnavailable
	}
	artifacts, err := constructor.Build(profile, armID, index, kind)
	if err != nil {
		return nil, TransportFixture{}, err
	}
	if err = ValidateSourceArtifacts(artifacts, profile); err != nil {
		return nil, TransportFixture{}, fmt.Errorf("%w: %v", ErrSourceConstructorUnavailable, err)
	}
	fixture := TransportFixture{
		Schema: "DRWA_S1_F1T_TRANSPORT_FIXTURE_V1", ArmID: armID, Profile: profile, FixtureKind: kind, FixtureIndex: index,
		Topic: topic, OriginPeer: origin, MessageID: fmt.Sprintf("%s/%s/%s/%d", profile, armID, kind, index),
		Function: vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope, ProtocolKind: artifacts.ProtocolKind, Selected: selected,
		PayloadHex: hex.EncodeToString(artifacts.BatchCanonical), SCRHex: hex.EncodeToString(artifacts.SCRCanonical),
		MiniBlockHex: hex.EncodeToString(artifacts.MiniBlockCanonical), SCRHash: hex.EncodeToString(artifacts.SCRHash[:]),
		MiniBlockHash: hex.EncodeToString(artifacts.MiniBlockHash[:]), BatchSHA256: hex.EncodeToString(artifacts.BatchSHA256[:]),
		ArtifactChainSHA256: hex.EncodeToString(artifacts.ArtifactChainHash[:]),
	}
	encoded, err := json.Marshal(fixture)
	return encoded, fixture, err
}

func ValidateSourceArtifacts(artifacts SourceArtifacts, profile Profile) error {
	if !knownProfile(profile) || artifacts.ProtocolKind != uint32(vmData.ProtocolMessageKindDRWA) || !isHexDigest(hex.EncodeToString(artifacts.ArtifactChainHash[:])) {
		return ErrSelectorMismatch
	}
	marshaller := &marshal.GogoProtoMarshalizer{}
	var scr smartContractResult.SmartContractResult
	if err := canonicalUnmarshal(marshaller, artifacts.SCRCanonical, &scr); err != nil {
		return err
	}
	function := vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope
	if scr.ProtocolMessageKind != vmData.ProtocolMessageKindDRWA || scr.CallType != vmData.DirectCall || scr.Value == nil || scr.Value.Sign() != 0 ||
		scr.GasLimit == 0 || scr.GasPrice == 0 || len(scr.RcvAddr) != 32 || len(scr.SndAddr) != 32 || len(scr.PrevTxHash) != 32 ||
		len(scr.OriginalTxHash) != 32 || len(scr.Data) < len(function) || string(scr.Data[:len(function)]) != function {
		return ErrSelectorMismatch
	}
	if (profile == ProfileLegacy && len(scr.OriginalSender) != 0) || (profile == ProfileV2 && string(scr.OriginalSender) != string(scr.SndAddr)) {
		return ErrSelectorMismatch
	}
	if blake2b.Sum256(artifacts.SCRCanonical) != artifacts.SCRHash {
		return ErrSelectorMismatch
	}
	var miniBlock block.MiniBlock
	if err := canonicalUnmarshal(marshaller, artifacts.MiniBlockCanonical, &miniBlock); err != nil {
		return err
	}
	if miniBlock.Type != block.SmartContractResultBlock || miniBlock.SenderShardID == miniBlock.ReceiverShardID || len(miniBlock.TxHashes) != 1 ||
		string(miniBlock.TxHashes[0]) != string(artifacts.SCRHash[:]) || len(miniBlock.Reserved) != 0 || blake2b.Sum256(artifacts.MiniBlockCanonical) != artifacts.MiniBlockHash {
		return ErrSelectorMismatch
	}
	var transportBatch batch.Batch
	if err := canonicalUnmarshal(marshaller, artifacts.BatchCanonical, &transportBatch); err != nil {
		return err
	}
	if len(transportBatch.Data) != 1 || string(transportBatch.Data[0]) != string(artifacts.MiniBlockCanonical) || len(transportBatch.Reference) != 0 ||
		transportBatch.ChunkIndex != 0 || transportBatch.MaxChunks != 0 || sha256.Sum256(artifacts.BatchCanonical) != artifacts.BatchSHA256 {
		return ErrSelectorMismatch
	}
	return nil
}

func canonicalUnmarshal(marshaller *marshal.GogoProtoMarshalizer, raw []byte, target any) error {
	if len(raw) == 0 {
		return ErrSelectorMismatch
	}
	if err := marshaller.Unmarshal(target, raw); err != nil {
		return ErrSelectorMismatch
	}
	reencoded, err := marshaller.Marshal(target)
	if err != nil || string(reencoded) != string(raw) {
		return ErrSelectorMismatch
	}
	return nil
}

func repeatedDigest(value byte) [32]byte {
	var result [32]byte
	for index := range result {
		result[index] = value
	}
	return result
}
