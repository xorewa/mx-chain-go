package shared

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/multiversx/mx-chain-core-go/core/pubkeyConverter"
)

// ErrMalformedObservation and ErrUnsupportedObservationVersion are public
// presentation errors. Neither conveys an operation outcome or authority.
var (
	ErrMalformedObservation          = errors.New("malformed observation presentation")
	ErrUnsupportedObservationVersion = errors.New("unsupported observation presentation version")
)

// EncodeObservationReport validates v1 presentation semantics without creating
// an observation or modifying the existing API envelope.
func EncodeObservationReport(report ObservationReportV1) ([]byte, error) {
	if report.SchemaVersion != ObservationVersionV1 {
		return nil, ErrUnsupportedObservationVersion
	}
	if !validObservationReport(report) {
		return nil, ErrMalformedObservation
	}
	return json.Marshal(report)
}

// DecodeObservationReport only interprets the exact supported schema. On an
// invalid or unsupported input it returns an empty limitation, not partial data.
func DecodeObservationReport(data []byte) (ObservationReportV1, error) {
	if !utf8.Valid(data) {
		return observationLimitation(ObservationMalformed), ErrMalformedObservation
	}
	object, err := observationObject(data)
	if err != nil {
		return observationLimitation(ObservationMalformed), ErrMalformedObservation
	}
	var version string
	if json.Unmarshal(object["schemaVersion"], &version) != nil || version == "" {
		return observationLimitation(ObservationMalformed), ErrMalformedObservation
	}
	if version != ObservationVersionV1 {
		return observationLimitation(ObservationUnsupported), ErrUnsupportedObservationVersion
	}
	var report ObservationReportV1
	known, err := observationKnownShape(data, reflect.TypeOf(report))
	if err != nil || json.Unmarshal(known, &report) != nil || !validObservationReport(report) {
		return observationLimitation(ObservationMalformed), ErrMalformedObservation
	}
	return report, nil
}

func observationLimitation(availability ObservationAvailability) ObservationReportV1 {
	return ObservationReportV1{SchemaVersion: ObservationVersionV1, Availability: availability}
}

// observationObject reads exact JSON member names. No supplied data is included
// in presentation errors; duplicate members are not interpreted as a value.
func observationObject(data []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, ErrMalformedObservation
	}
	object := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return nil, ErrMalformedObservation
		}
		if _, exists := object[key]; exists {
			return nil, ErrMalformedObservation
		}
		var raw json.RawMessage
		if decoder.Decode(&raw) != nil {
			return nil, ErrMalformedObservation
		}
		object[key] = raw
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return nil, ErrMalformedObservation
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, ErrMalformedObservation
	}
	return object, nil
}

// observationKnownShape preserves null and empty lists, checks that all known
// keys are present, and ignores extension keys without feeding them to the
// standard decoder's case-insensitive struct-field matching.
func observationKnownShape(raw json.RawMessage, shape reflect.Type) (json.RawMessage, error) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		if shape.Kind() == reflect.Pointer || shape.Kind() == reflect.Slice {
			return raw, nil
		}
		return nil, ErrMalformedObservation
	}
	if shape.Kind() == reflect.Pointer {
		return observationKnownShape(raw, shape.Elem())
	}
	switch shape.Kind() {
	case reflect.Struct:
		object, err := observationObject(raw)
		if err != nil {
			return nil, err
		}
		known := make(map[string]json.RawMessage, shape.NumField())
		for i := 0; i < shape.NumField(); i++ {
			field := shape.Field(i)
			key := field.Tag.Get("json")
			value, present := object[key]
			if !present {
				return nil, ErrMalformedObservation
			}
			known[key], err = observationKnownShape(value, field.Type)
			if err != nil {
				return nil, err
			}
		}
		return json.Marshal(known)
	case reflect.Slice:
		var items []json.RawMessage
		if json.Unmarshal(raw, &items) != nil {
			return nil, ErrMalformedObservation
		}
		for i, item := range items {
			value, err := observationKnownShape(item, shape.Elem())
			if err != nil {
				return nil, err
			}
			items[i] = value
		}
		return json.Marshal(items)
	default:
		return raw, nil
	}
}

func validObservationReport(report ObservationReportV1) bool {
	if !validObservationPrimitives(reflect.ValueOf(report)) {
		return false
	}
	if report.Availability != ObservationAvailable {
		return report.Observations == nil
	}
	if report.Observations == nil {
		return false
	}
	for _, observation := range report.Observations {
		if !validPublicObservation(observation) {
			return false
		}
	}
	return true
}

func validPublicObservation(o PublicObservation) bool {
	if !validObservationState(o.Kind, o.Availability, o.State) {
		return false
	}
	if o.Availability != ObservationAvailable {
		return o.Values == nil && o.OriginalValues == nil && o.GasRefund == nil && o.FinalityBasis == nil
	}
	if o.GasRefund != nil && (o.Kind != "ECONOMIC_GAS_REFUND" || !validObservationRefund(*o.GasRefund)) {
		return false
	}
	for _, list := range [][]PublicObservationValue{o.Values, o.OriginalValues} {
		for _, value := range list {
			if value.Unit != "ASSET_ATOMIC" {
				return false
			}
		}
	}
	if o.Kind == "CANONICAL_FINALITY" && !completePublicMembership(o.FinalityBasis) {
		return false
	}
	if o.Kind == "PROVISIONAL_EXECUTION" {
		return o.Subject != nil && o.Provenance != nil && o.Provenance.ExecutionShard != nil &&
			(o.Provenance.ExecutionObjectHash != nil || o.Provenance.BasisRef != nil)
	}
	return true
}

func validObservationState(kind ObservationKind, availability ObservationAvailability, state ObservationState) bool {
	var states []ObservationState
	switch kind {
	case "SUBMISSION":
		states = []ObservationState{"ACKNOWLEDGED", "SOURCE_ACCEPTED"}
	case "PROVISIONAL_EXECUTION":
		states = []ObservationState{"OBSERVED"}
	case "CANONICAL_FINALITY":
		states = []ObservationState{"FINALIZED"}
	case "VALUE_SETTLEMENT":
		states = []ObservationState{"SETTLED"}
	case "VALUE_RETURN":
		states = []ObservationState{"GENERATED", "IN_TRANSIT", "CREDITED"}
	case "ECONOMIC_GAS_REFUND":
		states = []ObservationState{"REPORTED"}
	case "SOURCE_COMPLETION":
		states = []ObservationState{"COMPLETED"}
	case "PREFLIGHT_ADVISORY":
		states = []ObservationState{"ADVISORY", "INDETERMINATE"}
	default:
		return false
	}
	switch availability {
	case ObservationAvailable:
		for _, allowed := range states {
			if state == allowed {
				return true
			}
		}
		return false
	case ObservationUnavailable, ObservationUnsupported:
		return state == "UNAVAILABLE"
	default:
		return state == "UNKNOWN"
	}
}

// completePublicMembership checks only the presence of required display fields;
// it cannot establish that such membership or finality actually occurred.
func completePublicMembership(b *PublicObservationFinalityBasis) bool {
	if b == nil || b.BlockHash == nil || b.BlockNonce == nil || b.BlockRound == nil || b.BlockShard == nil || b.MiniblockHash == nil || (b.TransactionHash == nil && b.SubjectResultHash == nil) {
		return false
	}
	switch b.MembershipKind {
	case "BLOCK_MINIBLOCK_TRANSACTION":
		return true
	case "EXECUTION_RESULT_MINIBLOCK_TRANSACTION":
		return b.ExecutionHeaderHash != nil && b.ExecutionHeaderNonce != nil && b.ExecutionHeaderRound != nil && b.ExecutionHeaderEpoch != nil
	default:
		return false
	}
}

func validObservationRefund(refund PublicObservationGasRefund) bool {
	if (refund.AmountAtomic == nil) != (refund.AmountUnit == nil) || (refund.GasUnits == nil) != (refund.GasUnit == nil) {
		return false
	}
	return (refund.AmountUnit == nil || (*refund.AmountUnit == "ASSET_ATOMIC" && refund.TokenID != nil)) &&
		(refund.GasUnit == nil || *refund.GasUnit == "GAS_UNIT")
}

func validObservationPrimitives(value reflect.Value) bool {
	switch value.Kind() {
	case reflect.Pointer:
		return value.IsNil() || validObservationPrimitives(value.Elem())
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			if !validObservationPrimitives(value.Field(i)) {
				return false
			}
		}
	case reflect.Slice:
		for i := 0; i < value.Len(); i++ {
			if !validObservationPrimitives(value.Index(i)) {
				return false
			}
		}
	default:
		switch v := value.Interface().(type) {
		case ObservationHash:
			return validObservationHash(v)
		case ObservationTokenID:
			return validObservationText(string(v))
		case ObservationPublicLabel:
			return validObservationText(string(v))
		case ObservationOpaqueRef:
			return validObservationText(string(v))
		case ObservationAddress:
			return validObservationAddress(v)
		case ObservationUInt64:
			return validObservationDecimal(string(v), true)
		case ObservationUnixMs:
			return validObservationDecimal(string(v), true)
		case ObservationUInt:
			return validObservationDecimal(string(v), false)
		case ObservationAvailability:
			switch v {
			case ObservationAvailable, ObservationUnknown, ObservationUnavailable, ObservationStale, ObservationMalformed, ObservationConflicting, ObservationUnsupported:
				return true
			}
			return false
		case ObservationMembershipKind:
			return v == "BLOCK_MINIBLOCK_TRANSACTION" || v == "EXECUTION_RESULT_MINIBLOCK_TRANSACTION" || v == "UNKNOWN" || v == "UNAVAILABLE"
		case ObservationRefundClass:
			return v == "INFORMATIONAL" || v == "EXECUTABLE" || v == "UNKNOWN" || v == "UNAVAILABLE"
		case ObservationUnit:
			return v == "ASSET_ATOMIC" || v == "GAS_UNIT"
		}
	}
	return true
}

func validObservationText(value string) bool { return value != "" && utf8.ValidString(value) }

func validObservationHash(value ObservationHash) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func validObservationDecimal(value string, bounded bool) bool {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return false
		}
	}
	if bounded {
		_, err := strconv.ParseUint(value, 10, 64)
		return err == nil
	}
	return true
}

func validObservationAddress(value ObservationAddress) bool {
	if string(value) != strings.ToLower(string(value)) {
		return false
	}
	converter, err := pubkeyConverter.NewBech32PubkeyConverter(32, "erd")
	if err != nil {
		return false
	}
	decoded, err := converter.Decode(string(value))
	if err != nil {
		return false
	}
	encoded, err := converter.Encode(decoded)
	return err == nil && encoded == string(value)
}
