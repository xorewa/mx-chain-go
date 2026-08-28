package f1t

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	SchemaVersion = "DRWA_S1_F1T_FRAME_V1"
	MaxFrameSize  = 1 << 20
)

var ErrInvalidFrame = errors.New("invalid F1-T frame")

type Kind string

const (
	KindCommand Kind = "COMMAND"
	KindEvent   Kind = "EVENT"
	KindAck     Kind = "ACK"
	KindDrain   Kind = "DRAIN"
	KindFailure Kind = "FAILURE"
)

type Frame struct {
	SchemaVersion  string          `json:"schema_version"`
	SessionID      string          `json:"session_id"`
	RunID          string          `json:"run_id"`
	Role           string          `json:"role"`
	PIDStartID     string          `json:"pid_start_id"`
	ExecutableHash string          `json:"executable_sha256"`
	SourceSequence uint64          `json:"source_sequence"`
	ReleaseEpoch   uint64          `json:"release_epoch"`
	Kind           Kind            `json:"kind"`
	PayloadHash    string          `json:"payload_sha256"`
	AdmissionState string          `json:"callback_admission_state"`
	Payload        json.RawMessage `json:"payload"`
}

type PayloadType string

const (
	PayloadRoleReady     PayloadType = "ROLE_READY"
	PayloadDurableAck    PayloadType = "DURABLE_ACK"
	PayloadSendCatalog   PayloadType = "SEND_CATALOG"
	PayloadCallbackEvent PayloadType = "CALLBACK_EVENT"
	PayloadCommand       PayloadType = "COMMAND_INTENT"
	PayloadDrain         PayloadType = "DRAIN_REPORT"
	PayloadFailure       PayloadType = "TERMINAL_FAILURE"
	PayloadAction        PayloadType = "CAMPAIGN_ACTION"
	PayloadRoleAck       PayloadType = "ROLE_COMMAND_ACK"
)

type RoleReadyPayload struct {
	Type  PayloadType `json:"type"`
	Phase string      `json:"phase"`
	Role  string      `json:"role"`
}

type DurableAckPayload struct {
	Type                  PayloadType `json:"type"`
	AckedSourceSequence   uint64      `json:"acked_source_sequence"`
	GlobalIngressSequence uint64      `json:"global_ingress_sequence"`
	DurableTimestampRawNS uint64      `json:"durable_timestamp_monotonic_raw_ns"`
	FrameSHA256           string      `json:"frame_sha256"`
}

type SendCatalogPayload struct {
	Type  PayloadType      `json:"type"`
	Entry SendCatalogEntry `json:"entry"`
}

type CallbackEventPayload struct {
	Type  PayloadType   `json:"type"`
	Event RecorderEvent `json:"event"`
}

type CommandIntentPayload struct {
	Type    PayloadType `json:"type"`
	Command string      `json:"command"`
}

type RoleCommandAckPayload struct {
	Type                  PayloadType `json:"type"`
	Command               string      `json:"command"`
	CommandSourceSequence uint64      `json:"command_source_sequence"`
}

type DrainReportPayload struct {
	Type         PayloadType `json:"type"`
	LastAdmitted uint64      `json:"last_admitted"`
	LastEmitted  uint64      `json:"last_emitted"`
	InFlight     uint64      `json:"in_flight"`
	QueueEmpty   bool        `json:"queue_empty"`
}

type FailurePayload struct {
	Type         PayloadType `json:"type"`
	FailureClass string      `json:"failure_class"`
	DetailSHA256 string      `json:"detail_sha256"`
}

type CampaignActionPayload struct {
	Type          PayloadType     `json:"type"`
	Kind          ObservationKind `json:"observation_kind"`
	Profile       Profile         `json:"profile"`
	Path          Path            `json:"path"`
	Load          LoadCell        `json:"load"`
	Index         uint64          `json:"index"`
	FixtureSHA256 string          `json:"fixture_sha256"`
}

func (frame Frame) Validate() error {
	if frame.SchemaVersion != SchemaVersion || frame.SessionID == "" || frame.RunID == "" || frame.Role == "" ||
		frame.PIDStartID == "" || frame.SourceSequence == 0 || frame.AdmissionState == "" {
		return fmt.Errorf("%w: required identity", ErrInvalidFrame)
	}
	if frame.Kind != KindCommand && frame.Kind != KindEvent && frame.Kind != KindAck && frame.Kind != KindDrain && frame.Kind != KindFailure {
		return fmt.Errorf("%w: kind", ErrInvalidFrame)
	}
	if !isHexDigest(frame.ExecutableHash) || !isHexDigest(frame.PayloadHash) || len(frame.Payload) == 0 || !json.Valid(frame.Payload) {
		return fmt.Errorf("%w: hashes or payload", ErrInvalidFrame)
	}
	if err := validateCanonicalJSON(frame.Payload); err != nil {
		return fmt.Errorf("%w: payload: %v", ErrInvalidFrame, err)
	}
	if err := validateClosedPayload(frame.Kind, frame.AdmissionState, frame.Payload); err != nil {
		return fmt.Errorf("%w: payload schema: %v", ErrInvalidFrame, err)
	}
	payloadSum := sha256.Sum256(frame.Payload)
	if frame.PayloadHash != hex.EncodeToString(payloadSum[:]) {
		return fmt.Errorf("%w: payload digest", ErrInvalidFrame)
	}
	return nil
}

func validateClosedPayload(kind Kind, admissionState string, raw []byte) error {
	var header struct {
		Type PayloadType `json:"type"`
	}
	if err := json.Unmarshal(raw, &header); err != nil || header.Type == "" {
		return errors.New("missing payload type")
	}
	switch header.Type {
	case PayloadRoleReady:
		var payload RoleReadyPayload
		if err := decodeExactPayload(raw, &payload); err != nil || kind != KindEvent || admissionState != "READY" ||
			(payload.Phase != "INTERCEPTED_REHEARSAL" && payload.Phase != "CAMPAIGN") || !validRole(payload.Role) {
			return errors.New("invalid role-ready payload")
		}
	case PayloadDurableAck:
		var payload DurableAckPayload
		if err := decodeExactPayload(raw, &payload); err != nil || kind != KindAck || admissionState != "DURABLE" ||
			payload.AckedSourceSequence == 0 || payload.GlobalIngressSequence == 0 || payload.DurableTimestampRawNS == 0 || !isHexDigest(payload.FrameSHA256) {
			return errors.New("invalid durable-ack payload")
		}
	case PayloadSendCatalog:
		var payload SendCatalogPayload
		if err := decodeExactPayload(raw, &payload); err != nil || kind != KindEvent || admissionState != "JOURNALED" ||
			ValidateSendCatalogEntry(payload.Entry) != nil {
			return errors.New("invalid send-catalog payload")
		}
	case PayloadCallbackEvent:
		var payload CallbackEventPayload
		if err := decodeExactPayload(raw, &payload); err != nil || kind != KindEvent || admissionState != "ADMITTED" ||
			payload.Event.SourceSequence == 0 || payload.Event.MessageID == "" || payload.Event.Callback.Role == "" || payload.Event.Callback.Path == "" || payload.Event.State != "ADMITTED" {
			return errors.New("invalid callback-event payload")
		}
	case PayloadCommand:
		var payload CommandIntentPayload
		if err := decodeExactPayload(raw, &payload); err != nil || kind != KindCommand || admissionState != "INTENT" ||
			(payload.Command != "RELEASE" && payload.Command != "QUIESCE" && payload.Command != "STOP") {
			return errors.New("invalid command payload")
		}
	case PayloadRoleAck:
		var payload RoleCommandAckPayload
		if err := decodeExactPayload(raw, &payload); err != nil || kind != KindEvent || admissionState != "APPLIED" ||
			(payload.Command != "RELEASE" && payload.Command != "STOP") || payload.CommandSourceSequence == 0 {
			return errors.New("invalid role-command-ack payload")
		}
	case PayloadDrain:
		var payload DrainReportPayload
		if err := decodeExactPayload(raw, &payload); err != nil || kind != KindDrain || admissionState != "QUIESCED" ||
			payload.LastAdmitted != payload.LastEmitted || payload.InFlight != 0 || !payload.QueueEmpty {
			return errors.New("invalid drain payload")
		}
	case PayloadFailure:
		var payload FailurePayload
		if err := decodeExactPayload(raw, &payload); err != nil || kind != KindFailure || admissionState != "TERMINAL_FAILURE" ||
			payload.FailureClass == "" || !isHexDigest(payload.DetailSHA256) {
			return errors.New("invalid failure payload")
		}
	case PayloadAction:
		var payload CampaignActionPayload
		if err := decodeExactPayload(raw, &payload); err != nil || kind != KindCommand || admissionState != "INTENT" ||
			!knownObservationKind(payload.Kind) || !knownProfile(payload.Profile) || !knownPath(payload.Path) || !knownLoad(payload.Load) ||
			payload.Index == 0 || !isHexDigest(payload.FixtureSHA256) {
			return errors.New("invalid campaign-action payload")
		}
	default:
		return errors.New("unknown payload type")
	}
	return nil
}

// DecodeClosedPayload decodes one already canonical frame payload with unknown
// fields rejected. Frame.Validate remains the authority for type/kind/state
// compatibility.
func DecodeClosedPayload(raw []byte, target any) error {
	if err := validateCanonicalJSON(raw); err != nil {
		return err
	}
	return decodeExactPayload(raw, target)
}

func decodeExactPayload(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := ensureEOF(decoder); err != nil {
		return err
	}
	return nil
}

func validRole(role string) bool {
	return role == "collector" || role == "publisher" || role == "target" || role == "passive"
}

func EncodeFrame(frame Frame) ([]byte, error) {
	if err := frame.Validate(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(frame)
	if err != nil || len(body) > MaxFrameSize {
		return nil, fmt.Errorf("%w: marshal or size", ErrInvalidFrame)
	}
	result := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(result[:4], uint32(len(body)))
	copy(result[4:], body)
	return result, nil
}

func DecodeFrame(packet []byte) (Frame, error) {
	var frame Frame
	if len(packet) < 5 || len(packet)-4 > MaxFrameSize || int(binary.BigEndian.Uint32(packet[:4])) != len(packet)-4 {
		return frame, fmt.Errorf("%w: length", ErrInvalidFrame)
	}
	body := packet[4:]
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&frame); err != nil {
		return Frame{}, fmt.Errorf("%w: decode: %v", ErrInvalidFrame, err)
	}
	if err := ensureEOF(decoder); err != nil {
		return Frame{}, err
	}
	canonical, err := json.Marshal(frame)
	if err != nil || !bytes.Equal(body, canonical) {
		return Frame{}, fmt.Errorf("%w: non-canonical or duplicate", ErrInvalidFrame)
	}
	if err = frame.Validate(); err != nil {
		return Frame{}, err
	}
	return frame, nil
}

func NewPayload(raw any) (json.RawMessage, string, error) {
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil, "", err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	value, err := decodeUniqueJSONValue(decoder)
	if err != nil {
		return nil, "", err
	}
	if err = ensureEOF(decoder); err != nil {
		return nil, "", err
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, "", err
	}
	if err = validateCanonicalJSON(payload); err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(payload)
	return payload, hex.EncodeToString(sum[:]), nil
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: multiple JSON values", ErrInvalidFrame)
	}
	return nil
}

func isHexDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

// validateCanonicalJSON rejects duplicate object members as well as valid but
// non-canonical encodings. json.Decoder.DisallowUnknownFields only closes the
// Frame schema; it does not detect duplicate members nested inside RawMessage.
func validateCanonicalJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := decodeUniqueJSONValue(decoder)
	if err != nil {
		return err
	}
	if err = ensureEOF(decoder); err != nil {
		return err
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(raw, canonical) {
		return errors.New("non-canonical JSON")
	}
	return nil
}

func decodeUniqueJSONValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return token, nil
	}

	switch delimiter {
	case '{':
		object := make(map[string]any)
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			if keyErr != nil {
				return nil, keyErr
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errors.New("object key is not a string")
			}
			if _, duplicate := object[key]; duplicate {
				return nil, fmt.Errorf("duplicate object member %q", key)
			}
			value, valueErr := decodeUniqueJSONValue(decoder)
			if valueErr != nil {
				return nil, valueErr
			}
			object[key] = value
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim('}') {
			return nil, errors.New("unterminated object")
		}
		return object, nil
	case '[':
		array := make([]any, 0)
		for decoder.More() {
			value, valueErr := decodeUniqueJSONValue(decoder)
			if valueErr != nil {
				return nil, valueErr
			}
			array = append(array, value)
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim(']') {
			return nil, errors.New("unterminated array")
		}
		return array, nil
	default:
		return nil, errors.New("unexpected delimiter")
	}
}
