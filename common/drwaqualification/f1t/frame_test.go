package f1t

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func validTestFrame(t *testing.T) Frame {
	t.Helper()
	payload, payloadHash, err := NewPayload(RoleReadyPayload{Type: PayloadRoleReady, Phase: "INTERCEPTED_REHEARSAL", Role: "target"})
	require.NoError(t, err)
	sum := sha256.Sum256([]byte("executable"))
	return Frame{SchemaVersion: SchemaVersion, SessionID: "session", RunID: "run", Role: "target",
		PIDStartID: "1:2", ExecutableHash: hex.EncodeToString(sum[:]), SourceSequence: 1,
		ReleaseEpoch: 1, Kind: KindEvent, PayloadHash: payloadHash, AdmissionState: "READY", Payload: payload}
}

func validPhaseIIFrame(t *testing.T, context string) Frame {
	t.Helper()
	frame := validTestFrame(t)
	payload, payloadHash, err := NewPayload(RoleReadyPayload{Type: PayloadRoleReady, Phase: "INTERCEPTED_REHEARSAL",
		Role: "target", CampaignContextSHA256: context})
	require.NoError(t, err)
	frame.SchemaVersion = PhaseIISchemaVersion
	frame.CampaignContextSHA256 = context
	frame.Payload = payload
	frame.PayloadHash = payloadHash
	return frame
}

func TestMeasurementEnvelopeBindsActionIdentityAndExactFixture(t *testing.T) {
	fixture := []byte("same-fixture-across-cells")
	fixtureHash := sha256.Sum256(fixture)
	action := CampaignActionPayload{Type: PayloadAction, Kind: ObservationCalibration, Profile: ProfileV2,
		Path: PathRemoteTarget, Load: LoadBaseline, Index: 1, ActionIndex: 1,
		FixtureSHA256: hex.EncodeToString(fixtureHash[:]), CampaignContextSHA256: strings.Repeat("ab", 32)}
	first, firstID, err := EncodeMeasurementEnvelope(action, fixture)
	require.NoError(t, err)
	decoded, decodedID, err := DecodeMeasurementEnvelope(first)
	require.NoError(t, err)
	require.Equal(t, firstID, decodedID)
	require.Equal(t, fixture, decoded.Fixture)

	action.Load = LoadCPU
	action.ActionIndex = 2
	second, secondID, err := EncodeMeasurementEnvelope(action, fixture)
	require.NoError(t, err)
	require.NotEqual(t, firstID, secondID, "repeated raw fixtures need unique transport identities")
	require.NotEqual(t, first, second)

	var mutated MeasurementEnvelope
	require.NoError(t, json.Unmarshal(first, &mutated))
	mutated.Fixture[0] ^= 1
	mutatedRaw, err := json.Marshal(mutated)
	require.NoError(t, err)
	_, _, err = DecodeMeasurementEnvelope(mutatedRaw)
	require.ErrorIs(t, err, ErrInvalidFrame)
}

func TestPhaseIIFrameRequiresMatchingContextAtOuterAndPayloadLayers(t *testing.T) {
	context := strings.Repeat("91", 32)
	frame := validPhaseIIFrame(t, context)
	packet, err := EncodeFrame(frame)
	require.NoError(t, err)
	_, err = DecodeFrame(packet)
	require.NoError(t, err)

	frame.CampaignContextSHA256 = strings.Repeat("92", 32)
	_, err = EncodeFrame(frame)
	require.ErrorIs(t, err, ErrInvalidFrame)

	frame = validTestFrame(t)
	frame.CampaignContextSHA256 = context
	_, err = EncodeFrame(frame)
	require.ErrorIs(t, err, ErrInvalidFrame)
}

func TestFrameRoundTripAndHostileShapes(t *testing.T) {
	frame := validTestFrame(t)
	packet, err := EncodeFrame(frame)
	require.NoError(t, err)
	decoded, err := DecodeFrame(packet)
	require.NoError(t, err)
	require.Equal(t, frame, decoded)

	mutated := append([]byte(nil), packet...)
	mutated[3]++
	_, err = DecodeFrame(mutated)
	require.ErrorIs(t, err, ErrInvalidFrame)

	frame.PayloadHash = frame.ExecutableHash
	_, err = EncodeFrame(frame)
	require.ErrorIs(t, err, ErrInvalidFrame)
}

func TestFrameRejectsTruncatedOversizedReorderedAndUnknownOuterContent(t *testing.T) {
	frame := validTestFrame(t)
	packet, err := EncodeFrame(frame)
	require.NoError(t, err)

	_, err = DecodeFrame(packet[:len(packet)-1])
	require.ErrorIs(t, err, ErrInvalidFrame)

	oversized := validTestFrame(t)
	oversized.SessionID = string(bytes.Repeat([]byte{'s'}, MaxFrameSize))
	_, err = EncodeFrame(oversized)
	require.ErrorIs(t, err, ErrInvalidFrame)

	body := packet[4:]
	var decoded map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(body, &decoded))
	unknownBody := append(append([]byte(nil), body[:len(body)-1]...), []byte(`,"unknown":true}`)...)
	unknownPacket := make([]byte, 4+len(unknownBody))
	copy(unknownPacket[4:], unknownBody)
	unknownPacket[0] = byte(uint32(len(unknownBody)) >> 24)
	unknownPacket[1] = byte(uint32(len(unknownBody)) >> 16)
	unknownPacket[2] = byte(uint32(len(unknownBody)) >> 8)
	unknownPacket[3] = byte(uint32(len(unknownBody)))
	_, err = DecodeFrame(unknownPacket)
	require.ErrorIs(t, err, ErrInvalidFrame)

	reorderedBody := append([]byte(`{"run_id":"run",`), body[1:]...)
	reorderedPacket := make([]byte, 4+len(reorderedBody))
	copy(reorderedPacket[4:], reorderedBody)
	reorderedPacket[0] = byte(uint32(len(reorderedBody)) >> 24)
	reorderedPacket[1] = byte(uint32(len(reorderedBody)) >> 16)
	reorderedPacket[2] = byte(uint32(len(reorderedBody)) >> 8)
	reorderedPacket[3] = byte(uint32(len(reorderedBody)))
	_, err = DecodeFrame(reorderedPacket)
	require.ErrorIs(t, err, ErrInvalidFrame)

	frame = validTestFrame(t)
	frame.SchemaVersion = "UNKNOWN"
	_, err = EncodeFrame(frame)
	require.ErrorIs(t, err, ErrInvalidFrame)
	frame = validTestFrame(t)
	frame.Kind = "UNKNOWN"
	_, err = EncodeFrame(frame)
	require.ErrorIs(t, err, ErrInvalidFrame)
}

func TestFrameRejectsDuplicateOrNonCanonicalPayload(t *testing.T) {
	frame := validTestFrame(t)
	frame.Payload = json.RawMessage(`{"type":"ROLE_READY","phase":"INTERCEPTED_REHEARSAL","role":"target","role":"again"}`)
	sum := sha256.Sum256(frame.Payload)
	frame.PayloadHash = hex.EncodeToString(sum[:])
	_, err := EncodeFrame(frame)
	require.ErrorIs(t, err, ErrInvalidFrame)

	frame = validTestFrame(t)
	frame.Payload = json.RawMessage(`{ "type": "ROLE_READY", "phase": "INTERCEPTED_REHEARSAL", "role": "target" }`)
	sum = sha256.Sum256(frame.Payload)
	frame.PayloadHash = hex.EncodeToString(sum[:])
	_, err = EncodeFrame(frame)
	require.ErrorIs(t, err, ErrInvalidFrame)
}

func TestFrameRejectsUnknownTypedPayloadContentAndKindMismatch(t *testing.T) {
	frame := validTestFrame(t)
	frame.Payload = json.RawMessage(`{"type":"ROLE_READY","phase":"INTERCEPTED_REHEARSAL","role":"target","unknown":true}`)
	sum := sha256.Sum256(frame.Payload)
	frame.PayloadHash = hex.EncodeToString(sum[:])
	_, err := EncodeFrame(frame)
	require.ErrorIs(t, err, ErrInvalidFrame)

	payload, payloadHash, err := NewPayload(DurableAckPayload{Type: PayloadDurableAck, AckedSourceSequence: 1,
		GlobalIngressSequence: 1, DurableTimestampRawNS: 1, FrameSHA256: frame.ExecutableHash})
	require.NoError(t, err)
	frame.Payload = payload
	frame.PayloadHash = payloadHash
	_, err = EncodeFrame(frame)
	require.ErrorIs(t, err, ErrInvalidFrame)
}

func TestFrameRejectsInvalidSendCatalogSemantics(t *testing.T) {
	frame := validTestFrame(t)
	callback := CallbackKey{Role: "target", Path: "pubsub"}
	payload, payloadHash, err := NewPayload(SendCatalogPayload{Type: PayloadSendCatalog, Entry: SendCatalogEntry{
		MessageID: "message", Kind: "CALIBRATION", Index: 1, Expected: []CallbackKey{callback, callback},
	}})
	require.NoError(t, err)
	frame.Payload = payload
	frame.PayloadHash = payloadHash
	frame.AdmissionState = "JOURNALED"
	_, err = EncodeFrame(frame)
	require.ErrorIs(t, err, ErrInvalidFrame)
}
