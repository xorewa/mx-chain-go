package f1t

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

var ErrCollectorClosed = errors.New("F1-T collector closed")

type CollectorRecord struct {
	Schema               string `json:"schema"`
	GlobalSequence       uint64 `json:"global_sequence"`
	SourceIdentity       string `json:"source_identity"`
	TimestampRawNS       uint64 `json:"timestamp_monotonic_raw_ns"`
	PreviousRecordSHA256 string `json:"previous_record_sha256"`
	FrameSHA256          string `json:"frame_sha256"`
	Frame                Frame  `json:"frame"`
	RuntimeCredit        int    `json:"authoritative_runtime_credit"`
}

type CollectorClosure struct {
	Schema              string `json:"schema"`
	FinalGlobalSequence uint64 `json:"final_global_sequence"`
	FinalRecordSHA256   string `json:"final_record_sha256"`
	AuthoritativeCredit int    `json:"authoritative_runtime_credit"`
	PhaseIOnly          bool   `json:"phase_i_only"`
	PhaseIISubmission   bool   `json:"phase_ii_submission"`
	NumericRatification bool   `json:"numeric_ratification"`
}

type CollectorHooks struct {
	Clock       func() (uint64, error)
	BeforeWrite func() error
	BeforeSync  func() error
}

type DurableCollector struct {
	mu         sync.Mutex
	file       *os.File
	sequence   uint64
	sealed     bool
	closed     bool
	failed     error
	lastHash   string
	lastByRole map[string]uint64
	catalog    map[string]SendCatalogEntry
	callbacks  map[string]map[CallbackKey]struct{}
	terminal   bool
	hooks      CollectorHooks
}

func CreateDurableCollector(path string) (*DurableCollector, error) {
	return createDurableCollector(path, CollectorHooks{})
}

func CreateDurableCollectorWithHooks(path string, hooks CollectorHooks) (*DurableCollector, error) {
	return createDurableCollector(path, hooks)
}

func createDurableCollector(path string, hooks CollectorHooks) (*DurableCollector, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("collector path must be clean absolute")
	}
	parent := filepath.Dir(path)
	parentFD, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parentFD)
	fd, err := unix.Openat(parentFD, filepath.Base(path), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if err = unix.Fsync(parentFD); err != nil {
		_ = file.Close()
		return nil, err
	}
	if hooks.Clock == nil {
		hooks.Clock = RawMonotonicNanoseconds
	}
	return &DurableCollector{file: file, hooks: hooks, lastByRole: make(map[string]uint64),
		catalog: make(map[string]SendCatalogEntry), callbacks: make(map[string]map[CallbackKey]struct{})}, nil
}

func (collector *DurableCollector) Append(frame Frame) (CollectorRecord, error) {
	return collector.AppendFrom(frame.Role, frame)
}

func (collector *DurableCollector) AppendFrom(sourceIdentity string, frame Frame) (CollectorRecord, error) {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	if collector.sealed || collector.closed || collector.file == nil || collector.failed != nil {
		return CollectorRecord{}, ErrCollectorClosed
	}
	if !sourceIdentityMatchesFrame(sourceIdentity, frame.Role) || frame.SourceSequence != collector.lastByRole[sourceIdentity]+1 {
		return CollectorRecord{}, collector.failLocked(fmt.Errorf("%w: source sequence", ErrInvalidFrame))
	}
	packet, err := EncodeFrame(frame)
	if err != nil {
		return CollectorRecord{}, collector.failLocked(err)
	}
	applySemantic, err := collector.prepareSemanticUpdate(sourceIdentity, frame)
	if err != nil {
		return CollectorRecord{}, collector.failLocked(err)
	}
	timestamp, err := collector.hooks.Clock()
	if err != nil {
		return CollectorRecord{}, collector.failLocked(err)
	}
	if collector.sequence == ^uint64(0) {
		return CollectorRecord{}, collector.failLocked(errors.New("collector sequence overflow"))
	}
	nextSequence := collector.sequence + 1
	sum := sha256.Sum256(packet)
	record := CollectorRecord{
		Schema: "DRWA_S1_F1T_COLLECTOR_RECORD_V1", GlobalSequence: nextSequence, SourceIdentity: sourceIdentity,
		TimestampRawNS: timestamp, PreviousRecordSHA256: collector.lastHash,
		FrameSHA256: hex.EncodeToString(sum[:]), Frame: frame,
		RuntimeCredit: 0,
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return CollectorRecord{}, collector.failLocked(err)
	}
	encoded = append(encoded, '\n')
	if collector.hooks.BeforeWrite != nil {
		if err = collector.hooks.BeforeWrite(); err != nil {
			return CollectorRecord{}, collector.failLocked(err)
		}
	}
	written, err := collector.file.Write(encoded)
	if err != nil || written != len(encoded) {
		if err == nil {
			err = io.ErrShortWrite
		}
		return CollectorRecord{}, collector.failLocked(err)
	}
	if collector.hooks.BeforeSync != nil {
		if err = collector.hooks.BeforeSync(); err != nil {
			return CollectorRecord{}, collector.failLocked(err)
		}
	}
	if err = collector.file.Sync(); err != nil {
		return CollectorRecord{}, collector.failLocked(err)
	}
	recordHash := sha256.Sum256(encoded)
	collector.sequence = nextSequence
	collector.lastByRole[sourceIdentity] = frame.SourceSequence
	collector.lastHash = hex.EncodeToString(recordHash[:])
	applySemantic()
	return record, nil
}

func (collector *DurableCollector) Seal() (CollectorClosure, error) {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	if collector.sealed || collector.closed || collector.file == nil || collector.failed != nil || collector.sequence == 0 || !isHexDigest(collector.lastHash) {
		return CollectorClosure{}, ErrCollectorClosed
	}
	if collector.terminal || !collector.reconciledLocked() {
		return CollectorClosure{}, collector.failLocked(ErrReconciliation)
	}
	closure := CollectorClosure{Schema: "DRWA_S1_F1T_COLLECTOR_CLOSURE_V1", FinalGlobalSequence: collector.sequence,
		FinalRecordSHA256: collector.lastHash, PhaseIOnly: true}
	encoded, err := json.Marshal(closure)
	if err != nil {
		return CollectorClosure{}, collector.failLocked(err)
	}
	encoded = append(encoded, '\n')
	if collector.hooks.BeforeWrite != nil {
		if err = collector.hooks.BeforeWrite(); err != nil {
			return CollectorClosure{}, collector.failLocked(err)
		}
	}
	written, err := collector.file.Write(encoded)
	if err != nil || written != len(encoded) {
		if err == nil {
			err = io.ErrShortWrite
		}
		return CollectorClosure{}, collector.failLocked(err)
	}
	if collector.hooks.BeforeSync != nil {
		if err = collector.hooks.BeforeSync(); err != nil {
			return CollectorClosure{}, collector.failLocked(err)
		}
	}
	if err = collector.file.Sync(); err != nil {
		return CollectorClosure{}, collector.failLocked(err)
	}
	collector.sealed = true
	return closure, nil
}

func (collector *DurableCollector) prepareSemanticUpdate(sourceIdentity string, frame Frame) (func(), error) {
	var header struct {
		Type PayloadType `json:"type"`
	}
	if err := json.Unmarshal(frame.Payload, &header); err != nil || header.Type == "" {
		return nil, err
	}
	switch header.Type {
	case PayloadSendCatalog:
		var payload SendCatalogPayload
		if err := DecodeClosedPayload(frame.Payload, &payload); err != nil || frame.Role != "publisher" || sourceIdentity != "publisher" ||
			validateGlobalSendCatalogEntry(payload.Entry) != nil {
			return nil, ErrReconciliation
		}
		if _, duplicate := collector.catalog[payload.Entry.MessageID]; duplicate {
			return nil, ErrDuplicateObservation
		}
		entry := payload.Entry
		entry.Expected = append([]CallbackKey(nil), entry.Expected...)
		return func() { collector.catalog[entry.MessageID] = entry }, nil
	case PayloadCallbackEvent:
		var payload CallbackEventPayload
		if err := DecodeClosedPayload(frame.Payload, &payload); err != nil || sourceIdentity != frame.Role ||
			payload.Event.Callback.Role != frame.Role {
			return nil, ErrReconciliation
		}
		entry, exists := collector.catalog[payload.Event.MessageID]
		if !exists || !callbackExpected(entry, payload.Event.Callback) {
			return nil, ErrReconciliation
		}
		if _, duplicate := collector.callbacks[payload.Event.MessageID][payload.Event.Callback]; duplicate {
			return nil, ErrDuplicateObservation
		}
		return func() {
			if collector.callbacks[payload.Event.MessageID] == nil {
				collector.callbacks[payload.Event.MessageID] = make(map[CallbackKey]struct{})
			}
			collector.callbacks[payload.Event.MessageID][payload.Event.Callback] = struct{}{}
		}, nil
	case PayloadFailure:
		return func() { collector.terminal = true }, nil
	default:
		return func() {}, nil
	}
}

func sourceIdentityMatchesFrame(sourceIdentity, frameRole string) bool {
	if sourceIdentity == "" || frameRole == "" {
		return false
	}
	if strings.HasPrefix(sourceIdentity, "collector/") {
		destinationRole := strings.TrimPrefix(sourceIdentity, "collector/")
		return frameRole == "collector" && (destinationRole == "publisher" || destinationRole == "target" || destinationRole == "passive")
	}
	return sourceIdentity == frameRole
}

func validateGlobalSendCatalogEntry(entry SendCatalogEntry) error {
	if err := ValidateSendCatalogEntry(entry); err != nil {
		return err
	}
	want := map[CallbackKey]struct{}{
		{Role: "target", Path: "pubsub"}:  {},
		{Role: "passive", Path: "pubsub"}: {},
	}
	if entry.Kind == "SELF_DIRECT" {
		want = map[CallbackKey]struct{}{{Role: "target", Path: "self-direct"}: {}}
	}
	if len(entry.Expected) != len(want) {
		return ErrReconciliation
	}
	for _, callback := range entry.Expected {
		if _, exists := want[callback]; !exists {
			return ErrReconciliation
		}
	}
	return nil
}

func (collector *DurableCollector) reconciledLocked() bool {
	for messageID, entry := range collector.catalog {
		if len(collector.callbacks[messageID]) != len(entry.Expected) {
			return false
		}
	}
	return true
}

func callbackExpected(entry SendCatalogEntry, callback CallbackKey) bool {
	for _, expected := range entry.Expected {
		if expected == callback {
			return true
		}
	}
	return false
}

func (collector *DurableCollector) Close() error {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	if collector.closed {
		return nil
	}
	collector.closed = true
	if collector.file == nil {
		return collector.failed
	}
	syncErr := collector.file.Sync()
	closeErr := collector.file.Close()
	collector.file = nil
	if collector.failed != nil {
		return collector.failed
	}
	return errors.Join(syncErr, closeErr)
}

func (collector *DurableCollector) failLocked(err error) error {
	if collector.failed == nil {
		collector.failed = err
	}
	return err
}

func (collector *DurableCollector) Sequence() uint64 {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	return collector.sequence
}

func MakeAck(source Frame, sourcePacket []byte, record CollectorRecord, role, startID, executableHash string, outboundSequence uint64) (Frame, error) {
	if outboundSequence == 0 {
		return Frame{}, ErrInvalidFrame
	}
	packetHash := sha256.Sum256(sourcePacket)
	if record.FrameSHA256 != hex.EncodeToString(packetHash[:]) {
		return Frame{}, ErrInvalidFrame
	}
	payload, payloadHash, err := NewPayload(DurableAckPayload{Type: PayloadDurableAck,
		AckedSourceSequence: source.SourceSequence, GlobalIngressSequence: record.GlobalSequence,
		DurableTimestampRawNS: record.TimestampRawNS, FrameSHA256: record.FrameSHA256})
	if err != nil {
		return Frame{}, err
	}
	ack := Frame{SchemaVersion: SchemaVersion, SessionID: source.SessionID, RunID: source.RunID,
		Role: role, PIDStartID: startID, ExecutableHash: executableHash,
		SourceSequence: outboundSequence, ReleaseEpoch: source.ReleaseEpoch,
		Kind: KindAck, PayloadHash: payloadHash, AdmissionState: "DURABLE", Payload: payload}
	if err = ack.Validate(); err != nil {
		return Frame{}, fmt.Errorf("ack: %w", err)
	}
	return ack, nil
}

func ValidateAck(source Frame, sourcePacket []byte, ack Frame, expectedOutboundSequence uint64) error {
	if ack.Kind != KindAck || ack.AdmissionState != "DURABLE" || ack.SessionID != source.SessionID || ack.RunID != source.RunID ||
		ack.SourceSequence != expectedOutboundSequence || ack.ReleaseEpoch != source.ReleaseEpoch {
		return ErrInvalidFrame
	}
	var payload DurableAckPayload
	if err := DecodeClosedPayload(ack.Payload, &payload); err != nil {
		return ErrInvalidFrame
	}
	hash := sha256.Sum256(sourcePacket)
	if payload.Type != PayloadDurableAck || payload.AckedSourceSequence != source.SourceSequence ||
		payload.FrameSHA256 != hex.EncodeToString(hash[:]) || payload.GlobalIngressSequence == 0 || payload.DurableTimestampRawNS == 0 {
		return ErrInvalidFrame
	}
	return nil
}
