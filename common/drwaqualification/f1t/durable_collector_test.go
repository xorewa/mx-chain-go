package f1t

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDurableCollectorOrdersAndRefusesAfterClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "record.jsonl")
	collector, err := CreateDurableCollector(path)
	require.NoError(t, err)
	first, err := collector.Append(validTestFrame(t))
	require.NoError(t, err)
	require.Equal(t, uint64(1), first.GlobalSequence)
	closure, err := collector.Seal()
	require.NoError(t, err)
	require.Equal(t, first.GlobalSequence, closure.FinalGlobalSequence)
	require.NotEmpty(t, closure.FinalRecordSHA256)
	require.NoError(t, collector.Close())
	_, err = collector.Append(validTestFrame(t))
	require.ErrorIs(t, err, ErrCollectorClosed)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(data), `"authoritative_runtime_credit":0`)
	require.Contains(t, string(data), `"phase_i_only":true`)
}

func TestDurableCollectorFailsPermanentlyOnDurabilityFailure(t *testing.T) {
	expected := errors.New("injected sync failure")
	collector, err := CreateDurableCollectorWithHooks(filepath.Join(t.TempDir(), "record.jsonl"), CollectorHooks{
		Clock:      func() (uint64, error) { return 1, nil },
		BeforeSync: func() error { return expected },
	})
	require.NoError(t, err)
	_, err = collector.Append(validTestFrame(t))
	require.ErrorIs(t, err, expected)
	_, err = collector.Append(validTestFrame(t))
	require.ErrorIs(t, err, ErrCollectorClosed)
	require.ErrorIs(t, collector.Close(), expected)
}

func TestDurableCollectorRefusesWriteFailureAndPathReuse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "record.jsonl")
	expected := errors.New("injected write failure")
	collector, err := CreateDurableCollectorWithHooks(path, CollectorHooks{
		Clock:       func() (uint64, error) { return 1, nil },
		BeforeWrite: func() error { return expected },
	})
	require.NoError(t, err)
	_, err = collector.Append(validTestFrame(t))
	require.ErrorIs(t, err, expected)
	require.ErrorIs(t, collector.Close(), expected)

	_, err = CreateDurableCollector(path)
	require.Error(t, err)
}

func TestDurableCollectorFailsPermanentlyOnClockOrFrameFailure(t *testing.T) {
	t.Run("clock", func(t *testing.T) {
		expected := errors.New("injected raw clock failure")
		collector, err := CreateDurableCollectorWithHooks(filepath.Join(t.TempDir(), "record.jsonl"), CollectorHooks{
			Clock: func() (uint64, error) { return 0, expected },
		})
		require.NoError(t, err)
		_, err = collector.Append(validTestFrame(t))
		require.ErrorIs(t, err, expected)
		_, err = collector.Append(validTestFrame(t))
		require.ErrorIs(t, err, ErrCollectorClosed)
		require.ErrorIs(t, collector.Close(), expected)
	})

	t.Run("frame", func(t *testing.T) {
		collector, err := CreateDurableCollector(filepath.Join(t.TempDir(), "record.jsonl"))
		require.NoError(t, err)
		frame := validTestFrame(t)
		frame.PayloadHash = frame.ExecutableHash
		_, err = collector.Append(frame)
		require.ErrorIs(t, err, ErrInvalidFrame)
		_, err = collector.Append(validTestFrame(t))
		require.ErrorIs(t, err, ErrCollectorClosed)
		require.ErrorIs(t, collector.Close(), ErrInvalidFrame)
	})
}

func TestDurableCollectorSealIsTerminalAndRecordChainIsBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "record.jsonl")
	collector, err := CreateDurableCollectorWithHooks(path, CollectorHooks{Clock: func() (uint64, error) { return 7, nil }})
	require.NoError(t, err)
	first := validTestFrame(t)
	first.Role = "target"
	firstRecord, err := collector.Append(first)
	require.NoError(t, err)
	second := validTestFrame(t)
	second.Role = "passive"
	secondRecord, err := collector.Append(second)
	require.NoError(t, err)
	require.Equal(t, firstRecord.GlobalSequence+1, secondRecord.GlobalSequence)
	require.NotEmpty(t, secondRecord.PreviousRecordSHA256)
	closure, err := collector.Seal()
	require.NoError(t, err)
	require.Equal(t, secondRecord.GlobalSequence, closure.FinalGlobalSequence)
	_, err = collector.Append(validTestFrame(t))
	require.ErrorIs(t, err, ErrCollectorClosed)
	_, err = collector.Seal()
	require.ErrorIs(t, err, ErrCollectorClosed)
	require.NoError(t, collector.Close())
}

func TestDurableCollectorRejectsSourceSequenceGap(t *testing.T) {
	collector, err := CreateDurableCollector(filepath.Join(t.TempDir(), "record.jsonl"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = collector.Close() })
	frame := validTestFrame(t)
	frame.SourceSequence = 2
	_, err = collector.Append(frame)
	require.Error(t, err)
	require.Zero(t, collector.Sequence())
}

func TestDurableAckBindsExactSourcePacketAndSequences(t *testing.T) {
	source := validTestFrame(t)
	packet, err := EncodeFrame(source)
	require.NoError(t, err)
	packetHash := sha256.Sum256(packet)
	record := CollectorRecord{GlobalSequence: 7, TimestampRawNS: 11, FrameSHA256: hex.EncodeToString(packetHash[:])}
	ack, err := MakeAck(source, packet, record, "collector", "1:2", source.ExecutableHash, 3)
	require.NoError(t, err)
	require.NoError(t, ValidateAck(source, packet, ack, 3))

	t.Run("make rejects record for another packet", func(t *testing.T) {
		mutated := append([]byte(nil), packet...)
		mutated[len(mutated)-1] ^= 1
		_, err = MakeAck(source, mutated, record, "collector", "1:2", source.ExecutableHash, 3)
		require.ErrorIs(t, err, ErrInvalidFrame)
	})

	t.Run("validate rejects another packet", func(t *testing.T) {
		mutated := append([]byte(nil), packet...)
		mutated[len(mutated)-1] ^= 1
		require.ErrorIs(t, ValidateAck(source, mutated, ack, 3), ErrInvalidFrame)
	})

	t.Run("validate rejects wrong outbound sequence", func(t *testing.T) {
		require.ErrorIs(t, ValidateAck(source, packet, ack, 4), ErrInvalidFrame)
	})

	t.Run("validate rejects source-sequence substitution", func(t *testing.T) {
		mutatedSource := source
		mutatedSource.SourceSequence++
		require.ErrorIs(t, ValidateAck(mutatedSource, packet, ack, 3), ErrInvalidFrame)
	})
}

func TestDurableCollectorReconcilesCatalogAgainstExactCallbacks(t *testing.T) {
	collector, err := CreateDurableCollector(filepath.Join(t.TempDir(), "record.jsonl"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = collector.Close() })
	target := CallbackKey{Role: "target", Path: "pubsub"}
	passive := CallbackKey{Role: "passive", Path: "pubsub"}
	entry := SendCatalogEntry{MessageID: "message-1", Kind: "CALIBRATION", Index: 1, Expected: []CallbackKey{target, passive}}
	catalog := frameWithPayload(t, "publisher", 1, KindEvent, "JOURNALED", SendCatalogPayload{Type: PayloadSendCatalog, Entry: entry})
	_, err = collector.AppendFrom("publisher", catalog)
	require.NoError(t, err)

	for _, callback := range []CallbackKey{target, passive} {
		event := RecorderEvent{SourceSequence: 1, ReleaseEpoch: 1, MessageID: entry.MessageID, Callback: callback, State: "ADMITTED"}
		frame := frameWithPayload(t, callback.Role, 1, KindEvent, "ADMITTED", CallbackEventPayload{Type: PayloadCallbackEvent, Event: event})
		_, err = collector.AppendFrom(callback.Role, frame)
		require.NoError(t, err)
	}
	closure, err := collector.Seal()
	require.NoError(t, err)
	require.Equal(t, uint64(3), closure.FinalGlobalSequence)
}

func TestDurableCollectorRefusesIncompleteOrDuplicateReconciliation(t *testing.T) {
	t.Run("incomplete", func(t *testing.T) {
		collector, err := CreateDurableCollector(filepath.Join(t.TempDir(), "record.jsonl"))
		require.NoError(t, err)
		t.Cleanup(func() { _ = collector.Close() })
		entry := SendCatalogEntry{MessageID: "message-1", Kind: "CALIBRATION", Index: 1,
			Expected: []CallbackKey{{Role: "target", Path: "pubsub"}, {Role: "passive", Path: "pubsub"}}}
		_, err = collector.AppendFrom("publisher", frameWithPayload(t, "publisher", 1, KindEvent, "JOURNALED",
			SendCatalogPayload{Type: PayloadSendCatalog, Entry: entry}))
		require.NoError(t, err)
		_, err = collector.Seal()
		require.ErrorIs(t, err, ErrReconciliation)
	})

	t.Run("duplicate callback", func(t *testing.T) {
		collector, err := CreateDurableCollector(filepath.Join(t.TempDir(), "record.jsonl"))
		require.NoError(t, err)
		t.Cleanup(func() { _ = collector.Close() })
		callback := CallbackKey{Role: "target", Path: "pubsub"}
		entry := SendCatalogEntry{MessageID: "message-1", Kind: "CALIBRATION", Index: 1,
			Expected: []CallbackKey{callback, {Role: "passive", Path: "pubsub"}}}
		_, err = collector.AppendFrom("publisher", frameWithPayload(t, "publisher", 1, KindEvent, "JOURNALED",
			SendCatalogPayload{Type: PayloadSendCatalog, Entry: entry}))
		require.NoError(t, err)
		event := RecorderEvent{SourceSequence: 1, ReleaseEpoch: 1, MessageID: entry.MessageID, Callback: callback, State: "ADMITTED"}
		_, err = collector.AppendFrom("target", frameWithPayload(t, "target", 1, KindEvent, "ADMITTED",
			CallbackEventPayload{Type: PayloadCallbackEvent, Event: event}))
		require.NoError(t, err)
		_, err = collector.AppendFrom("target", frameWithPayload(t, "target", 2, KindEvent, "ADMITTED",
			CallbackEventPayload{Type: PayloadCallbackEvent, Event: event}))
		require.ErrorIs(t, err, ErrDuplicateObservation)
	})
}

func TestDurableCollectorBindsSemanticRoleToAuthenticatedSourceIdentity(t *testing.T) {
	t.Run("frame role must match source identity", func(t *testing.T) {
		collector, err := CreateDurableCollector(filepath.Join(t.TempDir(), "record.jsonl"))
		require.NoError(t, err)
		t.Cleanup(func() { _ = collector.Close() })
		frame := validTestFrame(t)
		frame.Role = "target"
		_, err = collector.AppendFrom("passive", frame)
		require.ErrorIs(t, err, ErrInvalidFrame)
	})

	t.Run("catalog must come from publisher", func(t *testing.T) {
		collector, err := CreateDurableCollector(filepath.Join(t.TempDir(), "record.jsonl"))
		require.NoError(t, err)
		t.Cleanup(func() { _ = collector.Close() })
		entry := SendCatalogEntry{MessageID: "message-1", Kind: "CALIBRATION", Index: 1,
			Expected: []CallbackKey{{Role: "target", Path: "pubsub"}, {Role: "passive", Path: "pubsub"}}}
		frame := frameWithPayload(t, "target", 1, KindEvent, "JOURNALED", SendCatalogPayload{Type: PayloadSendCatalog, Entry: entry})
		_, err = collector.AppendFrom("target", frame)
		require.ErrorIs(t, err, ErrReconciliation)
	})

	t.Run("callback payload role must match authenticated frame role", func(t *testing.T) {
		collector, err := CreateDurableCollector(filepath.Join(t.TempDir(), "record.jsonl"))
		require.NoError(t, err)
		t.Cleanup(func() { _ = collector.Close() })
		callback := CallbackKey{Role: "target", Path: "pubsub"}
		entry := SendCatalogEntry{MessageID: "message-1", Kind: "CALIBRATION", Index: 1,
			Expected: []CallbackKey{callback, {Role: "passive", Path: "pubsub"}}}
		_, err = collector.AppendFrom("publisher", frameWithPayload(t, "publisher", 1, KindEvent, "JOURNALED",
			SendCatalogPayload{Type: PayloadSendCatalog, Entry: entry}))
		require.NoError(t, err)
		event := RecorderEvent{SourceSequence: 1, ReleaseEpoch: 1, MessageID: entry.MessageID,
			Callback: callback, State: "ADMITTED"}
		frame := frameWithPayload(t, "passive", 1, KindEvent, "ADMITTED", CallbackEventPayload{Type: PayloadCallbackEvent, Event: event})
		_, err = collector.AppendFrom("passive", frame)
		require.ErrorIs(t, err, ErrReconciliation)
	})

	t.Run("catalog callback topology must match message kind", func(t *testing.T) {
		collector, err := CreateDurableCollector(filepath.Join(t.TempDir(), "record.jsonl"))
		require.NoError(t, err)
		t.Cleanup(func() { _ = collector.Close() })
		entry := SendCatalogEntry{MessageID: "message-1", Kind: "SELF_DIRECT", Index: 1,
			Expected: []CallbackKey{{Role: "passive", Path: "pubsub"}}}
		_, err = collector.AppendFrom("publisher", frameWithPayload(t, "publisher", 1, KindEvent, "JOURNALED",
			SendCatalogPayload{Type: PayloadSendCatalog, Entry: entry}))
		require.ErrorIs(t, err, ErrReconciliation)
	})
}

func frameWithPayload(t *testing.T, role string, sequence uint64, kind Kind, state string, value any) Frame {
	t.Helper()
	payload, payloadHash, err := NewPayload(value)
	require.NoError(t, err)
	frame := validTestFrame(t)
	frame.Role = role
	frame.SourceSequence = sequence
	frame.Kind = kind
	frame.AdmissionState = state
	frame.Payload = payload
	frame.PayloadHash = payloadHash
	require.NoError(t, frame.Validate())
	return frame
}
