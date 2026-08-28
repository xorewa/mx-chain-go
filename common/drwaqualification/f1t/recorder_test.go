package f1t

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/multiversx/mx-chain-communication-go/p2p"
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/testscommon/p2pmocks"
	"github.com/stretchr/testify/require"
)

var targetPubsub = CallbackKey{Role: "target", Path: "pubsub"}

func recorderForTest(processorErr func() error, events *[]RecorderEvent, capacity int) *Recorder {
	config := RecorderConfig{
		Callback:      targetPubsub,
		QueueCapacity: capacity,
		MessageIdentity: func(message p2p.MessageP2P) (string, error) {
			if message == nil || message.IsInterfaceNil() {
				return "", ErrReconciliation
			}
			return string(message.Data()), nil
		},
	}
	if events != nil {
		config.DurableEmit = func(event RecorderEvent) error {
			*events = append(*events, event)
			return nil
		}
	}
	return NewRecorderWithConfig(func(p2p.MessageP2P, core.PeerID, p2p.MessageHandler) ([]byte, error) {
		if processorErr == nil {
			return []byte("digest"), nil
		}
		return []byte("digest"), processorErr()
	}, config)
}

func TestRecorderGuardedSendAndRealProcessorPathReconcileEveryCatalogKind(t *testing.T) {
	events := make([]RecorderEvent, 0, 5)
	recorder := recorderForTest(nil, &events, 8)
	require.NoError(t, recorder.SetReleaseEpoch(1))
	kinds := []string{"READINESS", "CALIBRATION", "SELECTED_SHAPED", "SENTINEL", "SELF_DIRECT"}
	for index, kind := range kinds {
		messageID := kind
		order := make([]string, 0, 2)
		require.NoError(t, recorder.GuardedSend(SendCatalogEntry{MessageID: messageID, Kind: kind, Index: uint64(index + 1), Expected: []CallbackKey{targetPubsub}},
			func(SendCatalogEntry) error { order = append(order, "journal"); return nil },
			func() error { order = append(order, "send"); return nil }))
		require.Equal(t, []string{"journal", "send"}, order)
		result, err := recorder.ProcessReceivedMessage(&p2pmocks.P2PMessageMock{DataField: []byte(messageID)}, "peer", nil)
		require.NoError(t, err)
		require.Equal(t, []byte("digest"), result)
	}
	require.NoError(t, recorder.SealSends())
	require.NoError(t, recorder.QuiesceAndDrain())
	require.Len(t, events, len(kinds))
	for index, event := range events {
		require.Equal(t, uint64(index+1), event.SourceSequence)
		require.Equal(t, uint64(1), event.ReleaseEpoch)
		require.Equal(t, "ADMITTED", event.State)
	}
	_, err := recorder.ProcessReceivedMessage(&p2pmocks.P2PMessageMock{DataField: []byte("late")}, "peer", nil)
	require.ErrorIs(t, err, ErrRecorderClosed)
	require.Equal(t, "TERMINAL_FAILURE", events[len(events)-1].State)
}

func TestRecorderSeparatesRemoteSendCatalogFromLocalCallbackExpectations(t *testing.T) {
	remoteEntry := SendCatalogEntry{MessageID: "remote", Kind: "CALIBRATION", Index: 1,
		Expected: []CallbackKey{{Role: "target", Path: "pubsub"}}}

	source := NewRecorderWithConfig(nil, RecorderConfig{Callback: CallbackKey{Role: "publisher", Path: "publisher"}})
	require.NoError(t, source.GuardedSend(remoteEntry, func(SendCatalogEntry) error { return nil }, func() error { return nil }))
	require.NoError(t, source.SealSends())
	require.NoError(t, source.QuiesceAndDrain())

	receiver := recorderForTest(nil, nil, 4)
	require.NoError(t, receiver.RegisterExpected(remoteEntry))
	_, err := receiver.ProcessReceivedMessage(&p2pmocks.P2PMessageMock{DataField: []byte(remoteEntry.MessageID)}, "peer", nil)
	require.NoError(t, err)
	require.NoError(t, receiver.SealSends())
	require.NoError(t, receiver.QuiesceAndDrain())
}

func TestRecorderQuiesceWaitsForPreQuiesceAdmittedWork(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	recorder := recorderForTest(func() error {
		close(started)
		<-release
		return nil
	}, nil, 1)
	require.NoError(t, recorder.GuardedSend(SendCatalogEntry{MessageID: "held", Kind: "SENTINEL", Index: 1, Expected: []CallbackKey{targetPubsub}},
		func(SendCatalogEntry) error { return nil }, func() error { return nil }))
	result := make(chan error, 1)
	go func() {
		_, err := recorder.ProcessReceivedMessage(&p2pmocks.P2PMessageMock{DataField: []byte("held")}, "peer", nil)
		result <- err
	}()
	<-started
	require.NoError(t, recorder.SealSends())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	drained := make(chan error, 1)
	go func() { drained <- recorder.QuiesceAndDrainContext(ctx) }()
	select {
	case err := <-drained:
		require.Failf(t, "drain returned before callback completion", "%v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	require.NoError(t, <-result)
	require.NoError(t, <-drained)
}

func TestRecorderQueueOverflowFailsClosed(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	var once sync.Once
	recorder := recorderForTest(func() error {
		once.Do(func() { close(started) })
		<-release
		return nil
	}, nil, 1)
	for index, id := range []string{"one", "two", "three"} {
		require.NoError(t, recorder.GuardedSend(SendCatalogEntry{MessageID: id, Kind: "CALIBRATION", Index: uint64(index + 1), Expected: []CallbackKey{targetPubsub}},
			func(SendCatalogEntry) error { return nil }, func() error { return nil }))
	}
	first := make(chan error, 1)
	go func() {
		_, err := recorder.ProcessReceivedMessage(&p2pmocks.P2PMessageMock{DataField: []byte("one")}, "peer", nil)
		first <- err
	}()
	<-started
	second := make(chan error, 1)
	go func() {
		_, err := recorder.ProcessReceivedMessage(&p2pmocks.P2PMessageMock{DataField: []byte("two")}, "peer", nil)
		second <- err
	}()
	require.Eventually(t, func() bool {
		admitted, _, inFlight, _ := recorder.Snapshot()
		return admitted == 2 && inFlight == 2
	}, time.Second, time.Millisecond)
	_, err := recorder.ProcessReceivedMessage(&p2pmocks.P2PMessageMock{DataField: []byte("three")}, "peer", nil)
	require.ErrorIs(t, err, ErrRecorderQueueFull)
	close(release)
	require.Error(t, <-first)
	require.Error(t, <-second)
}

func TestRecorderJournalAndTransportFailuresArePermanent(t *testing.T) {
	journalFailure := errors.New("injected journal failure")
	recorder := recorderForTest(nil, nil, 1)
	sent := false
	err := recorder.GuardedSend(SendCatalogEntry{MessageID: "ready", Kind: "READINESS", Index: 1, Expected: []CallbackKey{targetPubsub}},
		func(SendCatalogEntry) error { return journalFailure }, func() error { sent = true; return nil })
	require.ErrorIs(t, err, journalFailure)
	require.False(t, sent)
	require.ErrorIs(t, recorder.SealSends(), journalFailure)

	transportFailure := errors.New("injected send failure")
	recorder = recorderForTest(nil, nil, 1)
	err = recorder.GuardedSend(SendCatalogEntry{MessageID: "ready", Kind: "READINESS", Index: 1, Expected: []CallbackKey{targetPubsub}},
		func(SendCatalogEntry) error { return nil }, func() error { return transportFailure })
	require.ErrorIs(t, err, transportFailure)
	require.ErrorIs(t, recorder.SealSends(), transportFailure)
}

func TestRecorderHeldPreEntryMessageOfEveryKindBlocksClose(t *testing.T) {
	for index, kind := range []string{"READINESS", "CALIBRATION", "SELECTED_SHAPED", "SENTINEL", "SELF_DIRECT"} {
		t.Run(kind, func(t *testing.T) {
			recorder := recorderForTest(nil, nil, 1)
			require.NoError(t, recorder.GuardedSend(SendCatalogEntry{MessageID: kind, Kind: kind, Index: uint64(index + 1), Expected: []CallbackKey{targetPubsub}},
				func(SendCatalogEntry) error { return nil }, func() error { return nil }))
			require.NoError(t, recorder.SealSends())
			err := recorder.QuiesceAndDrain()
			require.ErrorIs(t, err, ErrReconciliation)
		})
	}
}

func TestV17RecorderExecutesAllThirtyOneTransitionFixtures(t *testing.T) {
	baseMachine, baseEvent := v17FixtureMachineAndEvent(t)
	type fixture struct {
		name     string
		state    V17RecorderState
		events   []string
		prepare  func(*V17RecorderMachine, *V17RecorderEvent)
		expected V17RecorderState
	}
	invalid := func(mutate func(*V17RecorderEvent)) func(*V17RecorderMachine, *V17RecorderEvent) {
		return func(_ *V17RecorderMachine, event *V17RecorderEvent) { mutate(event) }
	}
	fixtures := []fixture{
		{name: "RF_ARMED_READY", state: V17StateArmed, events: []string{V17EventArmContracts}, expected: V17StateReady},
		{name: "RF_ARMED_FAILED", state: V17StateArmed, events: []string{V17EventArmContracts}, prepare: func(machine *V17RecorderMachine, _ *V17RecorderEvent) { machine.Context.IdentityMismatchCount = 1 }, expected: V17StateFailed},
		{name: "RF_BEGIN_BLOCKED", state: V17StateReady, events: []string{V17EventBegin}, expected: V17StateFailed},
		{name: "RF_COUNTS_TO_QUIET", state: V17StateObserving, events: []string{V17EventCounts}, expected: V17StateQuiet},
		{name: "RF_COUNTS_FALSE", state: V17StateObserving, events: []string{V17EventCounts}, prepare: func(machine *V17RecorderMachine, _ *V17RecorderEvent) {
			machine.Context.ObservedArmCounts["SELECTED"] = 0
		}, expected: V17StateFailed},
		{name: "RF_QUIET_TO_OBSERVING", state: V17StateQuiet, events: []string{V17EventValid}, expected: V17StateObserving},
		{name: "RF_BEFORE_CLOSE_FALSE", state: V17StateQuiet, events: []string{V17EventValid}, prepare: invalid(func(event *V17RecorderEvent) { event.TimestampRawNS = 501 }), expected: V17StateFailed},
		{name: "RF_QUIET_ELAPSED_FALSE", state: V17StateQuiet, events: []string{V17EventClose}, prepare: func(machine *V17RecorderMachine, _ *V17RecorderEvent) {
			machine.Context.NumericRulingAuthorized = true
			machine.Context.HorizonStatus = "RATIFIED"
			machine.Context.ArmingAllowed = true
			machine.Context.NowRawNS = 149
		}, expected: V17StateFailed},
		{name: "RF_HORIZON_ARM_FALSE", state: V17StateReady, events: []string{V17EventBegin}, prepare: func(machine *V17RecorderMachine, _ *V17RecorderEvent) {
			machine.Context.NumericRulingAuthorized = true
			machine.Context.HorizonStatus = "RATIFIED"
			machine.Context.ArmingAllowed = false
		}, expected: V17StateFailed},
		{name: "RF_LATE_AFTER_CLOSE", state: V17StateClosed, events: []string{V17EventLater}, expected: V17StateFailed},
		{name: "RF_REMOTE_VALID", state: V17StateQuiet, events: []string{V17EventValid}, expected: V17StateObserving},
		{name: "RF_REMOTE_INVALID", state: V17StateObserving, events: []string{V17EventInvalid}, prepare: invalid(func(event *V17RecorderEvent) { event.FromPeer = "peer-other" }), expected: V17StateFailed},
		{name: "RF_SELF_VALID", state: V17StateQuiet, events: []string{V17EventValid}, prepare: invalid(func(event *V17RecorderEvent) {
			event.TransportKind = "SELF_DIRECT"
			event.FromPeer = "peer-self"
			event.ForwarderPeer = "peer-self"
		}), expected: V17StateObserving},
		{name: "RF_SELF_INVALID", state: V17StateObserving, events: []string{V17EventInvalid}, prepare: invalid(func(event *V17RecorderEvent) {
			event.TransportKind = "SELF_DIRECT"
			event.FromPeer = "peer-other"
			event.ForwarderPeer = "peer-self"
		}), expected: V17StateFailed},
		{name: "RF_ARM_VALID", state: V17StateQuiet, events: []string{V17EventValid}, expected: V17StateObserving},
		{name: "RF_ARM_BATCH_SHA256_INVALID", state: V17StateObserving, events: []string{V17EventInvalid}, prepare: invalid(func(event *V17RecorderEvent) { event.BatchSHA256 = event.SCRHash }), expected: V17StateFailed},
		{name: "RF_ARM_MINIBLOCK_HASH_INVALID", state: V17StateObserving, events: []string{V17EventInvalid}, prepare: invalid(func(event *V17RecorderEvent) { event.MiniBlockHash = event.SCRHash }), expected: V17StateFailed},
		{name: "RF_ARM_SCR_HASH_INVALID", state: V17StateObserving, events: []string{V17EventInvalid}, prepare: invalid(func(event *V17RecorderEvent) { event.SCRHash = event.BatchSHA256 }), expected: V17StateFailed},
		{name: "RF_ARM_VECTOR_INVALID", state: V17StateObserving, events: []string{V17EventInvalid}, prepare: invalid(func(event *V17RecorderEvent) {
			event.PredicateVector["PR001"] = PredicateResult{State: "FALSE"}
		}), expected: V17StateFailed},
		{name: "RF_ARM_VECTOR_NA_REASON_MISSING", state: V17StateObserving, events: []string{V17EventInvalid}, prepare: invalid(func(event *V17RecorderEvent) {
			event.PredicateVector["PR042_VM_INPUT_TRANSFORM"] = PredicateResult{State: "N_A"}
		}), expected: V17StateFailed},
		{name: "RF_ARM_LABEL_MISMATCH", state: V17StateObserving, events: []string{V17EventInvalid}, prepare: invalid(func(event *V17RecorderEvent) { event.ClassifiedArm = "SENTINEL_1" }), expected: V17StateFailed},
		{name: "RF_ROLE_MISMATCH", state: V17StateObserving, events: []string{V17EventInvalid}, prepare: invalid(func(event *V17RecorderEvent) { event.ReceiverRole = "PUBLISHER_ONLY" }), expected: V17StateFailed},
		{name: "RF_TOPIC_MISMATCH", state: V17StateObserving, events: []string{V17EventInvalid}, prepare: invalid(func(event *V17RecorderEvent) { event.Topic = "/wrong" }), expected: V17StateFailed},
		{name: "RF_COLLECTOR_FAILURE", state: V17StateObserving, events: []string{V17EventInvalid}, prepare: invalid(func(event *V17RecorderEvent) { event.CollectorResult = "COLLECTOR_FAILURE" }), expected: V17StateFailed},
		{name: "RF_SEQUENCE_GAP", state: V17StateObserving, events: []string{V17EventInvalid}, prepare: invalid(func(event *V17RecorderEvent) { event.Sequence = 11 }), expected: V17StateFailed},
		{name: "RF_SCHEMA_INVALID", state: V17StateObserving, events: []string{V17EventInvalid}, prepare: invalid(func(event *V17RecorderEvent) { event.SchemaValid = false }), expected: V17StateFailed},
		{name: "RF_DUPLICATE_RECEIVER_SEQUENCE", state: V17StateQuiet, events: []string{V17EventValid, V17EventInvalid}, expected: V17StateFailed},
		{name: "RF_BEGIN_RATIFIED_BLOCKED", state: V17StateReady, events: []string{V17EventBegin}, prepare: func(machine *V17RecorderMachine, _ *V17RecorderEvent) {
			machine.Context.HorizonStatus = "RATIFIED"
			machine.Context.ArmingAllowed = true
			machine.Context.NumericRulingAuthorized = false
		}, expected: V17StateFailed},
		{name: "RF_CLOSE_VALID_BLOCKED", state: V17StateQuiet, events: []string{V17EventClose}, prepare: func(machine *V17RecorderMachine, _ *V17RecorderEvent) {
			machine.Context.HorizonStatus = "RATIFIED"
			machine.Context.ArmingAllowed = true
			machine.Context.NumericRulingAuthorized = false
		}, expected: V17StateFailed},
		{name: "RF_LEGACY_PROFILE_VALID", state: V17StateQuiet, events: []string{V17EventValid}, prepare: func(machine *V17RecorderMachine, event *V17RecorderEvent) {
			applyV17Arm(event, ProfileLegacy, machine.Context.Arms[ProfileLegacy]["SELECTED"])
		}, expected: V17StateObserving},
		{name: "RF_LEGACY_PROFILE_WITH_V2_IDENTITY", state: V17StateObserving, events: []string{V17EventInvalid}, prepare: func(_ *V17RecorderMachine, event *V17RecorderEvent) { event.Profile = ProfileLegacy }, expected: V17StateFailed},
		{name: "RF_V2_PROFILE_WITH_LEGACY_IDENTITY", state: V17StateObserving, events: []string{V17EventInvalid}, prepare: func(machine *V17RecorderMachine, event *V17RecorderEvent) {
			legacy := machine.Context.Arms[ProfileLegacy]["SELECTED"]
			event.BatchSHA256 = legacy.BatchSHA256
			event.MiniBlockHash = legacy.MiniBlockHash
			event.SCRHash = legacy.SCRHash
		}, expected: V17StateFailed},
	}
	require.Len(t, fixtures, 32)
	for _, test := range fixtures {
		t.Run(test.name, func(t *testing.T) {
			machine := baseMachine
			machine.State = test.state
			machine.Context.RequiredArmCounts = cloneUint64Map(baseMachine.Context.RequiredArmCounts)
			machine.Context.ObservedArmCounts = cloneUint64Map(baseMachine.Context.ObservedArmCounts)
			event := baseEvent
			event.PredicateVector = V17ExpectedPredicateResults()
			if test.prepare != nil {
				test.prepare(&machine, &event)
			}
			var lastErr error
			for _, eventName := range test.events {
				lastErr = machine.Apply(eventName, &event)
			}
			require.Equal(t, test.expected, machine.State)
			if test.expected == V17StateFailed {
				require.Error(t, lastErr)
			} else {
				require.NoError(t, lastErr)
			}
		})
	}
}

func v17FixtureMachineAndEvent(t *testing.T) (V17RecorderMachine, V17RecorderEvent) {
	t.Helper()
	constructor := DefaultCanonicalSourceConstructor()
	arms := make(map[Profile]map[string]V17ArmIdentity)
	for _, profile := range Profiles() {
		arms[profile] = make(map[string]V17ArmIdentity)
		for _, armID := range []string{"SELECTED", "SENTINEL_1"} {
			_, fixture, err := BuildCalibrationFixture(constructor, profile, armID, 1, "fixture", "/drwa/qualification/f1t", "peer-remote", armID == "SELECTED")
			require.NoError(t, err)
			arms[profile][armID] = V17ArmIdentity{BatchSHA256: fixture.BatchSHA256, MiniBlockHash: fixture.MiniBlockHash,
				SCRHash: fixture.SCRHash, Vector: V17ExpectedPredicateResults()}
		}
	}
	machine := V17RecorderMachine{State: V17StateQuiet, Context: V17RecorderContext{
		ReceiverID: "receiver-1", RemotePublisherPeer: "peer-remote", SelfPeer: "peer-self", BoundTopic: "/drwa/qualification/f1t",
		SourceArmsConstructed: true, RequiredArmCounts: map[string]uint64{"SELECTED": 1, "SENTINEL_1": 1},
		ObservedArmCounts: map[string]uint64{"SELECTED": 1, "SENTINEL_1": 1}, CloseDeadlineRawNS: 500,
		PriorSequence: 9, ClosedSequence: 20, PriorTimestampRawNS: 99, LastExpectedEventRawNS: 100,
		NowRawNS: 200, HorizonStatus: "UNRESOLVED", HQuietNS: 50, Arms: arms,
	}}
	event := V17RecorderEvent{SchemaValid: true, Sequence: 10, TimestampRawNS: 101, ReceiverID: "receiver-1",
		ReceiverRole: "QUALIFICATION_RECORDER", TransportKind: "REMOTE_DELIVERY", FromPeer: "peer-remote", ForwarderPeer: "peer-remote",
		Topic: "/drwa/qualification/f1t", ClassifiedArm: "SELECTED", CollectorResult: "FSYNCED_APPEND_SUCCESS"}
	applyV17Arm(&event, ProfileV2, arms[ProfileV2]["SELECTED"])
	return machine, event
}

func applyV17Arm(event *V17RecorderEvent, profile Profile, arm V17ArmIdentity) {
	event.Profile = profile
	event.BatchSHA256 = arm.BatchSHA256
	event.MiniBlockHash = arm.MiniBlockHash
	event.SCRHash = arm.SCRHash
	event.PredicateVector = clonePredicateResults(arm.Vector)
}

func cloneUint64Map(source map[string]uint64) map[string]uint64 {
	result := make(map[string]uint64, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}
