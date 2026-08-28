//go:build drwa_s1_f1t_measure

package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/multiversx/mx-chain-communication-go/p2p"
	"github.com/multiversx/mx-chain-communication-go/p2p/libp2p"
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common/drwaqualification"
	"github.com/multiversx/mx-chain-go/common/drwaqualification/f1t"
)

const phaseIEnvironment = "DRWA_F1T_PHASE_I_OFFLINE_ONLY"
const phaseIFailRoleEnvironment = "DRWA_F1T_PHASE_I_INJECT_CHILD_FAILURE_ROLE"

type output struct {
	Schema              string                       `json:"schema"`
	Mode                string                       `json:"mode"`
	Status              string                       `json:"status"`
	RuntimeCredit       int                          `json:"authoritative_runtime_credit"`
	PhaseIOnly          bool                         `json:"phase_i_only"`
	PhaseIISubmission   bool                         `json:"phase_ii_submission"`
	ProtocolSubmission  bool                         `json:"protocol_submission"`
	NumericRatification bool                         `json:"numeric_ratification"`
	CollectorClosure    *f1t.CollectorClosure        `json:"collector_closure,omitempty"`
	TransportClosure    *f1t.CollectorClosure        `json:"transport_reconciliation_closure,omitempty"`
	Terminations        []f1t.TerminationObservation `json:"terminations,omitempty"`
}

type options struct {
	mode          string
	channelFD     int
	collectorPID  int
	sessionID     string
	runID         string
	rehearsalRoot string
}

type transportPayload struct {
	Kind  string `json:"kind"`
	Index uint64 `json:"index"`
}

type transportReconciliationHooks struct {
	Collector            f1t.CollectorHooks
	MutateRemoteCatalog  func(*f1t.SendCatalogEntry)
	MutateRemotePayload  func([]byte) []byte
	MutateRemoteCallback func(*f1t.RecorderEvent)
	BeforeRemoteSend     func()
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(arguments []string, writer io.Writer) error {
	parsed, err := parseOptions(arguments)
	if err != nil {
		return err
	}
	if os.Getenv(phaseIEnvironment) != "1" {
		return errors.New("Phase I offline environment not enabled")
	}
	if !libp2p.F1TDirectAdmissionEnabled() {
		return errors.New("F1-T tagged direct-admission seam not linked")
	}
	drwaqualification.RegisterVariant(drwaqualification.VariantF1T)
	if drwaqualification.ActiveVariant() != drwaqualification.VariantF1T || f1t.ConditionalWilksCoverage() < 0.99 {
		return errors.New("F1-T qualification precondition failed")
	}
	if parsed.channelFD >= 0 {
		return runChild(parsed)
	}
	if parsed.mode == "collector" && parsed.rehearsalRoot != "" {
		result, runErr := runInterceptedRehearsal(parsed)
		if runErr != nil {
			return runErr
		}
		return json.NewEncoder(writer).Encode(result)
	}
	result := output{Schema: "DRWA_S1_F1T_PHASE_I_COMMAND_V1", Mode: parsed.mode,
		Status: "OFFLINE_IMPLEMENTATION_VERIFICATION_ONLY_NO_CAMPAIGN", PhaseIOnly: true}
	return json.NewEncoder(writer).Encode(result)
}

func parseOptions(arguments []string) (options, error) {
	flags := flag.NewFlagSet("drwa-prototype-f1t-measure", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	parsed := options{channelFD: -1}
	flags.StringVar(&parsed.mode, "mode", "", "collector|publisher|target|passive")
	flags.IntVar(&parsed.channelFD, "channel-fd", -1, "inherited seqpacket descriptor")
	flags.IntVar(&parsed.collectorPID, "collector-pid", 0, "bound collector pid")
	flags.StringVar(&parsed.sessionID, "session-id", "", "session identity")
	flags.StringVar(&parsed.runID, "run-id", "", "run identity")
	flags.StringVar(&parsed.rehearsalRoot, "rehearsal-root", "", "validated disposable rehearsal root")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return options{}, errors.New("invalid arguments")
	}
	if parsed.mode != "collector" && parsed.mode != "publisher" && parsed.mode != "target" && parsed.mode != "passive" {
		return options{}, errors.New("invalid F1-T role")
	}
	if parsed.channelFD >= 0 && (parsed.mode == "collector" || parsed.collectorPID <= 0 || parsed.sessionID == "" || parsed.runID == "" || parsed.rehearsalRoot != "") {
		return options{}, errors.New("invalid child role arguments")
	}
	return parsed, nil
}

func runChild(parsed options) error {
	if os.Getenv(phaseIFailRoleEnvironment) == parsed.mode {
		return errors.New("injected Phase-I child failure")
	}
	endpoint, err := f1t.EndpointFromFD(parsed.channelFD)
	if err != nil {
		return err
	}
	defer endpoint.Close()
	self, err := f1t.CaptureProcessIdentity(os.Getpid(), parsed.mode, false)
	if err != nil {
		return err
	}
	collector, err := f1t.CaptureProcessIdentity(parsed.collectorPID, "collector", false)
	if err != nil {
		return err
	}
	recorder := f1t.NewRecorder(nil)
	payload, payloadHash, err := f1t.NewPayload(f1t.RoleReadyPayload{Type: f1t.PayloadRoleReady, Phase: "INTERCEPTED_REHEARSAL", Role: parsed.mode})
	if err != nil {
		return err
	}
	frame := f1t.Frame{SchemaVersion: f1t.SchemaVersion, SessionID: parsed.sessionID, RunID: parsed.runID,
		Role: parsed.mode, PIDStartID: self.StartID, ExecutableHash: self.ExecutableHash, SourceSequence: 1,
		ReleaseEpoch: 0, Kind: f1t.KindEvent, PayloadHash: payloadHash, AdmissionState: "READY", Payload: payload}
	if err = sendChildFrameAndAwaitAck(endpoint, collector, frame, 1); err != nil {
		return err
	}
	releaseCommand, err := receiveChildCommand(endpoint, collector, 2, "RELEASE", 1)
	if err != nil {
		return err
	}
	if err = recorder.SetReleaseEpoch(1); err != nil {
		return err
	}
	ackPayload, ackHash, err := f1t.NewPayload(f1t.RoleCommandAckPayload{Type: f1t.PayloadRoleAck,
		Command: "RELEASE", CommandSourceSequence: releaseCommand.SourceSequence})
	if err != nil {
		return err
	}
	roleAck := f1t.Frame{SchemaVersion: f1t.SchemaVersion, SessionID: parsed.sessionID, RunID: parsed.runID,
		Role: parsed.mode, PIDStartID: self.StartID, ExecutableHash: self.ExecutableHash, SourceSequence: 2,
		ReleaseEpoch: 1, Kind: f1t.KindEvent, PayloadHash: ackHash, AdmissionState: "APPLIED", Payload: ackPayload}
	if err = sendChildFrameAndAwaitAck(endpoint, collector, roleAck, 3); err != nil {
		return err
	}
	_, err = receiveChildCommand(endpoint, collector, 4, "QUIESCE", 1)
	if err != nil {
		return err
	}
	if err = recorder.SealSends(); err != nil {
		return err
	}
	if err = recorder.QuiesceAndDrain(); err != nil {
		return err
	}
	admitted, emitted, inFlight, failed := recorder.Snapshot()
	if failed != nil {
		return failed
	}
	drainPayload, drainHash, err := f1t.NewPayload(f1t.DrainReportPayload{Type: f1t.PayloadDrain,
		LastAdmitted: admitted, LastEmitted: emitted, InFlight: inFlight, QueueEmpty: true})
	if err != nil {
		return err
	}
	drain := f1t.Frame{SchemaVersion: f1t.SchemaVersion, SessionID: parsed.sessionID, RunID: parsed.runID,
		Role: parsed.mode, PIDStartID: self.StartID, ExecutableHash: self.ExecutableHash, SourceSequence: 3,
		ReleaseEpoch: 1, Kind: f1t.KindDrain, PayloadHash: drainHash, AdmissionState: "QUIESCED", Payload: drainPayload}
	if err = sendChildFrameAndAwaitAck(endpoint, collector, drain, 5); err != nil {
		return err
	}
	return endpoint.WaitForPeerClose()
}

func sendChildFrameAndAwaitAck(endpoint *f1t.Endpoint, collector f1t.ProcessIdentity, frame f1t.Frame, expectedAckSequence uint64) error {
	packet, err := f1t.EncodeFrame(frame)
	if err != nil {
		return err
	}
	if err = endpoint.Send(packet); err != nil {
		return err
	}
	ack, _, err := endpoint.ReceiveFrame(collector)
	if err != nil {
		return err
	}
	return f1t.ValidateAck(frame, packet, ack, expectedAckSequence)
}

func receiveChildCommand(endpoint *f1t.Endpoint, collector f1t.ProcessIdentity, expectedSequence uint64, command string, releaseEpoch uint64) (f1t.Frame, error) {
	frame, _, err := endpoint.ReceiveFrame(collector)
	if err != nil {
		return f1t.Frame{}, err
	}
	if frame.SourceSequence != expectedSequence || frame.ReleaseEpoch != releaseEpoch || frame.Kind != f1t.KindCommand || frame.AdmissionState != "INTENT" {
		return f1t.Frame{}, f1t.ErrInvalidFrame
	}
	var payload f1t.CommandIntentPayload
	if err = f1t.DecodeClosedPayload(frame.Payload, &payload); err != nil || payload.Type != f1t.PayloadCommand || payload.Command != command {
		return f1t.Frame{}, f1t.ErrInvalidFrame
	}
	return frame, nil
}

type childProcess struct {
	role              string
	endpoint          *f1t.Endpoint
	command           *exec.Cmd
	identity          f1t.ProcessIdentity
	stopNS            uint64
	waited            bool
	collectorOutbound uint64
	childInbound      uint64
}

func runInterceptedRehearsal(parsed options) (output, error) {
	root, err := filepath.Abs(parsed.rehearsalRoot)
	if err != nil || root != parsed.rehearsalRoot || filepath.Clean(root) != root {
		return output{}, errors.New("rehearsal root must be clean absolute")
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return output{}, errors.New("rehearsal root unavailable")
	}
	collector, err := f1t.CreateDurableCollector(filepath.Join(root, "f1t-phase-i-rehearsal.jsonl"))
	if err != nil {
		return output{}, err
	}
	defer collector.Close()
	executable, err := os.Executable()
	if err != nil {
		return output{}, err
	}
	sessionID := "phase-i-session"
	runID := "phase-i-run"
	roles := []string{"publisher", "target", "passive"}
	children := make([]childProcess, 0, len(roles))
	defer func() {
		for index := range children {
			child := &children[index]
			_ = child.endpoint.Close()
			_ = child.identity.Close()
			if !child.waited && child.command.Process != nil {
				_ = child.command.Process.Signal(os.Interrupt)
				_ = child.command.Wait()
				child.waited = true
			}
		}
	}()
	for _, role := range roles {
		parentEndpoint, childEndpoint, socketErr := f1t.NewSocketPair()
		if socketErr != nil {
			return output{}, socketErr
		}
		dupFD, socketErr := childEndpoint.DupFD()
		_ = childEndpoint.Close()
		if socketErr != nil {
			_ = parentEndpoint.Close()
			return output{}, socketErr
		}
		file := os.NewFile(uintptr(dupFD), "f1t-"+role)
		command := exec.Command(executable, "--mode="+role, "--channel-fd=3", "--collector-pid="+strconv.Itoa(os.Getpid()),
			"--session-id="+sessionID, "--run-id="+runID)
		command.Env = append(os.Environ(), phaseIEnvironment+"=1")
		command.ExtraFiles = []*os.File{file}
		if startErr := command.Start(); startErr != nil {
			_ = file.Close()
			_ = parentEndpoint.Close()
			return output{}, startErr
		}
		_ = file.Close()
		identity, identityErr := f1t.CaptureProcessIdentity(command.Process.Pid, role, true)
		if identityErr != nil {
			_ = parentEndpoint.Close()
			return output{}, identityErr
		}
		children = append(children, childProcess{role: role, endpoint: parentEndpoint, command: command, identity: identity})
	}
	collectorIdentity, err := f1t.CaptureProcessIdentity(os.Getpid(), "collector", false)
	if err != nil {
		return output{}, err
	}
	for index := range children {
		child := &children[index]
		frame, packet, receiveErr := receiveChildFrame(child, 1)
		if receiveErr != nil {
			return output{}, receiveErr
		}
		var ready f1t.RoleReadyPayload
		if frame.Kind != f1t.KindEvent || frame.AdmissionState != "READY" || frame.ReleaseEpoch != 0 ||
			f1t.DecodeClosedPayload(frame.Payload, &ready) != nil || ready.Type != f1t.PayloadRoleReady || ready.Role != child.role {
			return output{}, f1t.ErrInvalidFrame
		}
		if err = appendAndAck(collector, child, collectorIdentity, frame, packet); err != nil {
			return output{}, err
		}
	}
	transportClosure, err := runTransportReconciliation(filepath.Join(root, "f1t-phase-i-transport-reconciliation.jsonl"), collectorIdentity)
	if err != nil {
		return output{}, err
	}
	for index := range children {
		child := &children[index]
		command, commandErr := sendCollectorCommand(collector, child, collectorIdentity, sessionID, runID, "RELEASE", 1)
		if commandErr != nil {
			return output{}, commandErr
		}
		frame, packet, receiveErr := receiveChildFrame(child, 2)
		if receiveErr != nil {
			return output{}, receiveErr
		}
		var roleAck f1t.RoleCommandAckPayload
		if frame.Kind != f1t.KindEvent || frame.AdmissionState != "APPLIED" || frame.ReleaseEpoch != 1 ||
			f1t.DecodeClosedPayload(frame.Payload, &roleAck) != nil || roleAck.Type != f1t.PayloadRoleAck ||
			roleAck.Command != "RELEASE" || roleAck.CommandSourceSequence != command.SourceSequence {
			return output{}, f1t.ErrInvalidFrame
		}
		if err = appendAndAck(collector, child, collectorIdentity, frame, packet); err != nil {
			return output{}, err
		}
	}
	for index := range children {
		child := &children[index]
		_, commandErr := sendCollectorCommand(collector, child, collectorIdentity, sessionID, runID, "QUIESCE", 1)
		if commandErr != nil {
			return output{}, commandErr
		}
		frame, packet, receiveErr := receiveChildFrame(child, 3)
		if receiveErr != nil {
			return output{}, receiveErr
		}
		var drain f1t.DrainReportPayload
		if frame.Kind != f1t.KindDrain || frame.AdmissionState != "QUIESCED" || frame.ReleaseEpoch != 1 ||
			f1t.DecodeClosedPayload(frame.Payload, &drain) != nil || drain.Type != f1t.PayloadDrain ||
			drain.LastAdmitted != drain.LastEmitted || drain.InFlight != 0 || !drain.QueueEmpty {
			return output{}, f1t.ErrInvalidFrame
		}
		if err = appendAndAck(collector, child, collectorIdentity, frame, packet); err != nil {
			return output{}, err
		}
	}
	closure, err := collector.Seal()
	if err != nil {
		return output{}, err
	}
	if err = collector.Close(); err != nil {
		return output{}, err
	}
	terminations := make([]f1t.TerminationObservation, 0, len(children))
	for index := range children {
		child := &children[index]
		child.stopNS, err = f1t.RawMonotonicNanoseconds()
		if err != nil {
			return output{}, err
		}
		if err = child.endpoint.Close(); err != nil {
			return output{}, err
		}
	}
	for index := range children {
		child := &children[index]
		pidfdErr := f1t.WaitPIDFDExit(child.identity.PIDFD)
		waitErr := child.command.Wait()
		child.waited = true
		exitNS, clockErr := f1t.RawMonotonicNanoseconds()
		_ = child.identity.Close()
		if pidfdErr != nil || waitErr != nil || clockErr != nil {
			return output{}, errors.Join(pidfdErr, waitErr, clockErr)
		}
		terminations = append(terminations, f1t.TerminationObservation{Role: child.role, StopIntentNS: child.stopNS, PIDFDExitRawNS: exitNS})
	}
	return output{Schema: "DRWA_S1_F1T_PHASE_I_COMMAND_V1", Mode: "collector", Status: "OFFLINE_FULL_GUARDED_SEND_RECONCILIATION_REHEARSAL_PASS",
		PhaseIOnly: true, CollectorClosure: &closure, TransportClosure: &transportClosure, Terminations: terminations}, nil
}

func runTransportReconciliation(path string, identity f1t.ProcessIdentity) (f1t.CollectorClosure, error) {
	return runTransportReconciliationWithHooks(path, identity, transportReconciliationHooks{})
}

func runTransportReconciliationWithHooks(path string, identity f1t.ProcessIdentity, hooks transportReconciliationHooks) (f1t.CollectorClosure, error) {
	collector, err := f1t.CreateDurableCollectorWithHooks(path, hooks.Collector)
	if err != nil {
		return f1t.CollectorClosure{}, err
	}
	defer collector.Close()
	var sequencesMu sync.Mutex
	sequences := make(map[string]uint64)
	appendFrame := func(role string, kind f1t.Kind, state string, payloadForSequence func(uint64) (any, error)) error {
		sequencesMu.Lock()
		sequences[role]++
		sequence := sequences[role]
		sequencesMu.Unlock()
		payload, payloadErr := payloadForSequence(sequence)
		if payloadErr != nil {
			return payloadErr
		}
		encoded, digest, payloadErr := f1t.NewPayload(payload)
		if payloadErr != nil {
			return payloadErr
		}
		_, appendErr := collector.AppendFrom(role, f1t.Frame{SchemaVersion: f1t.SchemaVersion, SessionID: "phase-i-session",
			RunID: "phase-i-transport", Role: role, PIDStartID: identity.StartID, ExecutableHash: identity.ExecutableHash,
			SourceSequence: sequence, ReleaseEpoch: 1, Kind: kind, PayloadHash: digest, AdmissionState: state, Payload: encoded})
		return appendErr
	}
	targetRemoteKey := f1t.CallbackKey{Role: "target", Path: "pubsub"}
	passiveKey := f1t.CallbackKey{Role: "passive", Path: "pubsub"}
	targetSelfKey := f1t.CallbackKey{Role: "target", Path: "self-direct"}
	newReceiver := func(callback f1t.CallbackKey) *f1t.Recorder {
		return f1t.NewRecorderWithConfig(nil, f1t.RecorderConfig{Callback: callback,
			MessageIdentity: func(message p2p.MessageP2P) (string, error) {
				if message == nil || message.IsInterfaceNil() || len(message.Data()) == 0 {
					return "", f1t.ErrReconciliation
				}
				digest := sha256.Sum256(message.Data())
				return fmt.Sprintf("%x", digest[:]), nil
			},
			DurableEmit: func(event f1t.RecorderEvent) error {
				return appendFrame(callback.Role, f1t.KindEvent, "ADMITTED", func(sequence uint64) (any, error) {
					event.SourceSequence = sequence
					if hooks.MutateRemoteCallback != nil && callback == targetRemoteKey {
						hooks.MutateRemoteCallback(&event)
					}
					return f1t.CallbackEventPayload{Type: f1t.PayloadCallbackEvent, Event: event}, nil
				})
			},
		})
	}
	targetRemote := newReceiver(targetRemoteKey)
	passive := newReceiver(passiveKey)
	targetSelf := newReceiver(targetSelfKey)
	publisher := f1t.NewRecorder(nil)
	receivers := []*f1t.Recorder{targetRemote, passive, targetSelf}
	defer func() {
		_ = publisher.SealSends()
		_ = publisher.QuiesceAndDrain()
		for _, receiver := range receivers {
			_ = receiver.SealSends()
			_ = receiver.QuiesceAndDrain()
		}
	}()

	type declaredTransport struct {
		entry   f1t.SendCatalogEntry
		payload []byte
	}
	remoteTransports := make([]declaredTransport, 0, 4)
	for index, kind := range []string{"READINESS", "CALIBRATION", "SELECTED_SHAPED", "SENTINEL"} {
		payload, marshalErr := json.Marshal(transportPayload{Kind: kind, Index: uint64(index + 1)})
		if marshalErr != nil {
			return f1t.CollectorClosure{}, marshalErr
		}
		digest := sha256.Sum256(payload)
		entry := f1t.SendCatalogEntry{MessageID: fmt.Sprintf("%x", digest[:]), Kind: kind, Index: uint64(index + 1),
			Expected: []f1t.CallbackKey{targetRemoteKey, passiveKey}}
		if index == 0 && hooks.MutateRemoteCatalog != nil {
			hooks.MutateRemoteCatalog(&entry)
		}
		remoteTransports = append(remoteTransports, declaredTransport{entry: entry, payload: payload})
	}
	selfPayload, err := json.Marshal(transportPayload{Kind: "SELF_DIRECT", Index: 5})
	if err != nil {
		return f1t.CollectorClosure{}, err
	}
	selfDigest := sha256.Sum256(selfPayload)
	self := f1t.SendCatalogEntry{MessageID: fmt.Sprintf("%x", selfDigest[:]), Kind: "SELF_DIRECT", Index: 5,
		Expected: []f1t.CallbackKey{targetSelfKey}}
	for _, declared := range remoteTransports {
		for index, receiver := range []*f1t.Recorder{targetRemote, passive} {
			receiverEntry := declared.entry
			receiverEntry.Expected = []f1t.CallbackKey{declared.entry.Expected[index]}
			if err = receiver.RegisterExpected(receiverEntry); err != nil {
				return f1t.CollectorClosure{}, err
			}
		}
	}
	if err = targetSelf.RegisterExpected(self); err != nil {
		return f1t.CollectorClosure{}, err
	}
	journal := func(entry f1t.SendCatalogEntry) error {
		return appendFrame("publisher", f1t.KindEvent, "JOURNALED", func(uint64) (any, error) {
			return f1t.SendCatalogPayload{Type: f1t.PayloadSendCatalog, Entry: entry}, nil
		})
	}
	for index, declared := range remoteTransports {
		current := declared
		if err = publisher.GuardedSend(current.entry, journal, func() error {
			if hooks.BeforeRemoteSend != nil {
				hooks.BeforeRemoteSend()
			}
			payload := append([]byte(nil), current.payload...)
			if index == 0 && hooks.MutateRemotePayload != nil {
				payload = hooks.MutateRemotePayload(payload)
			}
			return libp2p.F1TProcessPubSub("/drwa/f1t", payload, targetRemote, passive)
		}); err != nil {
			return f1t.CollectorClosure{}, err
		}
	}
	if err = publisher.GuardedSend(self, journal, func() error {
		_, sendErr := libp2p.F1TProcessSelfDirect("/drwa/f1t", selfPayload, core.PeerID("target-peer"), targetSelf)
		return sendErr
	}); err != nil {
		return f1t.CollectorClosure{}, err
	}
	if err = publisher.SealSends(); err != nil {
		return f1t.CollectorClosure{}, err
	}
	for _, receiver := range receivers {
		if err = receiver.SealSends(); err != nil {
			return f1t.CollectorClosure{}, err
		}
		if err = receiver.QuiesceAndDrain(); err != nil {
			return f1t.CollectorClosure{}, err
		}
	}
	if err = publisher.QuiesceAndDrain(); err != nil {
		return f1t.CollectorClosure{}, err
	}
	return collector.Seal()
}

func receiveChildFrame(child *childProcess, expectedSequence uint64) (f1t.Frame, []byte, error) {
	frame, packet, err := child.endpoint.ReceiveFrame(child.identity)
	if err != nil {
		return f1t.Frame{}, nil, err
	}
	if frame.SourceSequence != expectedSequence || expectedSequence != child.childInbound+1 {
		return f1t.Frame{}, nil, f1t.ErrInvalidFrame
	}
	child.childInbound = expectedSequence
	return frame, packet, nil
}

func appendAndAck(collector *f1t.DurableCollector, child *childProcess, collectorIdentity f1t.ProcessIdentity, frame f1t.Frame, packet []byte) error {
	record, err := collector.AppendFrom(child.role, frame)
	if err != nil {
		return err
	}
	child.collectorOutbound++
	ack, err := f1t.MakeAck(frame, packet, record, "collector", collectorIdentity.StartID, collectorIdentity.ExecutableHash, child.collectorOutbound)
	if err != nil {
		return err
	}
	ackPacket, err := f1t.EncodeFrame(ack)
	if err != nil {
		return err
	}
	if _, err = collector.AppendFrom("collector/"+child.role, ack); err != nil {
		return err
	}
	return child.endpoint.Send(ackPacket)
}

func sendCollectorCommand(collector *f1t.DurableCollector, child *childProcess, collectorIdentity f1t.ProcessIdentity,
	sessionID, runID, command string, releaseEpoch uint64,
) (f1t.Frame, error) {
	payload, payloadHash, err := f1t.NewPayload(f1t.CommandIntentPayload{Type: f1t.PayloadCommand, Command: command})
	if err != nil {
		return f1t.Frame{}, err
	}
	child.collectorOutbound++
	frame := f1t.Frame{SchemaVersion: f1t.SchemaVersion, SessionID: sessionID, RunID: runID, Role: "collector",
		PIDStartID: collectorIdentity.StartID, ExecutableHash: collectorIdentity.ExecutableHash,
		SourceSequence: child.collectorOutbound, ReleaseEpoch: releaseEpoch, Kind: f1t.KindCommand,
		PayloadHash: payloadHash, AdmissionState: "INTENT", Payload: payload}
	packet, err := f1t.EncodeFrame(frame)
	if err != nil {
		return f1t.Frame{}, err
	}
	if _, err = collector.AppendFrom("collector/"+child.role, frame); err != nil {
		return f1t.Frame{}, err
	}
	if err = child.endpoint.Send(packet); err != nil {
		return f1t.Frame{}, err
	}
	return frame, nil
}
