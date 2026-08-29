//go:build drwa_s1_f1t_measure

package main

import (
	"bytes"
	"context"
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
	"time"

	"github.com/multiversx/mx-chain-communication-go/p2p"
	"github.com/multiversx/mx-chain-communication-go/p2p/libp2p"
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common/drwaqualification"
	"github.com/multiversx/mx-chain-go/common/drwaqualification/f1t"
)

const phaseIEnvironment = "DRWA_F1T_PHASE_I_OFFLINE_ONLY"
const phaseIFailRoleEnvironment = "DRWA_F1T_PHASE_I_INJECT_CHILD_FAILURE_ROLE"
const phaseIIEnvironment = "DRWA_F1T_PHASE_II_INTERCEPTED_REHEARSAL_ONLY"
const phaseIICampaignEnvironment = "DRWA_F1T_PHASE_II_CAMPAIGN_EXECUTION"

type output struct {
	Schema                string                       `json:"schema"`
	Mode                  string                       `json:"mode"`
	Status                string                       `json:"status"`
	RuntimeCredit         int                          `json:"authoritative_runtime_credit"`
	PhaseIOnly            bool                         `json:"phase_i_only"`
	PhaseIISubmission     bool                         `json:"phase_ii_submission"`
	ProtocolSubmission    bool                         `json:"protocol_submission"`
	NumericRatification   bool                         `json:"numeric_ratification"`
	CollectorClosure      *f1t.CollectorClosure        `json:"collector_closure,omitempty"`
	TransportClosure      *f1t.CollectorClosure        `json:"transport_reconciliation_closure,omitempty"`
	Terminations          []f1t.TerminationObservation `json:"terminations,omitempty"`
	CampaignContextSHA256 string                       `json:"campaign_context_sha256,omitempty"`
	PipelineObservations  int                          `json:"pipeline_observations,omitempty"`
	PopulationDisposition string                       `json:"population_validation_disposition,omitempty"`
	AttemptClaimPath      string                       `json:"attempt_claim_path,omitempty"`
	EvidenceSHA256        string                       `json:"campaign_evidence_sha256,omitempty"`
	CandidatesSHA256      string                       `json:"candidate_values_sha256,omitempty"`
	RejectionSHA256       string                       `json:"campaign_rejection_sha256,omitempty"`
	Candidates            *f1t.Candidates              `json:"candidates,omitempty"`
}

type preflightFactsOutput struct {
	Schema                          string `json:"schema"`
	Status                          string `json:"status"`
	CampaignExecutableSHA256        string `json:"campaign_executable_sha256"`
	ModuleGraphSHA256               string `json:"module_graph_sha256"`
	HostKernelCPUStorageFactsSHA256 string `json:"host_kernel_cpu_storage_facts_sha256"`
	PopulationManifestSHA256        string `json:"exact_population_manifest_sha256"`
	RuntimeCredit                   int    `json:"authoritative_runtime_credit"`
}

type options struct {
	mode                   string
	channelFD              int
	collectorPID           int
	sessionID              string
	runID                  string
	rehearsalRoot          string
	trustedRoot            string
	campaignIdentityPath   string
	campaignIdentitySHA256 string
	profileCatalogPath     string
	fixtureCatalogPath     string
	ownerAuthorizationPath string
	expectedSourceCommit   string
	campaignContextSHA256  string
	factsOnly              bool
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
	phaseI := os.Getenv(phaseIEnvironment) == "1"
	phaseII := os.Getenv(phaseIIEnvironment) == "1"
	phaseIICampaign := os.Getenv(phaseIICampaignEnvironment) == "1"
	if boolCount(phaseI, phaseII, phaseIICampaign) != 1 {
		return errors.New("exactly one F1-T execution environment must be enabled")
	}
	if !libp2p.F1TDirectAdmissionEnabled() {
		return errors.New("F1-T tagged direct-admission seam not linked")
	}
	drwaqualification.RegisterVariant(drwaqualification.VariantF1T)
	if drwaqualification.ActiveVariant() != drwaqualification.VariantF1T || f1t.ConditionalWilksCoverage() < 0.99 {
		return errors.New("F1-T qualification precondition failed")
	}
	if parsed.channelFD >= 0 {
		if childErr := runChild(parsed); childErr != nil {
			return fmt.Errorf("child %s: %w", parsed.mode, childErr)
		}
		return nil
	}
	if parsed.factsOnly && !phaseII {
		return errors.New("preflight facts require the Phase-II offline environment")
	}
	if phaseII && parsed.factsOnly {
		_, executableHash, factsErr := f1t.ExecutableIdentity(os.Getpid())
		if factsErr != nil {
			return factsErr
		}
		moduleGraph, factsErr := f1t.ModuleGraphSHA256()
		if factsErr != nil {
			return factsErr
		}
		hostFacts, factsErr := f1t.HostFactsSHA256(parsed.trustedRoot)
		if factsErr != nil {
			return factsErr
		}
		return json.NewEncoder(writer).Encode(preflightFactsOutput{
			Schema: "DRWA_S1_F1T_PHASE_II_PREFLIGHT_FACTS_V1", Status: "OBSERVED_OFFLINE_NO_CAMPAIGN_NO_CREDIT",
			CampaignExecutableSHA256: executableHash, ModuleGraphSHA256: moduleGraph,
			HostKernelCPUStorageFactsSHA256: hostFacts, PopulationManifestSHA256: f1t.PopulationManifestSHA256(),
		})
	}
	var verifiedPreflight *f1t.CampaignPreflight
	if phaseII || phaseIICampaign {
		preflight, preflightErr := f1t.VerifyCampaignPreflight(f1t.CampaignPreflightInput{
			TrustedRoot: parsed.trustedRoot, CampaignIdentityPath: parsed.campaignIdentityPath,
			CampaignIdentitySHA256: parsed.campaignIdentitySHA256, ProfileCatalogPath: parsed.profileCatalogPath,
			FixtureCatalogPath: parsed.fixtureCatalogPath, OwnerAuthorizationPath: parsed.ownerAuthorizationPath,
			ExpectedSourceCommit: parsed.expectedSourceCommit, CampaignExecution: phaseIICampaign,
		})
		if preflightErr != nil {
			return fmt.Errorf("Phase-II preflight: %w", preflightErr)
		}
		parsed.campaignContextSHA256 = preflight.ContextSHA256
		verifiedPreflight = &preflight
	}
	if parsed.mode == "collector" && parsed.rehearsalRoot != "" {
		result, runErr := runInterceptedRehearsal(parsed, verifiedPreflight)
		if runErr != nil {
			return runErr
		}
		return json.NewEncoder(writer).Encode(result)
	}
	result := output{Schema: "DRWA_S1_F1T_PHASE_I_COMMAND_V1", Mode: parsed.mode,
		Status: "OFFLINE_IMPLEMENTATION_VERIFICATION_ONLY_NO_CAMPAIGN", PhaseIOnly: true}
	return json.NewEncoder(writer).Encode(result)
}

func boolCount(values ...bool) int {
	count := 0
	for _, value := range values {
		if value {
			count++
		}
	}
	return count
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
	flags.StringVar(&parsed.trustedRoot, "trusted-root", "", "trusted workspace realpath")
	flags.StringVar(&parsed.campaignIdentityPath, "campaign-identity", "", "bound campaign identity")
	flags.StringVar(&parsed.campaignIdentitySHA256, "campaign-identity-sha256", "", "campaign identity file digest")
	flags.StringVar(&parsed.profileCatalogPath, "profile-catalog", "", "bound profile catalog")
	flags.StringVar(&parsed.fixtureCatalogPath, "fixture-catalog", "", "bound fixture catalog")
	flags.StringVar(&parsed.ownerAuthorizationPath, "owner-authorization", "", "bound owner authorization")
	flags.StringVar(&parsed.expectedSourceCommit, "source-commit", "", "bound source commit")
	flags.StringVar(&parsed.campaignContextSHA256, "campaign-context-sha256", "", "inherited Phase-II campaign context")
	flags.BoolVar(&parsed.factsOnly, "preflight-facts-only", false, "emit observed Phase-II identity facts without a campaign")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return options{}, errors.New("invalid arguments")
	}
	if parsed.mode != "collector" && parsed.mode != "publisher" && parsed.mode != "target" && parsed.mode != "passive" {
		return options{}, errors.New("invalid F1-T role")
	}
	if parsed.channelFD >= 0 && (parsed.mode == "collector" || parsed.collectorPID <= 0 || parsed.sessionID == "" || parsed.runID == "" || parsed.rehearsalRoot != "") {
		return options{}, errors.New("invalid child role arguments")
	}
	if parsed.channelFD < 0 && parsed.campaignContextSHA256 != "" {
		return options{}, errors.New("parent campaign context is derived, not supplied")
	}
	if parsed.factsOnly && (parsed.channelFD >= 0 || parsed.mode != "collector" || parsed.trustedRoot == "" ||
		parsed.rehearsalRoot != "" || parsed.campaignIdentityPath != "" || parsed.profileCatalogPath != "" ||
		parsed.fixtureCatalogPath != "" || parsed.ownerAuthorizationPath != "" || parsed.expectedSourceCommit != "") {
		return options{}, errors.New("invalid preflight-facts-only arguments")
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
	payload, payloadHash, err := f1t.NewPayload(f1t.RoleReadyPayload{Type: f1t.PayloadRoleReady, Phase: "INTERCEPTED_REHEARSAL", Role: parsed.mode,
		CampaignContextSHA256: parsed.campaignContextSHA256})
	if err != nil {
		return err
	}
	frame := f1t.Frame{SchemaVersion: frameSchema(parsed.campaignContextSHA256), CampaignContextSHA256: parsed.campaignContextSHA256,
		SessionID: parsed.sessionID, RunID: parsed.runID,
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
		Command: "RELEASE", CommandSourceSequence: releaseCommand.SourceSequence, CampaignContextSHA256: parsed.campaignContextSHA256})
	if err != nil {
		return err
	}
	roleAck := f1t.Frame{SchemaVersion: frameSchema(parsed.campaignContextSHA256), CampaignContextSHA256: parsed.campaignContextSHA256,
		SessionID: parsed.sessionID, RunID: parsed.runID,
		Role: parsed.mode, PIDStartID: self.StartID, ExecutableHash: self.ExecutableHash, SourceSequence: 2,
		ReleaseEpoch: 1, Kind: f1t.KindEvent, PayloadHash: ackHash, AdmissionState: "APPLIED", Payload: ackPayload}
	if err = sendChildFrameAndAwaitAck(endpoint, collector, roleAck, 3); err != nil {
		return err
	}
	collectorSequence := uint64(4)
	childSequence := uint64(3)
	for {
		incoming, _, receiveErr := endpoint.ReceiveFrame(collector)
		if receiveErr != nil || incoming.SourceSequence != collectorSequence || incoming.ReleaseEpoch != 1 ||
			incoming.Kind != f1t.KindCommand || incoming.AdmissionState != "INTENT" {
			return errors.Join(f1t.ErrInvalidFrame, receiveErr)
		}
		var action f1t.CampaignActionPayload
		if f1t.DecodeClosedPayload(incoming.Payload, &action) == nil && action.Type == f1t.PayloadAction {
			ackPayload, ackHash, payloadErr := f1t.NewPayload(f1t.CampaignActionAckPayload{Type: f1t.PayloadAction,
				Kind: action.Kind, Profile: action.Profile, Path: action.Path, Load: action.Load, Index: action.Index,
				ActionIndex: action.ActionIndex, FixtureSHA256: action.FixtureSHA256, MessageID: action.MessageID, CommandSourceSequence: incoming.SourceSequence,
				CampaignContextSHA256: parsed.campaignContextSHA256})
			if payloadErr != nil {
				return payloadErr
			}
			ackFrame := f1t.Frame{SchemaVersion: frameSchema(parsed.campaignContextSHA256), CampaignContextSHA256: parsed.campaignContextSHA256,
				SessionID: parsed.sessionID, RunID: parsed.runID, Role: parsed.mode, PIDStartID: self.StartID,
				ExecutableHash: self.ExecutableHash, SourceSequence: childSequence, ReleaseEpoch: 1, Kind: f1t.KindEvent,
				PayloadHash: ackHash, AdmissionState: "OBSERVED", Payload: ackPayload}
			if err = sendChildFrameAndAwaitAck(endpoint, collector, ackFrame, collectorSequence+1); err != nil {
				return err
			}
			collectorSequence += 2
			childSequence++
			continue
		}
		var quiesce f1t.CommandIntentPayload
		if f1t.DecodeClosedPayload(incoming.Payload, &quiesce) != nil || quiesce.Type != f1t.PayloadCommand || quiesce.Command != "QUIESCE" {
			return f1t.ErrInvalidFrame
		}
		collectorSequence++
		break
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
		LastAdmitted: admitted, LastEmitted: emitted, InFlight: inFlight, QueueEmpty: true,
		CampaignContextSHA256: parsed.campaignContextSHA256})
	if err != nil {
		return err
	}
	drain := f1t.Frame{SchemaVersion: frameSchema(parsed.campaignContextSHA256), CampaignContextSHA256: parsed.campaignContextSHA256,
		SessionID: parsed.sessionID, RunID: parsed.runID,
		Role: parsed.mode, PIDStartID: self.StartID, ExecutableHash: self.ExecutableHash, SourceSequence: childSequence,
		ReleaseEpoch: 1, Kind: f1t.KindDrain, PayloadHash: drainHash, AdmissionState: "QUIESCED", Payload: drainPayload}
	if err = sendChildFrameAndAwaitAck(endpoint, collector, drain, collectorSequence); err != nil {
		return err
	}
	return endpoint.WaitForPeerClose()
}

func frameSchema(contextDigest string) string {
	if contextDigest == "" {
		return f1t.SchemaVersion
	}
	return f1t.PhaseIISchemaVersion
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
	stderr            *bytes.Buffer
}

type interceptedCampaignObserver struct {
	collector     *f1t.DurableCollector
	transportLog  *f1t.DurableCollector
	children      map[string]*childProcess
	identity      f1t.ProcessIdentity
	sessionID     string
	runID         string
	contextDigest string
	transport     *libp2p.F1TPersistentTransport
	publisher     *f1t.Recorder
	targetRemote  *f1t.Recorder
	targetSelf    *f1t.Recorder
	passive       *f1t.Recorder
	mut           sync.Mutex
	sequences     map[string]uint64
	actions       map[string]f1t.CampaignActionPayload
	receipts      map[string]map[f1t.Path]uint64
}

type targetPathProcessor struct {
	remote *f1t.Recorder
	self   *f1t.Recorder
}

func (processor *targetPathProcessor) ProcessReceivedMessage(message p2p.MessageP2P, peer core.PeerID, handler p2p.MessageHandler) ([]byte, error) {
	if processor == nil || message == nil || message.IsInterfaceNil() {
		return nil, f1t.ErrReconciliation
	}
	if message.BroadcastMethod() == p2p.Direct {
		return processor.self.ProcessReceivedMessage(message, peer, handler)
	}
	return processor.remote.ProcessReceivedMessage(message, peer, handler)
}

func (processor *targetPathProcessor) IsInterfaceNil() bool             { return processor == nil }
func (processor *targetPathProcessor) IsDRWAS1F1TDirectAdmission() bool { return true }

func newInterceptedCampaignObserver(root string, collector *f1t.DurableCollector, children map[string]*childProcess,
	identity f1t.ProcessIdentity, sessionID, runID, contextDigest string,
) (*interceptedCampaignObserver, error) {
	transportLog, err := f1t.CreateDurableCollectorForCampaign(filepath.Join(root, "f1t-phase-ii-transport.jsonl"), contextDigest, f1t.CollectorHooks{})
	if err != nil {
		return nil, err
	}
	observer := &interceptedCampaignObserver{collector: collector, transportLog: transportLog, children: children, identity: identity,
		sessionID: sessionID, runID: runID, contextDigest: contextDigest, sequences: make(map[string]uint64),
		actions: make(map[string]f1t.CampaignActionPayload), receipts: make(map[string]map[f1t.Path]uint64)}
	messageIdentity := func(message p2p.MessageP2P) (string, error) {
		if message == nil || message.IsInterfaceNil() {
			return "", f1t.ErrReconciliation
		}
		_, messageID, decodeErr := f1t.DecodeMeasurementEnvelope(message.Data())
		return messageID, decodeErr
	}
	newReceiver := func(callback f1t.CallbackKey) *f1t.Recorder {
		return f1t.NewRecorderWithConfig(nil, f1t.RecorderConfig{Callback: callback, CampaignContextSHA256: contextDigest,
			MessageIdentity: messageIdentity, DurableEmit: observer.emitCallback})
	}
	observer.targetRemote = newReceiver(f1t.CallbackKey{Role: "target", Path: "pubsub"})
	observer.passive = newReceiver(f1t.CallbackKey{Role: "passive", Path: "pubsub"})
	observer.targetSelf = newReceiver(f1t.CallbackKey{Role: "target", Path: "self-direct"})
	observer.publisher = f1t.NewRecorderWithConfig(nil, f1t.RecorderConfig{CampaignContextSHA256: contextDigest})
	for _, recorder := range []*f1t.Recorder{observer.targetRemote, observer.passive, observer.targetSelf, observer.publisher} {
		if err = recorder.SetReleaseEpoch(1); err != nil {
			_ = transportLog.Close()
			return nil, err
		}
	}
	observer.transport, err = libp2p.NewF1TPersistentTransport("/drwa/f1t", &targetPathProcessor{remote: observer.targetRemote, self: observer.targetSelf}, observer.passive)
	if err != nil {
		_ = transportLog.Close()
		return nil, err
	}
	return observer, nil
}

func (observer *interceptedCampaignObserver) Observe(action f1t.CampaignActionPayload, raw []byte, selection f1t.Selection) (uint64, []f1t.PathReceipt, error) {
	if observer == nil || fmt.Sprintf("%x", sha256.Sum256(raw)) != action.FixtureSHA256 || selection.PredicateEvidenceStatus != "OBSERVED_STRUCTURED_SUCCESSOR" ||
		selection.Profile != action.Profile || selection.MessageID == "" {
		return 0, nil, f1t.ErrReconciliation
	}
	envelope, messageID, err := f1t.EncodeMeasurementEnvelope(action, raw)
	if err != nil {
		return 0, nil, err
	}
	action.MessageID = messageID
	entry := f1t.SendCatalogEntry{MessageID: messageID, Kind: observationSendKind(action.Kind), Index: action.Index,
		Expected:              []f1t.CallbackKey{{Role: "target", Path: "pubsub"}, {Role: "passive", Path: "pubsub"}, {Role: "target", Path: "self-direct"}},
		CampaignContextSHA256: observer.contextDigest}
	for _, recorder := range []*f1t.Recorder{observer.targetRemote, observer.passive, observer.targetSelf} {
		if err = recorder.RegisterExpected(entry); err != nil {
			return 0, nil, err
		}
	}
	observer.mut.Lock()
	observer.actions[messageID] = action
	observer.receipts[messageID] = make(map[f1t.Path]uint64)
	observer.mut.Unlock()
	intent, err := f1t.RawMonotonicNanoseconds()
	if err != nil {
		return 0, nil, err
	}
	publisherAction := action
	publisherAction.Path = f1t.PathRemoteTarget
	if err = sendCampaignAction(observer.collector, observer.children["publisher"], observer.identity, observer.sessionID, observer.runID, publisherAction, observer.contextDigest); err != nil {
		return 0, nil, fmt.Errorf("publisher action %s/%s/%d: %w", action.Profile, action.Load, action.Index, err)
	}
	if err = observer.publisher.GuardedSend(entry, observer.appendCatalog, func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return observer.transport.SendAll(ctx, envelope)
	}); err != nil {
		return 0, nil, err
	}
	observer.mut.Lock()
	observed := observer.receipts[messageID]
	delete(observer.actions, messageID)
	delete(observer.receipts, messageID)
	observer.mut.Unlock()
	receipts := make([]f1t.PathReceipt, 0, 3)
	for _, path := range f1t.Paths() {
		durable, exists := observed[path]
		if !exists || durable < intent {
			return 0, nil, f1t.ErrReconciliation
		}
		receipts = append(receipts, f1t.PathReceipt{Path: path, DurableAckNS: durable})
	}
	return intent, receipts, nil
}

func observationSendKind(kind f1t.ObservationKind) string {
	switch kind {
	case f1t.ObservationReadiness:
		return "READINESS"
	case f1t.ObservationSelectedShape:
		return "SELECTED_SHAPED"
	case f1t.ObservationSentinel:
		return "SENTINEL"
	default:
		return "CALIBRATION"
	}
}

func (observer *interceptedCampaignObserver) appendCatalog(entry f1t.SendCatalogEntry) error {
	payload := f1t.SendCatalogPayload{Type: f1t.PayloadSendCatalog, Entry: entry, CampaignContextSHA256: observer.contextDigest}
	_, err := observer.appendTransportFrame("publisher", f1t.KindEvent, "JOURNALED", payload)
	return err
}

func (observer *interceptedCampaignObserver) emitCallback(event f1t.RecorderEvent) error {
	observer.mut.Lock()
	action, exists := observer.actions[event.MessageID]
	observer.mut.Unlock()
	if !exists {
		return f1t.ErrReconciliation
	}
	role := event.Callback.Role
	switch event.Callback {
	case (f1t.CallbackKey{Role: "target", Path: "pubsub"}):
		action.Path = f1t.PathRemoteTarget
	case (f1t.CallbackKey{Role: "passive", Path: "pubsub"}):
		action.Path = f1t.PathRemotePassive
	case (f1t.CallbackKey{Role: "target", Path: "self-direct"}):
		action.Path = f1t.PathSelfDirect
	default:
		return f1t.ErrReconciliation
	}
	if err := sendCampaignAction(observer.collector, observer.children[role], observer.identity, observer.sessionID, observer.runID, action, observer.contextDigest); err != nil {
		return err
	}
	record, err := observer.appendTransportFrame(role, f1t.KindEvent, "ADMITTED", f1t.CallbackEventPayload{
		Type: f1t.PayloadCallbackEvent, Event: event, CampaignContextSHA256: observer.contextDigest})
	if err != nil {
		return err
	}
	observer.mut.Lock()
	if _, duplicate := observer.receipts[event.MessageID][action.Path]; duplicate {
		observer.mut.Unlock()
		return f1t.ErrDuplicateObservation
	}
	observer.receipts[event.MessageID][action.Path] = record.TimestampRawNS
	observer.mut.Unlock()
	return nil
}

func (observer *interceptedCampaignObserver) appendTransportFrame(role string, kind f1t.Kind, state string, value any) (f1t.CollectorRecord, error) {
	observer.mut.Lock()
	observer.sequences[role]++
	sequence := observer.sequences[role]
	observer.mut.Unlock()
	payload, payloadHash, err := f1t.NewPayload(value)
	if err != nil {
		return f1t.CollectorRecord{}, err
	}
	return observer.transportLog.AppendFrom(role, f1t.Frame{SchemaVersion: f1t.PhaseIISchemaVersion,
		CampaignContextSHA256: observer.contextDigest, SessionID: observer.sessionID, RunID: observer.runID,
		Role: role, PIDStartID: observer.identity.StartID, ExecutableHash: observer.identity.ExecutableHash,
		SourceSequence: sequence, ReleaseEpoch: 1, Kind: kind, PayloadHash: payloadHash, AdmissionState: state, Payload: payload})
}

func (observer *interceptedCampaignObserver) Close() (f1t.CollectorClosure, error) {
	if observer == nil {
		return f1t.CollectorClosure{}, f1t.ErrReconciliation
	}
	var err error
	for _, recorder := range []*f1t.Recorder{observer.publisher, observer.targetRemote, observer.passive, observer.targetSelf} {
		err = errors.Join(err, recorder.SealSends())
		err = errors.Join(err, recorder.QuiesceAndDrain())
	}
	err = errors.Join(err, observer.transport.Close())
	if err != nil {
		return f1t.CollectorClosure{}, err
	}
	closure, err := observer.transportLog.Seal()
	return closure, errors.Join(err, observer.transportLog.Close())
}

func runInterceptedRehearsal(parsed options, preflight *f1t.CampaignPreflight) (output, error) {
	root, err := filepath.Abs(parsed.rehearsalRoot)
	if err != nil || root != parsed.rehearsalRoot || filepath.Clean(root) != root {
		return output{}, errors.New("rehearsal root must be clean absolute")
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return output{}, errors.New("rehearsal root unavailable")
	}
	campaignExecution := os.Getenv(phaseIICampaignEnvironment) == "1"
	attemptClaimPath := ""
	if campaignExecution {
		if preflight == nil {
			return output{}, f1t.ErrPreflight
		}
		attemptClaimPath, err = f1t.ClaimCampaignAttempt(root, *preflight)
		if err != nil {
			return output{}, fmt.Errorf("consume Phase-II campaign authorization: %w", err)
		}
	}
	collectorPath := filepath.Join(root, "f1t-phase-i-rehearsal.jsonl")
	var collector *f1t.DurableCollector
	if parsed.campaignContextSHA256 == "" {
		collector, err = f1t.CreateDurableCollector(collectorPath)
	} else {
		collectorPath = filepath.Join(root, "f1t-phase-ii-rehearsal.jsonl")
		collector, err = f1t.CreateDurableCollectorForCampaign(collectorPath, parsed.campaignContextSHA256, f1t.CollectorHooks{})
	}
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
			"--session-id="+sessionID, "--run-id="+runID, "--campaign-context-sha256="+parsed.campaignContextSHA256)
		offlineEnvironment := phaseIEnvironment + "=1"
		if parsed.campaignContextSHA256 != "" {
			offlineEnvironment = phaseIIEnvironment + "=1"
			if campaignExecution {
				offlineEnvironment = phaseIICampaignEnvironment + "=1"
			}
		}
		command.Env = append(os.Environ(), offlineEnvironment)
		childStderr := &bytes.Buffer{}
		command.Stderr = childStderr
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
		children = append(children, childProcess{role: role, endpoint: parentEndpoint, command: command, identity: identity, stderr: childStderr})
	}
	collectorIdentity, err := f1t.CaptureProcessIdentity(os.Getpid(), "collector", false)
	if err != nil {
		return output{}, err
	}
	for index := range children {
		child := &children[index]
		frame, packet, receiveErr := receiveChildFrame(child, 1)
		if receiveErr != nil {
			return output{}, fmt.Errorf("ready receive %s: %w", child.role, receiveErr)
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
	var pipelineObservations []f1t.Observation
	var transportClosure f1t.CollectorClosure
	if parsed.campaignContextSHA256 == "" {
		transportClosure, err = runTransportReconciliationForCampaign(filepath.Join(root, "f1t-phase-i-transport-reconciliation.jsonl"),
			collectorIdentity, "", transportReconciliationHooks{})
		if err != nil {
			return output{}, err
		}
	}
	for index := range children {
		child := &children[index]
		command, commandErr := sendCollectorCommand(collector, child, collectorIdentity, sessionID, runID, "RELEASE", 1, parsed.campaignContextSHA256)
		if commandErr != nil {
			return output{}, commandErr
		}
		frame, packet, receiveErr := receiveChildFrame(child, 2)
		if receiveErr != nil {
			return output{}, fmt.Errorf("release acknowledgement receive %s: %w", child.role, receiveErr)
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
	if parsed.campaignContextSHA256 != "" {
		if preflight == nil || preflight.ContextSHA256 != parsed.campaignContextSHA256 {
			return output{}, f1t.ErrCampaignIdentity
		}
		childByRole := make(map[string]*childProcess, len(children))
		for index := range children {
			childByRole[children[index].role] = &children[index]
		}
		observer, observerErr := newInterceptedCampaignObserver(root, collector, childByRole, collectorIdentity,
			sessionID, runID, parsed.campaignContextSHA256)
		if observerErr != nil {
			return output{}, observerErr
		}
		samples := 1
		if campaignExecution {
			samples = f1t.SamplesPerProfilePathLoad
		}
		pipelineObservations, err = f1t.ExecuteCampaignActions(context.Background(), f1t.CampaignPipelineInput{
			Preflight: *preflight, Root: root, Samples: samples,
			LoadConfig: f1t.LoadConfig{CPUWorkers: 1, SchedulerWorkers: 2, GCRingEntries: 2, GCEntryBytes: 1024,
				FsyncBlocks: 2, FsyncBlockBytes: 4096}, Observer: observer,
		})
		if err != nil {
			_, _ = observer.Close()
			return output{}, fmt.Errorf("Phase-II pipeline rehearsal: %w", err)
		}
		transportClosure, err = observer.Close()
		if err != nil {
			return output{}, err
		}
	}
	for index := range children {
		child := &children[index]
		_, commandErr := sendCollectorCommand(collector, child, collectorIdentity, sessionID, runID, "QUIESCE", 1, parsed.campaignContextSHA256)
		if commandErr != nil {
			return output{}, commandErr
		}
		frame, packet, receiveErr := receiveChildFrame(child, child.childInbound+1)
		if receiveErr != nil {
			return output{}, fmt.Errorf("drain receive %s: %w", child.role, receiveErr)
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
	terminations := make([]f1t.TerminationObservation, len(children))
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
	type terminationResult struct {
		index int
		exit  uint64
		err   error
	}
	terminationResults := make(chan terminationResult, len(children))
	for index := range children {
		go func(index int) {
			child := &children[index]
			pidfdErr := f1t.WaitPIDFDExit(child.identity.PIDFD)
			waitErr := child.command.Wait()
			exitNS, clockErr := f1t.RawMonotonicNanoseconds()
			if waitErr != nil {
				waitErr = fmt.Errorf("%w: child %s stderr: %s", waitErr, child.role, child.stderr.String())
			}
			terminationResults <- terminationResult{index: index, exit: exitNS, err: errors.Join(pidfdErr, waitErr, clockErr)}
		}(index)
	}
	for range children {
		termination := <-terminationResults
		child := &children[termination.index]
		child.waited = true
		_ = child.identity.Close()
		if termination.err != nil {
			return output{}, termination.err
		}
		terminations[termination.index] = f1t.TerminationObservation{Role: child.role, StopIntentNS: child.stopNS, PIDFDExitRawNS: termination.exit}
	}
	result := output{Schema: "DRWA_S1_F1T_PHASE_I_COMMAND_V1", Mode: "collector", Status: "OFFLINE_FULL_GUARDED_SEND_RECONCILIATION_REHEARSAL_PASS",
		PhaseIOnly: true, CollectorClosure: &closure, TransportClosure: &transportClosure, Terminations: terminations}
	if parsed.campaignContextSHA256 != "" {
		result.Schema = "DRWA_S1_F1T_PHASE_II_INTERCEPTED_REHEARSAL_V1"
		result.Status = "OFFLINE_PHASE_II_FULL_PATH_REHEARSAL_PASS_NO_CAMPAIGN_NO_CREDIT"
		result.PhaseIOnly = false
		result.CampaignContextSHA256 = parsed.campaignContextSHA256
		result.PipelineObservations = len(pipelineObservations)
		if campaignExecution {
			evidence := f1t.CampaignEvidence{Observations: pipelineObservations, Terminations: terminations}
			candidates, validationErr := f1t.ValidateAndDerive(evidence)
			evidenceSHA, writeErr := writeExclusiveJSON(root, "f1t-phase-ii-campaign-evidence.json", struct {
				Schema                string               `json:"schema"`
				Status                string               `json:"status"`
				CampaignContextSHA256 string               `json:"campaign_context_sha256"`
				Evidence              f1t.CampaignEvidence `json:"evidence"`
			}{"DRWA_S1_F1T_PHASE_II_CAMPAIGN_EVIDENCE_V1", "PRESERVED_COMPLETE_ATTEMPT", parsed.campaignContextSHA256, evidence})
			if writeErr != nil {
				return output{}, writeErr
			}
			result.Schema = "DRWA_S1_F1T_PHASE_II_CAMPAIGN_RESULT_V1"
			result.Status = "PHASE_II_MEASUREMENT_COMPLETE_NUMERIC_RATIFICATION_REQUIRED_NO_RUNTIME_CREDIT"
			result.PhaseIISubmission = true
			result.AttemptClaimPath = attemptClaimPath
			result.EvidenceSHA256 = evidenceSHA
			if validationErr != nil {
				rejectionSHA, rejectionErr := writeExclusiveJSON(root, "f1t-phase-ii-rejection.json", struct {
					Schema                string                `json:"schema"`
					Status                string                `json:"status"`
					CampaignContextSHA256 string                `json:"campaign_context_sha256"`
					Diagnostics           f1t.DiagnosticsReport `json:"diagnostics"`
					NumericCandidates     []any                 `json:"numeric_candidates"`
					RuntimeCredit         int                   `json:"authoritative_runtime_credit"`
				}{"DRWA_S1_F1T_PHASE_II_CAMPAIGN_REJECTION_V1", "INVALIDATED_NO_NUMERIC_CANDIDATES", parsed.campaignContextSHA256,
					candidates.Diagnostics, []any{}, 0})
				if rejectionErr != nil {
					return output{}, rejectionErr
				}
				result.RejectionSHA256 = rejectionSHA
				result.Status = "PHASE_II_MEASUREMENT_INVALIDATED_NO_NUMERIC_CANDIDATES_NO_RUNTIME_CREDIT"
				return result, validationErr
			}
			candidateSHA, writeErr := writeExclusiveJSON(root, "f1t-phase-ii-candidates.json", candidates)
			if writeErr != nil {
				return output{}, writeErr
			}
			result.CandidatesSHA256 = candidateSHA
			result.Candidates = &candidates
			result.PopulationDisposition = "EXACT_COMPLETE_POPULATION_AND_DIAGNOSTICS_PASS"
		} else {
			_, validationErr := f1t.ValidateAndDerive(f1t.CampaignEvidence{Observations: pipelineObservations, Terminations: terminations})
			if !errors.Is(validationErr, f1t.ErrPopulationIncomplete) {
				return output{}, errors.New("intercepted rehearsal did not reach the expected incomplete-population gate")
			}
			result.PopulationDisposition = "EXPECTED_INCOMPLETE_REHEARSAL_POPULATION_REJECTED_BY_VALIDATE_AND_DERIVE"
		}
	}
	return result, nil
}

func writeExclusiveJSON(root, name string, value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	raw = append(raw, '\n')
	path := filepath.Join(root, name)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	written, writeErr := file.Write(raw)
	if writeErr == nil && written != len(raw) {
		writeErr = io.ErrShortWrite
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	directory, openErr := os.Open(root)
	var dirSyncErr, dirCloseErr error
	if openErr == nil {
		dirSyncErr = directory.Sync()
		dirCloseErr = directory.Close()
	}
	if err = errors.Join(writeErr, syncErr, closeErr, openErr, dirSyncErr, dirCloseErr); err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return fmt.Sprintf("%x", sum[:]), nil
}

func runTransportReconciliation(path string, identity f1t.ProcessIdentity) (f1t.CollectorClosure, error) {
	return runTransportReconciliationForCampaign(path, identity, "", transportReconciliationHooks{})
}

func runTransportReconciliationWithHooks(path string, identity f1t.ProcessIdentity, hooks transportReconciliationHooks) (f1t.CollectorClosure, error) {
	return runTransportReconciliationForCampaign(path, identity, "", hooks)
}

func runTransportReconciliationForCampaign(path string, identity f1t.ProcessIdentity, campaignContext string, hooks transportReconciliationHooks) (f1t.CollectorClosure, error) {
	var collector *f1t.DurableCollector
	var err error
	if campaignContext == "" {
		collector, err = f1t.CreateDurableCollectorWithHooks(path, hooks.Collector)
	} else {
		collector, err = f1t.CreateDurableCollectorForCampaign(path, campaignContext, hooks.Collector)
	}
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
		_, appendErr := collector.AppendFrom(role, f1t.Frame{SchemaVersion: frameSchema(campaignContext), CampaignContextSHA256: campaignContext,
			SessionID: "phase-i-session",
			RunID:     "phase-i-transport", Role: role, PIDStartID: identity.StartID, ExecutableHash: identity.ExecutableHash,
			SourceSequence: sequence, ReleaseEpoch: 1, Kind: kind, PayloadHash: digest, AdmissionState: state, Payload: encoded})
		return appendErr
	}
	targetRemoteKey := f1t.CallbackKey{Role: "target", Path: "pubsub"}
	passiveKey := f1t.CallbackKey{Role: "passive", Path: "pubsub"}
	targetSelfKey := f1t.CallbackKey{Role: "target", Path: "self-direct"}
	newReceiver := func(callback f1t.CallbackKey) *f1t.Recorder {
		return f1t.NewRecorderWithConfig(nil, f1t.RecorderConfig{Callback: callback, CampaignContextSHA256: campaignContext,
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
					return f1t.CallbackEventPayload{Type: f1t.PayloadCallbackEvent, Event: event,
						CampaignContextSHA256: campaignContext}, nil
				})
			},
		})
	}
	targetRemote := newReceiver(targetRemoteKey)
	passive := newReceiver(passiveKey)
	targetSelf := newReceiver(targetSelfKey)
	publisher := f1t.NewRecorderWithConfig(nil, f1t.RecorderConfig{CampaignContextSHA256: campaignContext})
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
			Expected: []f1t.CallbackKey{targetRemoteKey, passiveKey}, CampaignContextSHA256: campaignContext}
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
		Expected: []f1t.CallbackKey{targetSelfKey}, CampaignContextSHA256: campaignContext}
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
			return f1t.SendCatalogPayload{Type: f1t.PayloadSendCatalog, Entry: entry, CampaignContextSHA256: campaignContext}, nil
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
		return f1t.Frame{}, nil, fmt.Errorf("%w: child stderr: %s", err, child.stderr.String())
	}
	if frame.SourceSequence != expectedSequence || expectedSequence != child.childInbound+1 {
		return f1t.Frame{}, nil, f1t.ErrInvalidFrame
	}
	child.childInbound = expectedSequence
	return frame, packet, nil
}

func appendAndAck(collector *f1t.DurableCollector, child *childProcess, collectorIdentity f1t.ProcessIdentity, frame f1t.Frame, packet []byte) error {
	return appendAndAckWithSender(collector, child, collectorIdentity, frame, packet, child.endpoint.Send)
}

func appendAndAckWithSender(collector *f1t.DurableCollector, child *childProcess, collectorIdentity f1t.ProcessIdentity,
	frame f1t.Frame, packet []byte, send func([]byte) error,
) error {
	if send == nil {
		return f1t.ErrInvalidFrame
	}
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
	return send(ackPacket)
}

func sendCollectorCommand(collector *f1t.DurableCollector, child *childProcess, collectorIdentity f1t.ProcessIdentity,
	sessionID, runID, command string, releaseEpoch uint64, campaignContext string,
) (f1t.Frame, error) {
	payload, payloadHash, err := f1t.NewPayload(f1t.CommandIntentPayload{
		Type: f1t.PayloadCommand, Command: command, CampaignContextSHA256: campaignContext,
	})
	if err != nil {
		return f1t.Frame{}, err
	}
	child.collectorOutbound++
	frame := f1t.Frame{SchemaVersion: frameSchema(campaignContext), CampaignContextSHA256: campaignContext,
		SessionID: sessionID, RunID: runID, Role: "collector",
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

func sendCampaignAction(collector *f1t.DurableCollector, child *childProcess, collectorIdentity f1t.ProcessIdentity,
	sessionID, runID string, action f1t.CampaignActionPayload, campaignContext string,
) error {
	if action.CampaignContextSHA256 != campaignContext {
		return f1t.ErrCampaignIdentity
	}
	payload, payloadHash, err := f1t.NewPayload(action)
	if err != nil {
		return err
	}
	child.collectorOutbound++
	frame := f1t.Frame{SchemaVersion: frameSchema(campaignContext), CampaignContextSHA256: campaignContext,
		SessionID: sessionID, RunID: runID, Role: "collector", PIDStartID: collectorIdentity.StartID,
		ExecutableHash: collectorIdentity.ExecutableHash, SourceSequence: child.collectorOutbound, ReleaseEpoch: 1,
		Kind: f1t.KindCommand, PayloadHash: payloadHash, AdmissionState: "INTENT", Payload: payload}
	packet, err := f1t.EncodeFrame(frame)
	if err != nil {
		return err
	}
	if _, err = collector.AppendFrom("collector/"+child.role, frame); err != nil {
		return err
	}
	if err = child.endpoint.Send(packet); err != nil {
		return err
	}
	observed, observedPacket, err := receiveChildFrame(child, child.childInbound+1)
	if err != nil {
		return err
	}
	var acknowledgement f1t.CampaignActionAckPayload
	if observed.Kind != f1t.KindEvent || observed.AdmissionState != "OBSERVED" || observed.ReleaseEpoch != 1 ||
		f1t.DecodeClosedPayload(observed.Payload, &acknowledgement) != nil || acknowledgement.Type != f1t.PayloadAction ||
		acknowledgement.Kind != action.Kind || acknowledgement.Profile != action.Profile || acknowledgement.Path != action.Path ||
		acknowledgement.Load != action.Load || acknowledgement.Index != action.Index || acknowledgement.ActionIndex != action.ActionIndex ||
		acknowledgement.FixtureSHA256 != action.FixtureSHA256 || acknowledgement.MessageID != action.MessageID || acknowledgement.CommandSourceSequence != frame.SourceSequence ||
		acknowledgement.CampaignContextSHA256 != campaignContext {
		return f1t.ErrReconciliation
	}
	return appendAndAck(collector, child, collectorIdentity, observed, observedPacket)
}
