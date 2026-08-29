package f1t

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/multiversx/mx-chain-communication-go/p2p"
	"github.com/multiversx/mx-chain-core-go/core"
)

var (
	ErrRecorderClosed       = errors.New("F1-T recorder closed or quiescing")
	ErrReconciliation       = errors.New("F1-T send/callback reconciliation failed")
	ErrDuplicateObservation = errors.New("F1-T duplicate observation")
	ErrRecorderQueueFull    = errors.New("F1-T recorder application queue full")
)

const defaultRecorderQueueCapacity = 64

type CallbackKey struct {
	Role string `json:"role"`
	Path string `json:"path"`
}

type SendCatalogEntry struct {
	MessageID             string        `json:"message_id"`
	Kind                  string        `json:"kind"`
	Index                 uint64        `json:"index"`
	Expected              []CallbackKey `json:"expected"`
	CampaignContextSHA256 string        `json:"campaign_context_sha256,omitempty"`
}

type admissionToken struct {
	sequence uint64
	epoch    uint64
}

type RecorderEvent struct {
	SourceSequence        uint64      `json:"source_sequence"`
	ReleaseEpoch          uint64      `json:"release_epoch"`
	MessageID             string      `json:"message_id"`
	Callback              CallbackKey `json:"callback"`
	State                 string      `json:"state"`
	CampaignContextSHA256 string      `json:"campaign_context_sha256,omitempty"`
}

type RecorderConfig struct {
	Callback              CallbackKey
	QueueCapacity         int
	MessageIdentity       func(p2p.MessageP2P) (string, error)
	DurableEmit           func(RecorderEvent) error
	CampaignContextSHA256 string
}

type recorderWork struct {
	message p2p.MessageP2P
	peer    core.PeerID
	source  p2p.MessageHandler
	id      string
	token   admissionToken
	result  chan recorderResult
}

type recorderResult struct {
	data []byte
	err  error
}

type Recorder struct {
	mu     sync.Mutex
	sendMu sync.Mutex

	releaseEpoch uint64
	admitted     uint64
	emitted      uint64
	inFlight     uint64
	quiescing    bool
	closed       bool
	failed       error
	sendsSealed  bool
	catalog      map[string]SendCatalogEntry
	expected     map[string]SendCatalogEntry
	observed     map[string]map[CallbackKey]struct{}
	pending      map[uint64]admissionToken
	stateChanged chan struct{}
	config       RecorderConfig
	processor    func(p2p.MessageP2P, core.PeerID, p2p.MessageHandler) ([]byte, error)
	work         chan recorderWork
	workerDone   chan struct{}
	closeWork    sync.Once
}

func NewRecorder(processor func(p2p.MessageP2P, core.PeerID, p2p.MessageHandler) ([]byte, error)) *Recorder {
	return NewRecorderWithConfig(processor, RecorderConfig{})
}

func NewRecorderWithConfig(processor func(p2p.MessageP2P, core.PeerID, p2p.MessageHandler) ([]byte, error), config RecorderConfig) *Recorder {
	if config.CampaignContextSHA256 != "" && !isHexDigest(config.CampaignContextSHA256) {
		panic("F1-T recorder campaign context must be a digest")
	}
	if config.MessageIdentity == nil {
		config.MessageIdentity = func(message p2p.MessageP2P) (string, error) {
			if message == nil || message.IsInterfaceNil() {
				return "", ErrReconciliation
			}
			sum := sha256.Sum256(message.Data())
			return hex.EncodeToString(sum[:]), nil
		}
	}
	if config.QueueCapacity == 0 {
		config.QueueCapacity = defaultRecorderQueueCapacity
	}
	if config.QueueCapacity < 1 {
		panic("F1-T recorder queue capacity must be positive")
	}
	recorder := &Recorder{
		catalog: make(map[string]SendCatalogEntry), observed: make(map[string]map[CallbackKey]struct{}),
		expected: make(map[string]SendCatalogEntry),
		pending:  make(map[uint64]admissionToken), stateChanged: make(chan struct{}), processor: processor, config: config,
		work: make(chan recorderWork, config.QueueCapacity), workerDone: make(chan struct{}),
	}
	go recorder.runWorker()
	return recorder
}

// RegisterExpected installs a catalog row that the authenticated collector
// durably journaled before dispatching it to this receiver. It does not send a
// transport message and therefore cannot substitute for GuardedSend.
func (recorder *Recorder) RegisterExpected(entry SendCatalogEntry) error {
	recorder.sendMu.Lock()
	defer recorder.sendMu.Unlock()
	return recorder.addSend(entry)
}

func (recorder *Recorder) IsDRWAS1F1TDirectAdmission() bool { return true }
func (recorder *Recorder) IsInterfaceNil() bool             { return recorder == nil }

// ProcessReceivedMessage admits and sequences the callback before placing it
// on the bounded application queue. The single worker makes durable emission
// order identical to source-sequence order without relying on callback-goroutine
// scheduling.
func (recorder *Recorder) ProcessReceivedMessage(message p2p.MessageP2P, peer core.PeerID, source p2p.MessageHandler) ([]byte, error) {
	messageID, err := recorder.config.MessageIdentity(message)
	if err != nil {
		return nil, recorder.fail(err)
	}
	request := recorderWork{message: message, peer: peer, source: source, id: messageID, result: make(chan recorderResult, 1)}
	if err = recorder.admitAndQueue(messageID, recorder.config.Callback, &request); err != nil {
		return nil, recorder.emitTerminalFailure(messageID, recorder.config.Callback, admissionToken{}, err)
	}
	result := <-request.result
	return result.data, result.err
}

// GuardedSend is the only production send-catalog API. It serializes with
// SealSends, records the complete catalog row durably, and only then permits
// the supplied transport send. A failure permanently invalidates the recorder.
func (recorder *Recorder) GuardedSend(entry SendCatalogEntry, durableJournal func(SendCatalogEntry) error, send func() error) error {
	if durableJournal == nil || send == nil {
		return recorder.fail(ErrReconciliation)
	}
	recorder.sendMu.Lock()
	defer recorder.sendMu.Unlock()
	if err := recorder.addSend(entry); err != nil {
		return err
	}
	if err := durableJournal(entry); err != nil {
		return recorder.fail(err)
	}
	if err := send(); err != nil {
		return recorder.fail(err)
	}
	return nil
}

func (recorder *Recorder) SetReleaseEpoch(epoch uint64) error {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.quiescing || recorder.closed || recorder.failed != nil || epoch != recorder.releaseEpoch+1 {
		return recorder.failLocked(ErrRecorderClosed)
	}
	recorder.releaseEpoch = epoch
	recorder.signalLocked()
	return nil
}

func (recorder *Recorder) addSend(entry SendCatalogEntry) error {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.sendsSealed || recorder.quiescing || recorder.closed || recorder.failed != nil || ValidateSendCatalogEntry(entry) != nil ||
		entry.CampaignContextSHA256 != recorder.config.CampaignContextSHA256 {
		return recorder.failLocked(ErrReconciliation)
	}
	if _, exists := recorder.catalog[entry.MessageID]; exists {
		return recorder.failLocked(ErrDuplicateObservation)
	}
	entry.Expected = append([]CallbackKey(nil), entry.Expected...)
	recorder.catalog[entry.MessageID] = entry
	if callbackExpected(entry, recorder.config.Callback) {
		receiverEntry := entry
		receiverEntry.Expected = []CallbackKey{recorder.config.Callback}
		recorder.expected[entry.MessageID] = receiverEntry
	}
	recorder.signalLocked()
	return nil
}

// ValidateSendCatalogEntry is the single closed-schema validator used by the
// guarded sender, receiver-side frame protocol and collector reconciliation.
func ValidateSendCatalogEntry(entry SendCatalogEntry) error {
	if entry.MessageID == "" || !validSendKind(entry.Kind) || entry.Index == 0 || len(entry.Expected) == 0 {
		return ErrReconciliation
	}
	if entry.CampaignContextSHA256 != "" && !isHexDigest(entry.CampaignContextSHA256) {
		return ErrReconciliation
	}
	seen := make(map[CallbackKey]struct{}, len(entry.Expected))
	for _, expected := range entry.Expected {
		if expected.Role == "" || expected.Path == "" {
			return ErrReconciliation
		}
		if _, exists := seen[expected]; exists {
			return ErrDuplicateObservation
		}
		seen[expected] = struct{}{}
	}
	return nil
}

func (recorder *Recorder) SealSends() error {
	recorder.sendMu.Lock()
	defer recorder.sendMu.Unlock()
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.sendsSealed || recorder.closed || recorder.failed != nil {
		return recorder.failLocked(ErrReconciliation)
	}
	recorder.sendsSealed = true
	recorder.signalLocked()
	return nil
}

func (recorder *Recorder) QuiesceAndDrain() error {
	return recorder.QuiesceAndDrainContext(context.Background())
}

func (recorder *Recorder) QuiesceAndDrainContext(ctx context.Context) error {
	for {
		recorder.mu.Lock()
		recorder.quiescing = true
		if recorder.failed != nil {
			err := recorder.failed
			recorder.mu.Unlock()
			return err
		}
		if !recorder.sendsSealed {
			err := recorder.failLocked(ErrReconciliation)
			recorder.mu.Unlock()
			return err
		}
		complete, err := recorder.reconciledLocked()
		if err != nil {
			recorder.mu.Unlock()
			return err
		}
		if complete {
			recorder.closed = true
			recorder.signalLocked()
			recorder.closeWorkerLocked()
			recorder.mu.Unlock()
			<-recorder.workerDone
			return nil
		}
		changed := recorder.stateChanged
		recorder.mu.Unlock()
		select {
		case <-ctx.Done():
			return recorder.fail(errors.Join(ErrReconciliation, ctx.Err()))
		case <-changed:
		}
	}
}

func (recorder *Recorder) Snapshot() (admitted, emitted, inFlight uint64, failed error) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return recorder.admitted, recorder.emitted, recorder.inFlight, recorder.failed
}

func (recorder *Recorder) CatalogIDs() []string {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	ids := make([]string, 0, len(recorder.catalog))
	for id := range recorder.catalog {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (recorder *Recorder) failLocked(err error) error {
	if recorder.failed == nil {
		recorder.failed = err
		recorder.signalLocked()
		recorder.closeWorkerLocked()
	}
	return recorder.failed
}

func (recorder *Recorder) fail(err error) error {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return recorder.failLocked(err)
}

func (recorder *Recorder) admitAndQueue(messageID string, key CallbackKey, request *recorderWork) error {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.quiescing || recorder.closed || recorder.failed != nil {
		return recorder.failLocked(ErrRecorderClosed)
	}
	entry, exists := recorder.expected[messageID]
	if !exists || key.Role == "" || key.Path == "" {
		return recorder.failLocked(ErrReconciliation)
	}
	expected := false
	for _, candidate := range entry.Expected {
		if candidate == key {
			expected = true
			break
		}
	}
	if !expected {
		return recorder.failLocked(ErrReconciliation)
	}
	if recorder.observed[messageID] == nil {
		recorder.observed[messageID] = make(map[CallbackKey]struct{})
	}
	if _, duplicate := recorder.observed[messageID][key]; duplicate {
		return recorder.failLocked(ErrDuplicateObservation)
	}
	if recorder.admitted == ^uint64(0) {
		return recorder.failLocked(ErrReconciliation)
	}
	recorder.admitted++
	recorder.inFlight++
	token := admissionToken{sequence: recorder.admitted, epoch: recorder.releaseEpoch}
	recorder.pending[token.sequence] = token
	recorder.observed[messageID][key] = struct{}{}
	request.token = token
	select {
	case recorder.work <- *request:
		recorder.signalLocked()
		return nil
	default:
		delete(recorder.pending, token.sequence)
		delete(recorder.observed[messageID], key)
		recorder.inFlight--
		return recorder.failLocked(ErrRecorderQueueFull)
	}
}

func (recorder *Recorder) runWorker() {
	defer close(recorder.workerDone)
	for request := range recorder.work {
		result, err := recorder.processOne(request)
		request.result <- recorderResult{data: result, err: err}
		close(request.result)
	}
}

func (recorder *Recorder) processOne(request recorderWork) ([]byte, error) {
	var result []byte
	var err error
	if recorder.processor != nil {
		result, err = recorder.processor(request.message, request.peer, request.source)
	}
	if err != nil {
		cause := recorder.fail(err)
		recorder.finishFailed(request.token)
		return result, recorder.emitTerminalFailure(request.id, recorder.config.Callback, request.token, cause)
	}
	if recorder.config.DurableEmit != nil {
		err = recorder.config.DurableEmit(RecorderEvent{SourceSequence: request.token.sequence, ReleaseEpoch: request.token.epoch,
			MessageID: request.id, Callback: recorder.config.Callback, State: "ADMITTED",
			CampaignContextSHA256: recorder.config.CampaignContextSHA256})
		if err != nil {
			cause := recorder.fail(err)
			recorder.finishFailed(request.token)
			return result, cause
		}
	}
	if err = recorder.complete(request.token); err != nil {
		return result, recorder.emitTerminalFailure(request.id, recorder.config.Callback, request.token, err)
	}
	return result, nil
}

func (recorder *Recorder) complete(token admissionToken) error {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	pending, exists := recorder.pending[token.sequence]
	if recorder.failed != nil {
		if exists && pending == token {
			delete(recorder.pending, token.sequence)
			if recorder.inFlight > 0 {
				recorder.inFlight--
			}
			recorder.signalLocked()
		}
		return recorder.failed
	}
	if token.sequence == 0 || !exists || pending != token || token.sequence != recorder.emitted+1 || recorder.inFlight == 0 || token.epoch > recorder.releaseEpoch {
		return recorder.failLocked(ErrReconciliation)
	}
	delete(recorder.pending, token.sequence)
	recorder.inFlight--
	recorder.emitted++
	recorder.signalLocked()
	return nil
}

func (recorder *Recorder) finishFailed(token admissionToken) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if pending, exists := recorder.pending[token.sequence]; exists && pending == token {
		delete(recorder.pending, token.sequence)
		if recorder.inFlight > 0 {
			recorder.inFlight--
		}
		recorder.signalLocked()
	}
}

func (recorder *Recorder) reconciledLocked() (bool, error) {
	for messageID, entry := range recorder.expected {
		if len(recorder.observed[messageID]) != len(entry.Expected) {
			if recorder.inFlight == 0 {
				return false, recorder.failLocked(fmt.Errorf("%w: message %s", ErrReconciliation, messageID))
			}
			return false, nil
		}
	}
	return recorder.inFlight == 0 && len(recorder.pending) == 0 && recorder.admitted == recorder.emitted, nil
}

func (recorder *Recorder) signalLocked() {
	close(recorder.stateChanged)
	recorder.stateChanged = make(chan struct{})
}

func (recorder *Recorder) closeWorkerLocked() {
	recorder.closeWork.Do(func() { close(recorder.work) })
}

func (recorder *Recorder) emitTerminalFailure(messageID string, key CallbackKey, token admissionToken, cause error) error {
	if recorder.config.DurableEmit == nil {
		return cause
	}
	emitErr := recorder.config.DurableEmit(RecorderEvent{SourceSequence: token.sequence, ReleaseEpoch: token.epoch,
		MessageID: messageID, Callback: key, State: "TERMINAL_FAILURE", CampaignContextSHA256: recorder.config.CampaignContextSHA256})
	return errors.Join(cause, emitErr)
}

func validSendKind(kind string) bool {
	switch kind {
	case "READINESS", "CALIBRATION", "SELECTED_SHAPED", "SENTINEL", "SELF_DIRECT":
		return true
	default:
		return false
	}
}

type V17RecorderState string

const (
	V17StateArmed     V17RecorderState = "ARMED"
	V17StateReady     V17RecorderState = "READY"
	V17StateObserving V17RecorderState = "OBSERVING"
	V17StateQuiet     V17RecorderState = "QUIET"
	V17StateClosed    V17RecorderState = "CLOSED"
	V17StateFailed    V17RecorderState = "FAILED"
)

const (
	V17EventArmContracts = "ARM_CONTRACTS_VERIFIED"
	V17EventBegin        = "ORCHESTRATOR_BEGIN"
	V17EventCounts       = "REQUIRED_COUNTS_SATISFIED"
	V17EventValid        = "VALID_EXPECTED_EVENT"
	V17EventClose        = "ORCHESTRATOR_CLOSE"
	V17EventInvalid      = "INVALID_OR_GAP_OR_COLLECTOR_FAILURE"
	V17EventLater        = "ANY_LATER_EVENT"
)

var ErrV17RecorderTransition = errors.New("F1-T v17 recorder transition rejected")
var ErrNumericRulingRequired = errors.New("F1-T numeric horizon owner ruling required")

type V17ArmIdentity struct {
	BatchSHA256   string
	MiniBlockHash string
	SCRHash       string
	Vector        map[string]PredicateResult
}

type V17RecorderEvent struct {
	SchemaValid     bool
	Sequence        uint64
	TimestampRawNS  uint64
	ReceiverID      string
	ReceiverRole    string
	TransportKind   string
	FromPeer        string
	ForwarderPeer   string
	Topic           string
	ClassifiedArm   string
	BatchSHA256     string
	MiniBlockHash   string
	SCRHash         string
	PredicateVector map[string]PredicateResult
	CollectorResult string
	Profile         Profile
}

type V17RecorderContext struct {
	ReceiverID              string
	RemotePublisherPeer     string
	SelfPeer                string
	BoundTopic              string
	SourceArmsConstructed   bool
	IdentityMismatchCount   uint64
	RequiredArmCounts       map[string]uint64
	ObservedArmCounts       map[string]uint64
	CloseDeadlineRawNS      uint64
	PriorSequence           uint64
	ClosedSequence          uint64
	PriorTimestampRawNS     uint64
	LastExpectedEventRawNS  uint64
	NowRawNS                uint64
	HorizonStatus           string
	ArmingAllowed           bool
	HQuietNS                uint64
	NumericRulingAuthorized bool
	Arms                    map[Profile]map[string]V17ArmIdentity
}

type V17RecorderMachine struct {
	State   V17RecorderState
	Context V17RecorderContext
}

func (machine *V17RecorderMachine) Apply(eventName string, event *V17RecorderEvent) error {
	if machine == nil || machine.State == V17StateFailed {
		return ErrV17RecorderTransition
	}
	fail := func(cause error) error {
		machine.State = V17StateFailed
		return errors.Join(ErrV17RecorderTransition, cause)
	}

	if machine.State == V17StateClosed {
		if eventName == V17EventLater {
			return fail(ErrRecorderClosed)
		}
		return fail(ErrV17RecorderTransition)
	}

	switch eventName {
	case V17EventArmContracts:
		if machine.State != V17StateArmed || !machine.Context.SourceArmsConstructed || machine.Context.IdentityMismatchCount != 0 {
			return fail(ErrSelectorMismatch)
		}
		machine.State = V17StateReady
		return nil
	case V17EventBegin:
		if machine.State != V17StateReady || !machine.Context.NumericRulingAuthorized ||
			machine.Context.HorizonStatus != "RATIFIED" || !machine.Context.ArmingAllowed || machine.Context.HQuietNS == 0 {
			return fail(ErrNumericRulingRequired)
		}
		machine.State = V17StateObserving
		return nil
	case V17EventCounts:
		if machine.State != V17StateObserving || !equalUint64Map(machine.Context.RequiredArmCounts, machine.Context.ObservedArmCounts) {
			return fail(ErrReconciliation)
		}
		machine.State = V17StateQuiet
		return nil
	case V17EventValid:
		if machine.State != V17StateQuiet || event == nil || !machine.validEvent(*event) {
			return fail(ErrReconciliation)
		}
		machine.acceptEvent(*event)
		machine.State = V17StateObserving
		return nil
	case V17EventClose:
		if machine.State != V17StateQuiet || !equalUint64Map(machine.Context.RequiredArmCounts, machine.Context.ObservedArmCounts) ||
			!machine.Context.NumericRulingAuthorized || machine.Context.HorizonStatus != "RATIFIED" || !machine.Context.ArmingAllowed ||
			machine.Context.HQuietNS == 0 || machine.Context.LastExpectedEventRawNS > ^uint64(0)-machine.Context.HQuietNS ||
			machine.Context.NowRawNS < machine.Context.LastExpectedEventRawNS+machine.Context.HQuietNS {
			return fail(ErrReconciliation)
		}
		machine.State = V17StateClosed
		machine.Context.ClosedSequence = machine.Context.PriorSequence
		return nil
	case V17EventInvalid:
		if event == nil || machine.validEvent(*event) {
			return fail(ErrV17RecorderTransition)
		}
		return fail(ErrReconciliation)
	default:
		return fail(ErrV17RecorderTransition)
	}
}

func (machine *V17RecorderMachine) validEvent(event V17RecorderEvent) bool {
	context := machine.Context
	if !event.SchemaValid || event.Sequence == 0 || context.PriorSequence == ^uint64(0) || event.Sequence != context.PriorSequence+1 ||
		event.TimestampRawNS <= context.PriorTimestampRawNS || event.TimestampRawNS > context.CloseDeadlineRawNS ||
		event.ReceiverID != context.ReceiverID || event.ReceiverRole != "QUALIFICATION_RECORDER" || event.Topic != context.BoundTopic ||
		event.CollectorResult != "FSYNCED_APPEND_SUCCESS" || !knownProfile(event.Profile) {
		return false
	}
	switch event.TransportKind {
	case "REMOTE_DELIVERY":
		if event.FromPeer != context.RemotePublisherPeer || event.ForwarderPeer != context.RemotePublisherPeer {
			return false
		}
	case "SELF_DIRECT":
		if event.FromPeer != context.SelfPeer || event.ForwarderPeer != context.SelfPeer {
			return false
		}
	default:
		return false
	}
	profileArms, exists := context.Arms[event.Profile]
	if !exists {
		return false
	}
	arm, exists := profileArms[event.ClassifiedArm]
	return exists && event.BatchSHA256 == arm.BatchSHA256 && event.MiniBlockHash == arm.MiniBlockHash &&
		event.SCRHash == arm.SCRHash && equalPredicateResultMap(event.PredicateVector, arm.Vector)
}

func (machine *V17RecorderMachine) acceptEvent(event V17RecorderEvent) {
	machine.Context.PriorSequence = event.Sequence
	machine.Context.PriorTimestampRawNS = event.TimestampRawNS
	machine.Context.LastExpectedEventRawNS = event.TimestampRawNS
	if machine.Context.ObservedArmCounts == nil {
		machine.Context.ObservedArmCounts = make(map[string]uint64)
	}
	machine.Context.ObservedArmCounts[event.ClassifiedArm]++
}

func equalUint64Map(left, right map[string]uint64) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func equalPredicateResultMap(left, right map[string]PredicateResult) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value || (value.State == "N_A") != (value.ReasonID != "") {
			return false
		}
	}
	return true
}
