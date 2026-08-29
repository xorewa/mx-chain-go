package f1t

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"
)

const (
	SamplesPerProfilePathLoad  = 4603
	TotalActionIndices         = 55236
	TotalPathObservations      = 165708
	ProposedSentinelCount      = 4
	TotalAuxiliaryIntents      = 72
	TotalAuxiliaryObservations = 216
	TotalObservations          = 165924
)

var ErrPopulationIncomplete = errors.New("F1-T population incomplete")

type Path string
type LoadCell string
type ObservationKind string

const (
	PathRemoteTarget  Path = "REMOTE_TARGET"
	PathRemotePassive Path = "REMOTE_PASSIVE"
	PathSelfDirect    Path = "SELF_DIRECT_TARGET"

	LoadBaseline  LoadCell = "BASELINE"
	LoadCPU       LoadCell = "CPU_SATURATION"
	LoadScheduler LoadCell = "SCHEDULER_PRESSURE"
	LoadGC        LoadCell = "GC_PRESSURE"
	LoadFsync     LoadCell = "COLLECTOR_FSYNC_CONTENTION"
	LoadCombined  LoadCell = "COMBINED"

	ObservationCalibration   ObservationKind = "CALIBRATION"
	ObservationReadiness     ObservationKind = "READINESS"
	ObservationSelectedShape ObservationKind = "SELECTED_SHAPED"
	ObservationSentinel      ObservationKind = "SENTINEL_SHAPED"
)

var profileCatalog = [...]Profile{ProfileLegacy, ProfileV2}
var pathCatalog = [...]Path{PathRemoteTarget, PathRemotePassive, PathSelfDirect}
var loadCatalog = [...]LoadCell{LoadBaseline, LoadCPU, LoadScheduler, LoadGC, LoadFsync, LoadCombined}

const ordinaryLoadActivationTimeout = 5 * time.Second

func Profiles() []Profile   { return append([]Profile(nil), profileCatalog[:]...) }
func Paths() []Path         { return append([]Path(nil), pathCatalog[:]...) }
func LoadCells() []LoadCell { return append([]LoadCell(nil), loadCatalog[:]...) }

type Observation struct {
	Kind            ObservationKind `json:"observation_kind"`
	Profile         Profile         `json:"profile"`
	Path            Path            `json:"path"`
	Load            LoadCell        `json:"load"`
	Index           uint64          `json:"index"`
	ActionIndex     uint64          `json:"action_index"`
	DurableSequence uint64          `json:"durable_sequence"`
	IntentRawNS     uint64          `json:"intent_monotonic_raw_ns"`
	DurableAckNS    uint64          `json:"durable_ack_monotonic_raw_ns"`
}

type TerminationObservation struct {
	Role           string `json:"role"`
	StopIntentNS   uint64 `json:"stop_intent_monotonic_raw_ns"`
	PIDFDExitRawNS uint64 `json:"pidfd_exit_monotonic_raw_ns"`
}

type CampaignEvidence struct {
	Observations       []Observation            `json:"observations"`
	Terminations       []TerminationObservation `json:"terminations"`
	FailedSamples      uint64                   `json:"failed_samples"`
	RuntimeCredit      int                      `json:"authoritative_runtime_credit"`
	CasesCredited      int                      `json:"cases_credited"`
	InvariantsCredited int                      `json:"invariants_credited"`
	S1Pass             bool                     `json:"s1_pass"`
	S2Authorized       bool                     `json:"s2_authorized"`
}

type Candidates struct {
	HQuietMS            uint64            `json:"h_quiet_ms_candidate"`
	SentinelCadenceMS   uint64            `json:"sentinel_cadence_ms_candidate"`
	SentinelCount       uint64            `json:"sentinel_count_candidate"`
	CleanupTimeoutMS    uint64            `json:"process_termination_timeout_ms_candidate"`
	Status              string            `json:"status"`
	RuntimeCredit       int               `json:"authoritative_runtime_credit"`
	NumericRatification bool              `json:"numeric_ratification"`
	Diagnostics         DiagnosticsReport `json:"diagnostics"`
}

type CampaignActionObserver interface {
	Observe(CampaignActionPayload, []byte, Selection) (uint64, []PathReceipt, error)
}

// PathReceipt is independently durable callback evidence for one member of
// the exact three-path observation set emitted from one logical intent.
type PathReceipt struct {
	Path         Path
	DurableAckNS uint64
}

type CampaignPipelineInput struct {
	Preflight  CampaignPreflight
	Root       string
	Samples    int
	LoadConfig LoadConfig
	Observer   CampaignActionObserver
}

func ExecuteCampaignActions(ctx context.Context, input CampaignPipelineInput) (observations []Observation, err error) {
	if ctx == nil || input.Observer == nil || input.Samples < 1 || input.Samples > SamplesPerProfilePathLoad ||
		len(input.Preflight.Profiles) != len(profileCatalog) || !filepath.IsAbs(input.Root) || filepath.Clean(input.Root) != input.Root {
		return nil, ErrPopulationIncomplete
	}
	contexts := make(map[Profile]ObservationContext, len(input.Preflight.Profiles))
	for _, profile := range input.Preflight.Profiles {
		observationContext, err := NewObservationContext(profile, input.Preflight.Constructor)
		if err != nil {
			return nil, err
		}
		contexts[profile.Entry.ID] = observationContext
	}
	observations = make([]Observation, 0, input.Samples*len(profileCatalog)*len(loadCatalog)*len(pathCatalog)+
		len(profileCatalog)*len(pathCatalog)*len(loadCatalog)*(2+ProposedSentinelCount))
	appendObserved := func(action CampaignActionPayload, raw []byte, selection Selection) error {
		intent, receipts, err := input.Observer.Observe(action, raw, selection)
		if err != nil {
			return errors.Join(ErrPopulationIncomplete, err)
		}
		return appendPathObservations(&observations, action, intent, receipts)
	}
	observeWithActiveCell := func(handle *LoadHandle, action CampaignActionPayload, raw []byte, selection Selection) error {
		activationErr := activateCampaignCell(ctx, handle)
		if activationErr != nil {
			return fmt.Errorf("F1-T activate profile=%s load=%s kind=%s index=%d: %w",
				action.Profile, action.Load, action.Kind, action.Index, activationErr)
		}
		return errors.Join(appendObserved(action, raw, selection), handle.Deactivate())
	}
	type persistentCell struct {
		key    string
		handle *LoadHandle
	}
	cells := make(map[string]*LoadHandle, len(input.Preflight.Profiles)*len(loadCatalog))
	orderedCells := make([]persistentCell, 0, len(input.Preflight.Profiles)*len(loadCatalog))
	defer func() {
		var stopErr error
		for index := len(orderedCells) - 1; index >= 0; index-- {
			stopErr = errors.Join(stopErr, orderedCells[index].handle.Stop())
		}
		if stopErr != nil {
			observations = nil
			err = errors.Join(err, stopErr)
		}
	}()
	for profileIndex, profile := range input.Preflight.Profiles {
		for loadIndex, load := range loadCatalog {
			key := fmt.Sprintf("%s/%s", profile.Entry.ID, load)
			loadRoot := filepath.Join(input.Root, fmt.Sprintf("load-cell-%d-%d", profileIndex, loadIndex))
			if mkdirErr := os.Mkdir(loadRoot, 0o700); mkdirErr != nil {
				return nil, mkdirErr
			}
			handle, startErr := StartPersistentLoad(ctx, load, loadRoot, input.LoadConfig)
			if startErr != nil {
				return nil, startErr
			}
			cells[key] = handle
			orderedCells = append(orderedCells, persistentCell{key: key, handle: handle})
		}
	}

	for sample := 1; sample <= input.Samples; sample++ {
		for _, profile := range input.Preflight.Profiles {
			for _, load := range loadCatalog {
				actionIndex := expectedActionIndex(profile.Entry.ID, load, uint64(sample))
				handle := cells[fmt.Sprintf("%s/%s", profile.Entry.ID, load)]
				activationErr := activateCampaignCell(ctx, handle)
				if activationErr != nil {
					return nil, fmt.Errorf("F1-T activate profile=%s load=%s kind=%s index=%d: %w",
						profile.Entry.ID, load, ObservationCalibration, sample, activationErr)
				}
				cellErr := func() error {
					selected, _, buildErr := BuildCalibrationFixture(input.Preflight.Constructor, profile.Entry.ID, "SELECTED", uint64(sample),
						"calibration", "/drwa/f1t", "peer-remote", true)
					if buildErr != nil {
						return buildErr
					}
					sentinel, _, buildErr := BuildCalibrationFixture(input.Preflight.Constructor, profile.Entry.ID, "SENTINEL_1", uint64(sample),
						"calibration", "/drwa/f1t", "peer-remote", false)
					if buildErr != nil {
						return buildErr
					}
					selection, classifyErr := ClassifyObservedFixture(selected, profile.Entry.ID, "/drwa/f1t", "peer-remote",
						[][]byte{selected, sentinel}, contexts[profile.Entry.ID])
					if classifyErr != nil {
						return classifyErr
					}
					action := CampaignActionPayload{Type: PayloadAction, Kind: ObservationCalibration, Profile: profile.Entry.ID,
						Path: PathRemoteTarget, Load: load, Index: uint64(sample), ActionIndex: actionIndex, FixtureSHA256: digestHex(selected),
						CampaignContextSHA256: input.Preflight.ContextSHA256}
					if observeErr := appendObserved(action, selected, selection); observeErr != nil {
						return observeErr
					}
					return nil
				}()
				if combinedErr := errors.Join(cellErr, handle.Deactivate()); combinedErr != nil {
					return nil, combinedErr
				}
			}
		}
	}
	for _, profile := range input.Preflight.Profiles {
		selected, _, err := BuildCalibrationFixture(input.Preflight.Constructor, profile.Entry.ID, "SELECTED", 1,
			"auxiliary", "/drwa/f1t", "peer-remote", true)
		if err != nil {
			return nil, err
		}
		sentinels := make([][]byte, ProposedSentinelCount)
		arms := [][]byte{selected}
		for index := range sentinels {
			sentinels[index], _, err = BuildCalibrationFixture(input.Preflight.Constructor, profile.Entry.ID,
				fmt.Sprintf("SENTINEL_%d", index+1), uint64(index+1), "auxiliary", "/drwa/f1t", "peer-remote", false)
			if err != nil {
				return nil, err
			}
			arms = append(arms, sentinels[index])
		}
		for _, load := range loadCatalog {
			handle := cells[fmt.Sprintf("%s/%s", profile.Entry.ID, load)]
			for _, kind := range []ObservationKind{ObservationReadiness, ObservationSelectedShape} {
				selection, classifyErr := ClassifyObservedFixture(selected, profile.Entry.ID, "/drwa/f1t", "peer-remote", arms, contexts[profile.Entry.ID])
				if classifyErr != nil {
					return nil, classifyErr
				}
				action := CampaignActionPayload{Type: PayloadAction, Kind: kind, Profile: profile.Entry.ID, Path: PathRemoteTarget,
					Load: load, Index: 1, FixtureSHA256: digestHex(selected), CampaignContextSHA256: input.Preflight.ContextSHA256}
				if err = observeWithActiveCell(handle, action, selected, selection); err != nil {
					return nil, err
				}
			}
			for index, sentinel := range sentinels {
				selection, classifyErr := ClassifyObservedFixture(sentinel, profile.Entry.ID, "/drwa/f1t", "peer-remote", arms, contexts[profile.Entry.ID])
				if classifyErr != nil {
					return nil, classifyErr
				}
				action := CampaignActionPayload{Type: PayloadAction, Kind: ObservationSentinel, Profile: profile.Entry.ID, Path: PathRemoteTarget,
					Load: load, Index: uint64(index + 1), FixtureSHA256: digestHex(sentinel), CampaignContextSHA256: input.Preflight.ContextSHA256}
				if err = observeWithActiveCell(handle, action, sentinel, selection); err != nil {
					return nil, err
				}
			}
		}
	}
	return observations, nil
}

// activateCampaignCell bounds progress proof for each of the six eligible
// measurement load cells. Restart and reconnect are authoritative S1 matrix
// obligations, not members of the F1-T statistical timing population.
func activateCampaignCell(parent context.Context, handle *LoadHandle) error {
	if parent == nil || handle == nil {
		return ErrPopulationIncomplete
	}
	livenessContext, cancel := context.WithTimeout(parent, ordinaryLoadActivationTimeout)
	defer cancel()

	return handle.Activate(livenessContext)
}

func appendPathObservations(observations *[]Observation, action CampaignActionPayload, intent uint64, receipts []PathReceipt) error {
	if observations == nil || intent == 0 || len(receipts) != len(pathCatalog) {
		return ErrPopulationIncomplete
	}
	for index, path := range pathCatalog {
		receipt := receipts[index]
		if receipt.Path != path || receipt.DurableAckNS < intent {
			return ErrPopulationIncomplete
		}
	}
	for index, path := range pathCatalog {
		receipt := receipts[index]
		*observations = append(*observations, Observation{Kind: action.Kind, Profile: action.Profile, Path: path,
			Load: action.Load, Index: action.Index, ActionIndex: action.ActionIndex, DurableSequence: uint64(len(*observations) + 1),
			IntentRawNS: intent, DurableAckNS: receipt.DurableAckNS})
	}
	return nil
}

func ExpectedActionCount() int {
	return len(profileCatalog) * len(loadCatalog) * SamplesPerProfilePathLoad
}
func ExpectedObservationCount() int { return ExpectedActionCount() * len(pathCatalog) }
func ExpectedTotalObservationCount() int {
	return ExpectedObservationCount() + len(profileCatalog)*len(loadCatalog)*(2+ProposedSentinelCount)*len(pathCatalog)
}

func ValidateAndDerive(evidence CampaignEvidence) (Candidates, error) {
	if ExpectedActionCount() != TotalActionIndices || ExpectedObservationCount() != TotalPathObservations ||
		ExpectedTotalObservationCount() != TotalObservations ||
		evidence.FailedSamples != 0 || evidence.RuntimeCredit != 0 || evidence.CasesCredited != 0 ||
		evidence.InvariantsCredited != 0 || evidence.S1Pass || evidence.S2Authorized {
		return Candidates{}, ErrPopulationIncomplete
	}
	if !observationsInExactDurableOrder(evidence.Observations) {
		return Candidates{}, ErrPopulationIncomplete
	}
	seenCalibration := make(map[string]struct{}, TotalPathObservations)
	seenAuxiliary := make(map[string]struct{})
	actionIntents := make(map[uint64]uint64, TotalActionIndices)
	var maxLatency uint64
	for _, observation := range evidence.Observations {
		if !knownProfile(observation.Profile) || !knownPath(observation.Path) || !knownLoad(observation.Load) ||
			observation.Index == 0 || observation.DurableAckNS < observation.IntentRawNS || !knownObservationKind(observation.Kind) {
			return Candidates{}, ErrPopulationIncomplete
		}
		key := fmt.Sprintf("%s/%s/%s/%s/%d", observation.Kind, observation.Profile, observation.Path, observation.Load, observation.Index)
		if observation.Kind == ObservationCalibration {
			expectedAction := expectedActionIndex(observation.Profile, observation.Load, observation.Index)
			if observation.Index > SamplesPerProfilePathLoad || observation.ActionIndex != expectedAction {
				return Candidates{}, ErrPopulationIncomplete
			}
			if _, duplicate := seenCalibration[key]; duplicate {
				return Candidates{}, ErrPopulationIncomplete
			}
			seenCalibration[key] = struct{}{}
			if intent, exists := actionIntents[observation.ActionIndex]; exists && intent != observation.IntentRawNS {
				return Candidates{}, ErrPopulationIncomplete
			}
			actionIntents[observation.ActionIndex] = observation.IntentRawNS
		} else {
			if observation.ActionIndex != 0 {
				return Candidates{}, ErrPopulationIncomplete
			}
			if _, duplicate := seenAuxiliary[key]; duplicate {
				return Candidates{}, ErrPopulationIncomplete
			}
			seenAuxiliary[key] = struct{}{}
		}
		latency := observation.DurableAckNS - observation.IntentRawNS
		if latency > maxLatency {
			maxLatency = latency
		}
	}
	if len(seenCalibration) != TotalPathObservations || len(actionIntents) != TotalActionIndices ||
		!orderedActionIntents(actionIntents) || !completeAuxiliaryPopulation(seenAuxiliary) {
		return Candidates{}, ErrPopulationIncomplete
	}
	diagnostics, err := EvaluateCampaignDiagnostics(evidence.Observations)
	if err != nil {
		return Candidates{Status: "INVALIDATED_NO_NUMERIC_CANDIDATES", Diagnostics: diagnostics}, err
	}
	maxExit, err := validateTerminations(evidence.Terminations)
	if err != nil {
		return Candidates{}, err
	}
	h := ceilNSToMS(maxLatency)
	return Candidates{HQuietMS: h, SentinelCadenceMS: h, SentinelCount: ProposedSentinelCount,
		CleanupTimeoutMS: ceilNSToMS(maxExit), Status: "PROPOSED_ONLY_PHASE_II_AND_NUMERIC_RULING_REQUIRED", Diagnostics: diagnostics}, nil
}

func observationsInExactDurableOrder(observations []Observation) bool {
	expectedCount := TotalPathObservations + len(profileCatalog)*len(pathCatalog)*len(loadCatalog)*(2+ProposedSentinelCount)
	if len(observations) != expectedCount {
		return false
	}
	position := 0
	for sample := uint64(1); sample <= SamplesPerProfilePathLoad; sample++ {
		for _, profile := range profileCatalog {
			for _, load := range loadCatalog {
				action := expectedActionIndex(profile, load, sample)
				for _, path := range pathCatalog {
					observation := observations[position]
					position++
					if observation.DurableSequence != uint64(position) || observation.Kind != ObservationCalibration ||
						observation.Profile != profile || observation.Load != load || observation.Path != path ||
						observation.Index != sample || observation.ActionIndex != action {
						return false
					}
				}
			}
		}
	}
	for _, profile := range profileCatalog {
		for _, load := range loadCatalog {
			for _, kind := range []ObservationKind{ObservationReadiness, ObservationSelectedShape} {
				for _, path := range pathCatalog {
					observation := observations[position]
					position++
					if observation.DurableSequence != uint64(position) || observation.Kind != kind || observation.Profile != profile ||
						observation.Load != load || observation.Path != path || observation.Index != 1 || observation.ActionIndex != 0 {
						return false
					}
				}
			}
			for index := uint64(1); index <= ProposedSentinelCount; index++ {
				for _, path := range pathCatalog {
					observation := observations[position]
					position++
					if observation.DurableSequence != uint64(position) || observation.Kind != ObservationSentinel || observation.Profile != profile ||
						observation.Load != load || observation.Path != path || observation.Index != index || observation.ActionIndex != 0 {
						return false
					}
				}
			}
		}
	}
	return position == len(observations)
}

func expectedActionIndex(profile Profile, load LoadCell, sample uint64) uint64 {
	profileOffset := -1
	for index, candidate := range profileCatalog {
		if candidate == profile {
			profileOffset = index
			break
		}
	}
	loadOffset := -1
	for index, candidate := range loadCatalog {
		if candidate == load {
			loadOffset = index
			break
		}
	}
	if profileOffset < 0 || loadOffset < 0 || sample == 0 || sample > SamplesPerProfilePathLoad {
		return 0
	}
	return (sample-1)*uint64(len(profileCatalog)*len(loadCatalog)) +
		uint64(profileOffset*len(loadCatalog)+loadOffset+1)
}

func orderedActionIntents(intents map[uint64]uint64) bool {
	var previous uint64
	for action := uint64(1); action <= TotalActionIndices; action++ {
		intent, exists := intents[action]
		if !exists || intent < previous {
			return false
		}
		previous = intent
	}
	return true
}

func ConditionalWilksCoverage() float64 { return 1 - math.Pow(0.999, SamplesPerProfilePathLoad) }

func DeterministicRoundRobinKeys() []string {
	keys := make([]string, 0, TotalActionIndices)
	for index := 1; index <= SamplesPerProfilePathLoad; index++ {
		for _, profile := range profileCatalog {
			for _, load := range loadCatalog {
				keys = append(keys, fmt.Sprintf("%s/%s/%d", profile, load, index))
			}
		}
	}
	return keys
}

func knownProfile(value Profile) bool { return value == ProfileLegacy || value == ProfileV2 }
func knownPath(value Path) bool {
	return value == PathRemoteTarget || value == PathRemotePassive || value == PathSelfDirect
}
func knownLoad(value LoadCell) bool {
	for _, candidate := range loadCatalog {
		if candidate == value {
			return true
		}
	}
	return false
}

func knownObservationKind(value ObservationKind) bool {
	return value == ObservationCalibration || value == ObservationReadiness || value == ObservationSelectedShape || value == ObservationSentinel
}

func completeAuxiliaryPopulation(seen map[string]struct{}) bool {
	for _, profile := range profileCatalog {
		for _, path := range pathCatalog {
			for _, load := range loadCatalog {
				for _, kind := range []ObservationKind{ObservationReadiness, ObservationSelectedShape} {
					if _, exists := seen[fmt.Sprintf("%s/%s/%s/%s/1", kind, profile, path, load)]; !exists {
						return false
					}
				}
				for index := 1; index <= ProposedSentinelCount; index++ {
					if _, exists := seen[fmt.Sprintf("%s/%s/%s/%s/%d", ObservationSentinel, profile, path, load, index)]; !exists {
						return false
					}
				}
			}
		}
	}
	return len(seen) == len(profileCatalog)*len(pathCatalog)*len(loadCatalog)*(2+ProposedSentinelCount)
}

func validateTerminations(observations []TerminationObservation) (uint64, error) {
	required := map[string]bool{"publisher": false, "target": false, "passive": false}
	var maximum uint64
	if len(observations) != len(required) {
		return 0, ErrPopulationIncomplete
	}
	for _, observation := range observations {
		if _, exists := required[observation.Role]; !exists || required[observation.Role] || observation.StopIntentNS == 0 || observation.PIDFDExitRawNS < observation.StopIntentNS {
			return 0, ErrPopulationIncomplete
		}
		required[observation.Role] = true
		duration := observation.PIDFDExitRawNS - observation.StopIntentNS
		if duration > maximum {
			maximum = duration
		}
	}
	return maximum, nil
}

func ceilNSToMS(value uint64) uint64 {
	if value == 0 {
		return 1
	}
	return 1 + (value-1)/1_000_000
}
