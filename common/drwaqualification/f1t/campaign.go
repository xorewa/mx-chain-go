package f1t

import (
	"errors"
	"fmt"
	"math"
)

const (
	SamplesPerProfilePathLoad = 4603
	TotalActionIndices        = 64442
	TotalPathObservations     = 193326
	ProposedSentinelCount     = 4
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
	LoadReconnect LoadCell = "RECENT_RECONNECT"

	ObservationCalibration   ObservationKind = "CALIBRATION"
	ObservationReadiness     ObservationKind = "READINESS"
	ObservationSelectedShape ObservationKind = "SELECTED_SHAPED"
	ObservationSentinel      ObservationKind = "SENTINEL_SHAPED"
)

var profileCatalog = [...]Profile{ProfileLegacy, ProfileV2}
var pathCatalog = [...]Path{PathRemoteTarget, PathRemotePassive, PathSelfDirect}
var loadCatalog = [...]LoadCell{LoadBaseline, LoadCPU, LoadScheduler, LoadGC, LoadFsync, LoadCombined, LoadReconnect}

func Profiles() []Profile   { return append([]Profile(nil), profileCatalog[:]...) }
func Paths() []Path         { return append([]Path(nil), pathCatalog[:]...) }
func LoadCells() []LoadCell { return append([]LoadCell(nil), loadCatalog[:]...) }

type Observation struct {
	Kind         ObservationKind
	Profile      Profile
	Path         Path
	Load         LoadCell
	Index        uint64
	IntentRawNS  uint64
	DurableAckNS uint64
}

type TerminationObservation struct {
	Role           string
	StopIntentNS   uint64
	PIDFDExitRawNS uint64
}

type CampaignEvidence struct {
	Observations       []Observation
	Terminations       []TerminationObservation
	FailedSamples      uint64
	RuntimeCredit      int
	CasesCredited      int
	InvariantsCredited int
	S1Pass             bool
	S2Authorized       bool
}

type Candidates struct {
	HQuietMS            uint64 `json:"h_quiet_ms_candidate"`
	SentinelCadenceMS   uint64 `json:"sentinel_cadence_ms_candidate"`
	SentinelCount       uint64 `json:"sentinel_count_candidate"`
	CleanupTimeoutMS    uint64 `json:"process_termination_timeout_ms_candidate"`
	Status              string `json:"status"`
	RuntimeCredit       int    `json:"authoritative_runtime_credit"`
	NumericRatification bool   `json:"numeric_ratification"`
}

func ExpectedActionCount() int {
	return len(profileCatalog) * len(loadCatalog) * SamplesPerProfilePathLoad
}
func ExpectedObservationCount() int { return ExpectedActionCount() * len(pathCatalog) }

func ValidateAndDerive(evidence CampaignEvidence) (Candidates, error) {
	if ExpectedActionCount() != TotalActionIndices || ExpectedObservationCount() != TotalPathObservations ||
		evidence.FailedSamples != 0 || evidence.RuntimeCredit != 0 || evidence.CasesCredited != 0 ||
		evidence.InvariantsCredited != 0 || evidence.S1Pass || evidence.S2Authorized {
		return Candidates{}, ErrPopulationIncomplete
	}
	seenCalibration := make(map[string]struct{}, TotalPathObservations)
	seenAuxiliary := make(map[string]struct{})
	var maxLatency uint64
	for _, observation := range evidence.Observations {
		if !knownProfile(observation.Profile) || !knownPath(observation.Path) || !knownLoad(observation.Load) ||
			observation.Index == 0 || observation.DurableAckNS < observation.IntentRawNS || !knownObservationKind(observation.Kind) {
			return Candidates{}, ErrPopulationIncomplete
		}
		key := fmt.Sprintf("%s/%s/%s/%s/%d", observation.Kind, observation.Profile, observation.Path, observation.Load, observation.Index)
		if observation.Kind == ObservationCalibration {
			if observation.Index > SamplesPerProfilePathLoad {
				return Candidates{}, ErrPopulationIncomplete
			}
			if _, duplicate := seenCalibration[key]; duplicate {
				return Candidates{}, ErrPopulationIncomplete
			}
			seenCalibration[key] = struct{}{}
		} else {
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
	if len(seenCalibration) != TotalPathObservations || !completeAuxiliaryPopulation(seenAuxiliary) {
		return Candidates{}, ErrPopulationIncomplete
	}
	maxExit, err := validateTerminations(evidence.Terminations)
	if err != nil {
		return Candidates{}, err
	}
	h := ceilNSToMS(maxLatency)
	return Candidates{HQuietMS: h, SentinelCadenceMS: h, SentinelCount: ProposedSentinelCount,
		CleanupTimeoutMS: ceilNSToMS(maxExit), Status: "PROPOSED_ONLY_PHASE_II_AND_NUMERIC_RULING_REQUIRED"}, nil
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
