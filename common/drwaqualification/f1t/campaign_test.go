package f1t

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCampaignExactPopulationAndConditionalFormula(t *testing.T) {
	require.Equal(t, 55236, ExpectedActionCount())
	require.Equal(t, 165708, ExpectedObservationCount())
	require.Equal(t, TotalAuxiliaryIntents, len(Profiles())*len(LoadCells())*(2+ProposedSentinelCount))
	require.Equal(t, TotalAuxiliaryObservations, TotalAuxiliaryIntents*len(Paths()))
	require.Equal(t, TotalObservations, ExpectedTotalObservationCount())
	require.Equal(t, 6, len(LoadCells()))
	require.NotContains(t, LoadCells(), LoadCell("RECENT_RECONNECT"))
	require.GreaterOrEqual(t, ConditionalWilksCoverage(), 0.99)
	evidence := completeCampaignEvidence()
	candidates, err := ValidateAndDerive(evidence)
	require.NoError(t, err)
	require.Equal(t, uint64(4), candidates.SentinelCount)
	require.Equal(t, "PROPOSED_ONLY_PHASE_II_AND_NUMERIC_RULING_REQUIRED", candidates.Status)
	require.False(t, candidates.NumericRatification)
	require.Zero(t, candidates.RuntimeCredit)
	require.False(t, candidates.Diagnostics.IIDProved)
	require.False(t, candidates.Diagnostics.StationaryProved)

	evidence.Observations = evidence.Observations[:len(evidence.Observations)-1]
	_, err = ValidateAndDerive(evidence)
	require.ErrorIs(t, err, ErrPopulationIncomplete)
}

func TestCampaignRejectsCreditFailureAndMutableCatalogAttacks(t *testing.T) {
	evidence := completeCampaignEvidence()
	evidence.RuntimeCredit = 1
	_, err := ValidateAndDerive(evidence)
	require.ErrorIs(t, err, ErrPopulationIncomplete)

	profiles := Profiles()
	profiles[0] = "MUTATED"
	require.Equal(t, ProfileLegacy, Profiles()[0])
	require.Len(t, DeterministicRoundRobinKeys(), TotalActionIndices)
}

func TestCampaignRejectsPopulationAndAuthorityMutations(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*CampaignEvidence)
	}{
		{name: "failed sample", mutate: func(evidence *CampaignEvidence) { evidence.FailedSamples = 1 }},
		{name: "case credit", mutate: func(evidence *CampaignEvidence) { evidence.CasesCredited = 1 }},
		{name: "invariant credit", mutate: func(evidence *CampaignEvidence) { evidence.InvariantsCredited = 1 }},
		{name: "S1 pass", mutate: func(evidence *CampaignEvidence) { evidence.S1Pass = true }},
		{name: "S2 authority", mutate: func(evidence *CampaignEvidence) { evidence.S2Authorized = true }},
		{name: "unknown profile", mutate: func(evidence *CampaignEvidence) { evidence.Observations[0].Profile = "UNKNOWN" }},
		{name: "unknown path", mutate: func(evidence *CampaignEvidence) { evidence.Observations[0].Path = "UNKNOWN" }},
		{name: "unknown load", mutate: func(evidence *CampaignEvidence) { evidence.Observations[0].Load = "UNKNOWN" }},
		{name: "zero index", mutate: func(evidence *CampaignEvidence) { evidence.Observations[0].Index = 0 }},
		{name: "clock regression", mutate: func(evidence *CampaignEvidence) { evidence.Observations[0].DurableAckNS = 0 }},
		{name: "duplicate observation", mutate: func(evidence *CampaignEvidence) { evidence.Observations[1] = evidence.Observations[0] }},
		{name: "substituted action index", mutate: func(evidence *CampaignEvidence) { evidence.Observations[0].ActionIndex++ }},
		{name: "path intent mismatch", mutate: func(evidence *CampaignEvidence) { evidence.Observations[1].IntentRawNS++ }},
		{name: "equal timestamp durable reorder", mutate: func(evidence *CampaignEvidence) {
			evidence.Observations[0].IntentRawNS = 10
			evidence.Observations[1].IntentRawNS = 10
			evidence.Observations[0], evidence.Observations[1] = evidence.Observations[1], evidence.Observations[0]
		}},
		{name: "action order regression", mutate: func(evidence *CampaignEvidence) {
			for index := range evidence.Observations {
				if evidence.Observations[index].Kind == ObservationCalibration && evidence.Observations[index].ActionIndex == 2 {
					evidence.Observations[index].IntentRawNS = 0
					evidence.Observations[index].DurableAckNS = 1
				}
			}
		}},
		{name: "missing termination", mutate: func(evidence *CampaignEvidence) { evidence.Terminations = evidence.Terminations[:2] }},
		{name: "duplicate termination", mutate: func(evidence *CampaignEvidence) { evidence.Terminations[1].Role = evidence.Terminations[0].Role }},
		{name: "termination clock regression", mutate: func(evidence *CampaignEvidence) { evidence.Terminations[0].PIDFDExitRawNS = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence := completeCampaignEvidence()
			test.mutate(&evidence)
			_, err := ValidateAndDerive(evidence)
			require.ErrorIs(t, err, ErrPopulationIncomplete)
		})
	}
}

func TestCampaignPathReceiptContractRejectsExecutionAndRouteMutations(t *testing.T) {
	action := CampaignActionPayload{Kind: ObservationCalibration, Profile: ProfileV2, Load: LoadBaseline, Index: 1, ActionIndex: 1}
	valid := []PathReceipt{
		{Path: PathRemoteTarget, DurableAckNS: 11},
		{Path: PathRemotePassive, DurableAckNS: 12},
		{Path: PathSelfDirect, DurableAckNS: 13},
	}
	tests := []struct {
		name     string
		intent   uint64
		receipts []PathReceipt
	}{
		{name: "empty executor output", intent: 10, receipts: nil},
		{name: "zero intent", intent: 0, receipts: valid},
		{name: "missing receipt", intent: 10, receipts: valid[:2]},
		{name: "extra receipt", intent: 10, receipts: append(append([]PathReceipt(nil), valid...), valid[0])},
		{name: "passive routed to target", intent: 10, receipts: []PathReceipt{valid[0], valid[0], valid[2]}},
		{name: "self direct replaced by remote", intent: 10, receipts: []PathReceipt{valid[0], valid[1], valid[0]}},
		{name: "receipt before shared intent", intent: 12, receipts: valid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observations := make([]Observation, 0, 3)
			err := appendPathObservations(&observations, action, test.intent, test.receipts)
			require.ErrorIs(t, err, ErrPopulationIncomplete)
			require.Empty(t, observations)
		})
	}

	observations := make([]Observation, 0, 3)
	require.NoError(t, appendPathObservations(&observations, action, 10, valid))
	require.Len(t, observations, 3)
	for index, observation := range observations {
		require.Equal(t, uint64(10), observation.IntentRawNS, "all paths must bind the one logical-intent timestamp")
		require.Equal(t, valid[index].Path, observation.Path)
	}
}

func TestCampaignCandidateFormulaUsesEveryEligibleObservationClass(t *testing.T) {
	evidence := completeCampaignEvidence()
	evidence.Observations[0].DurableAckNS = 2_000_002
	evidence.Terminations[2].PIDFDExitRawNS = 3_000_002
	candidates, err := ValidateAndDerive(evidence)
	require.NoError(t, err)
	require.Equal(t, uint64(3), candidates.HQuietMS)
	require.Equal(t, candidates.HQuietMS, candidates.SentinelCadenceMS)
	require.Equal(t, uint64(4), candidates.CleanupTimeoutMS)

	for _, kind := range []ObservationKind{ObservationReadiness, ObservationSelectedShape, ObservationSentinel} {
		evidence = completeCampaignEvidence()
		for index := range evidence.Observations {
			if evidence.Observations[index].Kind == kind {
				evidence.Observations[index].DurableAckNS = 5_000_002
				break
			}
		}
		candidates, err = ValidateAndDerive(evidence)
		require.NoError(t, err)
		require.Equal(t, uint64(6), candidates.HQuietMS, kind)
	}
}

func TestCampaignDiagnosticFailureInvalidatesWholeCandidateSet(t *testing.T) {
	evidence := completeCampaignEvidence()
	for index := range evidence.Observations {
		observation := &evidence.Observations[index]
		if observation.Kind == ObservationCalibration && observation.Profile == ProfileLegacy &&
			observation.Path == PathRemoteTarget && observation.Load == LoadBaseline {
			observation.DurableAckNS = observation.IntentRawNS + observation.Index
		}
	}
	_, err := ValidateAndDerive(evidence)
	require.ErrorIs(t, err, ErrDiagnostics)
}

func completeCampaignEvidence() CampaignEvidence {
	observations := make([]Observation, 0, TotalPathObservations+252)
	for index := 1; index <= SamplesPerProfilePathLoad; index++ {
		for _, profile := range Profiles() {
			for _, load := range LoadCells() {
				action := expectedActionIndex(profile, load, uint64(index))
				intent := action
				for _, path := range Paths() {
					latency := deterministicDiagnosticLatency(uint64(index))
					observations = append(observations, Observation{Kind: ObservationCalibration, Profile: profile, Load: load, Path: path,
						Index: uint64(index), ActionIndex: action, DurableSequence: uint64(len(observations) + 1), IntentRawNS: intent, DurableAckNS: intent + latency})
				}
			}
		}
	}
	for _, profile := range Profiles() {
		for _, load := range LoadCells() {
			for _, kind := range []ObservationKind{ObservationReadiness, ObservationSelectedShape} {
				for _, path := range Paths() {
					observations = append(observations,
						Observation{Kind: kind, Profile: profile, Load: load, Path: path, Index: 1, DurableSequence: uint64(len(observations) + 1), IntentRawNS: 1, DurableAckNS: 2})
				}
			}
			for index := 1; index <= ProposedSentinelCount; index++ {
				for _, path := range Paths() {
					observations = append(observations, Observation{Kind: ObservationSentinel, Profile: profile, Load: load, Path: path,
						Index: uint64(index), DurableSequence: uint64(len(observations) + 1), IntentRawNS: 1, DurableAckNS: 2})
				}
			}
		}
	}
	return CampaignEvidence{Observations: observations, Terminations: []TerminationObservation{
		{Role: "publisher", StopIntentNS: 1, PIDFDExitRawNS: 2},
		{Role: "target", StopIntentNS: 1, PIDFDExitRawNS: 3},
		{Role: "passive", StopIntentNS: 1, PIDFDExitRawNS: 4},
	}}
}

func deterministicDiagnosticLatency(index uint64) uint64 {
	value := index + 0x9e3779b97f4a7c15
	value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9
	value = (value ^ (value >> 27)) * 0x94d049bb133111eb
	value ^= value >> 31
	return 1 + value%1_000_000
}

func TestLoadConfigurationIsBounded(t *testing.T) {
	config := LoadConfig{CPUWorkers: 1, SchedulerWorkers: 1, GCRingEntries: 4, GCEntryBytes: 16, FsyncBlocks: 2, FsyncBlockBytes: 4096}
	handle, err := StartLoad(context.Background(), LoadFsync, t.TempDir(), config)
	require.NoError(t, err)
	require.NoError(t, handle.Stop())
	require.NoError(t, handle.Stop())

	invalid := config
	invalid.GCRingEntries = 3
	require.Error(t, invalid.Validate())

	realRoot := t.TempDir()
	symlinkRoot := filepath.Join(t.TempDir(), "linked-root")
	require.NoError(t, os.Symlink(realRoot, symlinkRoot))
	_, err = StartLoad(context.Background(), LoadBaseline, symlinkRoot, config)
	require.Error(t, err)
}

func TestEveryLoadCellStartsAndStopsWithBoundedTestConfiguration(t *testing.T) {
	config := LoadConfig{CPUWorkers: 1, SchedulerWorkers: 2, GCRingEntries: 4, GCEntryBytes: 16, FsyncBlocks: 2, FsyncBlockBytes: 4096}
	for _, cell := range []LoadCell{LoadBaseline, LoadCPU, LoadScheduler, LoadGC, LoadFsync, LoadCombined} {
		t.Run(string(cell), func(t *testing.T) {
			root := t.TempDir()
			handle, err := StartLoad(context.Background(), cell, root, config)
			require.NoError(t, err)
			require.NoError(t, handle.Stop())
			_, statErr := os.Stat(filepath.Join(root, "f1t-fsync-ring.bin"))
			if cell == LoadFsync || cell == LoadCombined {
				require.NoError(t, statErr)
				return
			}
			require.ErrorIs(t, statErr, os.ErrNotExist)
		})
	}
}
