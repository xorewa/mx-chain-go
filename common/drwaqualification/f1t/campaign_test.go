package f1t

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCampaignExactPopulationAndConditionalFormula(t *testing.T) {
	require.Equal(t, 64442, ExpectedActionCount())
	require.Equal(t, 193326, ExpectedObservationCount())
	require.GreaterOrEqual(t, ConditionalWilksCoverage(), 0.99)
	evidence := completeCampaignEvidence()
	candidates, err := ValidateAndDerive(evidence)
	require.NoError(t, err)
	require.Equal(t, uint64(4), candidates.SentinelCount)
	require.Equal(t, "PROPOSED_ONLY_PHASE_II_AND_NUMERIC_RULING_REQUIRED", candidates.Status)
	require.False(t, candidates.NumericRatification)
	require.Zero(t, candidates.RuntimeCredit)

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

func completeCampaignEvidence() CampaignEvidence {
	observations := make([]Observation, 0, TotalPathObservations+252)
	for _, profile := range Profiles() {
		for _, load := range LoadCells() {
			for _, path := range Paths() {
				for index := 1; index <= SamplesPerProfilePathLoad; index++ {
					observations = append(observations, Observation{Kind: ObservationCalibration, Profile: profile, Load: load, Path: path,
						Index: uint64(index), IntentRawNS: 1, DurableAckNS: uint64(index) + 1})
				}
				observations = append(observations,
					Observation{Kind: ObservationReadiness, Profile: profile, Load: load, Path: path, Index: 1, IntentRawNS: 1, DurableAckNS: 2},
					Observation{Kind: ObservationSelectedShape, Profile: profile, Load: load, Path: path, Index: 1, IntentRawNS: 1, DurableAckNS: 2})
				for index := 1; index <= ProposedSentinelCount; index++ {
					observations = append(observations, Observation{Kind: ObservationSentinel, Profile: profile, Load: load, Path: path,
						Index: uint64(index), IntentRawNS: 1, DurableAckNS: 2})
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

type reconnectProbe struct {
	calls  []string
	failAt string
}

func (probe *reconnectProbe) CloseConnections(context.Context) error { return probe.call("close") }
func (probe *reconnectProbe) Reconnect(context.Context) error        { return probe.call("reconnect") }
func (probe *reconnectProbe) ProveReadiness(context.Context) error   { return probe.call("ready") }
func (probe *reconnectProbe) call(name string) error {
	probe.calls = append(probe.calls, name)
	if probe.failAt == name {
		return errors.New("injected reconnect failure")
	}
	return nil
}

func TestRecentReconnectRequiresExactCloseReconnectReadinessOrder(t *testing.T) {
	config := LoadConfig{CPUWorkers: 1, SchedulerWorkers: 1, GCRingEntries: 4, GCEntryBytes: 16, FsyncBlocks: 2, FsyncBlockBytes: 4096}
	_, err := StartLoad(context.Background(), LoadReconnect, t.TempDir(), config)
	require.Error(t, err)
	probe := &reconnectProbe{}
	handle, err := StartLoadWithReconnect(context.Background(), LoadReconnect, t.TempDir(), config, probe)
	require.NoError(t, err)
	require.Equal(t, []string{"close", "reconnect", "ready"}, probe.calls)
	require.NoError(t, handle.Stop())
}
