package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualSP259StartupConfigurationClone(t *testing.T) {
	var absent *DRWAStartupConfiguration
	require.Nil(t, absent.Clone())
	original := &DRWAStartupConfiguration{RecordDigest: [32]byte{1}, MainConfigDigest: [32]byte{2}, RestartConfigDigest: [32]byte{3}, Exclusions: []HardforkRoundExclusionConfig{{StartRound: 10, EndRound: 20}}}
	cloned := original.Clone()
	require.Equal(t, original, cloned)
	require.NotSame(t, original, cloned)
	cloned.RecordDigest[0]++
	cloned.Exclusions[0].EndRound++
	require.Equal(t, byte(1), original.RecordDigest[0])
	require.Equal(t, uint64(20), original.Exclusions[0].EndRound)
	carrier := &DRWAInitialProgrammeStartup{SelectedConfiguration: original, PredecessorConfiguration: original}
	copy := carrier.Clone()
	require.Equal(t, carrier, copy)
	copy.PredecessorConfiguration.Exclusions[0].EndRound++
	require.Equal(t, uint64(20), carrier.PredecessorConfiguration.Exclusions[0].EndRound)
	require.Equal(t, uint64(20), copy.SelectedConfiguration.Exclusions[0].EndRound)
}
