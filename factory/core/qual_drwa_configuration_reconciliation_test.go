package core

import (
	"testing"

	"github.com/multiversx/mx-chain-go/config"
	factoryBlock "github.com/multiversx/mx-chain-go/factory/block"
	"github.com/stretchr/testify/require"
)

// Non-normative U0-RIDER-001/E05 source reconciliation, Plan UQ-02.
// Exercise the actual reader and actual in-place sorter, not copies of them.
// Synthetic repeated version labels demonstrate order sensitivity; this does
// not establish that the complete node admits such a configuration.
func TestQualDRWAHeaderVersionReaderOrder(t *testing.T) {
	versions := []config.VersionByEpochs{
		{StartEpoch: 0, Version: "1"},
		{StartEpoch: 20, StartRound: 200, Version: supernovaHeaderVersion},
		{StartEpoch: 10, StartRound: 100, Version: supernovaHeaderVersion},
	}
	before := append([]config.VersionByEpochs(nil), versions...)
	require.NoError(t, checkSupernovaVersionEntry(versions, 20, 200), "first matching label controls the reader")
	handler, err := factoryBlock.NewHeaderVersionHandler(versions, "1")
	require.NoError(t, err)
	require.Equal(t, uint32(10), versions[1].StartEpoch, "constructor sorts the caller's backing slice")
	require.Equal(t, uint32(20), before[1].StartEpoch, "independent copy retains original order")
	require.Error(t, checkSupernovaVersionEntry(versions, 20, 200))
	require.NoError(t, checkSupernovaVersionEntry(before, 20, 200))
	require.Equal(t, supernovaHeaderVersion, handler.GetVersion(20, 200))
}

func TestQualDRWAHeaderVersionSingleEntryControl(t *testing.T) {
	versions := []config.VersionByEpochs{
		{StartEpoch: 20, StartRound: 200, Version: supernovaHeaderVersion},
		{StartEpoch: 0, Version: "1"},
	}
	require.NoError(t, checkSupernovaVersionEntry(versions, 20, 200))
	_, err := factoryBlock.NewHeaderVersionHandler(versions, "1")
	require.NoError(t, err)
	require.NoError(t, checkSupernovaVersionEntry(versions, 20, 200))
	require.Error(t, checkSupernovaVersionEntry(versions, 20, 201))
}

// U0-RIDER-002: this helper enforces equality before activation, not a complete
// positivity/range/startup predicate. Later core/economics/chronology consumers
// remain separate obligations. No deployment duration is selected here.
func TestQualDRWARoundDurationValidatorBoundary(t *testing.T) {
	for _, tc := range []struct {
		name      string
		entries   []config.ChainParametersByEpochConfig
		wantError bool
	}{
		{"constant_before_activation", []config.ChainParametersByEpochConfig{{EnableEpoch: 0, RoundDuration: 6000}, {EnableEpoch: 9, RoundDuration: 6000}}, false},
		{"changed_before_activation", []config.ChainParametersByEpochConfig{{EnableEpoch: 0, RoundDuration: 6000}, {EnableEpoch: 9, RoundDuration: 1000}}, true},
		{"zero_at_activation_not_rejected_here", []config.ChainParametersByEpochConfig{{EnableEpoch: 0, RoundDuration: 6000}, {EnableEpoch: 10, RoundDuration: 0}}, false},
		{"missing_genesis_not_rejected_here", []config.ChainParametersByEpochConfig{{EnableEpoch: 9, RoundDuration: 0}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRoundDurationChanges(tc.entries, 10)
			if tc.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
