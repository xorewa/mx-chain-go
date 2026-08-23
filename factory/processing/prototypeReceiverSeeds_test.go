package processing

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/config"
	processGenesis "github.com/multiversx/mx-chain-go/genesis/process"
)

func TestValidatePrototypeDRWAReceiverSeedingMode(t *testing.T) {
	t.Parallel()

	oneSeed := []config.PrototypeDRWAReceiverSeedConfig{{HolderAddress: "configured"}}
	tests := map[string]struct {
		seeds      []config.PrototypeDRWAReceiverSeedConfig
		hardFork   config.HardforkConfig
		startEpoch uint32
		wantError  bool
	}{
		"empty list remains valid during hard-fork import": {
			hardFork:   config.HardforkConfig{AfterHardFork: true, StartEpoch: 10},
			startEpoch: 10,
		},
		"non-empty fresh genesis is valid": {
			seeds: oneSeed,
		},
		"non-empty restart after import epoch does not re-seed": {
			seeds:      oneSeed,
			hardFork:   config.HardforkConfig{AfterHardFork: true, StartEpoch: 10},
			startEpoch: 11,
		},
		"non-empty hard-fork import is rejected": {
			seeds:      oneSeed,
			hardFork:   config.HardforkConfig{AfterHardFork: true, StartEpoch: 10},
			startEpoch: 10,
			wantError:  true,
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := validatePrototypeDRWAReceiverSeedingMode(test.seeds, test.hardFork, test.startEpoch)
			if test.wantError {
				require.ErrorIs(t, err, processGenesis.ErrInvalidPrototypeDRWAReceiverSeeds)
				return
			}
			require.NoError(t, err)
		})
	}
}
