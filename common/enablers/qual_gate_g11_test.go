package enablers_test

import (
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/enablers"
	"github.com/multiversx/mx-chain-go/statusHandler"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/epochNotifier"
	"github.com/stretchr/testify/require"
)

// G11: distinct experimental thresholds expose crossed configuration fields.
// The oracle is the four inclusive predicates in pinned node v2.1.9.
func TestQualGateG11LoadedFlagsAndMetrics(t *testing.T) {
	p := filepath.Join(t.TempDir(), "epochs.toml")
	require.NoError(t, os.WriteFile(p, []byte(`[EnableEpochs]
FixDataTrieLeafValidationEnableEpoch = 11
FixCorrectSmallIntAndGasLimitsEnableEpoch = 23
OutputRollbackOnDestContextEnableEpoch = 37
KeepReturnDataOnAsyncTransferCallbackEnableEpoch = 53
`), 0600))
	cfg, err := common.LoadEpochConfig(p)
	require.NoError(t, err)
	h, err := enablers.NewEnableEpochsHandler(cfg.EnableEpochs, &epochNotifier.EpochNotifierStub{})
	require.NoError(t, err)
	m, err := statusHandler.NewStatusMetrics(h, &testscommon.EnableRoundsHandlerStub{})
	require.NoError(t, err)
	cases := []struct {
		field string
		flag  core.EnableEpochFlag
		at    uint32
	}{
		{"FixDataTrieLeafValidationEnableEpoch", common.FixDataTrieLeafValidationFlag, 11},
		{"FixCorrectSmallIntAndGasLimitsEnableEpoch", common.FixCorrectSmallIntAndGasLimitsFlag, 23},
		{"OutputRollbackOnDestContextEnableEpoch", common.OutputRollbackOnDestContextFlag, 37},
		{"KeepReturnDataOnAsyncTransferCallbackEnableEpoch", common.KeepReturnDataOnAsyncTransferCallbackFlag, 53},
	}
	for _, c := range cases {
		t.Run(c.field, func(t *testing.T) {
			require.True(t, h.IsFlagDefined(c.flag))
			require.Equal(t, c.at, h.GetActivationEpoch(c.flag), "independent loaded field")
			value, exists := m.EnableEpochsMetricsV2()[c.field]
			require.True(t, exists, "metric name")
			require.Equal(t, c.at, value, "metric value")
			for _, epoch := range []uint32{0, 10, 11, 12, 22, 23, 24, 36, 37, 38, 52, 53, 54, math.MaxUint32} {
				// A contrary current epoch cannot replace explicit query coordinates.
				h.EpochConfirmed(0, 0)
				require.Equal(t, epoch >= c.at, h.IsFlagEnabledInEpoch(c.flag, epoch), "explicit epoch %d", epoch)
				h.EpochConfirmed(epoch, 0)
				require.Equal(t, epoch, h.GetCurrentEpoch())
				require.Equal(t, epoch >= c.at, h.IsFlagEnabled(c.flag), "notified epoch %d", epoch)
			}
			// Metrics are exported snapshots, not writable aliases to configuration.
			published := m.EnableEpochsMetricsV2()
			published[c.field] = 999
			require.Equal(t, c.at, m.EnableEpochsMetricsV2()[c.field])
		})
	}
}

func TestQualGateG11PackagedConfiguration(t *testing.T) {
	cfg, err := common.LoadEpochConfig("../../cmd/node/config/enableEpochs.toml")
	require.NoError(t, err)
	require.Equal(t, uint32(1), cfg.EnableEpochs.FixDataTrieLeafValidationEnableEpoch)
	require.Equal(t, uint32(2), cfg.EnableEpochs.FixCorrectSmallIntAndGasLimitsEnableEpoch)
	require.Equal(t, uint32(2), cfg.EnableEpochs.OutputRollbackOnDestContextEnableEpoch)
	require.Equal(t, uint32(2), cfg.EnableEpochs.KeepReturnDataOnAsyncTransferCallbackEnableEpoch)
}
