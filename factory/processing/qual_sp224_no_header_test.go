package processing

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/process/drwa"
)

// SP2-24 open point D-2, evidence only; no product code belongs to it. It
// records what a hook that carries the built-in admission does TODAY before any
// header was installed in it: the hook's empty header has epoch 0 and round 0,
// which is before the enforcement of this deployment (epoch 12, round 440), so
// the admission is not applied. The owner decides whether that stays.
func TestQualSP224BuiltInAdmissionOnAHookWithNoHeaderInstalled(t *testing.T) {
	resolved := func() *qualSP225RegistrySource {
		return &qualSP225RegistrySource{regulated: map[string]bool{qualSP225Regulated: true}}
	}
	for route := range (&qualSP225Shard{}).routes(qualSP225Ordinary) {
		t.Run(route, func(t *testing.T) {
			enabled, native := qualSP224ShardNode(t, true, resolved()), qualSP224ShardNode(t, false, nil)
			for _, node := range []*qualSP225Shard{enabled, native} {
				require.Zero(t, node.hook.CurrentEpoch())
				require.Zero(t, node.hook.CurrentRound())
				require.Zero(t, node.hook.CurrentNonce())
			}
			// Ordinary and unknown identifiers: as on the node without DRWA.
			for _, token := range []string{qualSP225Ordinary, "UNKNOWN-abcdef", qualSP225Regulated} {
				expected, nativeErr := native.hook.ProcessBuiltInFunction(native.routes(token)[route])
				actual, enabledErr := enabled.hook.ProcessBuiltInFunction(enabled.routes(token)[route])
				require.Equal(t, nativeErr, enabledErr, token)
				require.Equal(t, expected, actual, token)
			}
			require.Zero(t, enabled.source.asked, "the admission was not consulted: the regulated identifier took the native path")

			// Control: the same hook after a header at the enforcement coordinate.
			require.NoError(t, enabled.hook.SetCurrentHeader(&block.Header{Epoch: 12, Round: 440, Nonce: 5}))
			output, err := enabled.hook.ProcessBuiltInFunction(enabled.routes(qualSP225Regulated)[route])
			require.ErrorIs(t, err, drwa.ErrRegulatedTokenOperation)
			require.Nil(t, output)
			require.Positive(t, enabled.source.asked)
		})
	}
}
