package drwa

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualSP237OrdinaryPhaseViewCopy(t *testing.T) {
	t.Parallel()

	original := lifecycleReadView{
		token: []byte("sample"), cebHash: []byte("summary"),
		closurePlan: []byte("plan"), supplyOrigin: []byte("label"),
		cebEpoch: 4, supplyOriginShard: 2, tokenType: 1,
		activation: "activation label", lifecycle: "phase label",
	}
	copyView := cloneLifecycleReadView(original)
	require.Equal(t, original, copyView)

	copyView.token[0] = 'S'
	copyView.cebHash[0] = 'S'
	copyView.closurePlan[0] = 'P'
	copyView.supplyOrigin[0] = 'L'
	require.Equal(t, []byte("sample"), original.token)
	require.Equal(t, []byte("summary"), original.cebHash)
	require.Equal(t, []byte("plan"), original.closurePlan)
	require.Equal(t, []byte("label"), original.supplyOrigin)

	original.token[1] = 'A'
	require.Equal(t, []byte("Sample"), copyView.token)
}
