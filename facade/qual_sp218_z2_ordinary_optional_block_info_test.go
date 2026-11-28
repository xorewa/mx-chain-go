package facade

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/api"
	"github.com/stretchr/testify/require"
)

// Absent optional display metadata has the same zero-value DTO as any other
// absent block-information representation. No query or facade is invoked.
func TestQualSP218OrdinaryBlockInfoOptionalDisplay(t *testing.T) {
	t.Parallel()

	require.Equal(t, api.BlockInfo{}, queryBlockInfoToApiResource(nil))
}
