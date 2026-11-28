package drwa

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// The canonical leg of a role grant: opened on the metachain, applied once on
// the holder's shard through the native role built-in, acknowledged from
// canonical-final evidence, closed.
func TestQualSP232RoleGrantFromItsCanonicalOrigin(t *testing.T) {
	w := sp232New(t)
	shard := w.shards[1]
	id, transfers := w.open(w.grant(1, core.ESDTRoleLocalMint))

	open, err := w.effects.Read(id)
	require.NoError(t, err)
	require.Equal(t, uint32(1), open.Legs)
	require.Equal(t, []byte{0}, open.Acknowledged)
	require.Equal(t, core.ESDTSCAddress, transfers[0].SenderAddress)

	require.Empty(t, shard.roles())
	output, err := shard.deliver(transfers[0])
	require.NoError(t, err)
	require.Equal(t, vmcommon.Ok, output.ReturnCode)
	require.Equal(t, sp232Roles(core.ESDTRoleLocalMint), shard.roles())
	require.Equal(t, uint64(sp232LegGas-40), output.GasRemaining)
	require.Equal(t, id, output.ReturnData[0])

	shard.settle()
	progress, err := w.acknowledge(shard, id, 0)
	require.NoError(t, err)
	require.Equal(t, AdminEffectProgress{Applied: true, Closed: true, Remaining: 5}, progress)
	open, err = w.effects.Read(id)
	require.NoError(t, err)
	require.Nil(t, open)
	require.Equal(t, CarrierTerminal, w.fundingState(id).Phase)
}
