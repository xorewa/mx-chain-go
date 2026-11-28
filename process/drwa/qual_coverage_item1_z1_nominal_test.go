package drwa

import (
	"testing"

	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Two independent local fixture stores participate in a normal, fully completed
// accounting lifecycle. All receipt assertions concern only participating stores
// and their legitimate committed roots; there are no fault or rejection inputs.
func TestQualCoverageItem1NominalMultiStoreAccounting(t *testing.T) {
	t.Run("commit both stores", func(t *testing.T) {
		a, b := qualContainmentStore(t), qualContainmentStore(t)
		owner, err := newNativeRollbackContainment(a, b)
		require.NoError(t, err)
		output := &vmcommon.VMOutput{GasRemaining: 100}
		require.NoError(t, owner.Execute(func() (*vmcommon.VMOutput, error) {
			if err := qualContainmentBalance(a, 95); err != nil {
				return nil, err
			}
			return output, qualContainmentBalance(b, 105)
		}))
		require.NoError(t, owner.nativeBeforeCommit())
		rootA, err := a.Commit()
		require.NoError(t, err)
		rootB, err := b.Commit()
		require.NoError(t, err)
		roots, outputs, err := owner.nativeCommitReceipt()
		require.NoError(t, err)
		require.Equal(t, [][]byte{rootA, rootB}, roots)
		require.Equal(t, []*vmcommon.VMOutput{output}, outputs)
		require.NoError(t, owner.nativeCommittedFor(a))
		require.NoError(t, owner.nativeCommittedFor(b))
		qualAssertContainmentBalance(t, a, 95)
		qualAssertContainmentBalance(t, b, 105)
		require.Zero(t, a.JournalLen())
		require.Zero(t, b.JournalLen())
	})
	t.Run("close a locally cancelled empty operation", func(t *testing.T) {
		a, b := qualContainmentStore(t), qualContainmentStore(t)
		beforeA, err := a.RootHash()
		require.NoError(t, err)
		beforeB, err := b.RootHash()
		require.NoError(t, err)
		owner, err := newNativeRollbackContainment(a, b)
		require.NoError(t, err)
		// Nothing was sent for execution. The owner records the normal reset of
		// its unchanged stores without touching protected state or injecting errors.
		require.NoError(t, owner.nativeResetReceipt())
		require.NoError(t, owner.nativeResetFor(a))
		require.NoError(t, owner.nativeResetFor(b))
		afterA, err := a.RootHash()
		require.NoError(t, err)
		afterB, err := b.RootHash()
		require.NoError(t, err)
		require.Equal(t, beforeA, afterA)
		require.Equal(t, beforeB, afterB)
		qualAssertContainmentBalance(t, a, 100)
		qualAssertContainmentBalance(t, b, 100)
		require.Zero(t, a.JournalLen())
		require.Zero(t, b.JournalLen())
	})
}
