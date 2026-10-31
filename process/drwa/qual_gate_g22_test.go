package drwa

import (
	"testing"

	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func TestQualGateG22NativeDependency(t *testing.T) {
	r, user := qualSystemSCOrdinaryCandidate(t)
	f := qualSystemSCNative(t, user, r)
	observed := false
	f.onRead = func() {
		f.onRead = nil
		observed = true
		called := false
		err := r.RegisterToken(func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
			called = true
			return nil, nil, nil
		})
		require.ErrorIs(t, err, ErrExecutionBusy)
		require.False(t, called, "native account read must retain classification dependency")
		_, _, err = r.commit()
		require.ErrorIs(t, err, ErrExecutionBusy)
		handoff := f.runtime.(interface {
			ReplaceDRWAClassifier(vm.DRWATokenClassifier) error
		})
		require.ErrorIs(t, handoff.ReplaceDRWAClassifier(r), vm.ErrDRWAExecution)
	}
	before, err := user.RootHash()
	require.NoError(t, err)
	out, err := f.runtime.RunSmartContractCall(qualSystemSCOwnerCall("pause"))
	require.NoError(t, err)
	require.True(t, observed)
	require.Equal(t, vmcommon.Ok, out.ReturnCode)
	require.NotEmpty(t, out.OutputAccounts)
	after, err := user.RootHash()
	require.NoError(t, err)
	require.Equal(t, before, after)
	require.Zero(t, user.JournalLen(), "native output has not been persisted by this unit fixture")
}

// Nil native call ingress retains the pinned upstream limitation. A caught panic
// is a characterization restriction and never rejection or containment credit.
func TestQualGateG22NilIngressRestriction(t *testing.T) {
	r, user := qualSystemSCOrdinaryCandidate(t)
	f := qualSystemSCNative(t, user, r)
	out, err := f.runtime.RunSmartContractCreate(nil)
	require.Nil(t, out)
	require.ErrorIs(t, err, vm.ErrInputArgsIsNil)
	require.Panics(t, func() { _, _ = f.runtime.RunSmartContractCall(nil) })
	require.Zero(t, f.reads)
	called := false
	want := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}
	out, err = f.context.(vm.DRWASystemCallContext).ExecuteDRWASystemCall(nil, func() (*vmcommon.VMOutput, error) {
		called = true
		return want, nil
	})
	require.NoError(t, err)
	require.True(t, called)
	require.Same(t, want, out)
}
