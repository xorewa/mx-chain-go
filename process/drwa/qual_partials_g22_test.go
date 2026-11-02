package drwa

import (
	"testing"

	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/vm"
	"github.com/multiversx/mx-chain-go/vm/systemSmartContracts"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Cross owner identity with lifecycle at the real context constructor. Busy
// identity validation is permitted; it does not grant execution admission.
func TestQualPartialsG22OwnerLifecycleMatrix(t *testing.T) {
	for _, lifecycle := range []string{"active", "busy", "sealed"} {
		for _, binding := range []string{"pair", "alias", "foreign-user", "foreign-peer", "nil-classifier", "typed-nil"} {
			t.Run(lifecycle+"/"+binding, func(t *testing.T) {
				var participants []state.AccountsAdapter
				peer := qualSystemSCOwnerPeer(t)
				if binding != "alias" {
					participants = append(participants, peer)
				}
				r, user := qualSystemSCOrdinaryCandidate(t, participants...)
				args := qualSystemSCBindingArgs(t, user, peer, r)
				switch binding {
				case "alias":
					args.ValidatorAccountsDB = user
				case "foreign-user":
					_, args.UserAccountsDB = qualSystemSCOrdinaryCandidate(t)
				case "foreign-peer":
					args.ValidatorAccountsDB = qualSystemSCOwnerPeer(t)
				case "nil-classifier":
					args.DRWAClassifier = nil
				case "typed-nil":
					args.DRWAClassifier = (*registrationCandidate)(nil)
				}
				before, err := user.RootHash()
				require.NoError(t, err)
				if lifecycle == "sealed" {
					_, _, err = r.commit()
					require.NoError(t, err)
				}
				inspect := func() {
					reads := user.reads
					context, createErr := systemSmartContracts.NewVMContext(args)
					allow := binding == "nil-classifier" || (lifecycle != "sealed" && (binding == "pair" || binding == "alias"))
					if allow {
						require.NoError(t, createErr)
						require.NotNil(t, context)
					} else {
						require.ErrorIs(t, createErr, vm.ErrDRWAExecution)
						require.Nil(t, context)
						if lifecycle == "sealed" && (binding == "pair" || binding == "alias") {
							require.ErrorIs(t, createErr, ErrExecutionClosed)
						}
					}
					require.Equal(t, reads, user.reads)
				}
				if lifecycle == "busy" {
					require.NoError(t, r.writer.boundary.Execute(func() (*vmcommon.VMOutput, error) { inspect(); return nil, nil }))
				} else {
					inspect()
				}
				after, err := user.RootHash()
				require.NoError(t, err)
				require.Equal(t, before, after)
				require.Zero(t, user.JournalLen())
			})
		}
	}
}

// Reach the projection mutex with a valid replacement. Passing the old owner
// again would reject earlier and could conceal a missing busy guard.
func TestQualPartialsG22ProjectionBusyHandoff(t *testing.T) {
	for _, paired := range []bool{false, true} {
		t.Run(map[bool]string{false: "alias", true: "pair"}[paired], func(t *testing.T) {
			var peers []state.AccountsAdapter
			if paired {
				peers = append(peers, qualSystemSCOwnerPeer(t))
			}
			old, user := qualSystemSCOrdinaryCandidate(t, peers...)
			f := qualSystemSCNative(t, user, old, peers...)
			next := qualNextSystemSCOwner(t, old, user, false, peers...)
			handoff := f.runtime.(qualClassifierHandoff)
			func() {
				old.view.parent.mut.Lock()
				defer old.view.parent.mut.Unlock()
				err := handoff.ReplaceDRWAClassifier(next)
				require.ErrorIs(t, err, vm.ErrDRWAExecution)
				require.ErrorIs(t, err, ErrExecutionBusy)
			}()
			require.NoError(t, f.runtime.(interface{ DRWAExecutionError() error }).DRWAExecutionError())
			require.Equal(t, 1, f.gasRegistrations)
			require.NoError(t, handoff.ReplaceDRWAClassifier(next))
			out, err := f.runtime.RunSmartContractCall(qualSystemSCOwnerCall("getTokenProperties"))
			require.NoError(t, err)
			require.Equal(t, vmcommon.Ok, out.ReturnCode)
			require.Equal(t, 1, f.gasRegistrations)
		})
	}
}
