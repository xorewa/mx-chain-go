package drwa

import (
	"bytes"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/vm"
	"github.com/multiversx/mx-chain-go/vm/systemSmartContracts"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// DS02-M6/M7: the existing shared owner can fail outside a classified VM call.
// No second public-token dispatch may be required to make that failure visible.
// Real AccountsDB/trie and System VM are reused; supplied anchors and the shared
// owner remain component fixtures, not canonical factory/scheduler admission.
// All selected values are experimental, replace/confirm before testnet (R7).
func TestQualDRWASystemSCOwnerFailureStatus(t *testing.T) {
	for _, phase := range []string{"rollback", "abort_rollback", "commit", "panic", "closed", "healthy_rollback", "healthy", "running"} {
		for _, observe := range []string{"status", "ordinary_call"} {
			t.Run(phase+"/"+observe, func(t *testing.T) {
				r, store := qualSystemSCOrdinaryCandidate(t)
				before := copyRegistryAnchor(&r.view.parent.anchor)
				selected := copyRegistryAnchor(&r.view.after)
				originalRoot, err := store.RootHash()
				require.NoError(t, err)
				f := qualSystemSCNative(t, store, r)
				status := f.runtime.(interface{ DRWAExecutionError() error })
				require.NoError(t, status.DRWAExecutionError())
				original, rollback := errors.New("experimental operation failure"), errors.New("experimental rollback failure")
				var expected error
				mutate := func() (*vmcommon.VMOutput, error) {
					a, loadErr := store.LoadAccount(core.ESDTSCAddress)
					if loadErr != nil {
						return nil, loadErr
					}
					if saveErr := a.(state.UserAccountHandler).SaveKeyValue([]byte("experimental/pending"), []byte("unpublished")); saveErr != nil {
						return nil, saveErr
					}
					if saveErr := store.SaveAccount(a); saveErr != nil {
						return nil, saveErr
					}
					return &vmcommon.VMOutput{ReturnData: [][]byte{[]byte("unpublished")}}, nil
				}
				switch phase {
				case "rollback", "healthy_rollback":
					if phase == "rollback" {
						store.revertErr, expected = rollback, rollback
					}
					err = r.writer.boundary.Execute(func() (*vmcommon.VMOutput, error) {
						_, mutationErr := mutate()
						require.NoError(t, mutationErr)
						return nil, original
					})
					require.ErrorIs(t, err, original)
					if expected != nil {
						require.ErrorIs(t, err, rollback)
					}
				case "abort_rollback":
					require.NoError(t, r.writer.boundary.Execute(mutate))
					store.revertErr, expected = rollback, rollback
					require.ErrorIs(t, r.abort(), rollback)
				case "commit":
					require.NoError(t, r.writer.boundary.Execute(mutate))
					store.commitErr, expected = original, original
					_, out, commitErr := r.commit()
					require.ErrorIs(t, commitErr, original)
					require.Nil(t, out)
				case "panic":
					expected = ErrExecutionInterrupted
					require.PanicsWithValue(t, "experimental native panic", func() {
						_ = r.writer.boundary.Execute(func() (*vmcommon.VMOutput, error) {
							_, mutationErr := mutate()
							require.NoError(t, mutationErr)
							panic("experimental native panic")
						})
					})
				case "closed":
					require.NoError(t, r.abort())
					expected = ErrExecutionClosed
				case "running":
					// A healthy contained operation may itself enter the native VM;
					// status observation is not another execution admission.
					require.NoError(t, r.writer.boundary.Execute(func() (*vmcommon.VMOutput, error) {
						require.NoError(t, status.DRWAExecutionError())
						input := qualSystemSCInput("getTokenProperties", "TOKEN-abcdef")
						input.Arguments = input.Arguments[:1]
						out, callErr := f.runtime.RunSmartContractCall(input)
						require.NoError(t, callErr)
						require.Equal(t, vmcommon.Ok, out.ReturnCode)
						return out, nil
					}))
				}
				input := qualSystemSCInput("getTokenProperties", "TOKEN-abcdef")
				input.Arguments = input.Arguments[:1]
				// This method is deliberately outside drwaPublicTokenMutation.
				var output *vmcommon.VMOutput
				if observe == "status" {
					err = status.DRWAExecutionError()
				} else {
					output, err = f.runtime.RunSmartContractCall(input)
				}
				if expected == nil {
					require.NoError(t, err)
					if observe == "ordinary_call" {
						require.Equal(t, vmcommon.Ok, output.ReturnCode)
						require.NotEmpty(t, output.ReturnData)
					}
					return
				}
				if phase == "closed" && observe == "status" {
					require.NoError(t, err, "healthy closure must not poison passive status")
					require.Zero(t, f.reads)
					output, err = f.runtime.RunSmartContractCall(input)
				}
				require.ErrorIs(t, err, vm.ErrDRWAExecution)
				require.ErrorIs(t, err, expected)
				require.Nil(t, output)
				require.Zero(t, f.reads, "no native VM account/trie effect after owner failure")
				failure := status.DRWAExecutionError()
				require.Same(t, err, failure)
				if phase == "rollback" {
					require.ErrorIs(t, failure, original)
				}
				store.revertErr, store.commitErr = nil, nil
				if phase != "closed" {
					require.NoError(t, r.recover())
				}
				root, rootErr := store.RootHash()
				require.NoError(t, rootErr)
				require.Equal(t, originalRoot, root)
				require.Zero(t, store.JournalLen())
				f.context.CleanCache()
				require.Same(t, failure, status.DRWAExecutionError(), "recovering stores does not revive the old VM")
				old, oldErr := systemSmartContracts.NewVMContext(qualSystemSCBindingArgs(t, store, store, r))
				require.ErrorIs(t, oldErr, vm.ErrDRWAExecution)
				require.ErrorIs(t, oldErr, ErrExecutionClosed)
				require.Nil(t, old, "closed ownership is refused before creating native contracts")
				parent, discardErr := r.discard()
				require.NoError(t, discardErr)
				fresh, freshErr := parent.beginRegistration(store, qualRegistrationCoordinator(), 2, &before, &selected)
				require.NoError(t, freshErr)
				// Compare fresh VM execution with the genuine native no-classifier
				// path on identical restored bytes. No persistence or gas oracle is
				// manufactured from DRWA output, and neither output is published.
				native := qualSystemSCNative(t, store, nil)
				rebuilt := qualSystemSCNative(t, store, fresh)
				want, nativeErr := native.runtime.RunSmartContractCall(input)
				got, rebuiltErr := rebuilt.runtime.RunSmartContractCall(input)
				require.NoError(t, nativeErr)
				require.NoError(t, rebuiltErr)
				require.Equal(t, vmcommon.Ok, want.ReturnCode)
				require.Equal(t, want, got, "complete VM output including gas/refund/logs/storage/results")
				require.Equal(t, native.reads, rebuilt.reads)
				after, afterErr := store.RootHash()
				require.NoError(t, afterErr)
				require.True(t, bytes.Equal(root, after))
				require.Zero(t, store.JournalLen())
			})
		}
	}
}
