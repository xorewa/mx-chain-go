package drwa

import (
	"errors"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Owner-authorized SP1 handoff fixtures reuse the existing native VM, real
// account stores and private projection. These are not canonical admission.
type qualClassifierHandoff interface {
	ReplaceDRWAClassifier(vm.DRWATokenClassifier) error
}

func qualNextSystemSCOwner(t *testing.T, old *registrationCandidate, user state.AccountsAdapter,
	commit bool, peers ...state.AccountsAdapter) *registrationCandidate {
	t.Helper()
	var parent *committedRegistry
	var err error
	if commit {
		roots, _, commitErr := old.commit()
		require.NoError(t, commitErr)
		parent, err = old.commitProjection(qualRegistrationProjectionAnchor(t, roots[0]))
	} else {
		require.NoError(t, old.abort())
		parent, err = old.discard()
	}
	require.NoError(t, err)
	a := copyRegistryAnchor(&parent.anchor)
	next, err := parent.beginRegistration(user, qualRegistrationCoordinator(), 2, &a, &a, peers...)
	require.NoError(t, err)
	return next
}

func TestQualDRWASystemSCHandoff(t *testing.T) {
	for _, paired := range []bool{false, true} {
		for _, commit := range []bool{false, true} {
			name := "user/abort"
			if paired {
				name = "user-peer/abort"
			}
			if commit {
				name = name[:len(name)-len("abort")] + "commit"
			}
			t.Run(name, func(t *testing.T) {
				var peers []state.AccountsAdapter
				if paired {
					peers = append(peers, qualSystemSCOwnerPeer(t))
				}
				old, user := qualSystemSCOrdinaryCandidate(t, peers...)
				f := qualSystemSCNative(t, user, old, peers...)
				ctx, sc, container := f.context, f.contract, f.container
				require.Equal(t, 1, f.gasRegistrations)
				next := qualNextSystemSCOwner(t, old, user, commit, peers...)
				status := f.runtime.(interface{ DRWAExecutionError() error })
				require.NoError(t, status.DRWAExecutionError(), "healthy closure is passive health, not execution admission")
				handoff, exists := f.runtime.(qualClassifierHandoff)
				require.True(t, exists, "native System VM must own the serialized handoff")
				var readers sync.WaitGroup
				observed := make(chan error, 16)
				readers.Add(1)
				go func() {
					defer readers.Done()
					for i := 0; i < 16; i++ {
						observed <- status.DRWAExecutionError()
					}
				}()
				require.NoError(t, handoff.ReplaceDRWAClassifier(next))
				readers.Wait()
				close(observed)
				for err := range observed {
					require.NoError(t, err)
				}
				require.Same(t, ctx, f.context)
				require.Same(t, sc, f.contract)
				require.Same(t, container, f.container)
				require.Equal(t, 1, f.gasRegistrations, "handoff cannot register another gas subscriber")
				for _, method := range []string{"getTokenProperties", "pause"} {
					native := qualSystemSCNative(t, user, nil, peers...)
					want, nativeErr := native.runtime.RunSmartContractCall(qualSystemSCOwnerCall(method))
					got, callErr := f.runtime.RunSmartContractCall(qualSystemSCOwnerCall(method))
					require.NoError(t, nativeErr)
					require.NoError(t, callErr)
					require.Equal(t, vmcommon.Ok, want.ReturnCode)
					require.Equal(t, want, got, "full native output including gas, refunds, logs and storage")
				}
				qualAssertRegistrationClassification(t, next, next.view.after.candidateHash, "AAA-abcdef", true)
				out, err := f.runtime.RunSmartContractCall(qualSystemSCInput("setBurnRoleGlobally", "AAA-abcdef"))
				require.NoError(t, err)
				require.Equal(t, vmcommon.UserError, out.ReturnCode)
				require.Equal(t, "DRWA public operation denied", out.ReturnMessage)
			})
		}
	}
}

func TestQualDRWASystemSCHandoffRefusal(t *testing.T) {
	for _, fault := range []string{"active", "same", "nil", "typed-nil", "foreign-lineage", "user", "peer", "profile", "next-closed", "next-running", "next-poison", "poison", "recovered", "latched", "stale-publication"} {
		t.Run(fault, func(t *testing.T) {
			peer := qualSystemSCOwnerPeer(t)
			old, user := qualSystemSCOrdinaryCandidate(t, peer)
			f := qualSystemSCNative(t, user, old, peer)
			handoff, exists := f.runtime.(qualClassifierHandoff)
			require.True(t, exists)
			if fault == "poison" {
				original, undo := errors.New("experimental native operation failure"), errors.New("experimental handoff rollback failure")
				user.revertErr = undo
				require.ErrorIs(t, old.writer.boundary.Execute(func() (*vmcommon.VMOutput, error) { return nil, original }), original)
				err := handoff.ReplaceDRWAClassifier(old)
				require.ErrorIs(t, err, vm.ErrDRWAExecution)
				require.ErrorIs(t, err, original)
				require.ErrorIs(t, err, undo)
				failure := f.runtime.(interface{ DRWAExecutionError() error }).DRWAExecutionError()
				require.ErrorIs(t, failure, original)
				user.revertErr = nil
				require.NoError(t, old.recover())
				parent, err := old.discard()
				require.NoError(t, err)
				a := copyRegistryAnchor(&parent.anchor)
				next, err := parent.beginRegistration(user, qualRegistrationCoordinator(), 2, &a, &a, peer)
				require.NoError(t, err)
				f.context.CleanCache()
				require.Same(t, failure, handoff.ReplaceDRWAClassifier(next), "handoff cannot clear the existing cause or latch")
				return
			}
			if fault == "active" {
				require.ErrorIs(t, handoff.ReplaceDRWAClassifier(old), vm.ErrDRWAExecution)
				out, err := f.runtime.RunSmartContractCall(qualSystemSCOwnerCall("getTokenProperties"))
				require.NoError(t, err)
				require.Equal(t, vmcommon.Ok, out.ReturnCode)
				return
			}
			if fault == "recovered" {
				undo := errors.New("experimental handoff rollback failure")
				user.revertErr = undo
				require.ErrorIs(t, old.writer.boundary.Execute(func() (*vmcommon.VMOutput, error) { return nil, undo }), undo)
				user.revertErr = nil
				require.NoError(t, old.recover())
				_, err := old.discard()
				require.NoError(t, err)
			} else {
				require.NoError(t, old.abort())
				if fault == "latched" {
					out, err := f.runtime.RunSmartContractCall(qualSystemSCOwnerCall("getTokenProperties"))
					require.Nil(t, out)
					require.ErrorIs(t, err, ErrExecutionClosed)
				}
				_, err := old.discard()
				require.NoError(t, err)
			}
			parent := old.view.parent
			a := copyRegistryAnchor(&parent.anchor)
			var accounts state.AccountsAdapter = user
			var validators state.AccountsAdapter = peer
			cap := uint64(2)
			if fault == "user" {
				_, accounts = qualSystemSCOrdinaryCandidate(t, peer)
			}
			if fault == "peer" {
				validators = qualSystemSCOwnerPeer(t)
			}
			if fault == "profile" {
				cap = 3
			}
			var next *registrationCandidate
			var err error
			if fault == "foreign-lineage" {
				next, err = reconstructRegistrationCandidate(user, qualRegistrationCoordinator(), 2,
					&registryProjection{anchor: a, members: parent.members}, peer)
			} else {
				next, err = parent.beginRegistration(accounts, qualRegistrationCoordinator(), cap, &a, &a, validators)
			}
			require.NoError(t, err)
			if fault == "next-closed" {
				require.NoError(t, next.abort())
			}
			if fault == "next-poison" {
				undo := errors.New("experimental next owner failure")
				user.revertErr = undo
				require.ErrorIs(t, next.writer.boundary.Execute(func() (*vmcommon.VMOutput, error) { return nil, undo }), undo)
				user.revertErr = nil
			}
			if fault == "stale-publication" {
				require.NoError(t, next.writer.boundary.Execute(func() (*vmcommon.VMOutput, error) {
					qualSystemSCOwnerMutation(t, user, peer, common.WaitingList)
					return nil, nil
				}))
				next = qualNextSystemSCOwner(t, next, user, true, peer)
			}
			var replacement vm.DRWATokenClassifier = next
			switch fault {
			case "same":
				replacement = old
			case "nil":
				replacement = nil
			case "typed-nil":
				replacement = (*registrationCandidate)(nil)
			}
			if fault == "next-running" {
				require.NoError(t, next.writer.boundary.Execute(func() (*vmcommon.VMOutput, error) {
					require.ErrorIs(t, handoff.ReplaceDRWAClassifier(next), vm.ErrDRWAExecution)
					return nil, nil
				}))
			} else {
				require.ErrorIs(t, handoff.ReplaceDRWAClassifier(replacement), vm.ErrDRWAExecution)
			}
			require.Equal(t, 1, f.gasRegistrations)
			f.reads = 0
			out, err := f.runtime.RunSmartContractCall(qualSystemSCOwnerCall("getTokenProperties"))
			require.Nil(t, out)
			require.ErrorIs(t, err, vm.ErrDRWAExecution)
			require.Zero(t, f.reads, "refusal cannot switch to another candidate or reach native effects")
		})
	}
}

func TestQualDRWASystemSCHandoffUnconfigured(t *testing.T) {
	r, user := qualSystemSCOrdinaryCandidate(t)
	f := qualSystemSCNative(t, user, nil)
	handoff, exists := f.runtime.(qualClassifierHandoff)
	require.True(t, exists)
	require.ErrorIs(t, handoff.ReplaceDRWAClassifier(r), vm.ErrDRWAExecution, "handoff cannot enable enforcement on an unconfigured context")
	out, err := f.runtime.RunSmartContractCall(qualSystemSCOwnerCall("getTokenProperties"))
	require.NoError(t, err)
	require.Equal(t, vmcommon.Ok, out.ReturnCode)
	require.Equal(t, 1, f.gasRegistrations)
}

func TestQualDRWASystemSCHandoffSerialization(t *testing.T) {
	for _, boundary := range []string{"system-vm", "context", "projection"} {
		t.Run(boundary, func(t *testing.T) {
			old, user := qualSystemSCOrdinaryCandidate(t)
			f := qualSystemSCNative(t, user, old)
			handoff, exists := f.runtime.(qualClassifierHandoff)
			require.True(t, exists)
			attempted := false
			attempt := func() { attempted = true; require.ErrorIs(t, handoff.ReplaceDRWAClassifier(old), vm.ErrDRWAExecution) }
			switch boundary {
			case "system-vm":
				f.onRead = func() { f.onRead = nil; attempt() }
				out, err := f.runtime.RunSmartContractCall(qualSystemSCOwnerCall("getTokenProperties"))
				require.NoError(t, err)
				require.Equal(t, vmcommon.Ok, out.ReturnCode)
			case "context":
				ctx := f.context.(vm.DRWASystemCallContext)
				_, err := ctx.ExecuteDRWASystemCall(nil, func() (*vmcommon.VMOutput, error) { attempt(); return nil, nil })
				require.NoError(t, err)
			case "projection":
				old.view.parent.mut.Lock()
				attempt()
				old.view.parent.mut.Unlock()
			}
			require.True(t, attempted)
			require.NoError(t, f.runtime.(interface{ DRWAExecutionError() error }).DRWAExecutionError())
		})
	}
}
