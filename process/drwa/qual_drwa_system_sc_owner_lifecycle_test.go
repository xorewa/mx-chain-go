package drwa

import (
	"bytes"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Experimental component coordinates reuse XV-T41-S5-04/11/12. Native list
// choices and peer positions are registered under XV-T41-S5-13. No supplied
// root, synthetic header or private handoff establishes canonical admission.
func qualSystemSCOwnerPeer(t *testing.T) *qualRegistrationPeerStore {
	t.Helper()
	peer := qualRegistrationPeer(t)
	qualSystemSCOwnerPeerList(t, peer, common.EligibleList)
	_, err := peer.AccountsAdapter.Commit()
	require.NoError(t, err)
	return peer
}

func qualSystemSCOwnerPeerList(t *testing.T, peer *qualRegistrationPeerStore, list common.PeerType) {
	t.Helper()
	a, err := peer.LoadAccount(qualContainmentAddress)
	require.NoError(t, err)
	a.(state.PeerAccountHandler).SetListAndIndex(0, string(list), 0, false)
	require.NoError(t, peer.SaveAccount(a))
}

func qualSystemSCOwnerMutation(t *testing.T, user state.AccountsAdapter, peer *qualRegistrationPeerStore, list common.PeerType) {
	t.Helper()
	a, err := user.LoadAccount(core.ESDTSCAddress)
	require.NoError(t, err)
	require.NoError(t, a.(state.UserAccountHandler).SaveKeyValue([]byte("experimental/pending"), []byte("unpublished")))
	require.NoError(t, user.SaveAccount(a))
	if peer != nil {
		qualSystemSCOwnerPeerList(t, peer, list)
	}
}

func qualSystemSCOwnerCall(method string) *vmcommon.ContractCallInput {
	input := qualSystemSCInput(method, "TOKEN-abcdef")
	input.Arguments = input.Arguments[:1]
	return input
}

func qualSystemSCFreshEquivalent(t *testing.T, user state.AccountsAdapter, peer *qualRegistrationPeerStore, candidate *registrationCandidate, list common.PeerType) {
	t.Helper()
	var validators []state.AccountsAdapter
	if peer != nil {
		validators = append(validators, peer)
	}
	for _, method := range []string{"getTokenProperties", "pause"} {
		native := qualSystemSCNative(t, user, nil, validators...)
		fresh := qualSystemSCNative(t, user, candidate, validators...)
		want, nativeErr := native.runtime.RunSmartContractCall(qualSystemSCOwnerCall(method))
		got, freshErr := fresh.runtime.RunSmartContractCall(qualSystemSCOwnerCall(method))
		require.NoError(t, nativeErr)
		require.NoError(t, freshErr)
		require.Equal(t, vmcommon.Ok, want.ReturnCode)
		require.Equal(t, want, got, "complete native output, including gas/refund/logs/storage/results")
		require.Equal(t, native.reads, fresh.reads)
		if peer != nil {
			// An incorrectly reused user database would yield InactiveList and
			// false. Expected native list is independently seeded above.
			require.Equal(t, string(list), fresh.context.StatusFromValidatorStatistics(qualContainmentAddress))
			require.True(t, fresh.context.IsValidator(qualContainmentAddress))
		}
	}
}

// T41-S5-11-1: successful persistence and stale-handle refusal are distinct
// observations. The receipt survives; the old VM remains unusable. Production
// factory/scheduler handoff is not installed or admitted by these fixtures.
func TestQualDRWASystemSCOwnerHealthyCommit(t *testing.T) {
	for _, stores := range []string{"user", "user-peer"} {
		for _, observe := range []string{"status", "ordinary-call", "classified-call", "create"} {
			t.Run(stores+"/"+observe, func(t *testing.T) {
				var peer *qualRegistrationPeerStore
				var participating []state.AccountsAdapter
				if stores == "user-peer" {
					peer = qualSystemSCOwnerPeer(t)
					participating = append(participating, peer)
				}
				r, user := qualSystemSCOrdinaryCandidate(t, participating...)
				originalRoot, err := user.RootHash()
				require.NoError(t, err)
				old := qualSystemSCNative(t, user, r, participating...)
				var pending *vmcommon.VMOutput
				require.NoError(t, r.writer.boundary.Execute(func() (*vmcommon.VMOutput, error) {
					qualSystemSCOwnerMutation(t, user, peer, common.WaitingList)
					out, err := old.runtime.RunSmartContractCall(qualSystemSCOwnerCall("getTokenProperties"))
					require.NoError(t, err)
					require.Equal(t, vmcommon.Ok, out.ReturnCode)
					pending = out
					return out, nil
				}))
				roots, outputs, err := r.commit()
				require.NoError(t, err)
				require.Len(t, roots, 1+len(participating))
				require.Equal(t, []*vmcommon.VMOutput{pending}, outputs)
				require.NotEqual(t, originalRoot, roots[0])
				require.Equal(t, 1, user.commits)
				a, err := user.GetExistingAccount(core.ESDTSCAddress)
				require.NoError(t, err)
				value, _, err := a.(state.UserAccountHandler).RetrieveValue([]byte("experimental/pending"))
				require.NoError(t, err)
				require.Equal(t, []byte("unpublished"), value)
				require.Zero(t, user.JournalLen())
				if peer != nil {
					require.Equal(t, 1, peer.commits)
					require.Zero(t, peer.JournalLen())
				}
				old.reads = 0
				status := old.runtime.(interface{ DRWAExecutionError() error })
				var refused *vmcommon.VMOutput
				switch observe {
				case "status":
					err = status.DRWAExecutionError()
				case "ordinary-call":
					refused, err = old.runtime.RunSmartContractCall(qualSystemSCOwnerCall("getTokenProperties"))
				case "classified-call":
					refused, err = old.runtime.RunSmartContractCall(qualSystemSCOwnerCall("pause"))
				case "create":
					refused, err = old.runtime.RunSmartContractCreate(&vmcommon.ContractCreateInput{
						VMInput: vmcommon.VMInput{CallerAddr: core.ESDTSCAddress, CallValue: qualSystemSCOwnerCall("pause").CallValue},
					})
				}
				require.ErrorIs(t, err, vm.ErrDRWAExecution)
				require.ErrorIs(t, err, ErrExecutionClosed)
				require.Nil(t, refused)
				require.Zero(t, old.reads)
				failure := status.DRWAExecutionError()
				require.Same(t, err, failure)
				old.context.CleanCache()
				require.Same(t, failure, status.DRWAExecutionError())
				require.ErrorIs(t, r.recover(), ErrExecutionClosed, "healthy committed state must not be undone")
				_, err = r.discard()
				require.ErrorIs(t, err, errInvalidMetaContext)
				_, releasedAgain, err := r.commit()
				require.ErrorIs(t, err, ErrExecutionClosed)
				require.Nil(t, releasedAgain)
				// Private native-context fixture, explicitly not finality admission.
				anchor := qualRegistrationProjectionAnchor(t, roots[0])
				parent, err := r.commitProjection(anchor)
				require.NoError(t, err)
				fresh, err := parent.beginRegistration(user, qualRegistrationCoordinator(), 2, anchor, anchor, participating...)
				require.NoError(t, err)
				qualSystemSCFreshEquivalent(t, user, peer, fresh, common.WaitingList)
				require.Same(t, failure, status.DRWAExecutionError(), "new ownership does not revive old VM")
				for i, store := range append([]state.AccountsAdapter{user}, participating...) {
					root, rootErr := store.RootHash()
					require.NoError(t, rootErr)
					require.Equal(t, roots[i], root)
					require.Zero(t, store.JournalLen())
				}
			})
		}
	}
}

func TestQualDRWASystemSCOwnerPeerRecovery(t *testing.T) {
	for _, fault := range []string{"user-undo", "peer-undo", "both-undo", "peer-commit", "peer-recreate", "missing-peer-root", "equal-peer-root"} {
		t.Run(fault, func(t *testing.T) {
			peer := qualSystemSCOwnerPeer(t)
			r, user := qualSystemSCOrdinaryCandidate(t, peer)
			before, selected := copyRegistryAnchor(&r.view.parent.anchor), copyRegistryAnchor(&r.view.after)
			userRoot, err := user.RootHash()
			require.NoError(t, err)
			peerRoot, err := peer.RootHash()
			require.NoError(t, err)
			peerNode, err := peer.backing.Get(peerRoot)
			require.NoError(t, err)
			old := qualSystemSCNative(t, user, r, peer)
			original, undo := errors.New("experimental operation failure"), errors.New("experimental rollback failure")
			if fault == "user-undo" || fault == "both-undo" {
				user.revertErr = undo
			}
			if fault != "user-undo" && fault != "peer-commit" && fault != "missing-peer-root" {
				peer.revertErr = undo
			}
			err = r.writer.boundary.Execute(func() (*vmcommon.VMOutput, error) {
				list := common.JailedList
				if fault == "equal-peer-root" {
					list = common.EligibleList
				}
				qualSystemSCOwnerMutation(t, user, peer, list)
				out, callErr := old.runtime.RunSmartContractCall(qualSystemSCOwnerCall("getTokenProperties"))
				require.NoError(t, callErr)
				require.Equal(t, vmcommon.Ok, out.ReturnCode)
				if fault == "peer-commit" || fault == "missing-peer-root" {
					return out, nil
				}
				return nil, original
			})
			if fault == "peer-commit" || fault == "missing-peer-root" {
				require.NoError(t, err)
				peer.commitErr = undo
				roots, out, commitErr := r.commit()
				require.ErrorIs(t, commitErr, undo)
				require.Nil(t, roots)
				require.Nil(t, out)
				require.Zero(t, user.JournalLen())
			} else {
				require.ErrorIs(t, err, original)
				require.ErrorIs(t, err, undo)
			}
			status := old.runtime.(interface{ DRWAExecutionError() error })
			failure := status.DRWAExecutionError()
			require.ErrorIs(t, failure, vm.ErrDRWAExecution)
			require.ErrorIs(t, failure, undo)
			old.reads = 0
			out, err := old.runtime.RunSmartContractCall(qualSystemSCOwnerCall("pause"))
			require.Same(t, failure, err)
			require.Nil(t, out)
			require.Zero(t, old.reads)
			if fault == "peer-recreate" || fault == "missing-peer-root" {
				if fault == "peer-recreate" {
					peer.recreateErr = undo
				} else {
					require.NoError(t, peer.backing.Remove(peerRoot))
				}
				require.ErrorIs(t, r.recover(), undo)
				_, err = r.discard()
				require.ErrorIs(t, err, undo)
				peer.recreateErr = nil
				if fault == "missing-peer-root" {
					require.NoError(t, peer.backing.Put(peerRoot, peerNode))
				}
			}
			require.NoError(t, r.recover())
			for i, store := range []state.AccountsAdapter{user, peer} {
				root, rootErr := store.RootHash()
				require.NoError(t, rootErr)
				require.True(t, bytes.Equal([][]byte{userRoot, peerRoot}[i], root))
				require.Zero(t, store.JournalLen())
			}
			old.context.CleanCache()
			require.Same(t, failure, status.DRWAExecutionError())
			parent, err := r.discard()
			require.NoError(t, err)
			fresh, err := parent.beginRegistration(user, qualRegistrationCoordinator(), 2, &before, &selected, peer)
			require.NoError(t, err)
			qualSystemSCFreshEquivalent(t, user, peer, fresh, common.EligibleList)
			require.Same(t, failure, status.DRWAExecutionError())
		})
	}
}
