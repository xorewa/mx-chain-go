package drwa

import (
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/vm"
	"github.com/multiversx/mx-chain-go/vm/mock"
	"github.com/multiversx/mx-chain-go/vm/systemSmartContracts"
	"github.com/multiversx/mx-chain-vm-common-go/parsers"
	"github.com/stretchr/testify/require"
)

// Experimental native fixtures reuse XV-T41-S5-04/12/13. Adapter identity,
// including independently created equal-root stores, is not canonical admission.
func qualSystemSCBindingArgs(t *testing.T, user, peer state.AccountsAdapter,
	classifier vm.DRWATokenClassifier) systemSmartContracts.VMContextArgs {
	t.Helper()
	cfg := qualCandidateEpochs(t, qualDRWACandidateFixtures["enableEpochs.toml"].body)
	flags := qualCandidateFlags(t, cfg, cfg.EnableEpochs.SupernovaEnableEpoch)
	require.False(t, flags.IsFlagEnabled(common.GlobalMintBurnFlag))
	return systemSmartContracts.VMContextArgs{
		BlockChainHook: &mock.BlockChainHookStub{}, CryptoHook: hooks.NewVMCryptoHook(),
		InputParser: parsers.NewCallArgsParser(), UserAccountsDB: user, ValidatorAccountsDB: peer,
		ChanceComputer: &mock.RaterMock{}, EnableEpochsHandler: flags, DRWAClassifier: classifier,
	}
}

func TestQualDRWASystemSCStoreBinding(t *testing.T) {
	for _, binding := range []string{"user", "peer", "missing-peer", "pair", "alias", "nil-classifier"} {
		t.Run(binding, func(t *testing.T) {
			peer := qualSystemSCOwnerPeer(t)
			var participating []state.AccountsAdapter
			if binding != "missing-peer" && binding != "alias" {
				participating = append(participating, peer)
			}
			r, user := qualSystemSCOrdinaryCandidate(t, participating...)
			args := qualSystemSCBindingArgs(t, user, peer, r)
			switch binding {
			case "user":
				_, other := qualSystemSCOrdinaryCandidate(t)
				want, err := user.RootHash()
				require.NoError(t, err)
				got, err := other.RootHash()
				require.NoError(t, err)
				require.Equal(t, want, got, "equal roots do not establish the same journal owner")
				args.UserAccountsDB = other
			case "peer":
				other := qualSystemSCOwnerPeer(t)
				want, err := peer.RootHash()
				require.NoError(t, err)
				got, err := other.RootHash()
				require.NoError(t, err)
				require.Equal(t, want, got)
				args.ValidatorAccountsDB = other
			case "alias":
				args.ValidatorAccountsDB = user
			case "nil-classifier":
				args.DRWAClassifier = nil
			}
			reads := user.reads
			ctx, err := systemSmartContracts.NewVMContext(args)
			if binding == "user" || binding == "peer" || binding == "missing-peer" {
				require.ErrorIs(t, err, vm.ErrDRWAExecution)
				require.ErrorIs(t, err, errInvalidMetaContext)
				require.Nil(t, ctx, "no native VM or contract may receive an unowned account handle")
			} else {
				require.NoError(t, err)
				require.NotNil(t, ctx)
				if binding == "pair" {
					require.Equal(t, string(common.EligibleList), ctx.StatusFromValidatorStatistics(qualContainmentAddress))
				}
			}
			require.Equal(t, reads, user.reads, "constructor admission is identity-only, without registry/trie reads")
			require.Zero(t, user.JournalLen())
			require.Zero(t, peer.JournalLen())
		})
	}
}
