package core

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"

	nativeCore "github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/guardians"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/guardian"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// T09-M38: actual loaded native guardian delay and accounts, with synthetic
// epochs and direct component calls. No transaction signature, privileged
// authority, canonical epoch, node bootstrap or deployment admission follows.
func TestQualDRWACandidateGuardianNativeAccounts(t *testing.T) {
	for _, epoch := range []uint32{0, 3} {
		for _, shard := range []uint32{0, 1, 2, nativeCore.MetachainShardId} {
			t.Run(fmt.Sprintf("epoch_%d_shard_%d", epoch, shard), func(t *testing.T) {
				args := qualDRWACandidateDataArgs(t, epoch, shard)
				require.Equal(t, uint32(2), args.Config.GeneralSettings.SetGuardianEpochsDelay)
				args.Core.EpochNotifier().CheckEpoch(&block.Header{Epoch: epoch})
				handler, _ := qualDRWACandidateStateComponents(t, args)
				accounts := handler.AccountsAdapter()
				guarded, err := guardian.NewGuardedAccount(args.Core.InternalMarshalizer(), args.Core.EpochNotifier(), args.Config.GeneralSettings.SetGuardianEpochsDelay)
				require.NoError(t, err)
				owner := bytes.Repeat([]byte{0x17}, args.Core.AddressPubKeyConverter().Len())
				first := bytes.Repeat([]byte{0x21}, len(owner))
				second := bytes.Repeat([]byte{0x22}, len(owner))
				wrong := bytes.Repeat([]byte{0x23}, len(owner))
				key, value := []byte("T09 ordinary guardian probe"), []byte("unchanged")
				account, err := accounts.LoadAccount(owner)
				require.NoError(t, err)
				user := account.(interface {
					state.UserAccountHandler
					vmcommon.UserAccountHandler
				})
				user.IncreaseNonce(7)
				require.NoError(t, user.AddToBalance(big.NewInt(37)))
				require.NoError(t, user.SaveKeyValue(key, value))
				require.NoError(t, guarded.SetGuardian(user, first, nil, []byte("service1")))
				require.NoError(t, accounts.SaveAccount(user))
				_, err = accounts.Commit()
				require.NoError(t, err)
				for _, current := range []uint32{epoch, epoch + 1, epoch + 2} {
					args.Core.EpochNotifier().CheckEpoch(&block.Header{Epoch: current})
					active, pending, err := guarded.GetConfiguredGuardians(user)
					require.NoError(t, err)
					expected := &guardians.Guardian{Address: first, ActivationEpoch: epoch + 2, ServiceUID: []byte("service1")}
					if current < epoch+2 {
						require.Nil(t, active)
						require.Equal(t, expected, pending)
						require.False(t, guarded.HasActiveGuardian(user))
						require.True(t, guarded.HasPendingGuardian(user))
						_, err = guarded.GetActiveGuardian(user)
						require.ErrorIs(t, err, process.ErrAccountHasNoActiveGuardian)
					} else {
						require.Equal(t, expected, active)
						require.Nil(t, pending)
						require.True(t, guarded.HasActiveGuardian(user))
						require.False(t, guarded.HasPendingGuardian(user))
						address, err := guarded.GetActiveGuardian(user)
						require.NoError(t, err)
						require.Equal(t, first, address)
					}
				}
				root, err := accounts.RootHash()
				require.NoError(t, err)
				journal := accounts.JournalLen()
				require.ErrorIs(t, guarded.SetGuardian(user, second, wrong, []byte("service2")), process.ErrTransactionAndAccountGuardianMismatch)
				afterDenial, err := accounts.RootHash()
				require.NoError(t, err)
				require.Equal(t, root, afterDenial)
				require.Equal(t, journal, accounts.JournalLen())
				active, pending, err := guarded.GetConfiguredGuardians(user)
				require.NoError(t, err)
				require.Equal(t, &guardians.Guardian{Address: first, ActivationEpoch: epoch + 2, ServiceUID: []byte("service1")}, active)
				require.Nil(t, pending)
				require.NoError(t, guarded.SetGuardian(user, second, first, []byte("service2")))
				require.NoError(t, accounts.SaveAccount(user))
				root, err = accounts.Commit()
				require.NoError(t, err)
				require.NoError(t, accounts.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
				account, err = accounts.GetExistingAccount(owner)
				require.NoError(t, err)
				user = account.(interface {
					state.UserAccountHandler
					vmcommon.UserAccountHandler
				})
				fresh, err := guardian.NewGuardedAccount(args.Core.InternalMarshalizer(), args.Core.EpochNotifier(), args.Config.GeneralSettings.SetGuardianEpochsDelay)
				require.NoError(t, err)
				active, pending, err = fresh.GetConfiguredGuardians(user)
				require.NoError(t, err)
				require.Equal(t, &guardians.Guardian{Address: second, ActivationEpoch: epoch + 2, ServiceUID: []byte("service2")}, active)
				require.Nil(t, pending)
				require.Equal(t, uint64(7), user.GetNonce())
				require.Equal(t, big.NewInt(37), user.GetBalance())
				got, _, err := user.RetrieveValue(key)
				require.NoError(t, err)
				require.Equal(t, value, got)
			})
		}
	}
}

func TestQualDRWACandidateGuardianConfiguration(t *testing.T) {
	t.Run("zero_delay", func(t *testing.T) {
		paths, overlay := qualDRWALoadedFiles(t)
		cfg, err := common.LoadMainConfig(paths.MainConfig)
		require.NoError(t, err)
		cfg.GeneralSettings.SetGuardianEpochsDelay = 0
		qualDRWAEncodeLoaded(t, paths.MainConfig, cfg)
		candidate, err := LoadDRWAConfigurationCandidate(paths, overlay, DRWAConfigurationSupport{RelayedV3: true})
		require.ErrorIs(t, err, process.ErrInvalidSetGuardianEpochsDelay)
		require.Nil(t, candidate)
	})
	t.Run("native_dependencies", func(t *testing.T) {
		args := qualDRWACandidateDataArgs(t, 0, 0)
		value, err := guardian.NewGuardedAccount(nil, args.Core.EpochNotifier(), args.Config.GeneralSettings.SetGuardianEpochsDelay)
		require.ErrorIs(t, err, process.ErrNilMarshalizer)
		require.Nil(t, value)
		value, err = guardian.NewGuardedAccount(args.Core.InternalMarshalizer(), nil, args.Config.GeneralSettings.SetGuardianEpochsDelay)
		require.ErrorIs(t, err, process.ErrNilEpochNotifier)
		require.Nil(t, value)
		value, err = guardian.NewGuardedAccount(args.Core.InternalMarshalizer(), args.Core.EpochNotifier(), 0)
		require.ErrorIs(t, err, process.ErrInvalidSetGuardianEpochsDelay)
		require.Nil(t, value)
	})
}
