package drwa

import (
	"bytes"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/enablers"
	"github.com/multiversx/mx-chain-go/common/forking"
	"github.com/multiversx/mx-chain-go/config"
	factoryDisabled "github.com/multiversx/mx-chain-go/factory/disabled"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
)

// Native adoption diagnostics only: real AccountsDB/trie, native protobuf,
// loaders, epoch predicates and liquidity method. No transfer, regulated gate,
// canonical SupplyState, native distributed recovery or profile admission.
func qualCandidateEpochs(t *testing.T, body string) *config.EpochConfig {
	t.Helper()
	path := filepath.Join(t.TempDir(), "enableEpochs.toml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0600))
	cfg, err := common.LoadEpochConfig(path)
	require.NoError(t, err)
	return cfg
}

func qualCandidateFlags(t *testing.T, cfg *config.EpochConfig, epoch uint32) common.EnableEpochsHandler {
	t.Helper()
	notifier := forking.NewGenericEpochNotifier()
	t.Cleanup(notifier.UnRegisterAll)
	handler, err := enablers.NewEnableEpochsHandler(cfg.EnableEpochs, notifier)
	require.NoError(t, err)
	notifier.CheckEpoch(&block.Header{Epoch: epoch})
	return handler
}

// Literal protobuf field tags and BigIntCaster bytes from the independent
// native schema. Neither the storage implementation nor its encoder generates
// the input. Value nil is {0}; zero is {0,0}; small positive is {0,magnitude}.
func qualLiquidityWire(kind core.ESDTType, value, reserved []byte) []byte {
	out := []byte{0x08, byte(kind)}
	if value != nil {
		out = append(out, 0x12, byte(len(value)))
		out = append(out, value...)
	}
	if len(reserved) != 0 {
		out = append(out, 0x2a, byte(len(reserved)))
		out = append(out, reserved...)
	}
	return out
}

func qualLiquidityRun(t *testing.T, cfg *config.EpochConfig, epoch uint32, kind core.ESDTType,
	nonce uint64, input []byte, delta int64, keep bool, wantErr error,
	unchanged, deleted bool, wantValue *big.Int, wantReserved []byte) {
	t.Helper()
	db := qualGenesisAccounts(t, false)
	flags := qualCandidateFlags(t, cfg, epoch)
	codec := &marshal.GogoProtoMarshalizer{}
	storage, err := builtInFunctions.NewESDTDataStorage(builtInFunctions.ArgsNewESDTDataStorage{
		Accounts: db, Marshalizer: codec, EnableEpochsHandler: flags,
		GlobalSettingsHandler: factoryDisabled.NewDisabledGlobalSettingHandler(),
		ShardCoordinator:      &testscommon.ShardsCoordinatorMock{NoShards: 3, CurrentShard: 0},
	})
	require.NoError(t, err)
	base := []byte(core.ProtectedKeyPrefix + core.ESDTKeyIdentifier + "TOKEN-abcdef")
	key := append(bytes.Clone(base), new(big.Int).SetUint64(nonce).Bytes()...)
	account, err := db.LoadAccount(vmcommon.SystemAccountAddress)
	require.NoError(t, err)
	if input != nil {
		require.NoError(t, account.(state.UserAccountHandler).SaveKeyValue(key, input))
	} else {
		// An absent liquidity leaf is distinct from an account with no native
		// data trie. Provision only an unrelated fixture leaf before committing.
		require.NoError(t, account.(state.UserAccountHandler).SaveKeyValue([]byte("qual-liquidity-unrelated"), []byte{1}))
	}
	require.NoError(t, db.SaveAccount(account))
	_, err = db.Commit()
	require.NoError(t, err)
	beforeRoot, err := db.RootHash()
	require.NoError(t, err)
	require.Zero(t, db.JournalLen())
	if input == nil {
		missing, _, missingErr := account.(state.UserAccountHandler).RetrieveValue(key)
		require.NoError(t, missingErr)
		require.Empty(t, missing)
	}
	err = storage.AddToLiquiditySystemAcc(bytes.Clone(base), uint32(kind), nonce, big.NewInt(delta), keep)
	if wantErr == nil {
		require.NoError(t, err)
	} else {
		require.ErrorIs(t, err, wantErr)
	}
	account, err = db.GetExistingAccount(vmcommon.SystemAccountAddress)
	require.NoError(t, err)
	actual, _, err := account.(state.UserAccountHandler).RetrieveValue(key)
	require.NoError(t, err)
	if unchanged {
		if input == nil {
			require.Empty(t, actual)
		} else {
			require.Equal(t, input, actual)
		}
		require.Zero(t, db.JournalLen())
		afterRoot, rootErr := db.RootHash()
		require.NoError(t, rootErr)
		require.Equal(t, beforeRoot, afterRoot)
		return
	}
	if deleted {
		require.Empty(t, actual)
		return
	}
	decoded := &esdt.ESDigitalToken{}
	require.NoError(t, codec.Unmarshal(decoded, actual))
	require.Equal(t, uint32(kind), decoded.Type)
	require.Equal(t, wantValue, decoded.Value)
	require.Equal(t, wantReserved, decoded.Reserved)
}

func TestQualDRWACandidateLiquidityValues(t *testing.T) {
	// Intentionally separated native flags, not another admitted candidate:
	// at2 storage/send are active while old-token repair is off; at3 it is on.
	cfg := qualCandidateEpochs(t, "[EnableEpochs]\nOptimizeNFTStoreEnableEpoch=1\nESDTMetadataContinuousCleanupEnableEpoch=1\nFixOldTokenLiquidityEnableEpoch=3\n")
	for _, kind := range []core.ESDTType{core.SemiFungible, core.MetaFungible, core.DynamicSFT, core.DynamicMeta} {
		for _, epoch := range []uint32{2, 3} {
			t.Run(fmt.Sprintf("type_%d_epoch_%d", kind, epoch), func(t *testing.T) {
				flags := qualCandidateFlags(t, cfg, epoch)
				require.True(t, flags.IsFlagEnabled(common.SaveToSystemAccountFlag))
				require.True(t, flags.IsFlagEnabled(common.SendAlwaysFlag))
				require.Equal(t, epoch == 3, flags.IsFlagEnabled(common.FixOldTokenLiquidityFlag))
				t.Run("nil_positive", func(t *testing.T) {
					qualLiquidityRun(t, cfg, epoch, kind, 1, qualLiquidityWire(kind, []byte{0}, []byte{1}), 10, false, nil, false, false, big.NewInt(10), []byte{1})
				})
				t.Run("explicit_zero_positive", func(t *testing.T) {
					qualLiquidityRun(t, cfg, epoch, kind, 1, qualLiquidityWire(kind, []byte{0, 0}, []byte{1}), 10, false, nil, false, false, big.NewInt(10), []byte{1})
				})
				t.Run("nonzero_positive", func(t *testing.T) {
					qualLiquidityRun(t, cfg, epoch, kind, 1, qualLiquidityWire(kind, []byte{0, 7}, []byte{1}), 5, false, nil, false, false, big.NewInt(12), []byte{1})
				})
				for _, marker := range []byte{1, 2} {
					t.Run(fmt.Sprintf("nil_negative_marker_%d", marker), func(t *testing.T) {
						wantErr, unchanged, reserved := error(nil), false, []byte{marker}
						if epoch == 2 {
							wantErr, unchanged = builtInFunctions.ErrInvalidLiquidityForESDT, true
						} else if marker == 1 {
							reserved = nil
						}
						qualLiquidityRun(t, cfg, epoch, kind, 1, qualLiquidityWire(kind, []byte{0}, []byte{marker}), -1, false, wantErr, unchanged, false, big.NewInt(0), reserved)
					})
				}
				t.Run("nonzero_underflow", func(t *testing.T) {
					qualLiquidityRun(t, cfg, epoch, kind, 1, qualLiquidityWire(kind, []byte{0, 7}, []byte{1}), -8, false, builtInFunctions.ErrInvalidLiquidityForESDT, true, false, nil, nil)
				})
				for _, keep := range []bool{false, true} {
					t.Run(fmt.Sprintf("exact_zero_keep_%t", keep), func(t *testing.T) {
						qualLiquidityRun(t, cfg, epoch, kind, 1, qualLiquidityWire(kind, []byte{0, 7}, []byte{1}), -7, keep, nil, false, !keep, big.NewInt(0), []byte{1})
					})
				}
				t.Run("old_style_nil_unchanged", func(t *testing.T) {
					qualLiquidityRun(t, cfg, epoch, kind, 1, qualLiquidityWire(kind, []byte{0}, nil), 10, false, nil, true, false, nil, nil)
				})
				t.Run("missing_active_record", func(t *testing.T) {
					qualLiquidityRun(t, cfg, epoch, kind, 1, nil, 1, false, builtInFunctions.ErrNilESDTData, true, false, nil, nil)
				})
			})
		}
	}
}

func TestQualDRWACandidateLiquidityGates(t *testing.T) {
	for _, body := range []string{
		"OptimizeNFTStoreEnableEpoch=3\nESDTMetadataContinuousCleanupEnableEpoch=3\n",
		"OptimizeNFTStoreEnableEpoch=3\nESDTMetadataContinuousCleanupEnableEpoch=1\n",
		"OptimizeNFTStoreEnableEpoch=1\nESDTMetadataContinuousCleanupEnableEpoch=3\n",
	} {
		t.Run(body, func(t *testing.T) {
			cfg := qualCandidateEpochs(t, "[EnableEpochs]\n"+body)
			qualLiquidityRun(t, cfg, 2, core.SemiFungible, 1, qualLiquidityWire(core.SemiFungible, []byte{0}, []byte{1}), 10, false, nil, true, false, nil, nil)
		})
	}
	cfg := qualCandidateEpochs(t, "[EnableEpochs]\n")
	for _, kind := range []core.ESDTType{core.Fungible, core.NonFungibleV2, core.DynamicNFT} {
		t.Run(fmt.Sprintf("user_metadata_type_%d", kind), func(t *testing.T) {
			qualLiquidityRun(t, cfg, 0, kind, 1, qualLiquidityWire(kind, []byte{0}, []byte{1}), 10, false, nil, true, false, nil, nil)
		})
	}
	t.Run("zero_nonce", func(t *testing.T) {
		qualLiquidityRun(t, cfg, 0, core.SemiFungible, 0, qualLiquidityWire(core.SemiFungible, []byte{0}, []byte{1}), 10, false, nil, true, false, nil, nil)
	})
}

func TestQualDRWACandidateLiquidityLoadedProposal(t *testing.T) {
	path := filepath.Join(qualDRWACandidateFixtureDir(t), "enableEpochs.toml")
	cfg, err := common.LoadEpochConfig(path)
	require.NoError(t, err)
	require.Equal(t, uint32(1), cfg.EnableEpochs.OptimizeNFTStoreEnableEpoch)
	require.Equal(t, uint32(1), cfg.EnableEpochs.ESDTMetadataContinuousCleanupEnableEpoch)
	require.Equal(t, uint32(1), cfg.EnableEpochs.FixOldTokenLiquidityEnableEpoch)
	for _, epoch := range []uint32{0, 1, 2, 3} {
		t.Run(fmt.Sprint(epoch), func(t *testing.T) {
			flags := qualCandidateFlags(t, cfg, epoch)
			for _, flag := range []core.EnableEpochFlag{common.SaveToSystemAccountFlag, common.SendAlwaysFlag, common.FixOldTokenLiquidityFlag} {
				require.Equal(t, epoch >= 1, flags.IsFlagEnabled(flag))
			}
			qualLiquidityRun(t, cfg, epoch, core.SemiFungible, 1, qualLiquidityWire(core.SemiFungible, []byte{0}, []byte{1}), 10, false, nil, epoch == 0, false, big.NewInt(10), []byte{1})
		})
	}
}

func TestQualDRWACandidateLiquidityNilWire(t *testing.T) {
	for _, value := range [][]byte{nil, {0}} {
		t.Run(fmt.Sprintf("value_%x", value), func(t *testing.T) {
			decoded := &esdt.ESDigitalToken{}
			require.NoError(t, (&marshal.GogoProtoMarshalizer{}).Unmarshal(decoded, qualLiquidityWire(core.SemiFungible, value, []byte{1})))
			require.Nil(t, decoded.Value)
			require.Equal(t, []byte{1}, decoded.Reserved)
		})
	}
}

func TestQualDRWACandidateLiquidityMalformedValue(t *testing.T) {
	cfg := qualCandidateEpochs(t, "[EnableEpochs]\nOptimizeNFTStoreEnableEpoch=1\nESDTMetadataContinuousCleanupEnableEpoch=1\nFixOldTokenLiquidityEnableEpoch=3\n")
	for _, epoch := range []uint32{2, 3} {
		t.Run(fmt.Sprint(epoch), func(t *testing.T) {
			db := qualGenesisAccounts(t, false)
			storage, err := builtInFunctions.NewESDTDataStorage(builtInFunctions.ArgsNewESDTDataStorage{
				Accounts: db, Marshalizer: &marshal.GogoProtoMarshalizer{},
				EnableEpochsHandler:   qualCandidateFlags(t, cfg, epoch),
				GlobalSettingsHandler: factoryDisabled.NewDisabledGlobalSettingHandler(),
				ShardCoordinator:      &testscommon.ShardsCoordinatorMock{NoShards: 3, CurrentShard: 0},
			})
			require.NoError(t, err)
			base := []byte(core.ProtectedKeyPrefix + core.ESDTKeyIdentifier + "TOKEN-abcdef")
			key := append(bytes.Clone(base), byte(1))
			// Empty field2 payload reaches BigIntCaster's independently specified
			// len0 error. The body is otherwise well-framed protobuf.
			input := []byte{0x08, byte(core.SemiFungible), 0x12, 0, 0x2a, 1, 1}
			account, err := db.LoadAccount(vmcommon.SystemAccountAddress)
			require.NoError(t, err)
			require.NoError(t, account.(state.UserAccountHandler).SaveKeyValue(key, input))
			require.NoError(t, db.SaveAccount(account))
			_, err = db.Commit()
			require.NoError(t, err)
			before, err := db.RootHash()
			require.NoError(t, err)
			require.EqualError(t, storage.AddToLiquiditySystemAcc(base, uint32(core.SemiFungible), 1, big.NewInt(10), false), "bad input")
			require.Zero(t, db.JournalLen())
			account, err = db.GetExistingAccount(vmcommon.SystemAccountAddress)
			require.NoError(t, err)
			actual, _, err := account.(state.UserAccountHandler).RetrieveValue(key)
			require.NoError(t, err)
			require.Equal(t, input, actual)
			after, err := db.RootHash()
			require.NoError(t, err)
			require.Equal(t, before, after)
		})
	}
}
