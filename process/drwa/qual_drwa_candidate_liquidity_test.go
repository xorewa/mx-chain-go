package drwa

import (
	"bytes"
	"crypto/sha256"
	"fmt"
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
	"math/big"
	"os"
	"path/filepath"
	"testing"
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

// Immutable public candidate fixtures only. No admission or current-generation
// proof is inferred. Package-local copies are required because qualification
// helpers cannot enter production code or import another package's test files.
// The native loaders consume these exact bytes from test-owned temporary files.
var qualDRWACandidateFixtures = map[string]struct{ body, sha256 string }{
	// evidence/sp1_t09_configuration_candidate_02 and candidate_03 byte-identical: enableEpochs.toml; SHA-256 b1ac9bc61a7eb19c3e9b0d4e7e4860921df6b25520094f462282ccb0e84eb9c8.
	"enableEpochs.toml": {"[EnableEpochs]\n    # SCDeployEnableEpoch represents the epoch when the deployment of smart contracts will be enabled\n    SCDeployEnableEpoch = 0\n\n    # BuiltInFunctionsEnableEpoch represents the epoch when the built in functions will be enabled\n    BuiltInFunctionsEnableEpoch = 0\n\n    # RelayedTransactionsEnableEpoch represents the epoch when the relayed transactions will be enabled\n    RelayedTransactionsEnableEpoch = 0\n\n    # PenalizedTooMuchGasEnableEpoch represents the epoch when the penalization for using too much gas will be enabled\n    PenalizedTooMuchGasEnableEpoch = 0\n\n    # SwitchJailWaitingEnableEpoch represents the epoch when the system smart contract processing at end of epoch is enabled\n    SwitchJailWaitingEnableEpoch = 0\n\n    # BelowSignedThresholdEnableEpoch represents the epoch when the change for computing rating for validators below signed rating is enabled\n    BelowSignedThresholdEnableEpoch = 0\n\n    # SwitchHysteresisForMinNodesEnableEpoch represents the epoch when the system smart contract changes its config to consider\n    # also (minimum) hysteresis nodes for the minimum number of nodes\n    SwitchHysteresisForMinNodesEnableEpoch = 1\n\n    # TransactionSignedWithTxHashEnableEpoch represents the epoch when the node will also accept transactions that are\n    # signed with the hash of transaction\n    TransactionSignedWithTxHashEnableEpoch = 1\n\n    # MetaProtectionEnableEpoch represents the epoch when the transactions to the metachain are checked to have enough gas\n    MetaProtectionEnableEpoch = 1\n\n    # AheadOfTimeGasUsageEnableEpoch represents the epoch when the cost of smart contract prepare changes from compiler per byte to ahead of time prepare per byte\n    AheadOfTimeGasUsageEnableEpoch = 1\n\n    # GasPriceModifierEnableEpoch represents the epoch when the gas price modifier in fee computation is enabled\n    GasPriceModifierEnableEpoch = 1\n\n    # RepairCallbackEnableEpoch represents the epoch when the callback repair is activated for scrs\n    RepairCallbackEnableEpoch = 1\n\n    # BlockGasAndFeesReCheckEnableEpoch represents the epoch when gas and fees used in each created or processed block are re-checked\n    BlockGasAndFeesReCheckEnableEpoch = 1\n\n    # BalanceWaitingListsEnableEpoch represents the epoch when the shard waiting lists are balanced at the start of an epoch\n    BalanceWaitingListsEnableEpoch = 1\n\n    # ReturnDataToLastTransferEnableEpoch represents the epoch when returned data is added to last output transfer for callbacks\n    ReturnDataToLastTransferEnableEpoch = 1\n\n    # SenderInOutTransferEnableEpoch represents the epoch when the feature of having different senders in output transfer is enabled\n    SenderInOutTransferEnableEpoch = 1\n\n    # StakeEnableEpoch represents the epoch when staking is enabled\n    StakeEnableEpoch = 0\n\n    # StakingV2EnableEpoch represents the epoch when staking v2 is enabled\n    StakingV2EnableEpoch = 1\n\n    # DoubleKeyProtectionEnableEpoch represents the epoch when the double key protection will be enabled\n    DoubleKeyProtectionEnableEpoch = 1\n\n    # ESDTEnableEpoch represents the epoch when ESDT is enabled\n    ESDTEnableEpoch = 1\n\n    # GovernanceEnableEpoch represents the epoch when governance is enabled\n    GovernanceEnableEpoch = 1\n\n    # GovernanceDisableProposeEnableEpoch represents the epoch when governance disable proposal is enabled\n    GovernanceDisableProposeEnableEpoch = 1\n\n    # GovernanceFixesEnableEpoch represents the epoch when governance fixes are enabled\n    GovernanceFixesEnableEpoch = 1\n\n    # DelegationManagerEnableEpoch represents the epoch when the delegation manager is enabled\n    # epoch should not be 0\n    DelegationManagerEnableEpoch = 1\n\n    # DelegationSmartContractEnableEpoch represents the epoch when delegation smart contract is enabled\n    # epoch should not be 0\n    DelegationSmartContractEnableEpoch = 1\n\n    # CorrectLastUnjailedEnableEpoch represents the epoch when the fix regaring the last unjailed node should apply\n    CorrectLastUnjailedEnableEpoch = 1\n\n    # RelayedTransactionsV2EnableEpoch represents the epoch when the relayed transactions V2 will be enabled\n    RelayedTransactionsV2EnableEpoch = 0\n\n    # UnbondTokensV2EnableEpoch represents the epoch when the new implementation of the unbond tokens function is available\n    UnbondTokensV2EnableEpoch = 1\n\n    # SaveJailedAlwaysEnableEpoch represents the epoch when saving jailed status at end of epoch will happen in all cases\n    SaveJailedAlwaysEnableEpoch = 1\n\n    # ReDelegateBelowMinCheckEnableEpoch represents the epoch when the check for the re-delegated value will be enabled\n    ReDelegateBelowMinCheckEnableEpoch = 1\n\n    # ValidatorToDelegationEnableEpoch represents the epoch when the validator-to-delegation feature will be enabled\n    ValidatorToDelegationEnableEpoch = 1\n\n    # IncrementSCRNonceInMultiTransferEnableEpoch represents the epoch when the fix for preventing the generation of the same SCRs\n    # is enabled. The fix is done by adding an extra increment.\n    IncrementSCRNonceInMultiTransferEnableEpoch = 1\n\n    # ESDTMultiTransferEnableEpoch represents the epoch when esdt multitransfer built in function is enabled\n    ESDTMultiTransferEnableEpoch = 1\n\n    # GlobalMintBurnDisableEpoch represents the epoch when the global mint and burn functions are disabled\n    GlobalMintBurnDisableEpoch = 1\n\n    # ESDTTransferRoleEnableEpoch represents the epoch when esdt transfer role set is enabled\n    ESDTTransferRoleEnableEpoch = 1\n\n    # ComputeRewardCheckpointEnableEpoch represents the epoch when compute rewards checkpoint epoch is enabled\n    ComputeRewardCheckpointEnableEpoch = 1\n\n    # SCRSizeInvariantCheckEnableEpoch represents the epoch when the scr size invariant check is enabled\n    SCRSizeInvariantCheckEnableEpoch = 1\n\n    # BackwardCompSaveKeyValueEnableEpoch represents the epoch when the backward compatibility for save key value error is enabled\n    BackwardCompSaveKeyValueEnableEpoch = 1\n\n    # ESDTNFTCreateOnMultiShardEnableEpoch represents the epoch when esdt nft creation is enabled on multiple shards\n    ESDTNFTCreateOnMultiShardEnableEpoch = 1\n\n    # MetaESDTSetEnableEpoch represents the epoch when the backward compatibility for save key value error is enabled\n    MetaESDTSetEnableEpoch = 1\n\n    # AddTokensToDelegationEnableEpoch represents the epoch when adding tokens to delegation is enabled for whitelisted address\n    AddTokensToDelegationEnableEpoch = 1\n\n    # MultiESDTTransferFixOnCallBackOnEnableEpoch represents the epoch when multi esdt transfer on callback fix is enabled\n    MultiESDTTransferFixOnCallBackOnEnableEpoch = 1\n\n    # OptimizeGasUsedInCrossMiniBlocksEnableEpoch represents the epoch when gas used in cross shard mini blocks will be optimized\n    OptimizeGasUsedInCrossMiniBlocksEnableEpoch = 1\n\n    # CorrectFirstQueuedEpoch represents the epoch when the backward compatibility for setting the first queued node is enabled\n    CorrectFirstQueuedEpoch = 1\n\n    # DeleteDelegatorAfterClaimRewardsEnableEpoch represents the epoch when the delegators data is deleted for delegators that have to claim rewards after they withdraw all funds\n    DeleteDelegatorAfterClaimRewardsEnableEpoch = 1\n\n    # FixOOGReturnCodeEnableEpoch represents the epoch when the backward compatibility returning out of gas error is enabled\n    FixOOGReturnCodeEnableEpoch = 1\n\n    # RemoveNonUpdatedStorageEnableEpoch represents the epoch when the backward compatibility for removing non updated storage is enabled\n    RemoveNonUpdatedStorageEnableEpoch = 1\n\n    # OptimizeNFTStoreEnableEpoch represents the epoch when optimizations on NFT metadata store and send are enabled\n    OptimizeNFTStoreEnableEpoch = 1\n\n    # CreateNFTThroughExecByCallerEnableEpoch represents the epoch when nft creation through execution on destination by caller is enabled\n    CreateNFTThroughExecByCallerEnableEpoch = 1\n\n    # StopDecreasingValidatorRatingWhenStuckEnableEpoch represents the epoch when we should stop decreasing validator's rating if, for instance, a shard gets stuck\n    StopDecreasingValidatorRatingWhenStuckEnableEpoch = 1\n\n    # FrontRunningProtectionEnableEpoch represents the epoch when the first version of protection against front running is enabled\n    FrontRunningProtectionEnableEpoch = 1\n\n    # IsPayableBySCEnableEpoch represents the epoch when a new flag isPayable by SC is enabled\n    IsPayableBySCEnableEpoch = 1\n\n    # CleanUpInformativeSCRsEnableEpoch represents the epoch when the informative-only scrs are cleaned from miniblocks and logs are created from them\n    CleanUpInformativeSCRsEnableEpoch = 1\n\n    # StorageAPICostOptimizationEnableEpoch represents the epoch when new storage helper functions are enabled and cost is reduced in Wasm VM\n    StorageAPICostOptimizationEnableEpoch = 1\n\n    # ESDTRegisterAndSetAllRolesEnableEpoch represents the epoch when new function to register tickerID and set all roles is enabled\n    ESDTRegisterAndSetAllRolesEnableEpoch = 1\n\n    # ScheduledMiniBlocksEnableEpoch represents the epoch when scheduled mini blocks would be created if needed\n    ScheduledMiniBlocksEnableEpoch = 1\n\n    # CorrectJailedNotUnstakedEpoch represents the epoch when the jailed validators will also be unstaked if the queue is empty\n    CorrectJailedNotUnstakedEmptyQueueEpoch = 1\n\n    # DoNotReturnOldBlockInBlockchainHookEnableEpoch represents the epoch when the fetch old block operation is\n    # disabled in the blockchain hook component\n    DoNotReturnOldBlockInBlockchainHookEnableEpoch = 1\n\n    # AddFailedRelayedTxToInvalidMBsDisableEpoch represents the epoch when adding the failed relayed txs to invalid miniblocks is disabled\n    AddFailedRelayedTxToInvalidMBsDisableEpoch = 1\n\n    # SCRSizeInvariantOnBuiltInResultEnableEpoch represents the epoch when scr size invariant on built in result is enabled\n    SCRSizeInvariantOnBuiltInResultEnableEpoch = 1\n\n    # CheckCorrectTokenIDForTransferRoleEnableEpoch represents the epoch when the correct token ID check is applied for transfer role verification\n    CheckCorrectTokenIDForTransferRoleEnableEpoch = 1\n\n    # DisableExecByCallerEnableEpoch represents the epoch when the check on value is disabled on exec by caller\n    DisableExecByCallerEnableEpoch = 1\n\n    # RefactorContextEnableEpoch represents the epoch when refactoring/simplifying is enabled in contexts\n    RefactorContextEnableEpoch = 1\n\n    # FailExecutionOnEveryAPIErrorEnableEpoch represent the epoch when new protection in VM is enabled to fail all wrong API calls\n    FailExecutionOnEveryAPIErrorEnableEpoch = 1\n\n    # ManagedCryptoAPIsEnableEpoch represents the epoch when new managed crypto APIs are enabled in the wasm VM\n    ManagedCryptoAPIsEnableEpoch = 1\n\n    # CheckFunctionArgumentEnableEpoch represents the epoch when the extra argument check is enabled in vm-common\n    CheckFunctionArgumentEnableEpoch = 1\n\n    # CheckExecuteOnReadOnlyEnableEpoch represents the epoch when the extra checks are enabled for execution on read only\n    CheckExecuteOnReadOnlyEnableEpoch = 1\n\n    # ESDTMetadataContinuousCleanupEnableEpoch represents the epoch when esdt metadata is automatically deleted according to inshard liquidity\n    ESDTMetadataContinuousCleanupEnableEpoch = 1\n\n    # MiniBlockPartialExecutionEnableEpoch represents the epoch when mini block partial execution will be enabled\n    MiniBlockPartialExecutionEnableEpoch = 1\n\n    # FixAsyncCallBackArgsListEnableEpoch represents the epoch when the async callback arguments lists fix will be enabled\n    FixAsyncCallBackArgsListEnableEpoch = 1\n\n    # FixOldTokenLiquidityEnableEpoch represents the epoch when the fix for old token liquidity is enabled\n    FixOldTokenLiquidityEnableEpoch = 1\n\n    # RuntimeMemStoreLimitEnableEpoch represents the epoch when the condition for Runtime MemStore is enabled\n    RuntimeMemStoreLimitEnableEpoch = 1\n\n    # SetSenderInEeiOutputTransferEnableEpoch represents the epoch when setting the sender in eei output transfers will be enabled\n    SetSenderInEeiOutputTransferEnableEpoch = 1\n\n    # RefactorPeersMiniBlocksEnableEpoch represents the epoch when refactor of the peers mini blocks will be enabled\n    RefactorPeersMiniBlocksEnableEpoch = 1\n\n    # MaxBlockchainHookCountersEnableEpoch represents the epoch when the max blockchainhook counters are enabled\n    MaxBlockchainHookCountersEnableEpoch = 1\n\n    # WipeSingleNFTLiquidityDecreaseEnableEpoch represents the epoch when the system account liquidity is decreased for wipeSingleNFT as well\n    WipeSingleNFTLiquidityDecreaseEnableEpoch = 1\n\n    # AlwaysSaveTokenMetaDataEnableEpoch represents the epoch when the token metadata is always saved\n    AlwaysSaveTokenMetaDataEnableEpoch = 1\n\n    # RuntimeCodeSizeFixEnableEpoch represents the epoch when the code size fix in the VM is enabled\n    RuntimeCodeSizeFixEnableEpoch = 1\n\n    # RelayedNonceFixEnableEpoch represents the epoch when the nonce fix for relayed txs is enabled\n    RelayedNonceFixEnableEpoch = 1\n\n    # SetGuardianEnableEpoch represents the epoch when the guard account feature is enabled in the protocol\n    SetGuardianEnableEpoch = 1\n\n    # DeterministicSortOnValidatorsInfoEnableEpoch represents the epoch when the deterministic sorting on validators info is enabled\n    DeterministicSortOnValidatorsInfoEnableEpoch = 1\n\n    # SCProcessorV2EnableEpoch represents the epoch when SC processor V2 will be used\n    SCProcessorV2EnableEpoch = 1\n\n    # AutoBalanceDataTriesEnableEpoch represents the epoch when the data tries are automatically balanced by inserting at the hashed key instead of the normal key\n    AutoBalanceDataTriesEnableEpoch = 1\n\n    # MigrateDataTrieEnableEpoch represents the epoch when the data tries migration is enabled\n    MigrateDataTrieEnableEpoch = 1\n\n    # KeepExecOrderOnCreatedSCRsEnableEpoch represents the epoch when the execution order of created SCRs is ensured\n    KeepExecOrderOnCreatedSCRsEnableEpoch = 1\n\n    # MultiClaimOnDelegationEnableEpoch represents the epoch when the multi claim on delegation is enabled\n    MultiClaimOnDelegationEnableEpoch = 1\n\n    # ChangeUsernameEnableEpoch represents the epoch when changing username is enabled\n    ChangeUsernameEnableEpoch = 4\n\n    # ConsistentTokensValuesLengthCheckEnableEpoch represents the epoch when the consistent tokens values length check is enabled\n    ConsistentTokensValuesLengthCheckEnableEpoch = 1\n\n    # FixDelegationChangeOwnerOnAccountEnableEpoch represents the epoch when the fix for the delegation system smart contract is enabled\n    FixDelegationChangeOwnerOnAccountEnableEpoch = 1\n\n    # DynamicGasCostForDataTrieStorageLoadEnableEpoch represents the epoch when dynamic gas cost for data trie storage load will be enabled\n    DynamicGasCostForDataTrieStorageLoadEnableEpoch = 1\n\n    # ScToScLogEventEnableEpoch represents the epoch when the sc to sc log event feature is enabled\n    ScToScLogEventEnableEpoch = 1\n\n    # NFTStopCreateEnableEpoch represents the epoch when NFT stop create feature is enabled\n    NFTStopCreateEnableEpoch = 1\n\n    # ChangeOwnerAddressCrossShardThroughSCEnableEpoch represents the epoch when the change owner address built in function will work also through a smart contract call cross shard\n    ChangeOwnerAddressCrossShardThroughSCEnableEpoch = 1\n\n    # FixGasRemainingForSaveKeyValueBuiltinFunctionEnableEpoch represents the epoch when the fix for the remaining gas in the SaveKeyValue builtin function is enabled\n    FixGasRemainingForSaveKeyValueBuiltinFunctionEnableEpoch = 1\n\n    # CurrentRandomnessOnSortingEnableEpoch represents the epoch when the current randomness on sorting is enabled\n    CurrentRandomnessOnSortingEnableEpoch = 1\n\n    # StakeLimitsEnableEpoch represents the epoch when stake limits on validators are enabled\n    # Should have the same value as StakingV4Step1EnableEpoch that triggers the automatic unstake operations for the queue nodes\n    StakeLimitsEnableEpoch = 1\n\n    # StakingV4Step1EnableEpoch represents the epoch when staking v4 is initialized. This is the epoch in which\n    # all nodes from staking queue are moved in the auction list\n    StakingV4Step1EnableEpoch = 1\n\n    # StakingV4Step2EnableEpoch represents the epoch when staking v4 is enabled. Should have a greater value than StakingV4Step1EnableEpoch.\n    # From this epoch, all shuffled out nodes are moved to auction nodes. No auction nodes selection is done yet.\n    StakingV4Step2EnableEpoch = 2\n\n    # StakingV4Step3EnableEpoch represents the epoch in which selected nodes from auction will be distributed to waiting list\n    StakingV4Step3EnableEpoch = 3\n\n    # CleanupAuctionOnLowWaitingListEnableEpoch represents the epoch when duplicated data cleanup from auction list is enabled in the condition of a low waiting list\n    # Should have the same value as StakingV4Step1EnableEpoch if the low waiting list has not happened, otherwise should have a greater value\n    CleanupAuctionOnLowWaitingListEnableEpoch = 1\n\n    # AlwaysMergeContextsInEEIEnableEpoch represents the epoch in which the EEI will always merge the contexts\n    AlwaysMergeContextsInEEIEnableEpoch = 1\n\n    # UseGasBoundedShouldFailExecutionEnableEpoch represents the epoch when use bounded gas function should fail execution in case of error\n    UseGasBoundedShouldFailExecutionEnableEpoch = 1\n\n    # DynamicESDTEnableEpoch represents the epoch when dynamic NFT feature is enabled\n    DynamicESDTEnableEpoch = 1\n\n    # EGLDInMultiTransferEnableEpoch represents the epoch when EGLD in multitransfer is enabled\n    EGLDInMultiTransferEnableEpoch = 1\n\n    # CryptoOpcodesV2EnableEpoch represents the epoch when BLSMultiSig, Secp256r1 and other opcodes are enabled\n    CryptoOpcodesV2EnableEpoch = 1\n\n    # UnjailCleanupEnableEpoch represents the epoch when the cleanup of the unjailed nodes is enabled\n    UnJailCleanupEnableEpoch = 1\n\n    # FixRelayedBaseCostEnableEpoch represents the epoch when the fix for relayed base cost will be enabled\n    FixRelayedBaseCostEnableEpoch = 1\n\n    # MultiESDTNFTTransferAndExecuteByUserEnableEpoch represents the epoch when enshrined sovereign cross chain opcodes are enabled\n    MultiESDTNFTTransferAndExecuteByUserEnableEpoch = 9999999\n\n    # FixRelayedMoveBalanceToNonPayableSCEnableEpoch represents the epoch when the fix for relayed move balance to non payable sc will be enabled\n    FixRelayedMoveBalanceToNonPayableSCEnableEpoch = 1\n\n    # RelayedTransactionsV3EnableEpoch represents the epoch when the relayed transactions v3 will be enabled\n    RelayedTransactionsV3EnableEpoch = 1\n\n    # RelayedTransactionsV3FixESDTTransferEnableEpoch represents the epoch when the fix for relayed transactions v3 with esdt transfer will be enabled\n    RelayedTransactionsV3FixESDTTransferEnableEpoch = 1 # TODO: keep this equal to RelayedTransactionsV3EnableEpoch for mainnet\n\n    # AndromedaEnableEpoch represents the epoch when the equivalent messages and fix order for consensus features are enabled\n    AndromedaEnableEpoch = 1\n\n    # SupernovaEnableEpoch represents the epoch when sub-second finality will be enabled\n    SupernovaEnableEpoch = 2\n\n    # FixEpochChangeProposedCurrentEpochEnableEpoch represents the epoch when epoch change proposed blocks expose the prepared epoch\n    FixEpochChangeProposedCurrentEpochEnableEpoch = 3\n\n    # CheckBuiltInCallOnTransferValueAndFailEnableRound represents the ROUND when the check on transfer value fix is activated\n    CheckBuiltInCallOnTransferValueAndFailEnableRound = 1\n\n    # MaskVMInternalDependenciesErrorsEnableEpoch represents the epoch when the additional internal erorr masking in vm is enabled\n    MaskVMInternalDependenciesErrorsEnableEpoch = 1\n\n    # FixBackTransferOPCODEEnableEpoch represents the epoch when the fix for back transfers opcode will be enabled\n    FixBackTransferOPCODEEnableEpoch = 1\n\n    # ValidationOnGobDecodeEnableEpoch represents the epoch when validation on GobDecode will be taken into account\n    ValidationOnGobDecodeEnableEpoch = 1\n\n    # BarnardOpcodesEnableEpoch represents the epoch when Barnard opcodes will be enabled\n    BarnardOpcodesEnableEpoch = 1\n\n    # FixGetBalanceEnableEpoch represents the epoch when get balance opcode fix is enabled\n    FixGetBalanceEnableEpoch = 1\n\n    # AutomaticActivationOfNodesDisableEpoch represents the epoch when automatic activation of nodes for validators is disabled\n    AutomaticActivationOfNodesDisableEpoch = 1\n\n    # RelayedTransactionsV1V2DisableEpoch represents the epoch when relayed transactions v1 and v2 are disabled\n    RelayedTransactionsV1V2DisableEpoch = 1\n\n    # FullShardDataValidationEnableEpoch represents the epoch when NumPendingMiniBlocks and LastIncludedMetaNonce\n    # in meta ShardData are enforced during verification; before it, these two fields are skipped.\n    FullShardDataValidationEnableEpoch = 1\n\n    # ConsumedGasInEconomicsFixEnableEpoch represents the epoch when consumed gas in accumulated economics is fixed\n    ConsumedGasInEconomicsFixEnableEpoch = 1\n\n    # AttributeExtraGasUsageEnableEpoch represents the epoch when the extra gas usage for attributes is enabled\n    AttributeExtraGasUsageEnableEpoch = 1\n\n    # BLSMultiSignerEnableEpoch represents the activation epoch for different types of BLS multi-signers\n    BLSMultiSignerEnableEpoch = [\n        { EnableEpoch = 0, Type = \"no-KOSK\" },\n        { EnableEpoch = 1, Type = \"KOSK\" }\n    ]\n\n    # MaxNodesChangeEnableEpoch holds configuration for changing the maximum number of nodes and the enabling epoch\n    MaxNodesChangeEnableEpoch = [\n        { EpochEnable = 0, MaxNumNodes = 48, NodesToShufflePerShard = 4 },  # 4 shuffled out keys / shard will not be reached normally\n        { EpochEnable = 1, MaxNumNodes = 64, NodesToShufflePerShard = 2 },\n        # Staking v4 configuration, where:\n        # - Enable epoch = StakingV4Step3EnableEpoch\n        # - NodesToShufflePerShard = same as previous entry in MaxNodesChangeEnableEpoch\n        # - MaxNumNodes = (MaxNumNodesFromPreviousEpochEnable - (numOfShards+1)*NodesToShufflePerShard)\n        { EpochEnable = 3, MaxNumNodes = 56, NodesToShufflePerShard = 2 },\n    ]\n\n[GasSchedule]\n    # GasScheduleByEpochs holds the configuration for the gas schedule that will be applied from specific epochs\n    GasScheduleByEpochs = [\n        { StartEpoch = 0, FileName = \"gasScheduleV9.toml\" },\n    ]\n", "b1ac9bc61a7eb19c3e9b0d4e7e4860921df6b25520094f462282ccb0e84eb9c8"},
}

func qualDRWACandidateFixtureDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, fixture := range qualDRWACandidateFixtures {
		body := []byte(fixture.body)
		require.Equal(t, fixture.sha256, fmt.Sprintf("%x", sha256.Sum256(body)), name)
		path := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0700))
		require.NoError(t, os.WriteFile(path, body, 0600))
	}
	return dir
}
