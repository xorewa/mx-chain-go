package core

import (
	"fmt"

	nativeCore "github.com/multiversx/mx-chain-core-go/core"
	hashFactory "github.com/multiversx/mx-chain-core-go/hashing/factory"
	"github.com/multiversx/mx-chain-core-go/marshal"
	marshalFactory "github.com/multiversx/mx-chain-core-go/marshal/factory"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/chainparametersnotifier"
	commonConfigs "github.com/multiversx/mx-chain-go/common/configs"
	"github.com/multiversx/mx-chain-go/common/enablers"
	converterFactory "github.com/multiversx/mx-chain-go/common/factory"
	"github.com/multiversx/mx-chain-go/common/forking"
	"github.com/multiversx/mx-chain-go/common/graceperiod"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/epochStart/notifier"
	factoryBlock "github.com/multiversx/mx-chain-go/factory/block"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/guardian"
	"github.com/multiversx/mx-chain-go/sharding"
)

// DRWAConfigurationSupport is an explicit proposed route/processor matrix.
// Its values are not defaults or a grant to exclude an architecture obligation.
// Owner admission and T10's transitive inventory remain separate prerequisites.
type DRWAConfigurationSupport struct {
	ProcessorV1, RelayedV3 bool
	// RegisterMetaESDTPath denotes a supported path calling the native
	// registerMetaESDT handler (E05 L606); it does not select a token family.
	RegisterMetaESDTPath bool
}

// DRWAConfigurationCandidate retains native handlers built from actual files.
// This unwired T09 component checks the E05 minimum and the existing native
// startup tuple. It does not admit a profile, validate the entire node startup,
// appoint authorities, launch a node, or grant an enforcement capability.
// The real startup/decorator owner must bind these exact inputs and all further
// T10-discovered prerequisites before enabling any DRWA dependent effect.
type DRWAConfigurationCandidate struct {
	enforcement uint32
	epochs      common.EnableEpochsHandler
	rounds      common.EnableRoundsHandler
	support     DRWAConfigurationSupport
}

// LoadDRWAConfigurationCandidate reuses the actual native loaders and handlers.
// The DRWA-defined enforcement coordinate is in an EXPERIMENTAL separate TOML
// overlay; pointer presence distinguishes explicit epoch zero from an absent
// field. This location is a construction candidate, not a release allocation.
// No shared loader, native field, notifier or ordinary startup path is changed.
func LoadDRWAConfigurationCandidate(paths config.ConfigurationPathsHolder, overlay string,
	support DRWAConfigurationSupport) (*DRWAConfigurationCandidate, error) {
	var drwa struct{ DRWAEnforcementEnableEpoch *uint32 }
	if err := nativeCore.LoadTomlFile(&drwa, overlay); err != nil {
		return nil, err
	}
	if drwa.DRWAEnforcementEnableEpoch == nil {
		return nil, fmt.Errorf("missing DRWAEnforcementEnableEpoch")
	}
	main, err := common.LoadMainConfig(paths.MainConfig)
	if err != nil {
		return nil, err
	}
	epoch, err := common.LoadEpochConfig(paths.Epoch)
	if err != nil {
		return nil, err
	}
	round, err := common.LoadRoundConfig(paths.RoundActivation)
	if err != nil {
		return nil, err
	}
	economics, err := common.LoadEconomicsConfig(paths.Economics)
	if err != nil {
		return nil, err
	}
	ratings, err := common.LoadRatingsConfig(paths.Ratings)
	if err != nil {
		return nil, err
	}
	epochs, err := enablers.NewEnableEpochsHandler(epoch.EnableEpochs, forking.NewGenericEpochNotifier())
	if err != nil {
		return nil, err
	}
	roundNotifier := forking.NewGenericRoundNotifier()
	rounds, err := enablers.NewEnableRoundsHandler(*round, roundNotifier)
	if err != nil {
		return nil, err
	}
	if err = validateDRWAStartupConfigs(*main, roundNotifier); err != nil {
		return nil, err
	}
	// Reuse the WHOLE native cross-file tuple validation, including every epoch
	// and round table, versions, economics, ratings and round-duration changes.
	if err = validateSupernovaActivationTuple(*main, *economics, *ratings,
		epochs.GetActivationEpoch(common.SupernovaFlag), rounds.GetActivationRound(common.SupernovaRoundFlag)); err != nil {
		return nil, err
	}
	// Validate the actual next consumers too. The tuple helper alone permits a
	// missing epoch-zero chain entry; the native holder rejects it. The header
	// constructor sorts in place, so reconcile the tuple AFTER that real sorter.
	_, err = sharding.NewChainParametersHolder(sharding.ArgsChainParametersHolder{
		ChainParameters:         main.GeneralSettings.ChainParametersByEpoch,
		EpochStartEventNotifier: notifier.NewEpochStartSubscriptionHandler(),
		ChainParametersNotifier: chainparametersnotifier.NewChainParametersNotifier(),
	})
	if err != nil {
		return nil, err
	}
	_, err = factoryBlock.NewHeaderVersionHandler(main.Versions.VersionsByEpochs, main.Versions.DefaultVersion)
	if err != nil {
		return nil, err
	}
	if err = validateSupernovaActivationTuple(*main, *economics, *ratings,
		epochs.GetActivationEpoch(common.SupernovaFlag), rounds.GetActivationRound(common.SupernovaRoundFlag)); err != nil {
		return nil, err
	}
	candidate := &DRWAConfigurationCandidate{enforcement: *drwa.DRWAEnforcementEnableEpoch,
		epochs: epochs, rounds: rounds, support: support}
	if err = candidate.checkPrerequisites(candidate.enforcement); err != nil {
		return nil, err
	}
	return candidate, nil
}

// validateDRWAStartupConfigs adopts the pure native core startup constructors.
// The activation-tuple check only requires matching boundary entries; these
// constructors also reject missing base entries, duplicates and invalid values
// throughout the tables, including future entries. No startup timer, network,
// account adapter or parallel configuration mechanism is created here.
func validateDRWAStartupConfigs(cfg config.Config, rounds process.RoundNotifier) error {
	for _, name := range []string{cfg.Hasher.Type, cfg.TxSignHasher.Type} {
		if _, err := hashFactory.NewHasher(name); err != nil {
			return err
		}
	}
	var internalMarshalizer marshal.Marshalizer
	for index, name := range []string{cfg.Marshalizer.Type, cfg.VmMarshalizer.Type, cfg.TxSignMarshalizer.Type} {
		marshaller, err := marshalFactory.NewMarshalizer(name)
		if err != nil {
			return err
		}
		if index == 0 {
			internalMarshalizer = marshaller
		}
	}
	for _, pubkeyCfg := range []config.PubkeyConfig{cfg.AddressPubkeyConverter, cfg.ValidatorPubkeyConverter} {
		if _, err := converterFactory.NewPubkeyConverter(pubkeyCfg); err != nil {
			return err
		}
	}
	gs := cfg.GeneralSettings
	// E05 also binds the actual bootstrap guardian-delay consumer. Reuse its
	// constructor and native error; this local notifier starts no runtime.
	if _, err := guardian.NewGuardedAccount(internalMarshalizer, forking.NewGenericEpochNotifier(), gs.SetGuardianEpochsDelay); err != nil {
		return err
	}
	if _, err := graceperiod.NewEpochChangeGracePeriod(gs.EpochChangeGracePeriodByEpoch); err != nil {
		return err
	}
	if _, err := commonConfigs.NewCommonConfigsHandler(gs.EpochStartConfigsByEpoch,
		gs.EpochStartConfigsByRound, gs.ConsensusConfigsByEpoch, gs.ConsensusConfigsByRound, false); err != nil {
		return err
	}
	if _, err := commonConfigs.NewProcessConfigsHandler(gs.ProcessConfigsByEpoch, gs.ProcessConfigsByRound, rounds); err != nil {
		return err
	}
	_, err := commonConfigs.NewAntifloodConfigsHandler(cfg.Antiflood, rounds)
	return err
}

func (c *DRWAConfigurationCandidate) checkPrerequisites(epoch uint32) error {
	if c == nil || c.epochs == nil || c.rounds == nil {
		return fmt.Errorf("missing DRWA loaded configuration candidate")
	}
	// E05's positive predicates, plus actual transitive native consumers:
	// ManagedCryptoAPIsFlag for MetaESDT special-role validation and
	// ESDTNFTImprovementV1Flag for the retained multi-transfer builtin.
	// EGLDInESDTMultiTransferFlag alone does not activate that builtin.
	// Do not infer polarity from names; the remaining T10 inventory stays due.
	required := []nativeCore.EnableEpochFlag{common.SupernovaFlag, common.DynamicESDTFlag,
		common.ESDTFlag, common.NFTStopCreateFlag, common.SetGuardianFlag,
		common.EGLDInESDTMultiTransferFlag, common.ManagedCryptoAPIsFlag,
		common.ESDTNFTImprovementV1Flag}
	if c.support.RegisterMetaESDTPath {
		required = append(required, common.MetaESDTSetFlag)
	}
	if !c.support.ProcessorV1 {
		required = append(required, common.SCProcessorV2Flag)
	}
	// The native proxy selects V1 only while this actual predicate is false.
	// V1 dispatch requires BuiltInFunctionsFlag; V2 does not inherit that gate.
	if !c.epochs.IsFlagEnabledInEpoch(common.SCProcessorV2Flag, epoch) {
		required = append(required, common.BuiltInFunctionsFlag)
	}
	if c.support.RelayedV3 {
		required = append(required, common.RelayedTransactionsV3Flag,
			common.RelayedTransactionsV3FixESDTTransferFlag, common.FixRelayedBaseCostFlag,
			common.FixRelayedMoveBalanceToNonPayableSCFlag)
	}
	for _, flag := range required {
		if !c.epochs.IsFlagDefined(flag) || !c.epochs.IsFlagEnabledInEpoch(flag, epoch) {
			return fmt.Errorf("DRWA prerequisite %s is inactive at epoch %d", flag, epoch)
		}
	}
	// The negative predicate is deliberately separate: E05/W01 require FALSE.
	if !c.epochs.IsFlagDefined(common.GlobalMintBurnFlag) || c.epochs.IsFlagEnabledInEpoch(common.GlobalMintBurnFlag, epoch) {
		return fmt.Errorf("DRWA requires GlobalMintBurnFlag=false at epoch %d", epoch)
	}
	return nil
}

// Enabled is the exact A L573/E05 joint predicate using pinned native semantics.
// In particular, the epoch-on/round-off drain window cannot enable DRWA.
func (c *DRWAConfigurationCandidate) Enabled(epoch uint32, round uint64) bool {
	return c != nil && c.epochs != nil && c.rounds != nil && epoch >= c.enforcement &&
		common.IsAsyncExecutionEnabledForEpochAndRound(c.epochs, c.rounds, epoch, round)
}

// CheckEnforcedBlock rejects unsupported coordinates BEFORE dependent execution.
// It is a configuration predicate only, never a caller-authenticated block token.
func (c *DRWAConfigurationCandidate) CheckEnforcedBlock(epoch uint32, round uint64) error {
	if !c.Enabled(epoch, round) {
		return fmt.Errorf("DRWA is inactive for epoch %d round %d", epoch, round)
	}
	return c.checkPrerequisites(epoch)
}

// ActivationInventory records all actual native epoch and round values, including
// flags outside the E05 minimum (e.g. cleanup). Returned maps are native copies.
// Source/loader/consumer provenance and actual selected processor bindings must
// be retained alongside these values; this map alone is not an admission record.
func (c *DRWAConfigurationCandidate) ActivationInventory() (map[string]uint32, map[string]uint64) {
	if c == nil {
		return nil, nil
	}
	return c.epochs.GetAllEnableEpochs(), c.rounds.GetAllEnableRounds()
}
