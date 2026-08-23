package builtInFunctions

import (
	"errors"
	"fmt"

	"github.com/multiversx/mx-chain-core-go/core"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwaprototype"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// REPLACED_BY_PART_B

// ErrPrototypeGasScheduleUnavailable signals that no retained configured identity matches current gas truth.
var ErrPrototypeGasScheduleUnavailable = errors.New("non-normative DRWA prototype gas schedule unavailable")

type prototypeConfiguredGasScheduleProvider interface {
	common.PrototypeDRWAGasScheduleProvider
	LatestGasScheduleCopy() map[string]map[string]uint64
}

func sealPrototypeConfiguredGasScheduleCatalog(
	notifier core.GasScheduleNotifier,
) (*drwaprototype.GasScheduleCatalog, error) {
	provider, ok := notifier.(prototypeConfiguredGasScheduleProvider)
	if !ok {
		return nil, nil
	}

	versions := provider.PrototypeDRWAVersionedGasSchedules()
	profiles := make([]drwaprototype.GasScheduleProfile, len(versions))
	for index, version := range versions {
		profiles[index] = drwaprototype.GasScheduleProfile{
			StartEpoch: version.StartEpoch,
			Schedule:   drwaprototype.GasScheduleMap(version.Schedule),
		}
	}

	catalog, err := drwaprototype.SealGasScheduleCatalog(profiles)
	if err != nil {
		return nil, fmt.Errorf("%w: seal configured catalog: %w", ErrPrototypeGasScheduleUnavailable, err)
	}

	return catalog, nil
}

func currentPrototypeGasScheduleIdentity(
	provider prototypeConfiguredGasScheduleProvider,
	catalog *drwaprototype.GasScheduleCatalog,
) ([32]byte, error) {
	if provider == nil || catalog == nil {
		return [32]byte{}, ErrPrototypeGasScheduleUnavailable
	}
	identity, err := drwaprototype.GasScheduleIdentity(
		drwaprototype.GasScheduleMap(provider.LatestGasScheduleCopy()),
	)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: current map identity: %w", ErrPrototypeGasScheduleUnavailable, err)
	}
	_, err = catalog.Schedule(identity)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: current map not retained: %w", ErrPrototypeGasScheduleUnavailable, err)
	}

	return identity, nil
}

func currentPrototypeWorkBudgets(
	provider prototypeConfiguredGasScheduleProvider,
	catalog *drwaprototype.GasScheduleCatalog,
) ([32]byte, drwaprototype.WorkBudgets, uint64, error) {
	identity, err := currentPrototypeGasScheduleIdentity(provider, catalog)
	if err != nil {
		return [32]byte{}, drwaprototype.WorkBudgets{}, 0, err
	}
	budgets, err := catalog.MaximumWorkBudgets()
	if err != nil {
		return [32]byte{}, drwaprototype.WorkBudgets{}, 0,
			fmt.Errorf("%w: configured work budgets: %w", ErrPrototypeGasScheduleUnavailable, err)
	}
	total, err := budgets.Total()
	if err != nil {
		return [32]byte{}, drwaprototype.WorkBudgets{}, 0,
			fmt.Errorf("%w: configured work total: %w", ErrPrototypeGasScheduleUnavailable, err)
	}

	return identity, budgets, total, nil
}
