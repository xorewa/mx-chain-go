package builtInFunctions

import (
	"errors"
	"fmt"

	"github.com/multiversx/mx-chain-core-go/core"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwa"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// REPLACED_BY_PART_B

// ErrDRWAGasScheduleUnavailable signals that no retained configured identity matches current gas truth.
var ErrDRWAGasScheduleUnavailable = errors.New("non-normative DRWA prototype gas schedule unavailable")

type drwaConfiguredGasScheduleProvider interface {
	common.DRWAGasScheduleProvider
	LatestGasScheduleCopy() map[string]map[string]uint64
}

func sealDRWAConfiguredGasScheduleCatalog(
	notifier core.GasScheduleNotifier,
) (*drwa.GasScheduleCatalog, error) {
	provider, ok := notifier.(drwaConfiguredGasScheduleProvider)
	if !ok {
		return nil, nil
	}

	versions := provider.DRWAVersionedGasSchedules()
	profiles := make([]drwa.GasScheduleProfile, len(versions))
	for index, version := range versions {
		profiles[index] = drwa.GasScheduleProfile{
			StartEpoch: version.StartEpoch,
			Schedule:   drwa.GasScheduleMap(version.Schedule),
		}
	}

	catalog, err := drwa.SealGasScheduleCatalog(profiles)
	if err != nil {
		return nil, fmt.Errorf("%w: seal configured catalog: %w", ErrDRWAGasScheduleUnavailable, err)
	}

	return catalog, nil
}

func currentDRWAGasScheduleIdentity(
	provider drwaConfiguredGasScheduleProvider,
	catalog *drwa.GasScheduleCatalog,
) ([32]byte, error) {
	if provider == nil || catalog == nil {
		return [32]byte{}, ErrDRWAGasScheduleUnavailable
	}
	identity, err := drwa.GasScheduleIdentity(
		drwa.GasScheduleMap(provider.LatestGasScheduleCopy()),
	)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: current map identity: %w", ErrDRWAGasScheduleUnavailable, err)
	}
	_, err = catalog.Schedule(identity)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: current map not retained: %w", ErrDRWAGasScheduleUnavailable, err)
	}

	return identity, nil
}

func currentDRWAWorkBudgets(
	provider drwaConfiguredGasScheduleProvider,
	catalog *drwa.GasScheduleCatalog,
) ([32]byte, drwa.WorkBudgets, uint64, error) {
	identity, err := currentDRWAGasScheduleIdentity(provider, catalog)
	if err != nil {
		return [32]byte{}, drwa.WorkBudgets{}, 0, err
	}
	budgets, err := catalog.MaximumWorkBudgets()
	if err != nil {
		return [32]byte{}, drwa.WorkBudgets{}, 0,
			fmt.Errorf("%w: configured work budgets: %w", ErrDRWAGasScheduleUnavailable, err)
	}
	total, err := budgets.Total()
	if err != nil {
		return [32]byte{}, drwa.WorkBudgets{}, 0,
			fmt.Errorf("%w: configured work total: %w", ErrDRWAGasScheduleUnavailable, err)
	}

	return identity, budgets, total, nil
}

func retainedDRWAWorkBudgets(
	identity [32]byte,
	catalog *drwa.GasScheduleCatalog,
) (drwa.WorkBudgets, uint64, error) {
	if catalog == nil {
		return drwa.WorkBudgets{}, 0, ErrDRWAGasScheduleUnavailable
	}
	_, err := catalog.Schedule(identity)
	if err != nil {
		return drwa.WorkBudgets{}, 0,
			fmt.Errorf("%w: context map not retained: %w", ErrDRWAGasScheduleUnavailable, err)
	}
	budgets, err := catalog.MaximumWorkBudgets()
	if err != nil {
		return drwa.WorkBudgets{}, 0,
			fmt.Errorf("%w: configured work budgets: %w", ErrDRWAGasScheduleUnavailable, err)
	}
	total, err := budgets.Total()
	if err != nil {
		return drwa.WorkBudgets{}, 0,
			fmt.Errorf("%w: configured work total: %w", ErrDRWAGasScheduleUnavailable, err)
	}
	return budgets, total, nil
}
