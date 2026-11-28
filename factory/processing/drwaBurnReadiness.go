package processing

import (
	"github.com/multiversx/mx-chain-go/process/drwa"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/vm/systemSmartContracts"
)

// newDRWABurnReadiness creates, for the metachain node of a DRWA deployment,
// the E10 readiness owner over the node's own admin-effect and funding owners
// and the convergence host with that readiness bound into phase completion.
// The metachain role is read from the ESDT system contract's own records in
// the same account store.
func (pcf *processComponentsFactory) newDRWABurnReadiness(
	accounts state.AccountsAdapter,
	block drwa.ConvergenceBlockSource,
	host *drwa.ConvergenceHost,
	effects *drwa.AdminEffects,
	funding *drwa.CarrierFunding,
) (*drwa.BurnForAllReadiness, *drwa.BurnBoundConvergenceHost, error) {
	roles, err := systemSmartContracts.NewDRWABurnRoleReader(accounts, pcf.coreData.InternalMarshalizer())
	if err != nil {
		return nil, nil, err
	}
	limits := pcf.drwaInitialProgrammeStartup.Limits
	readiness, err := drwa.NewBurnForAllReadiness(drwa.ArgsBurnForAllReadiness{
		Accounts:   accounts,
		Marshaller: pcf.coreData.InternalMarshalizer(),
		Hasher:     pcf.coreData.Hasher(),
		Domain:     pcf.drwaDomain,
		Effects:    effects,
		Funding:    funding,
		Roles:      roles,
		Block:      block,
		Flags:      pcf.coreData.EnableEpochsHandler(),
		Limits: drwa.RegistrationResourceLimits{
			Records: limits.Records, RetainedBytes: limits.RetainedBytes, NewRecordsPerEpoch: limits.NewRecordsPerEpoch},
		RecordBytes: limits.RecordBytes,
		Shards:      pcf.bootstrapComponents.ShardCoordinator().NumberOfShards(),
	})
	if err != nil {
		return nil, nil, err
	}
	bound, err := drwa.NewBurnBoundConvergenceHost(host, readiness)
	if err != nil {
		return nil, nil, err
	}

	return readiness, bound, nil
}
