package processing

import (
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/marshal"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/dataRetriever"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/drwa"
	"github.com/multiversx/mx-chain-go/state"
)

// drwaFinalityEvidence reads native headers and header proofs the node already
// holds: the pools first, then the block storage. It decides nothing; the
// import owner accepts an object only by its committed hash.
type drwaFinalityEvidence struct {
	headers    dataRetriever.HeadersPool
	proofs     dataRetriever.ProofsPool
	storage    dataRetriever.StorageService
	marshaller marshal.Marshalizer
}

// Header returns the header with the given hash from the pool or the storage
func (e *drwaFinalityEvidence) Header(shardID uint32, hash []byte) (data.HeaderHandler, error) {
	return process.GetHeader(hash, e.headers, e.storage, e.marshaller, shardID)
}

// Proof returns the header proof with the given header hash from the pool or the storage
func (e *drwaFinalityEvidence) Proof(shardID uint32, hash []byte) (data.HeaderProofHandler, error) {
	proof, err := e.proofs.GetProof(shardID, hash)
	if err == nil && !check.IfNil(proof) {
		return proof, nil
	}
	raw, err := e.storage.Get(dataRetriever.ProofsUnit, hash)
	if err != nil {
		return nil, err
	}
	stored := &block.HeaderProof{}
	err = e.marshaller.Unmarshal(stored, raw)
	if err != nil {
		return nil, err
	}

	return stored, nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (e *drwaFinalityEvidence) IsInterfaceNil() bool {
	return e == nil
}

// newDRWAFinalityImport creates the owner of the pending/final heads of the
// processing account store. It exists only on a node started on an admitted
// DRWA deployment; every other node gets nil and keeps native block processing.
// No record class is installed here: each class is added by the row that owns
// its protected write, so until then every staging request is refused.
func (pcf *processComponentsFactory) newDRWAFinalityImport(
	accounts state.AccountsAdapter,
	headerValidator process.HeaderConstructionValidator,
) (process.DRWAFinalityImportHandler, error) {
	if pcf.drwaConfigurationCandidate == nil || pcf.drwaInitialProgrammeStartup == nil {
		return nil, nil
	}

	exclusions, err := common.NewConfiguredRoundExclusionHandler(&pcf.config)
	if err != nil {
		return nil, err
	}

	owner, err := drwa.NewFinalityImport(drwa.ArgsFinalityImport{
		Accounts:    accounts,
		Marshaller:  pcf.coreData.InternalMarshalizer(),
		Hasher:      pcf.coreData.Hasher(),
		SelfShardID: pcf.bootstrapComponents.ShardCoordinator().SelfId(),
		Source: &drwaFinalityEvidence{
			headers:    pcf.data.Datapool().Headers(),
			proofs:     pcf.data.Datapool().Proofs(),
			storage:    pcf.data.StorageService(),
			marshaller: pcf.coreData.InternalMarshalizer(),
		},
		Validator:      headerValidator,
		Proofs:         pcf.drwaHeaderProofVerifier,
		Integrity:      pcf.bootstrapComponents.HeaderIntegrityVerifier(),
		Exclusions:     exclusions,
		MaxRecordBytes: pcf.drwaInitialProgrammeStartup.Limits.RecordBytes,
	})
	if err != nil {
		return nil, err
	}
	pcf.drwaFinalityImport = owner
	if owner.SelfShardID() != core.MetachainShardId {
		return owner, nil
	}

	// The metachain node also owns the production convergence host (Part A
	// E.17). No family owner is installed here: each is added by the row that
	// owns that family's producer, so until then every transition is refused.
	limits := pcf.drwaInitialProgrammeStartup.Limits
	host, err := drwa.NewNativeConvergenceHost(drwa.ArgsNativeConvergenceHost{
		Accounts:             accounts,
		Marshaller:           pcf.coreData.InternalMarshalizer(),
		Hasher:               pcf.coreData.Hasher(),
		EnableEpochsHandler:  pcf.coreData.EnableEpochsHandler(),
		MaxTrieLevelInMemory: pcf.config.StateTriesConfig.MaxStateTrieLevelInMemory,
		Validator:            headerValidator,
		Proofs:               pcf.drwaHeaderProofVerifier,
		Integrity:            pcf.bootstrapComponents.HeaderIntegrityVerifier(),
		Exclusions:           exclusions,
		Block:                owner,
		Limits: drwa.RegistrationResourceLimits{
			Records: limits.Records, RetainedBytes: limits.RetainedBytes, NewRecordsPerEpoch: limits.NewRecordsPerEpoch},
		RecordBytes:   limits.RecordBytes,
		EvidenceBytes: limits.AggregateBytes,
	})
	if err != nil {
		return nil, err
	}

	// The cap validator of a requalification reads the origin shard's SupplyState
	// evidence through this verifier (Part A L2673-2686). It has no caller
	// until the row that owns that validator is built.
	supply, err := drwa.NewNativeSupplyEvidenceVerifier(drwa.ArgsNativeSupplyEvidenceVerifier{
		Accounts:             accounts,
		Marshaller:           pcf.coreData.InternalMarshalizer(),
		Hasher:               pcf.coreData.Hasher(),
		EnableEpochsHandler:  pcf.coreData.EnableEpochsHandler(),
		MaxTrieLevelInMemory: pcf.config.StateTriesConfig.MaxStateTrieLevelInMemory,
		Validator:            headerValidator,
		Proofs:               pcf.drwaHeaderProofVerifier,
		Integrity:            pcf.bootstrapComponents.HeaderIntegrityVerifier(),
		Exclusions:           exclusions,
		Block:                owner,
		RecordBytes:          limits.RecordBytes,
		EvidenceBytes:        limits.AggregateBytes,
	})
	if err != nil {
		return nil, err
	}

	// The metachain node owns the funding of carried effects (Part A 4.7.4,
	// E.18): prices come from the native gas schedule, records are charged to
	// the same retained budget. It has no caller until the rows that own the
	// carriers install it (the registration ingress, P06), and it prices
	// nothing until an admitted schedule carries the entries.
	prices, err := drwa.NewGasScheduleCarrierPricing(pcf.gasSchedule)
	if err != nil {
		return nil, err
	}
	funding, err := drwa.NewCarrierFunding(drwa.ArgsCarrierFunding{
		Accounts:   accounts,
		Marshaller: pcf.coreData.InternalMarshalizer(),
		Hasher:     pcf.coreData.Hasher(),
		Block:      owner,
		Prices:     prices,
		Limits: drwa.RegistrationResourceLimits{
			Records: limits.Records, RetainedBytes: limits.RetainedBytes, NewRecordsPerEpoch: limits.NewRecordsPerEpoch},
		RecordBytes: limits.RecordBytes,
	})
	if err != nil {
		return nil, err
	}

	// The metachain node owns the origin of protected admin effects (Part A
	// 4.5.2, 4.7.1): OpenEffects, their legs, the acknowledgement evidence
	// entry point and the redrive. It has no caller until the rows that own the
	// protected metachain operations install it (registration: SP2-38).
	adminEffects, err := drwa.NewAdminEffects(drwa.ArgsAdminEffects{
		Accounts:   accounts,
		Marshaller: pcf.coreData.InternalMarshalizer(),
		Hasher:     pcf.coreData.Hasher(),
		Domain:     pcf.drwaDomain,
		Funding:    funding,
		Block:      owner,
		Evidence:   host,
		Limits: drwa.RegistrationResourceLimits{
			Records: limits.Records, RetainedBytes: limits.RetainedBytes, NewRecordsPerEpoch: limits.NewRecordsPerEpoch},
		RecordBytes: limits.RecordBytes,
		Shards:      pcf.bootstrapComponents.ShardCoordinator().NumberOfShards(),
	})
	// The metachain node also owns the replication of the setup seal and is
	// the owner of the setup convergence family (Part A L2489-2503,
	// L5466-5470). The two origin owners are built together: a failure of
	// either refuses the node.
	var seal *drwa.LifecycleSealOrigin
	if err == nil {
		seal, err = pcf.installDRWALifecycleSealOrigin(accounts, host, funding)
	}
	if err != nil {
		return nil, err
	}

	// E10 (Part A E.20): the readiness owner of the false global-burn state of
	// every shard, and the convergence host with that readiness bound into the
	// completion of every phase. The registration ingress opens a token's
	// readiness and uses the bound host for its phases (SP2-38).
	readiness, bound, err := pcf.newDRWABurnReadiness(accounts, owner, host, adminEffects, funding)
	if err != nil {
		return nil, err
	}

	return &drwaMetaFinalityImport{FinalityImport: owner, convergence: host, supplyEvidence: supply, funding: funding,
		adminEffects: adminEffects, lifecycleSeal: seal, burnReadiness: readiness, burnBound: bound}, nil
}

// drwaMetaFinalityImport is the metachain block processor's import owner
// together with the convergence host that reads the block it opens.
type drwaMetaFinalityImport struct {
	*drwa.FinalityImport
	convergence    *drwa.ConvergenceHost
	supplyEvidence *drwa.SupplyEvidenceVerifier
	funding        *drwa.CarrierFunding
	adminEffects   *drwa.AdminEffects
	lifecycleSeal  *drwa.LifecycleSealOrigin
	burnReadiness  *drwa.BurnForAllReadiness
	burnBound      *drwa.BurnBoundConvergenceHost
}

// DRWABurnForAllReadiness returns the metachain node's owner of E10's shard
// readiness.
func (m *drwaMetaFinalityImport) DRWABurnForAllReadiness() *drwa.BurnForAllReadiness {
	return m.burnReadiness
}

// DRWABurnBoundConvergenceHost returns the convergence host with E10's
// readiness bound into phase completion.
func (m *drwaMetaFinalityImport) DRWABurnBoundConvergenceHost() *drwa.BurnBoundConvergenceHost {
	return m.burnBound
}

// DRWAAdminEffects returns the metachain node's origin owner of protected
// admin effects.
func (m *drwaMetaFinalityImport) DRWAAdminEffects() *drwa.AdminEffects { return m.adminEffects }

// DRWACarrierFunding returns the metachain node's owner of the pricing and
// phase of carried effects.
func (m *drwaMetaFinalityImport) DRWACarrierFunding() *drwa.CarrierFunding { return m.funding }

// DRWASupplyEvidenceVerifier returns the metachain node's verifier of
// closure-bound origin SupplyState evidence.
func (m *drwaMetaFinalityImport) DRWASupplyEvidenceVerifier() *drwa.SupplyEvidenceVerifier {
	return m.supplyEvidence
}

// DRWALifecycleSealOrigin returns the metachain node's owner of the setup
// seal's replication.
func (m *drwaMetaFinalityImport) DRWALifecycleSealOrigin() *drwa.LifecycleSealOrigin {
	return m.lifecycleSeal
}

// DRWAConvergenceHost returns the metachain node's convergence host.
func (m *drwaMetaFinalityImport) DRWAConvergenceHost() *drwa.ConvergenceHost { return m.convergence }

// IsInterfaceNil returns true if there is no value under the interface
func (m *drwaMetaFinalityImport) IsInterfaceNil() bool { return m == nil || m.FinalityImport == nil }
