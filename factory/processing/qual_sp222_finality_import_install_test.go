package processing

import (
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/stretchr/testify/require"

	nodeFactory "github.com/multiversx/mx-chain-go/cmd/node/factory"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/dataRetriever"
	"github.com/multiversx/mx-chain-go/factory"
	factoryMock "github.com/multiversx/mx-chain-go/factory/mock"
	"github.com/multiversx/mx-chain-go/process"
	processMock "github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/storage"
	"github.com/multiversx/mx-chain-go/testscommon"
	consensusMock "github.com/multiversx/mx-chain-go/testscommon/consensus"
	dataMock "github.com/multiversx/mx-chain-go/testscommon/dataRetriever"
	"github.com/multiversx/mx-chain-go/testscommon/pool"
	"github.com/multiversx/mx-chain-go/testscommon/processMocks"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	storageMock "github.com/multiversx/mx-chain-go/testscommon/storage"
)

// SP2-22: the finalized-result import owner is created only on a DRWA
// deployment, and its evidence source only reads what the node holds.

type qualSP222Bootstrap struct {
	factory.BootstrapComponentsHolder
	coordinator sharding.Coordinator
}

func (b *qualSP222Bootstrap) ShardCoordinator() sharding.Coordinator { return b.coordinator }
func (b *qualSP222Bootstrap) HeaderIntegrityVerifier() nodeFactory.HeaderIntegrityVerifierHandler {
	return &processMock.HeaderIntegrityVerifierStub{}
}

func qualSP222Factory(t *testing.T) (*processComponentsFactory, map[string][]byte) {
	t.Helper()
	stored := map[string][]byte{}
	return &processComponentsFactory{
		coreData: &factoryMock.CoreComponentsMock{Hash: blake2b.NewBlake2b(), IntMarsh: &marshal.GogoProtoMarshalizer{}},
		data: &factoryMock.DataComponentsMock{
			Storage: &storageMock.ChainStorerStub{
				GetCalled: func(unit dataRetriever.UnitType, key []byte) ([]byte, error) {
					value, ok := stored[unit.String()+string(key)]
					if !ok {
						return nil, errors.New("not stored")
					}
					return value, nil
				},
			},
			DataPool: &dataMock.PoolsHolderStub{
				HeadersCalled: func() dataRetriever.HeadersPool { return &pool.HeadersPoolStub{} },
				ProofsCalled:  func() dataRetriever.ProofsPool { return &dataMock.ProofsPoolMock{} },
			},
		},
		bootstrapComponents: &qualSP222Bootstrap{coordinator: &testscommon.ShardsCoordinatorMock{CurrentShard: 1}},
		// The native gas schedule every node has (SP2-79 reads its carrier section).
		gasSchedule: testscommon.NewGasScheduleNotifierMock(map[string]map[string]uint64{}),
	}, stored
}

func TestQualSP222ImportOwnerExistsOnlyOnADRWADeployment(t *testing.T) {
	accounts := &stateMock.AccountsStub{}
	validator := &processMocks.HeaderValidatorMock{}

	pcf, _ := qualSP222Factory(t)
	owner, err := pcf.newDRWAFinalityImport(accounts, validator)
	require.NoError(t, err)
	require.Nil(t, owner, "an ordinary node gets no owner")
	require.Nil(t, pcf.drwaFinalityImport)

	pcf.drwaConfigurationCandidate, _, _ = qualS1OverlayCandidate(t, 12)
	owner, err = pcf.newDRWAFinalityImport(accounts, validator)
	require.NoError(t, err)
	require.Nil(t, owner, "the configuration alone is not a DRWA deployment")

	pcf.drwaInitialProgrammeStartup = &config.DRWAInitialProgrammeStartup{}
	_, err = pcf.newDRWAFinalityImport(accounts, validator)
	require.Error(t, err, "no proof verifier, no record limit: refused, not defaulted")

	pcf.drwaHeaderProofVerifier = &consensusMock.HeaderSigVerifierMock{}
	_, err = pcf.newDRWAFinalityImport(accounts, validator)
	require.Error(t, err, "no record limit")

	pcf.drwaInitialProgrammeStartup.Limits.RecordBytes = 4096
	owner, err = pcf.newDRWAFinalityImport(accounts, validator)
	require.NoError(t, err)
	require.NotNil(t, owner)
	require.Same(t, pcf.drwaFinalityImport, owner)
	var handler process.DRWAFinalityImportHandler = owner
	require.False(t, handler.IsInterfaceNil())

	pcf.config.HardforkRoundExclusions = []config.HardforkRoundExclusionConfig{{StartRound: 2, EndRound: 1}}
	_, err = pcf.newDRWAFinalityImport(accounts, validator)
	require.Error(t, err, "an invalid exclusion configuration is refused")
}

func TestQualSP222EvidenceSourceReadsPoolThenStorage(t *testing.T) {
	mar := &marshal.GogoProtoMarshalizer{}
	header := &block.MetaBlockV3{Nonce: 7}
	pooledProof := &block.HeaderProof{HeaderHash: []byte("pooled"), HeaderShardId: core.MetachainShardId}
	storedProof := &block.HeaderProof{HeaderHash: []byte("stored"), HeaderShardId: core.MetachainShardId, HeaderNonce: 9}
	rawProof, err := mar.Marshal(storedProof)
	require.NoError(t, err)
	stored := map[string][]byte{dataRetriever.ProofsUnit.String() + "stored": rawProof, dataRetriever.ProofsUnit.String() + "garbage": {0xff}}
	source := &drwaFinalityEvidence{
		headers: &pool.HeadersPoolStub{GetHeaderByHashCalled: func(hash []byte) (data.HeaderHandler, error) {
			if string(hash) == "held" {
				return header, nil
			}
			return nil, errors.New("not pooled")
		}},
		proofs: &dataMock.ProofsPoolMock{GetProofCalled: func(_ uint32, hash []byte) (data.HeaderProofHandler, error) {
			if string(hash) == "pooled" {
				return pooledProof, nil
			}
			return nil, errors.New("not pooled")
		}},
		storage: &storageMock.ChainStorerStub{
			GetCalled: func(unit dataRetriever.UnitType, key []byte) ([]byte, error) {
				value, ok := stored[unit.String()+string(key)]
				if !ok {
					return nil, errors.New("not stored")
				}
				return value, nil
			},
			GetStorerCalled: func(dataRetriever.UnitType) (storage.Storer, error) {
				return &storageMock.StorerStub{GetCalled: func([]byte) ([]byte, error) { return nil, errors.New("not stored") }}, nil
			},
		},
		marshaller: mar,
	}
	require.False(t, source.IsInterfaceNil())
	require.True(t, (*drwaFinalityEvidence)(nil).IsInterfaceNil())

	got, err := source.Header(core.MetachainShardId, []byte("held"))
	require.NoError(t, err)
	require.Same(t, header, got)
	_, err = source.Header(core.MetachainShardId, []byte("absent"))
	require.Error(t, err, "a header the node does not hold is an error")

	proof, err := source.Proof(core.MetachainShardId, []byte("pooled"))
	require.NoError(t, err)
	require.Same(t, pooledProof, proof)
	proof, err = source.Proof(core.MetachainShardId, []byte("stored"))
	require.NoError(t, err)
	require.Equal(t, uint64(9), proof.GetHeaderNonce())
	_, err = source.Proof(core.MetachainShardId, []byte("absent"))
	require.Error(t, err)
	_, err = source.Proof(core.MetachainShardId, []byte("garbage"))
	require.Error(t, err)
}
