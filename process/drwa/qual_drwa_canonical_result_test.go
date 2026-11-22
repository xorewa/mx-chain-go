package drwa_test

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	crypto "github.com/multiversx/mx-chain-crypto-go"
	"github.com/multiversx/mx-chain-crypto-go/signing"
	"github.com/multiversx/mx-chain-crypto-go/signing/mcl"
	llsig "github.com/multiversx/mx-chain-crypto-go/signing/mcl/multisig"
	"github.com/multiversx/mx-chain-crypto-go/signing/mcl/singlesig"
	"github.com/multiversx/mx-chain-crypto-go/signing/multisig"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process"
	nativeBlock "github.com/multiversx/mx-chain-go/process/block"
	"github.com/multiversx/mx-chain-go/process/drwa"
	"github.com/multiversx/mx-chain-go/process/headerCheck"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/testscommon"
	consensusMocks "github.com/multiversx/mx-chain-go/testscommon/consensus"
	"github.com/multiversx/mx-chain-go/testscommon/cryptoMocks"
	dataRetrieverMocks "github.com/multiversx/mx-chain-go/testscommon/dataRetriever"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/genericMocks"
	"github.com/multiversx/mx-chain-go/testscommon/shardingMocks"
	"github.com/stretchr/testify/require"
)

type canonicalNativeFixture interface {
	ReaderArgs() drwa.ArgsResultAccountReader
	SetNativeValidators(process.HeaderConstructionValidator, process.HeaderIntegrityVerifier)
	InstallNativeProofVerifier(*testing.T, process.InterceptedHeaderSigVerifier, func(*block.HeaderProof) error)
	CorruptProofSignature(*testing.T)
	P13Snapshot(*testing.T) [][]byte
	ExportWitness(*testing.T) []byte
	ImportWitness(*testing.T, []byte)
	ImportCanonical() error
	ReadCanonical() ([]byte, error)
}

// Two independent native stores/readers exchange a test-only witness over a
// loopback listener. Real native integrity/ancestry, HeaderSigVerifier, BLS,
// reconciliation and Patricia proofs execute. The one-validator test rosters,
// header-version fixture and admitted B context are synthetic; this is neither
// a running MultiversX chain nor SP2-13/AR-01 qualification.
func TestQualCanonicalResultReader_NativeLoopback(t *testing.T) {
	kg := signing.NewKeyGenerator(mcl.NewSuiteBLS12())
	ms, err := multisig.NewBLSMultisig(&llsig.BlsMultiSignerKOSK{}, kg)
	require.NoError(t, err)
	private := make(map[uint32]crypto.PrivateKey)
	public := make(map[uint32]crypto.PublicKey)
	encoded := make(map[uint32][]byte)
	seen := make(map[string]bool)
	for _, shard := range []uint32{0, 1, 2, core.MetachainShardId} {
		private[shard], public[shard] = kg.GeneratePair()
		encoded[shard], err = public[shard].ToByteArray()
		require.NoError(t, err)
		require.False(t, seen[string(encoded[shard])])
		seen[string(encoded[shard])] = true
	}
	// Private keys remain in memory only; no fixture, log or artifact contains them.
	first := drwa.NewCanonicalResultTestFixture(t, 1, 2)
	second := drwa.NewCanonicalResultTestFixture(t, 1, 2)
	for _, f := range []canonicalNativeFixture{first, second} {
		args := f.ReaderArgs()
		flags := enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
		flags.AddActiveFlags(common.AndromedaFlag)
		flags.IsFlagEnabledInEpochCalled = func(flag core.EnableEpochFlag, epoch uint32) bool {
			return flag == common.AndromedaFlag && epoch == 4
		}
		validator, err := nativeBlock.NewHeaderValidator(nativeBlock.ArgsHeaderValidator{Hasher: args.Hasher, Marshalizer: args.Marshaller, EnableEpochsHandler: flags})
		require.NoError(t, err)
		integrity, err := headerCheck.NewHeaderIntegrityVerifier([]byte("unit-chain"), &testscommon.HeaderVersionHandlerStub{})
		require.NoError(t, err)
		proofs, err := headerCheck.NewHeaderSigVerifier(&headerCheck.ArgsHeaderSigVerifier{
			Marshalizer: args.Marshaller, Hasher: args.Hasher, KeyGen: kg, SingleSigVerifier: &singlesig.BlsSingleSigner{},
			MultiSigContainer: &cryptoMocks.MultiSignerContainerStub{GetMultiSignerCalled: func(uint32) (crypto.MultiSignerV2, error) { return ms, nil }},
			NodesCoordinator: &shardingMocks.NodesCoordinatorMock{GetAllEligibleValidatorsPublicKeysForShardCalled: func(_ uint32, shard uint32) ([]string, error) {
				key, found := encoded[shard]
				if !found {
					return nil, errors.New("no test roster")
				}
				return []string{string(key)}, nil
			}},
			FallbackHeaderValidator: &testscommon.FallBackHeaderValidatorStub{}, EnableEpochsHandler: flags,
			HeadersPool: &mock.HeadersCacherStub{}, ProofsPool: &dataRetrieverMocks.ProofsPoolMock{}, StorageService: &genericMocks.ChainStorerMock{},
			PubKeysHandler: &consensusMocks.SigningHandlerStub{GetPubKeysFromBytesCalled: func(raw [][]byte) ([]crypto.PublicKey, error) {
				out := make([]crypto.PublicKey, 0, len(raw))
				for _, key := range raw {
					p, e := kg.PublicKeyFromByteArray(key)
					if e != nil {
						return nil, e
					}
					out = append(out, p)
				}
				return out, nil
			}},
		})
		require.NoError(t, err)
		f.SetNativeValidators(validator, integrity)
		f.InstallNativeProofVerifier(t, proofs, func(p *block.HeaderProof) error {
			share, e := ms.CreateSignatureShareV2(private[p.HeaderShardId], p.HeaderHash)
			if e != nil {
				return e
			}
			p.AggregatedSignature, e = ms.AggregateSigsV2([]crypto.PublicKey{public[p.HeaderShardId]}, [][]byte{share})
			p.PubKeysBitmap = []byte{1}
			return e
		})
	}
	before := second.P13Snapshot(t)
	second.CorruptProofSignature(t)
	require.Error(t, second.ImportCanonical())
	require.Equal(t, before, second.P13Snapshot(t))
	payload := first.ExportWitness(t)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(payload) }))
	t.Cleanup(server.Close)
	require.True(t, server.Listener.Addr().(*net.TCPAddr).IP.IsLoopback())
	server.Start()
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	response, err := client.Get(server.URL)
	require.NoError(t, err)
	raw, err := io.ReadAll(io.LimitReader(response.Body, int64(len(payload)+1)))
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.Len(t, raw, len(payload))
	second.ImportWitness(t, raw)
	left, err := first.ReadCanonical()
	require.NoError(t, err)
	right, err := second.ReadCanonical()
	require.NoError(t, err)
	require.Equal(t, left, right)
	require.NoError(t, first.ImportCanonical())
	require.NoError(t, second.ImportCanonical())
	after := second.P13Snapshot(t)
	require.Equal(t, first.P13Snapshot(t), after)
	require.NoError(t, second.ImportCanonical())
	require.Equal(t, after, second.P13Snapshot(t))
}
