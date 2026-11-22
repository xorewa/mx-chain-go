package processing

import (
	"testing"

	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/dataRetriever"
	"github.com/multiversx/mx-chain-go/dataRetriever/txpool"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/factory/interceptorscontainer"
	"github.com/multiversx/mx-chain-go/vm"
	"github.com/stretchr/testify/require"
)

func TestQualD19NativeProviderWiringUnconfiguredAndMissing(t *testing.T) {
	factory := &processComponentsFactory{}
	// No core/pool/crypto dereference or implicit defaults on the native branch.
	require.NoError(t, factory.configureNativeValidationSource(interceptorscontainer.CommonInterceptorsContainerFactoryArgs{}))
	factory.drwaDeploymentIdentity = &config.DRWADeploymentIdentityConfig{}
	require.ErrorIs(t, factory.configureNativeValidationSource(interceptorscontainer.CommonInterceptorsContainerFactoryArgs{}), vm.ErrDRWAExecution)
}

// These holders deliberately provide no codec/crypto metadata. Missing pool
// admission must reject before any getter; they are not authentication stubs.
type qualD20UnavailableCore struct{ process.CoreComponentsHolder }

func (q *qualD20UnavailableCore) IsInterfaceNil() bool { return q == nil }

type qualD20UnavailableCrypto struct{ process.CryptoComponentsHolder }

func (q *qualD20UnavailableCrypto) IsInterfaceNil() bool { return q == nil }

type qualD20MissingPoolHolder struct {
	dataRetriever.PoolsHolder
	pool  dataRetriever.ShardedDataCacherNotifier
	reads int
}

func (q *qualD20MissingPoolHolder) IsInterfaceNil() bool { return q == nil }
func (q *qualD20MissingPoolHolder) Transactions() dataRetriever.ShardedDataCacherNotifier {
	q.reads++
	return q.pool
}

func TestQualD20NativeProviderTypedNilPoolDenial(t *testing.T) {
	// Failed native construction supplies its actual typed-nil pool, never an
	// accepting implementation of the optional receipt capability.
	nativePool, err := txpool.NewShardedTxPool(txpool.ArgShardedTxPool{})
	require.Error(t, err)
	require.Nil(t, nativePool)
	for _, tc := range []struct {
		name string
		pool dataRetriever.ShardedDataCacherNotifier
	}{{"absent", nil}, {"native-typed-nil", nativePool}} {
		t.Run(tc.name, func(t *testing.T) {
			holder := &qualD20MissingPoolHolder{pool: tc.pool}
			args := interceptorscontainer.CommonInterceptorsContainerFactoryArgs{
				CoreComponents:   &qualD20UnavailableCore{},
				CryptoComponents: &qualD20UnavailableCrypto{},
				DataPool:         holder,
			}
			factory := &processComponentsFactory{}
			require.NoError(t, factory.configureNativeValidationSource(args))
			require.Zero(t, holder.reads, "unconfigured native path must not inspect the pool")
			factory.drwaDeploymentIdentity = &config.DRWADeploymentIdentityConfig{}
			var admissionErr error
			require.NotPanics(t, func() { admissionErr = factory.configureNativeValidationSource(args) })
			require.ErrorIs(t, admissionErr, vm.ErrDRWAExecution)
			require.Equal(t, 1, holder.reads)
		})
	}
}
