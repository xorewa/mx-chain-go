package factory

import (
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-go/dataRetriever"
	"github.com/multiversx/mx-chain-go/storage"
	storageMocks "github.com/multiversx/mx-chain-go/testscommon/storage"
	"github.com/stretchr/testify/require"
)

func TestQualDRWAOrdinaryOutportFactorySelectsTransactionStore(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		hasDrivers bool
		wantType   string
		wantReads  []dataRetriever.UnitType
	}{
		{name: "disabled", wantType: "*disabled.disabledOutportDataProvider"},
		{name: "enabled", hasDrivers: true, wantType: "*process.outportDataProvider", wantReads: []dataRetriever.UnitType{dataRetriever.TransactionUnit}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := createArgOutportDataProviderFactory()
			args.HasDrivers = tc.hasDrivers
			var reads []dataRetriever.UnitType
			args.StorageService = &storageMocks.ChainStorerStub{GetStorerCalled: func(unit dataRetriever.UnitType) (storage.Storer, error) {
				reads = append(reads, unit)
				return &storageMocks.StorerStub{}, nil
			}}
			provider, err := CreateOutportDataProvider(args)
			require.NoError(t, err)
			require.NotNil(t, provider)
			require.Equal(t, tc.wantType, fmt.Sprintf("%T", provider))
			require.Equal(t, tc.wantReads, reads)
		})
	}
}
