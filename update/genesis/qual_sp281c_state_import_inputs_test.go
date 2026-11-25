package genesis

import (
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/dataRetriever"
	"github.com/multiversx/mx-chain-go/errors"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/hashingMocks"
	"github.com/multiversx/mx-chain-go/testscommon/storageManager"
	"github.com/multiversx/mx-chain-go/update"
	"github.com/multiversx/mx-chain-go/update/mock"
	"github.com/stretchr/testify/require"
)

func TestQualSP281CNewStateImportRejectsMissingOrdinaryInputs(t *testing.T) {
	cases := []struct {
		name string
		omit func(*ArgsNewStateImport)
		want error
	}{
		{"trie storage managers", func(args *ArgsNewStateImport) { args.TrieStorageManagers = nil }, update.ErrNilTrieStorageManagers},
		{"address converter", func(args *ArgsNewStateImport) { args.AddressConverter = nil }, update.ErrNilAddressConverter},
		{"enable epochs handler", func(args *ArgsNewStateImport) { args.EnableEpochsHandler = nil }, errors.ErrNilEnableEpochsHandler},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := qualSP281CStateImportArgs()
			tc.omit(&args)

			importer, err := NewStateImport(args)

			require.ErrorIs(t, err, tc.want)
			require.Nil(t, importer)
		})
	}
}

func TestQualSP281CNewStateImportRejectsInvalidProtectedInputs(t *testing.T) {
	cases := []struct {
		name   string
		change func(*ArgsNewStateImport)
		detail string
	}{
		{"child root decoder absent", func(args *ArgsNewStateImport) {
			args.ProtectedChildRoot = nil
		}, "missing protected import inputs"},
		{"checkpoint selectors absent", func(args *ArgsNewStateImport) {
			args.ProtectedCheckpoints = nil
		}, "missing protected import inputs"},
		{"expected roots absent", func(args *ArgsNewStateImport) {
			args.ExpectedProtectedRoots = nil
		}, "missing protected import inputs"},
		{"expected roots empty", func(args *ArgsNewStateImport) {
			clear(args.ExpectedProtectedRoots)
		}, "missing protected import inputs"},
		{"expected root too short", func(args *ArgsNewStateImport) {
			args.ExpectedProtectedRoots[0] = make([]byte, args.Hasher.Size()-1)
		}, "invalid expected protected checkpoint"},
		{"expected root too long", func(args *ArgsNewStateImport) {
			args.ExpectedProtectedRoots[0] = make([]byte, args.Hasher.Size()+1)
		}, "invalid expected protected checkpoint"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := qualSP281CStateImportArgs()
			args.ProtectedChildRoot = func(_, _, record []byte) ([]byte, error) { return record, nil }
			args.ProtectedCheckpoints = &state.ProtectedChildCheckpoints{}
			args.ExpectedProtectedRoots = map[uint32][]byte{0: args.Hasher.Compute("synthetic import checkpoint")}
			tc.change(&args)

			importer, err := NewStateImport(args)

			require.ErrorIs(t, err, update.ErrImportingData)
			require.ErrorContains(t, err, tc.detail)
			require.Nil(t, importer)
		})
	}
}

func qualSP281CStateImportArgs() ArgsNewStateImport {
	return ArgsNewStateImport{
		Hasher:      &hashingMocks.HasherMock{},
		Marshalizer: &mock.MarshalizerMock{},
		TrieStorageManagers: map[string]common.StorageManager{
			dataRetriever.UserAccountsUnit.String(): &storageManager.StorageManagerStub{},
		},
		HardforkStorer:      &mock.HardforkStorerStub{},
		AddressConverter:    &testscommon.PubkeyConverterMock{},
		EnableEpochsHandler: &enableEpochsHandlerMock.EnableEpochsHandlerStub{},
	}
}
