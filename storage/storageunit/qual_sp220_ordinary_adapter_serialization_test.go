package storageunit_test

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/storage/database"
	"github.com/multiversx/mx-chain-go/storage/storageunit"
	"github.com/multiversx/mx-chain-storage-go/lrucache/capacity"
	"github.com/stretchr/testify/require"
)

type qualOrdinaryReport struct {
	Title  string   `json:"title"`
	Count  int      `json:"count"`
	Labels []string `json:"labels"`
}

type qualOrdinaryReportFactory struct{}

func (*qualOrdinaryReportFactory) CreateEmpty() interface{} { return &qualOrdinaryReport{} }
func (f *qualOrdinaryReportFactory) IsInterfaceNil() bool   { return f == nil }

func TestQualSP220OrdinaryAdapterSerializationRoundtrip(t *testing.T) {
	samples := []struct {
		name   string
		report *qualOrdinaryReport
	}{
		{"simple", &qualOrdinaryReport{Title: "Blue sky", Count: 12, Labels: []string{"a", "b"}}},
		{"unicode", &qualOrdinaryReport{Title: "Café", Count: 37, Labels: []string{"été", "été"}}},
		{"zero_count", &qualOrdinaryReport{Title: "Clear", Count: 0, Labels: []string{}}},
		{"absent_labels", &qualOrdinaryReport{Title: "Morning", Count: 1}},
	}
	for _, sample := range samples {
		t.Run(sample.name, func(t *testing.T) {
			cache, err := capacity.NewCapacityLRU(1, 4096)
			require.NoError(t, err)
			db := database.NewMemDB()
			codec := &marshal.JsonMarshalizer{}
			adapter, err := storageunit.NewStorageCacherAdapter(cache, db, &qualOrdinaryReportFactory{}, codec)
			if err != nil {
				_ = db.Close()
			}
			require.NoError(t, err)
			defer func() { require.NoError(t, adapter.Close()) }()

			key := []byte("ordinary-display")
			encoded, err := codec.Marshal(sample.report)
			require.NoError(t, err)
			require.False(t, adapter.Put(key, sample.report, len(encoded)))
			next := &qualOrdinaryReport{Title: "Next display"}
			nextEncoded, err := codec.Marshal(next)
			require.NoError(t, err)
			require.True(t, adapter.Put([]byte("next-display"), next, len(nextEncoded)))

			stored, err := db.Get(key)
			require.NoError(t, err)
			require.Equal(t, encoded, stored)
			result, found := adapter.Get(key)
			require.True(t, found)
			decoded, ok := result.(*qualOrdinaryReport)
			require.True(t, ok)
			require.NotSame(t, sample.report, decoded)
			require.Equal(t, sample.report, decoded)
		})
	}
}
