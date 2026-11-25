package groups_test

import (
	"context"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/api"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-go/api/groups"
	"github.com/multiversx/mx-chain-go/api/mock"
	"github.com/stretchr/testify/require"
)

func TestQualLaneDOrdinaryTokenDisplayResponse(t *testing.T) {
	t.Parallel()

	t.Run("should work", func(t *testing.T) {
		t.Parallel()

		calls := 0
		facade := &mock.FacadeStub{
			GetAllESDTTokensCalled: func(_ context.Context, address string, _ api.AccountQueryOptions) (map[string]*esdt.ESDigitalToken, api.BlockInfo, error) {
				calls++
				require.Equal(t, "erd1alice", address)
				return map[string]*esdt.ESDigitalToken{
					"COIN-abcdef": {
						Type: uint32(core.Fungible), Value: big.NewInt(125), Properties: []byte{1, 2},
					},
					"ART-abcdef-07": {
						Type: uint32(core.SemiFungible), Value: big.NewInt(3), Properties: []byte{0x0a},
						TokenMetaData: &esdt.MetaData{
							Name: []byte("Gallery"), Nonce: 7, Creator: []byte("artist"), Royalties: 250,
							Hash: []byte("hash"), URIs: [][]byte{[]byte("uri")}, Attributes: []byte("plain"),
						},
					},
					"OLD-abcdef-01": {
						Type: uint32(core.NonFungible), Value: big.NewInt(1),
						TokenMetaData: &esdt.MetaData{Name: []byte("Classic"), Nonce: 1},
					},
				}, api.BlockInfo{Nonce: 11, Hash: "block", RootHash: "root"}, nil
			},
		}

		group, err := groups.NewAddressGroup(facade)
		require.NoError(t, err)
		handler := startWebServer(group, "address", getAddressRoutesConfig())
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/address/erd1alice/esdt", nil))

		require.Equal(t, 1, calls)
		require.Equal(t, http.StatusOK, recorder.Code)
		require.JSONEq(t, `{
			"data": {
				"esdts": {
					"COIN-abcdef": {"tokenIdentifier":"COIN-abcdef","balance":"125","type":"FungibleESDT","properties":"0102"},
					"ART-abcdef-07": {"tokenIdentifier":"ART-abcdef-07","balance":"3","type":"SemiFungibleESDT","properties":"0a","name":"Gallery","nonce":7,"creator":"artist","royalties":"250","hash":"aGFzaA==","uris":["dXJp"],"attributes":"cGxhaW4="},
					"OLD-abcdef-01": {"tokenIdentifier":"OLD-abcdef-01","balance":"1","type":"","name":"Classic","nonce":1,"royalties":"0"}
				},
				"blockInfo":{"nonce":11,"hash":"block","rootHash":"root"}
			},
			"error":"",
			"code":"successful"
		}`, recorder.Body.String())
	})
}
