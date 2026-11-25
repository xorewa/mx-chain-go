package alteredaccounts

import (
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/alteredAccount"
	"github.com/multiversx/mx-chain-core-go/data/api"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	outportcore "github.com/multiversx/mx-chain-core-go/data/outport"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/outport/process/alteredaccounts/shared"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func TestQualDRWAOrdinaryAlteredAccountsRepositoryBalanceDTO(t *testing.T) {
	t.Parallel()

	args := getMockArgs()
	args.AddressConverter = testscommon.NewPubkeyConverterMock(4)
	address := []byte("addr")
	query := api.AccountQueryOptions{WithKeys: true}
	balance, ok := new(big.Int).SetString("18446744073709551617", 10)
	require.True(t, ok)
	account := &state.UserAccountStub{Address: address, Balance: balance, Nonce: 42}
	defaultReads := 0
	args.AccountsDB = &state.AccountsStub{LoadAccountCalled: func(_ []byte) (vmcommon.AccountHandler, error) {
		defaultReads++
		return account, nil
	}}
	customReads := 0
	repository := &state.AccountsRepositoryStub{GetAccountWithBlockInfoCalled: func(got []byte, gotQuery api.AccountQueryOptions) (vmcommon.AccountHandler, common.BlockInfo, error) {
		customReads++
		require.Equal(t, address, got)
		require.Equal(t, query, gotQuery)
		return account, nil, nil
	}}
	provider, err := NewAlteredAccountsProvider(args)
	require.NoError(t, err)
	require.False(t, provider.IsInterfaceNil())
	pool := &outportcore.TransactionPool{Transactions: map[string]*outportcore.TxInfo{
		"ordinary": {Transaction: &transaction.Transaction{SndAddr: address, RcvAddr: address, Value: big.NewInt(1)}},
	}}
	result, err := provider.ExtractAlteredAccountsFromPool(pool, shared.AlteredAccountsOptions{
		WithCustomAccountsRepository: true,
		WithAdditionalOutportData:    true,
		AccountsRepository:           repository,
		AccountQueryOptions:          query,
	})
	require.NoError(t, err)
	require.Equal(t, 1, customReads)
	require.Zero(t, defaultReads)
	require.Equal(t, map[string]*alteredAccount.AlteredAccount{
		"61646472": {Address: "61646472", Balance: "18446744073709551617", Nonce: 42,
			AdditionalData: &alteredAccount.AdditionalAccountData{IsSender: true, BalanceChanged: true}},
	}, result)
}

func TestQualDRWAOrdinaryAlteredAccountsNFTMetadataDTO(t *testing.T) {
	t.Parallel()

	args := getMockArgs()
	args.AddressConverter = testscommon.NewPubkeyConverterMock(4)
	account := &state.AccountWrapMock{Balance: big.NewInt(11)}
	args.AccountsDB = &state.AccountsStub{LoadAccountCalled: func(_ []byte) (vmcommon.AccountHandler, error) {
		return account, nil
	}}
	token := &esdt.ESDigitalToken{Type: uint32(core.SemiFungible), Value: big.NewInt(37), Properties: []byte{0x01, 0x02},
		TokenMetaData: &esdt.MetaData{Nonce: 9, Name: []byte("collectible"), Creator: []byte("make"), Royalties: 250,
			Hash: []byte("hash"), URIs: [][]byte{[]byte("uri")}, Attributes: []byte("attrs")},
	}
	reads := 0
	args.EsdtDataStorageHandler = &testscommon.EsdtStorageHandlerStub{GetESDTNFTTokenOnDestinationCalled: func(got vmcommon.UserAccountHandler, _ []byte, nonce uint64) (*esdt.ESDigitalToken, bool, error) {
		reads++
		require.Same(t, account, got)
		require.Equal(t, uint64(9), nonce)
		return token, false, nil
	}}
	provider, err := NewAlteredAccountsProvider(args)
	require.NoError(t, err)
	pool := &outportcore.TransactionPool{Logs: []*transaction.LogData{{Log: &transaction.Log{Events: []*transaction.Event{{
		Address: []byte("addr"), Identifier: []byte(core.BuiltInFunctionESDTNFTCreate),
		Topics: [][]byte{[]byte("ordinary-abcdef"), big.NewInt(9).Bytes(), big.NewInt(37).Bytes()},
	}}}}}}
	result, err := provider.ExtractAlteredAccountsFromPool(pool, shared.AlteredAccountsOptions{WithAdditionalOutportData: true})
	require.NoError(t, err)
	require.Equal(t, 1, reads)
	require.Len(t, result, 1)
	require.NotNil(t, result["61646472"])
	require.Equal(t, "11", result["61646472"].Balance)
	require.Equal(t, []*alteredAccount.AccountTokenData{{
		Identifier: "ordinary-abcdef", Balance: "37", Nonce: 9, Properties: "0102", Type: core.SemiFungibleESDT,
		MetaData: &alteredAccount.TokenMetaData{Nonce: 9, Name: "collectible", Creator: "6d616b65", Royalties: 250,
			Hash: []byte("hash"), URIs: [][]byte{[]byte("uri")}, Attributes: []byte("attrs")},
		AdditionalData: &alteredAccount.AdditionalAccountTokenData{IsNFTCreate: true},
	}}, result["61646472"].Tokens)
}
