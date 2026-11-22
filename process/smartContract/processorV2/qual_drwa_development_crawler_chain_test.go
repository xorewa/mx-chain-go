package processorV2

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/state/accounts"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	trieMock "github.com/multiversx/mx-chain-go/testscommon/trie"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	nativeBuiltins "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
)

// N04/M13 connects native V2 sender policy, SCR protobuf, native call-data
// parsing and the actual metadata receiver. VM output, transaction lineage and
// account backing are explicitly synthetic. Neither serialization nor matching
// crawler addresses authenticate an origin or authorize a regulated mutation.
func TestQualDRWADevelopmentCrawlerReceiverChain(t *testing.T) {
	for source := uint32(0); source < 3; source++ {
		for destination := uint32(0); destination < 3; destination++ {
			for _, malformedSender := range []bool{false, true} {
				t.Run(fmt.Sprintf("source_%d_destination_%d_short_%t", source, destination, malformedSender), func(t *testing.T) {
					sc, crawlers := qualDRWACandidateCrawlerProcessor(t, source, 3)
					crawler := crawlers[destination]
					contract := make([]byte, 32)
					contract[8] = 5
					contract[31] = byte(source)
					sender := bytes.Clone(crawler)
					if malformedSender {
						sender = sender[:31]
					}
					caller := bytes.Repeat([]byte{2}, 32)
					tx := &transaction.Transaction{SndAddr: caller, RcvAddr: contract, Value: big.NewInt(0), GasPrice: 1}
					m := &marshal.GogoProtoMarshalizer{}
					metadata, err := m.Marshal(&esdt.MetaData{Nonce: 1, Name: []byte("experimental metadata")})
					require.NoError(t, err)
					token := []byte("QUAL-abcdef")
					payload := []byte(vmcommon.ESDTAddMetadata + "@" + hex.EncodeToString(token) + "@01@" + hex.EncodeToString(metadata))
					outAccount := &vmcommon.OutputAccount{Address: crawler, OutputTransfers: []vmcommon.OutputTransfer{{Index: 1, Value: big.NewInt(0), Data: payload, SenderAddress: sender, CallType: vmData.DirectCall}}}
					output := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, OutputAccounts: map[string]*vmcommon.OutputAccount{string(crawler): outAccount}}
					callback, results := sc.createSmartContractResults(&vmcommon.VMInput{CallType: vmData.DirectCall}, output, outAccount, tx, []byte("synthetic parent"))
					require.False(t, callback)
					require.Len(t, results, 1)
					encoded, err := m.Marshal(results[0].result)
					require.NoError(t, err)
					result := &smartContractResult.SmartContractResult{}
					require.NoError(t, m.Unmarshal(result, encoded))
					require.Equal(t, []byte("synthetic parent"), result.OriginalTxHash)
					require.Equal(t, []byte("synthetic parent"), result.PrevTxHash)
					require.Equal(t, payload, result.Data)
					function, arguments, err := sc.argsParser.ParseCallData(string(result.Data))
					require.NoError(t, err)
					require.Equal(t, vmcommon.ESDTAddMetadata, function)
					values := map[string][]byte{}
					loads, saves, writes := 0, 0, 0
					tracker := &trieMock.DataTrieTrackerStub{RetrieveValueCalled: func(key []byte) ([]byte, uint32, error) { return bytes.Clone(values[string(key)]), 0, nil }, SaveKeyValueCalled: func(key, value []byte) error { writes++; values[string(key)] = bytes.Clone(value); return nil }}
					system, err := accounts.NewUserAccount(core.SystemAccountAddress, tracker, &trieMock.TrieLeafParserStub{})
					require.NoError(t, err)
					adapter := &stateMock.AccountsStub{LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
						loads++
						require.Equal(t, core.SystemAccountAddress, address)
						return system, nil
					}, SaveAccountCalled: func(account vmcommon.AccountHandler) error { saves++; require.Same(t, system, account); return nil }}
					receiver, err := nativeBuiltins.NewESDTDeleteMetadataFunc(nativeBuiltins.ArgsNewESDTDeleteMetadata{Marshalizer: m, Accounts: adapter, AllowedAddress: crawler, EnableEpochsHandler: sc.enableEpochsHandler})
					require.NoError(t, err)
					require.True(t, receiver.IsActive())
					input := &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: result.SndAddr, CallValue: result.Value, Arguments: arguments}, RecipientAddr: result.RcvAddr, Function: function}
					received, err := receiver.ProcessBuiltinFunction(nil, nil, input)
					if source != destination || malformedSender {
						require.Equal(t, contract, result.SndAddr)
						require.ErrorIs(t, err, nativeBuiltins.ErrAddressIsNotAllowed)
						require.Nil(t, received)
						require.Zero(t, loads)
						require.Zero(t, saves)
						require.Zero(t, writes)
						require.Empty(t, values)
						return
					}
					require.Equal(t, crawler, result.SndAddr)
					require.NoError(t, err)
					require.Equal(t, vmcommon.Ok, received.ReturnCode)
					require.Equal(t, 1, loads)
					require.Equal(t, 1, saves)
					require.Equal(t, 1, writes)
					key := append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), token...)
					key = append(key, 1)
					stored := &esdt.ESDigitalToken{}
					require.NoError(t, m.Unmarshal(stored, values[string(key)]))
					require.Equal(t, uint32(core.NonFungible), stored.Type)
					require.Zero(t, stored.Value.Sign())
					require.Equal(t, uint64(1), stored.TokenMetaData.Nonce)
					require.Equal(t, []byte("experimental metadata"), stored.TokenMetaData.Name)
					// The real receiver accepts this synthetic matching pair. T10/T41 must
					// therefore contain authentic producers BEFORE its native storage effect;
					// unsignability or successful SCR parsing alone is not that containment.
				})
			}
		}
	}
}
