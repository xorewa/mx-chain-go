package txsFee

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/integrationTests/vm"
	"github.com/multiversx/mx-chain-go/integrationTests/vm/txsFee/utils"
	"github.com/multiversx/mx-chain-go/process"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// L46 DEVELOPMENT experiment for A E.22/P21, not a DRWA policy oracle.
// Actual native processors produce and consume distinct SCRs in two in-memory
// shards. No route finality, deduplication, network propagation, schema/authority
// acceptance or complete P21/capacity claim follows. Native field versions are
// rounds, not operation sequence numbers: equal versions use incoming data.
// Expectations were independently specified before this code in T18 M1-M3.
func TestQualDRWAMetadataCopyEqualRoundOrdering(t *testing.T) {
	for _, family := range []string{core.DynamicSFTESDT, core.DynamicMetaESDT} {
		for _, operation := range []struct {
			name, role string
			makeTx     func([]byte, []byte, uint64, *MetaData) *transaction.Transaction
		}{
			{core.ESDTMetaDataUpdate, core.ESDTRoleNFTUpdate, esdtMetaDataUpdateTx},
			{core.ESDTSetNewURIs, core.ESDTRoleSetNewURI, esdtSetNewUrisTx},
		} {
			for _, mode := range []struct {
				name  string
				round uint64
			}{{"same-round", 7}, {"later-round-control", 8}} {
				t.Run(family+"/"+operation.name+"/"+mode.name, func(t *testing.T) {
					source, err := vm.CreatePreparedTxProcessorWithVMsMultiShard(0, config.EnableEpochs{}, 1)
					require.NoError(t, err)
					t.Cleanup(source.Close)
					destination, err := vm.CreatePreparedTxProcessorWithVMsMultiShard(1, config.EnableEpochs{}, 1)
					require.NoError(t, err)
					t.Cleanup(destination.Close)
					origin := []byte("12345678901234567890123456789010")
					holder := []byte("12345678901234567890123456789011")
					writer := []byte("12345678901234567890123456789014")
					token := []byte("tokenId")
					require.Equal(t, uint32(0), source.ShardCoordinator.ComputeId(origin))
					require.Equal(t, uint32(0), source.ShardCoordinator.ComputeId(writer))
					require.Equal(t, uint32(1), destination.ShardCoordinator.ComputeId(holder))
					for _, ctx := range []*vm.VMTestContext{source, destination} {
						require.NoError(t, ctx.BlockchainHook.(process.BlockChainHookHandler).SetCurrentHeader(&block.Header{Round: 1}))
						// Explicit fixture role/type setup; not bootstrap provenance.
						address := bytes.Clone(core.SystemAccountAddress)
						address[len(address)-1] = byte(ctx.ShardCoordinator.SelfId())
						utils.ProcessSCRResult(t, ctx, &smartContractResult.SmartContractResult{
							SndAddr: bytes.Clone(core.ESDTSCAddress), RcvAddr: address, Value: big.NewInt(0),
							Data: setTokenTypeTx(core.ESDTSCAddress, 0, token, family).Data,
						}, vmcommon.Ok, nil)
					}
					for _, address := range [][]byte{origin, writer} {
						createAccWithBalance(t, source.Accounts, address, big.NewInt(100000000))
					}
					createAccWithBalance(t, destination.Accounts, holder, big.NewInt(100000000))
					utils.SetESDTRoles(t, source.Accounts, origin, token, [][]byte{[]byte(core.ESDTRoleNFTCreate), []byte(core.ESDTRoleNFTAddQuantity)})
					utils.SetESDTRoles(t, source.Accounts, writer, token, [][]byte{[]byte(operation.role)})
					qualDRWAMetadataProcess(t, source, createTokenTx(origin, origin, 100000, 3, GetDefaultMetaData()))
					produce := func() data.TransactionHandler {
						t.Helper()
						source.CleanIntermediateTransactions(t)
						tx := utils.CreateESDTNFTTransferTx(getAccount(t, source, origin).GetNonce(), origin, holder, token, 1, big.NewInt(1), gasPrice, 1000000, "")
						qualDRWAMetadataProcess(t, source, tx)
						var selected []data.TransactionHandler
						for _, scr := range source.GetIntermediateTransactions(t) {
							if bytes.Equal(scr.GetRcvAddr(), holder) {
								selected = append(selected, scr)
							}
						}
						require.Len(t, selected, 1)
						raw, marshalErr := source.Marshalizer.Marshal(selected[0])
						require.NoError(t, marshalErr)
						t.Logf("native holder-bound SCR protobuf %x", raw)
						return selected[0]
					}
					read := func(ctx *vm.VMTestContext, address []byte) *esdt.ESDigitalToken {
						t.Helper()
						value, readErr := ctx.BlockchainHook.GetESDTToken(address, token, 1)
						require.NoError(t, readErr)
						return value
					}
					initial := &esdt.MetaData{Nonce: 1, Name: []byte("name"), Creator: origin, Royalties: 10,
						Hash: []byte("hash"), Attributes: []byte("attributes"), URIs: [][]byte{[]byte("uri")}}
					utils.ProcessSCRResult(t, destination, produce(), vmcommon.Ok, nil)
					require.Equal(t, initial, read(destination, holder).TokenMetaData)
					mutate := func(round uint64, label string) (*esdt.MetaData, *esdt.MetaDataVersion) {
						t.Helper()
						require.NoError(t, source.BlockchainHook.(process.BlockChainHookHandler).SetCurrentHeader(&block.Header{Round: round}))
						input := GetDefaultMetaData()
						input.Nonce = []byte("01")
						input.Attributes = []byte(hex.EncodeToString([]byte(label)))
						input.Uris = [][]byte{[]byte(hex.EncodeToString([]byte(label + " URI 1"))), []byte(hex.EncodeToString([]byte(label + " URI 2")))}
						tx := operation.makeTx(writer, writer, 100000, input)
						tx.Nonce = getAccount(t, source, writer).GetNonce()
						qualDRWAMetadataProcess(t, source, tx)
						want := &esdt.MetaData{Nonce: 1, Name: []byte("name"), Creator: origin, Royalties: 10,
							Hash: []byte("hash"), Attributes: []byte("attributes"), URIs: [][]byte{[]byte(label + " URI 1"), []byte(label + " URI 2")}}
						versions := &esdt.MetaDataVersion{URIs: round}
						if operation.name == core.ESDTMetaDataUpdate {
							want.Creator, want.Attributes = writer, []byte(label)
							want.URIs = [][]byte{[]byte(label + " URI 1")}
							versions = &esdt.MetaDataVersion{Name: round, Creator: round, Royalties: round, Hash: round, URIs: round, Attributes: round}
						}
						actual := read(source, origin)
						require.Equal(t, want, actual.TokenMetaData)
						actualVersions := &esdt.MetaDataVersion{}
						require.NoError(t, source.Marshalizer.Unmarshal(actualVersions, actual.Reserved))
						require.Equal(t, versions, actualVersions)
						return want, versions
					}
					first, firstVersions := mutate(7, "first")
					require.Equal(t, initial, read(destination, holder).TokenMetaData, "no destination propagation from a source mutation alone")
					delayed := produce() // first mutation's distinct carrying transfer
					second, secondVersions := mutate(mode.round, "second")
					fresh := produce()
					require.NotEqual(t, delayed.GetData(), fresh.GetData())
					require.NotEqual(t, delayed.(*smartContractResult.SmartContractResult).PrevTxHash, fresh.(*smartContractResult.SmartContractResult).PrevTxHash, "distinct transfers, not replay")
					utils.ProcessSCRResult(t, destination, fresh, vmcommon.Ok, nil)
					require.Equal(t, second, read(destination, holder).TokenMetaData)
					require.Equal(t, big.NewInt(2), read(destination, holder).Value)
					freshRoot, err := destination.Accounts.Commit()
					require.NoError(t, err)
					utils.ProcessSCRResult(t, destination, delayed, vmcommon.Ok, nil)
					want, wantVersions := second, secondVersions
					if mode.round == 7 {
						want, wantVersions = first, firstVersions
					}
					final := read(destination, holder)
					require.Equal(t, big.NewInt(3), final.Value)
					require.Equal(t, want, final.TokenMetaData, "equal native field rounds use the incoming copy; a strictly newer field round preserves the destination")
					actualVersions := &esdt.MetaDataVersion{}
					require.NoError(t, destination.Marshalizer.Unmarshal(actualVersions, final.Reserved))
					require.Equal(t, wantVersions, actualVersions)
					require.Zero(t, read(source, origin).Value.Sign(), "three original units were transferred; metadata created no supply")
					require.Equal(t, second, getMetaDataFromAcc(t, source, core.SystemAccountAddress, []byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier+string(token))))
					finalRoot, err := destination.Accounts.Commit()
					require.NoError(t, err)
					// Root restore only, never node restart/canonical reorg evidence.
					require.NoError(t, destination.Accounts.RecreateTrie(holders.NewDefaultRootHashesHolder(freshRoot)))
					require.Equal(t, second, read(destination, holder).TokenMetaData)
					require.NoError(t, destination.Accounts.RecreateTrie(holders.NewDefaultRootHashesHolder(finalRoot)))
					require.Equal(t, final, read(destination, holder))
				})
			}
		}
	}
}
