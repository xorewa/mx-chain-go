package txsFee

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/integrationTests/vm"
	"github.com/multiversx/mx-chain-go/integrationTests/vm/txsFee/utils"
	"github.com/multiversx/mx-chain-go/process"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// NON-NORMATIVE native feasibility: Part A 4.5.2/E.22.3 P21, Plan W07.
// Every listed metadata writer is checked against independently literal full
// metadata and per-field version expectations, after distribution to its real
// role-bearing holder. System-SC role applicability is tested separately by
// TestQualDRWAUpstreamCreationProfile. No DRWA authority/schema admission,
// cross-shard finality, node restart or complete P21 coverage is claimed.
func TestQualDRWAMetadataFieldWrites(t *testing.T) {
	operations := []struct {
		name, role string
		makeTx     func([]byte, []byte, uint64, *MetaData) *transaction.Transaction
	}{
		{core.ESDTMetaDataUpdate, core.ESDTRoleNFTUpdate, esdtMetaDataUpdateTx},
		{core.ESDTMetaDataRecreate, core.ESDTRoleNFTRecreate, esdtMetaDataRecreateTx},
		{core.ESDTModifyCreator, core.ESDTRoleModifyCreator, esdtModifyCreatorTx},
		{core.ESDTModifyRoyalties, core.ESDTRoleModifyRoyalties, esdtModifyRoyaltiesTx},
		{core.ESDTSetNewURIs, core.ESDTRoleSetNewURI, esdtSetNewUrisTx},
		{core.BuiltInFunctionESDTNFTUpdateAttributes, core.ESDTRoleNFTUpdateAttributes,
			func(sender, _ []byte, gas uint64, _ *MetaData) *transaction.Transaction {
				return utils.CreateESDTNFTUpdateAttributesTx(0, sender, []byte("tokenId"), gasPrice, gas, []byte("changed attributes"))
			}},
		{core.BuiltInFunctionESDTNFTAddURI, core.ESDTRoleNFTAddURI,
			func(sender, receiver []byte, gas uint64, metadata *MetaData) *transaction.Transaction {
				return &transaction.Transaction{
					SndAddr: sender, RcvAddr: receiver, GasLimit: gas, GasPrice: gasPrice, Value: big.NewInt(0),
					Data: bytes.Join([][]byte{[]byte(core.BuiltInFunctionESDTNFTAddURI), metadata.TokenId, metadata.Nonce, metadata.Uris[0], metadata.Uris[1]}, []byte("@")),
				}
			}},
	}
	for _, family := range append([]string{core.NonFungibleESDTv2}, getDynamicTokenTypes()...) {
		t.Run(family, func(t *testing.T) {
			for _, operation := range operations {
				t.Run(operation.name, func(t *testing.T) {
					ctx, err := vm.CreatePreparedTxProcessorWithVMs(config.EnableEpochs{}, 1)
					require.NoError(t, err)
					t.Cleanup(ctx.Close)
					require.NoError(t, ctx.BlockchainHook.(process.BlockChainHookHandler).SetCurrentHeader(&block.Header{Round: 7}))
					origin := []byte("12345678901234567890123456789012")
					writer := []byte("12345678901234567890123456789014")
					token := []byte("tokenId")
					for _, address := range [][]byte{origin, writer} {
						require.Equal(t, ctx.ShardCoordinator.SelfId(), ctx.ShardCoordinator.ComputeId(address))
						createAccWithBalance(t, ctx.Accounts, address, big.NewInt(100000000))
					}
					createAccWithBalance(t, ctx.Accounts, core.ESDTSCAddress, big.NewInt(100000000))
					utils.SetESDTRoles(t, ctx.Accounts, origin, token, [][]byte{[]byte(core.ESDTRoleNFTCreate)})
					qualDRWAMetadataProcess(t, ctx, setTokenTypeTx(core.ESDTSCAddress, 100000, token, family))
					qualDRWAMetadataProcess(t, ctx, createTokenTx(origin, origin, 100000, 1, GetDefaultMetaData()))
					qualDRWAMetadataProcess(t, ctx, utils.CreateESDTNFTTransferTx(getAccount(t, ctx, origin).GetNonce(), origin, writer, token, 1, big.NewInt(1), gasPrice, 1000000, ""))

					expected := &esdt.MetaData{Nonce: 1, Name: []byte("name"), Creator: origin, Royalties: 10,
						Hash: []byte("hash"), URIs: [][]byte{[]byte("uri")}, Attributes: []byte("attributes")}
					before, err := ctx.BlockchainHook.GetESDTToken(writer, token, 1)
					require.NoError(t, err)
					require.Equal(t, expected, before.TokenMetaData)
					require.Equal(t, big.NewInt(1), before.Value)
					input := GetDefaultMetaData()
					input.Nonce = []byte("01")
					input.Name = []byte(hex.EncodeToString([]byte("changed name")))
					input.Royalties = []byte("14") // independent expected uint32(20)
					input.Hash = []byte(hex.EncodeToString([]byte("changed hash")))
					input.Attributes = []byte(hex.EncodeToString([]byte("changed attributes")))
					input.Uris = [][]byte{[]byte(hex.EncodeToString([]byte("new URI 1"))), []byte(hex.EncodeToString([]byte("new URI 2"))), []byte(hex.EncodeToString([]byte("new URI 3")))}
					denied := operation.makeTx(writer, writer, 100000, input)
					denied.Nonce = getAccount(t, ctx, writer).GetNonce()
					code, deniedErr := ctx.TxProcessor.ProcessTransaction(denied)
					require.Equal(t, vmcommon.UserError, code)
					require.ErrorIs(t, deniedErr, process.ErrFailedTransaction)
					afterDenial, err := ctx.BlockchainHook.GetESDTToken(writer, token, 1)
					require.NoError(t, err)
					require.Equal(t, before, afterDenial, "role denial must not change token data; native fee/transaction nonce are outside this assertion")
					utils.SetESDTRoles(t, ctx.Accounts, writer, token, [][]byte{[]byte(operation.role)})
					preMutationRoot, err := ctx.Accounts.Commit()
					require.NoError(t, err)
					tx := operation.makeTx(writer, writer, 100000, input)
					tx.Nonce = getAccount(t, ctx, writer).GetNonce()
					qualDRWAMetadataProcess(t, ctx, tx)

					versions := &esdt.MetaDataVersion{}
					switch operation.name {
					case core.ESDTMetaDataUpdate, core.ESDTMetaDataRecreate:
						expected.Name, expected.Creator, expected.Royalties = []byte("changed name"), writer, 20
						expected.Hash, expected.Attributes = []byte("changed hash"), []byte("changed attributes")
						expected.URIs = [][]byte{[]byte("new URI 1")}
						if operation.name == core.ESDTMetaDataRecreate {
							expected.URIs = append(expected.URIs, []byte("new URI 2"), []byte("new URI 3"))
						}
						versions = &esdt.MetaDataVersion{Name: 7, Creator: 7, Royalties: 7, Hash: 7, URIs: 7, Attributes: 7}
					case core.ESDTModifyCreator:
						expected.Creator, versions.Creator = writer, 7
					case core.ESDTModifyRoyalties:
						expected.Royalties, versions.Royalties = 20, 7
					case core.ESDTSetNewURIs:
						expected.URIs, versions.URIs = [][]byte{[]byte("new URI 1"), []byte("new URI 2")}, 7
					case core.BuiltInFunctionESDTNFTUpdateAttributes:
						expected.Attributes, versions.Attributes = []byte("changed attributes"), 7
					case core.BuiltInFunctionESDTNFTAddURI:
						expected.URIs = append(expected.URIs, []byte("new URI 1"), []byte("new URI 2"))
						versions.URIs = 7
					}
					check := func() {
						t.Helper()
						actual, readErr := ctx.BlockchainHook.GetESDTToken(writer, token, 1)
						require.NoError(t, readErr)
						require.Equal(t, big.NewInt(1), actual.Value)
						require.Equal(t, expected, actual.TokenMetaData, "complete explicit and implicit write set")
						actualVersion := &esdt.MetaDataVersion{}
						require.NoError(t, ctx.Marshalizer.Unmarshal(actualVersion, actual.Reserved))
						require.Equal(t, versions, actualVersion, "untouched field versions must not advance")
						originData, readErr := ctx.BlockchainHook.GetESDTToken(origin, token, 1)
						require.NoError(t, readErr)
						require.Zero(t, originData.Value.Sign(), "metadata must not recreate spendable origin supply")
						locus := writer
						if family == core.DynamicSFTESDT || family == core.DynamicMetaESDT {
							locus = core.SystemAccountAddress
						}
						require.Equal(t, expected, getMetaDataFromAcc(t, ctx, locus, []byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier+string(token))))
					}
					check()
					postMutationRoot, err := ctx.Accounts.Commit()
					require.NoError(t, err)
					require.NotEqual(t, preMutationRoot, postMutationRoot)
					// In-process root restoration, not a node restart or canonical reorg.
					require.NoError(t, ctx.Accounts.RecreateTrie(holders.NewDefaultRootHashesHolder(preMutationRoot)))
					restored, err := ctx.BlockchainHook.GetESDTToken(writer, token, 1)
					require.NoError(t, err)
					require.Equal(t, before, restored)
					require.NoError(t, ctx.Accounts.RecreateTrie(holders.NewDefaultRootHashesHolder(postMutationRoot)))
					check()
				})
			}
		})
	}
}
