package txsFee

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/integrationTests/vm"
	"github.com/multiversx/mx-chain-go/integrationTests/vm/txsFee/utils"
	"github.com/multiversx/mx-chain-go/process"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// TestQualDRWADynamicMetadataLocus observes the pinned upstream implementation
// for Part A 4.5.2/E.22.3, P21 and Plan W07. This is not a DRWA policy oracle:
// metadata success does not imply that an already distributed NFT was updated.
// The expected storage split is independently stated in Part A 4.5.2 and in
// vm-common v1.7.2 getEsdtInfo/saveESDTMetaDataInfo and esdtDataStorage readers.
// This in-process, same-shard experiment does not establish cross-shard finality.
func TestQualDRWADynamicMetadataLocus(t *testing.T) {
	for _, family := range getDynamicTokenTypes() {
		for _, operation := range []struct {
			name   string
			role   string
			makeTx func([]byte, []byte, uint64, *MetaData) *transaction.Transaction
		}{
			{core.ESDTMetaDataUpdate, core.ESDTRoleNFTUpdate, esdtMetaDataUpdateTx},
			{core.ESDTMetaDataRecreate, core.ESDTRoleNFTRecreate, esdtMetaDataRecreateTx},
		} {
			t.Run(family+"/"+operation.name, func(t *testing.T) {
				ctx, err := vm.CreatePreparedTxProcessorWithVMs(config.EnableEpochs{}, 1)
				require.NoError(t, err)
				t.Cleanup(ctx.Close)
				require.NoError(t, ctx.BlockchainHook.(process.BlockChainHookHandler).SetCurrentHeader(&block.Header{Round: 7}))
				origin := []byte("12345678901234567890123456789012")
				holder := []byte("12345678901234567890123456789014")
				writer := []byte("12345678901234567890123456789016")
				token := []byte("tokenId")
				for _, address := range [][]byte{origin, holder, writer} {
					require.Equal(t, ctx.ShardCoordinator.SelfId(), ctx.ShardCoordinator.ComputeId(address))
					createAccWithBalance(t, ctx.Accounts, address, big.NewInt(100000000))
				}
				createAccWithBalance(t, ctx.Accounts, core.ESDTSCAddress, big.NewInt(100000000))
				utils.SetESDTRoles(t, ctx.Accounts, origin, token, [][]byte{[]byte(core.ESDTRoleNFTCreate)})
				utils.SetESDTRoles(t, ctx.Accounts, writer, token, [][]byte{[]byte(operation.role)})
				qualDRWAMetadataProcess(t, ctx, setTokenTypeTx(core.ESDTSCAddress, 100000, token, family))
				qualDRWAMetadataProcess(t, ctx, createTokenTx(origin, origin, 100000, 1, GetDefaultMetaData()))
				qualDRWAMetadataProcess(t, ctx, utils.CreateESDTNFTTransferTx(
					getAccount(t, ctx, origin).GetNonce(), origin, holder, token, 1, big.NewInt(1), gasPrice, 1000000, ""))
				before, err := ctx.BlockchainHook.GetESDTToken(holder, token, 1)
				require.NoError(t, err)
				require.Equal(t, big.NewInt(1), before.Value)
				require.NotNil(t, before.TokenMetaData)
				require.Equal(t, origin, before.TokenMetaData.Creator)
				require.Equal(t, []byte("attributes"), before.TokenMetaData.Attributes)
				writerBefore, err := ctx.BlockchainHook.GetESDTToken(writer, token, 1)
				require.NoError(t, err)
				require.Zero(t, writerBefore.Value.Sign())
				require.Nil(t, writerBefore.TokenMetaData)

				metadata := GetDefaultMetaData()
				metadata.Nonce = []byte("01")
				metadata.Attributes = []byte(hex.EncodeToString([]byte("changed attributes")))
				denied := operation.makeTx(holder, holder, 100000, metadata)
				denied.Nonce = getAccount(t, ctx, holder).GetNonce()
				code, deniedErr := ctx.TxProcessor.ProcessTransaction(denied)
				require.Equal(t, vmcommon.UserError, code)
				require.ErrorIs(t, deniedErr, process.ErrFailedTransaction)
				unchanged, err := ctx.BlockchainHook.GetESDTToken(holder, token, 1)
				require.NoError(t, err)
				require.Equal(t, before, unchanged, "missing role must not change token data or supply")
				tx := operation.makeTx(writer, writer, 100000, metadata)
				tx.Nonce = getAccount(t, ctx, writer).GetNonce()
				qualDRWAMetadataProcess(t, ctx, tx)
				_, err = ctx.Accounts.Commit()
				require.NoError(t, err)
				after, err := ctx.BlockchainHook.GetESDTToken(holder, token, 1)
				require.NoError(t, err)
				require.Equal(t, big.NewInt(1), after.Value)
				require.NotNil(t, after.TokenMetaData)
				writerAfter, err := ctx.BlockchainHook.GetESDTToken(writer, token, 1)
				require.NoError(t, err)
				require.Zero(t, writerAfter.Value.Sign(), "metadata must not create spendable supply")
				if family == core.DynamicNFTESDT {
					require.Equal(t, before.TokenMetaData, after.TokenMetaData, "holder retains its own metadata")
					require.NotNil(t, writerAfter.TokenMetaData, "role holder acquires a zero-balance local record")
					require.Equal(t, writer, writerAfter.TokenMetaData.Creator, "implicit Creator write")
					require.Equal(t, []byte("changed attributes"), writerAfter.TokenMetaData.Attributes)
				} else {
					require.Equal(t, writer, after.TokenMetaData.Creator, "holder reads updated shared metadata, including implicit Creator")
					require.Equal(t, []byte("changed attributes"), after.TokenMetaData.Attributes)
					require.Nil(t, writerAfter.TokenMetaData, "system-account update need not create a writer balance record")
				}
			})
		}
	}
}

func qualDRWAMetadataProcess(t *testing.T, ctx *vm.VMTestContext, tx *transaction.Transaction) {
	t.Helper()
	code, err := ctx.TxProcessor.ProcessTransaction(tx)
	require.NoError(t, err, "native transaction detail: %v", ctx.GetCompositeTestError())
	require.Equal(t, vmcommon.Ok, code)
}

// This uses two upstream in-memory shard processors and manually delivers their
// real SCRs. It establishes only the selected metadata merge behaviour, not
// routing, deduplication, consensus, canonical finality or localnet qualification.
// Pending P21 coverage: DynamicNFT cross-shard behaviour and source-supported
// Update/Recreate applicability for non-dynamic NFTv2/SFT/Meta. This quantity-3
// fixture cannot be extrapolated to a single-unit NFT or to other operations.
func TestQualDRWADynamicMetadataCrossShardOrdering(t *testing.T) {
	for _, family := range []string{core.DynamicSFTESDT, core.DynamicMetaESDT} {
		t.Run(family, func(t *testing.T) {
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
				// Shape follows System SC sendTokenTypeToSystemAccounts ->
				// SendGlobalSettingToAll: zero-value/gas effect, per-shard system
				// address, and ESDT SC sender. This is setup, not bootstrap proof.
				systemAddress := bytes.Clone(core.SystemAccountAddress)
				systemAddress[len(systemAddress)-1] = byte(ctx.ShardCoordinator.SelfId())
				typeEffect := &smartContractResult.SmartContractResult{
					SndAddr: bytes.Clone(core.ESDTSCAddress),
					RcvAddr: systemAddress,
					Data:    setTokenTypeTx(core.ESDTSCAddress, 0, token, family).Data,
					Value:   big.NewInt(0),
				}
				utils.ProcessSCRResult(t, ctx, typeEffect, vmcommon.Ok, nil)
			}
			for _, address := range [][]byte{origin, writer} {
				createAccWithBalance(t, source.Accounts, address, big.NewInt(100000000))
			}
			createAccWithBalance(t, destination.Accounts, holder, big.NewInt(100000000))
			// Native NFTCreate requires NFTAddQuantity as well when quantity > 1.
			utils.SetESDTRoles(t, source.Accounts, origin, token, [][]byte{[]byte(core.ESDTRoleNFTCreate), []byte(core.ESDTRoleNFTAddQuantity)})
			utils.SetESDTRoles(t, source.Accounts, writer, token, [][]byte{[]byte(core.ESDTRoleNFTUpdate)})
			qualDRWAMetadataProcess(t, source, createTokenTx(origin, origin, 100000, 3, GetDefaultMetaData()))
			produce := func() data.TransactionHandler {
				t.Helper()
				source.CleanIntermediateTransactions(t)
				tx := utils.CreateESDTNFTTransferTx(getAccount(t, source, origin).GetNonce(), origin, holder, token, 1, big.NewInt(1), gasPrice, 1000000, "")
				qualDRWAMetadataProcess(t, source, tx)
				var matching []data.TransactionHandler
				for _, scr := range source.GetIntermediateTransactions(t) {
					if bytes.Equal(scr.GetRcvAddr(), holder) {
						matching = append(matching, scr)
					}
				}
				require.Len(t, matching, 1, "deliver the actual holder-bound SCR, not an assumed first index")
				t.Logf("captured SCR data %x", matching[0].GetData())
				return matching[0]
			}
			utils.ProcessSCRResult(t, destination, produce(), vmcommon.Ok, nil)
			before, err := destination.BlockchainHook.GetESDTToken(holder, token, 1)
			require.NoError(t, err)
			require.Equal(t, big.NewInt(1), before.Value)
			require.Equal(t, []byte("attributes"), before.TokenMetaData.Attributes)
			// Keep a distinct pre-update transfer undelivered; this is not replay.
			oldTransfer := produce()
			require.NoError(t, source.BlockchainHook.(process.BlockChainHookHandler).SetCurrentHeader(&block.Header{Round: 7}))
			metadata := GetDefaultMetaData()
			metadata.Nonce = []byte("01")
			metadata.Attributes = []byte(hex.EncodeToString([]byte("changed attributes")))
			update := esdtMetaDataUpdateTx(writer, writer, 100000, metadata)
			update.Nonce = getAccount(t, source, writer).GetNonce()
			source.CleanIntermediateTransactions(t)
			qualDRWAMetadataProcess(t, source, update)
			for _, scr := range source.GetIntermediateTransactions(t) {
				require.NotEqual(t, uint32(1), source.ShardCoordinator.ComputeId(scr.GetRcvAddr()), "metadata update alone emitted no destination-shard propagation")
			}
			remoteBeforeTransfer, err := destination.BlockchainHook.GetESDTToken(holder, token, 1)
			require.NoError(t, err)
			require.Equal(t, before, remoteBeforeTransfer, "remote copy remains unchanged until an actual carrying transfer")
			utils.ProcessSCRResult(t, destination, produce(), vmcommon.Ok, nil)
			fresh, err := destination.BlockchainHook.GetESDTToken(holder, token, 1)
			require.NoError(t, err)
			require.Equal(t, big.NewInt(2), fresh.Value)
			require.Equal(t, []byte("changed attributes"), fresh.TokenMetaData.Attributes)
			require.Equal(t, writer, fresh.TokenMetaData.Creator)
			// On this upstream pin, delayed older data leaves the newer metadata unchanged.
			utils.ProcessSCRResult(t, destination, oldTransfer, vmcommon.Ok, nil)
			final, err := destination.BlockchainHook.GetESDTToken(holder, token, 1)
			require.NoError(t, err)
			require.Equal(t, big.NewInt(3), final.Value)
			require.Equal(t, fresh.TokenMetaData, final.TokenMetaData)
			originFinal, err := source.BlockchainHook.GetESDTToken(origin, token, 1)
			require.NoError(t, err)
			require.Zero(t, originFinal.Value.Sign())
		})
	}
}
