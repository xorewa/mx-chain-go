package txsFee

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/integrationTests/vm"
	"github.com/multiversx/mx-chain-go/integrationTests/vm/txsFee/utils"
	"github.com/multiversx/mx-chain-go/process"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
)

// T18 M4: existing native gas fixture and hook/account composition only.
// These sample lengths are not deployment limits or workload/capacity evidence.
// No guest WASM, transaction submission, DRWA pricing or authority is exercised.
func TestQualDRWAMetadataAttributeGasBoundary(t *testing.T) {
	for _, family := range append([]string{core.NonFungibleESDTv2}, getDynamicTokenTypes()...) {
		for _, size := range []int{0, 1, 32, 256, 4096} {
			t.Run(fmt.Sprintf("%s/bytes_%d", family, size), func(t *testing.T) {
				ctx, err := vm.CreatePreparedTxProcessorWithVMs(config.EnableEpochs{}, 1)
				require.NoError(t, err)
				t.Cleanup(ctx.Close)
				require.NoError(t, ctx.BlockchainHook.(process.BlockChainHookHandler).SetCurrentHeader(&block.Header{Round: 7}))
				schedule := ctx.GasSchedule.LatestGasSchedule()
				require.Equal(t, uint64(1), schedule["BuiltInCost"]["ESDTNFTUpdateAttributes"])
				require.Equal(t, uint64(1), schedule["BaseOperationCost"]["StorePerByte"])
				writer := []byte("12345678901234567890123456789012")
				token := []byte("tokenId")
				createAccWithBalance(t, ctx.Accounts, writer, big.NewInt(100000000))
				createAccWithBalance(t, ctx.Accounts, core.ESDTSCAddress, big.NewInt(100000000))
				utils.SetESDTRoles(t, ctx.Accounts, writer, token, [][]byte{[]byte(core.ESDTRoleNFTCreate), []byte(core.ESDTRoleNFTUpdateAttributes)})
				qualDRWAMetadataProcess(t, ctx, setTokenTypeTx(core.ESDTSCAddress, 100000, token, family))
				qualDRWAMetadataProcess(t, ctx, createTokenTx(writer, writer, 100000, 1, GetDefaultMetaData()))
				before, err := ctx.BlockchainHook.GetESDTToken(writer, token, 1)
				require.NoError(t, err)
				root, err := ctx.Accounts.Commit()
				require.NoError(t, err)
				journal := ctx.Accounts.JournalLen()
				attributes := bytes.Repeat([]byte{0x61}, size)
				if size == 0 {
					// Native proto3 metadata omits zero-length byte fields.
					attributes = nil
				}
				input := &vmcommon.ContractCallInput{
					VMInput: vmcommon.VMInput{CallerAddr: writer, CallValue: big.NewInt(0),
						Arguments: [][]byte{token, {1}, attributes}, GasProvided: uint64(size)},
					RecipientAddr: writer, Function: core.BuiltInFunctionESDTNFTUpdateAttributes,
				}
				output, err := ctx.BlockchainHook.ProcessBuiltInFunction(input)
				require.ErrorIs(t, err, builtInFunctions.ErrNotEnoughGas)
				require.Nil(t, output)
				afterDenial, err := ctx.BlockchainHook.GetESDTToken(writer, token, 1)
				require.NoError(t, err)
				require.Equal(t, before, afterDenial)
				afterRoot, err := ctx.Accounts.RootHash()
				require.NoError(t, err)
				require.Equal(t, root, afterRoot)
				require.Equal(t, journal, ctx.Accounts.JournalLen())
				for _, extra := range []uint64{0, 1} {
					input.GasProvided = uint64(1+size) + extra
					output, err = ctx.BlockchainHook.ProcessBuiltInFunction(input)
					require.NoError(t, err)
					require.Equal(t, vmcommon.Ok, output.ReturnCode)
					require.Equal(t, extra, output.GasRemaining)
					actual, err := ctx.BlockchainHook.GetESDTToken(writer, token, 1)
					require.NoError(t, err)
					expected := &esdt.MetaData{Nonce: 1, Name: []byte("name"), Creator: writer, Royalties: 10,
						Hash: []byte("hash"), Attributes: attributes, URIs: [][]byte{[]byte("uri")}}
					require.Equal(t, expected, actual.TokenMetaData)
					require.Equal(t, big.NewInt(1), actual.Value)
					version := &esdt.MetaDataVersion{}
					require.NoError(t, ctx.Marshalizer.Unmarshal(version, actual.Reserved))
					require.Equal(t, &esdt.MetaDataVersion{Attributes: 7}, version)
					committed, err := ctx.Accounts.Commit()
					require.NoError(t, err)
					require.NoError(t, ctx.Accounts.RecreateTrie(holders.NewDefaultRootHashesHolder(committed)))
					reloaded, err := ctx.BlockchainHook.GetESDTToken(writer, token, 1)
					require.NoError(t, err)
					require.Equal(t, actual, reloaded)
				}
			})
		}
	}
}
