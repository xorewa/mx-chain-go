package txsFee

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/integrationTests/vm"
	"github.com/multiversx/mx-chain-go/integrationTests/vm/txsFee/utils"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// This exercises native absence, not a fabricated DRWA registration. L33's
// remote-registration comparison additionally requires T19's fresh-identifier
// producer and the candidate-context causality proof. These cases prove only
// the native local precondition once absence is established independently.
func TestQualDRWAAbsentRawReferenceNativeFailure(t *testing.T) {
	token := []byte("AAA-abcdef") // Test identifier, not a protocol allocation.
	id := hex.EncodeToString(token)
	cases := []struct {
		name, function, arguments string
		self                      bool
	}{
		{"transfer", core.BuiltInFunctionESDTTransfer, id + "@01", false},
		{"mint", core.BuiltInFunctionESDTLocalMint, id + "@01", true},
		{"create", core.BuiltInFunctionESDTNFTCreate, id + "@01@4e@00@48@41@55", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			context, err := vm.CreatePreparedTxProcessorWithVMs(config.EnableEpochs{}, 1)
			require.NoError(t, err)
			defer context.Close()
			sender := []byte("12345678901234567890123456789012")
			receiver := []byte("12345678901234567890123456789022")
			addresses := [][]byte{sender, receiver, core.SystemAccountAddress}
			before := make([][]byte, len(addresses))
			for i, address := range addresses {
				balance := big.NewInt(0)
				if i == 0 {
					balance.SetInt64(100000000)
				}
				_, err = vm.CreateAccount(context.Accounts, address, 0, balance)
				require.NoError(t, err)
				account, err := context.Accounts.LoadAccount(address)
				require.NoError(t, err)
				user, ok := account.(state.UserAccountHandler)
				require.True(t, ok)
				// Non-token sentinel gives each prestate a real non-empty trie.
				require.NoError(t, user.SaveKeyValue([]byte("AN03-test-sentinel"), []byte("unchanged")))
				require.NoError(t, context.Accounts.SaveAccount(user))
				_, err = context.Accounts.Commit()
				require.NoError(t, err)
				account, err = context.Accounts.GetExistingAccount(address)
				require.NoError(t, err)
				before[i] = bytes.Clone(account.(state.UserAccountHandler).GetRootHash())
			}
			if tc.self {
				receiver = sender
			}
			tx := utils.CreateESDTTransferTx(0, sender, receiver, token, big.NewInt(1), 10, 1000)
			tx.Data = []byte(tc.function + "@" + tc.arguments)
			code, err := context.TxProcessor.ProcessTransaction(tx)
			require.Equal(t, vmcommon.UserError, code)
			require.Equal(t, process.ErrFailedTransaction, err)
			_, err = context.Accounts.Commit()
			require.NoError(t, err)
			for i, address := range addresses {
				account, err := context.Accounts.GetExistingAccount(address)
				require.NoError(t, err)
				require.Equal(t, before[i], account.(state.UserAccountHandler).GetRootHash(), "token/data trie changed")
			}
			utils.TestAccount(t, context.Accounts, sender, 1, big.NewInt(99990000))
			require.Equal(t, big.NewInt(10000), context.TxFeeHandler.GetAccumulatedFees())
			logs := context.TxsLogsProcessor.GetAllCurrentLogs()
			require.Len(t, logs, 1)
			// Exact native bytes are retained for the independent upstream run.
			for _, log := range logs {
				events := log.GetLogHandler().GetLogEvents()
				require.Len(t, events, 1)
				require.Equal(t, []byte(core.SignalErrorOperation), events[0].GetIdentifier())
				raw, err := context.Marshalizer.Marshal(log.GetLogHandler())
				require.NoError(t, err)
				t.Logf("AN03 native failure log %x", raw)
			}
			for _, result := range context.GetIntermediateTransactions(t) {
				// Native bad-transaction forwarding is distinct from an outgoing SCR.
				_, originalTransaction := result.(*transaction.Transaction)
				require.True(t, originalTransaction, "an outgoing SCR was produced")
				raw, err := context.Marshalizer.Marshal(result)
				require.NoError(t, err)
				t.Logf("AN03 native intermediate result %x", raw)
			}
			t.Log(fmt.Sprintf("AN03 outcome %s code=%d nonce=1 fee=10000 data_roots_unchanged=true", tc.name, code))
		})
	}
}
