package systemSmartContracts

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// R7 source label for producer-selected fixture inputs bound throughout this file:
// Experimental R7 fixture inputs: owner/caller bytes, token/name/ticker marker, zero token supply, gas 1000
// and price 9. Register: XV-SP2-81B3C-SWEEP-NODE-VM-SYSTEMSMARTCONTRACTS-QUAL-PARTIALS-G01; owner replaces
// or confirms before testnet admission.
// Native constants, structural indices/counters and derived assertions retain their source-defined meaning.

// G01.02 adds denied native SystemVM output -> real node output-account
// consumption. Reuse R02 for healthy fanout/late-error rollback, and R01 for
// node late-nonce error -> owning nonzero snapshot restoration.
func TestQualPartialsG01DeniedSystemOutputConsumer(t *testing.T) {
	f := qualPartialsNewSystemMachine(t)
	owner := bytes.Repeat([]byte{1}, 32)
	id := []byte("TOKEN-abcdef")
	token := &ESDTDataV2{OwnerAddress: owner, TokenName: []byte("TokenName"), TickerName: []byte("TOKEN"), TokenType: []byte(core.FungibleESDT), MintedValue: big.NewInt(0), BurntValue: big.NewInt(0), CanPause: true}
	before := qualPartialsSeedToken(t, f, id, token)
	root, err := f.db.RootHash()
	require.NoError(t, err)
	snapshot := f.db.JournalLen()
	in := qualTransitionInput("pause", [][]byte{id}, false)
	in.GasProvided = 1000
	in.GasPrice = 9
	in.CallerAddr = bytes.Repeat([]byte{2}, 32)
	denied, err := f.call(in)
	require.NoError(t, err)
	require.Equal(t, vmcommon.UserError, denied.ReturnCode, "native owner denial survives SystemVM")
	require.Empty(t, denied.OutputAccounts, "denied SystemVM account effects suppressed")
	require.Empty(t, denied.Logs)
	require.Zero(t, denied.GasRemaining)
	results, err := f.consume(denied, &transaction.Transaction{SndAddr: in.CallerAddr, RcvAddr: in.RecipientAddr, Value: big.NewInt(0), GasPrice: 9})
	require.NoError(t, err)
	require.Empty(t, results, "denied output cannot generate node SCRs")
	after, err := f.db.RootHash()
	require.NoError(t, err)
	require.Equal(t, root, after, "denied output cannot change persistent state")
	require.Equal(t, snapshot, f.db.JournalLen(), "denied output cannot add a journal effect")
	require.Equal(t, before, qualNativeRegistrationValue(t, f.db, core.ESDTSCAddress, id))
}
