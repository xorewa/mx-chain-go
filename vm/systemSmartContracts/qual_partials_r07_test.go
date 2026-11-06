package systemSmartContracts

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// R7 source label for producer-selected fixture inputs bound throughout this file:
// Experimental R7 fixture inputs: owner/caller bytes, token/name/ticker, gas 1000, price 9 and three-shard
// fanout. Register: XV-SP2-81B3C-SWEEP-NODE-VM-SYSTEMSMARTCONTRACTS-QUAL-PARTIALS-R07; owner replaces or
// confirms before testnet admission.
// Native constants, structural indices/counters and derived assertions retain their source-defined meaning.

func TestQualPartialsR07UpdateComposition(t *testing.T) {
	f := qualPartialsNewSystemMachine(t)
	f.flags.AddActiveFlags(common.DynamicESDTFlag)
	owner := bytes.Repeat([]byte{1}, 32)
	caller := bytes.Repeat([]byte{2}, 32)
	id := []byte("TOKEN-abcdef")
	token := &ESDTDataV2{OwnerAddress: owner, TokenName: []byte("TokenName"), TickerName: []byte("TOKEN"), TokenType: []byte(core.NonFungibleESDT), MintedValue: big.NewInt(0), BurntValue: big.NewInt(0), Upgradable: true, CanAddSpecialRoles: true}
	qualPartialsSeedToken(t, f, id, token)
	in := qualTransitionInput("updateTokenID", [][]byte{id}, false)
	in.CallerAddr = caller
	in.GasProvided = 1000
	in.GasPrice = 9
	out, err := f.call(in)
	require.NoError(t, err)
	require.Equal(t, vmcommon.Ok, out.ReturnCode)
	require.Equal(t, uint64(993), out.GasRemaining)
	require.Empty(t, out.ReturnData)
	require.Equal(t, []*vmcommon.LogEntry{{Identifier: []byte(core.ESDTSetTokenType), Address: caller, Topics: [][]byte{id, []byte(core.NonFungibleESDTv2)}}}, out.Logs)
	token.TokenType = []byte(core.NonFungibleESDTv2)
	expected, err := (&marshal.GogoProtoMarshalizer{}).Marshal(token)
	require.NoError(t, err)
	var recipients, payloads [][]byte
	for shard := byte(0); shard < 3; shard++ {
		a := bytes.Clone(core.SystemAccountAddress)
		a[31] = shard
		recipients = append(recipients, a)
		payloads = append(payloads, []byte(core.ESDTSetTokenType+"@"+hex.EncodeToString(id)+"@"+hex.EncodeToString([]byte(core.NonFungibleESDTv2))))
	}
	qualPartialsConsumeSystemOutput(t, f, in, out, id, expected, recipients, payloads)
	root, err := f.db.RootHash()
	require.NoError(t, err)
	repeated, err := f.call(in)
	require.NoError(t, err)
	require.Equal(t, vmcommon.UserError, repeated.ReturnCode)
	require.Equal(t, "token was already updated or not non-fungible", repeated.ReturnMessage)
	require.Empty(t, repeated.OutputAccounts)
	require.Empty(t, repeated.Logs)
	require.Zero(t, repeated.GasRemaining)
	after, err := f.db.RootHash()
	require.NoError(t, err)
	require.Equal(t, root, after)
	require.Equal(t, expected, qualNativeRegistrationValue(t, f.db, core.ESDTSCAddress, id))
}
