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

func TestQualPartialsR06ConversionComposition(t *testing.T) {
	for _, mode := range []string{"valid", "non-SFT", "wide32", "wide64"} {
		t.Run(mode, func(t *testing.T) {
			f := qualPartialsNewSystemMachine(t)
			f.flags.AddActiveFlags(common.DynamicESDTFlag)
			owner := bytes.Repeat([]byte{1}, 32)
			id := []byte("TOKEN-abcdef")
			family := core.SemiFungibleESDT
			if mode == "non-SFT" {
				family = core.NonFungibleESDT
			}
			token := &ESDTDataV2{OwnerAddress: owner, TokenName: []byte("TokenName"), TickerName: []byte("TOKEN"), TokenType: []byte(family), MintedValue: big.NewInt(0), BurntValue: big.NewInt(0), Upgradable: true, CanAddSpecialRoles: true}
			before := qualPartialsSeedToken(t, f, id, token)
			root, err := f.db.RootHash()
			require.NoError(t, err)
			decimals := big.NewInt(18)
			if mode == "wide32" {
				decimals.Add(decimals, new(big.Int).Lsh(big.NewInt(1), 32))
			}
			if mode == "wide64" {
				decimals.Add(decimals, new(big.Int).Lsh(big.NewInt(1), 64))
			}
			in := qualTransitionInput("changeSFTToMetaESDT", [][]byte{id, decimals.Bytes()}, false)
			in.GasProvided = 1000
			in.GasPrice = 9
			out, err := f.call(in)
			require.NoError(t, err)
			if mode != "valid" {
				require.Equal(t, vmcommon.UserError, out.ReturnCode)
				require.Empty(t, out.OutputAccounts)
				require.Empty(t, out.Logs)
				require.Zero(t, out.GasRemaining)
				after, e := f.db.RootHash()
				require.NoError(t, e)
				require.Equal(t, root, after)
				require.Equal(t, before, qualNativeRegistrationValue(t, f.db, core.ESDTSCAddress, id))
				return
			}
			require.Equal(t, vmcommon.Ok, out.ReturnCode)
			require.Equal(t, uint64(993), out.GasRemaining)
			require.Empty(t, out.ReturnData)
			require.Equal(t, []*vmcommon.LogEntry{{Identifier: []byte(in.Function), Address: owner, Topics: [][]byte{id, []byte("TokenName"), []byte("TOKEN"), []byte(core.MetaESDT), {18}}}, {Identifier: []byte(core.ESDTSetTokenType), Address: owner, Topics: [][]byte{id, []byte(core.MetaESDT)}}}, out.Logs)
			token.TokenType = []byte(core.MetaESDT)
			token.NumDecimals = 18
			expected, err := (&marshal.GogoProtoMarshalizer{}).Marshal(token)
			require.NoError(t, err)
			var recipients, payloads [][]byte
			for shard := byte(0); shard < 3; shard++ {
				a := bytes.Clone(core.SystemAccountAddress)
				a[31] = shard
				recipients = append(recipients, a)
				payloads = append(payloads, []byte(core.ESDTSetTokenType+"@"+hex.EncodeToString(id)+"@"+hex.EncodeToString([]byte(core.MetaESDT))))
			}
			qualPartialsConsumeSystemOutput(t, f, in, out, id, expected, recipients, payloads)
		})
	}
}
