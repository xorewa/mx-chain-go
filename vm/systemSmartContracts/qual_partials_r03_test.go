package systemSmartContracts

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/vm/mock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Explicit expected definition fields and a fixed input digest make neither
// the native output nor the producer's saved bytes the expected-value oracle.
func qualPartialsCreationComposition(t *testing.T, method string) {
	t.Helper()
	for _, width := range []uint{0, 32, 64} {
		t.Run(fmt.Sprintf("width_%d", width), func(t *testing.T) {
			f := qualPartialsNewSystemMachine(t)
			owner := bytes.Repeat([]byte{1}, 32)
			seed := []byte("resume2-seed")
			f.host.blockChainHook.(*mock.BlockChainHookStub).CurrentRandomSeedCalled = func() []byte { return seed }
			f.contract.hasher = &testscommon.HasherStub{ComputeCalled: func(value string) []byte {
				require.Equal(t, string(owner)+string(seed), value)
				return bytes.Repeat([]byte{0xab}, 32)
			}}
			id := []byte("TOKEN-ababab")
			decimals := big.NewInt(18)
			if width > 0 {
				decimals.Add(decimals, new(big.Int).Lsh(big.NewInt(1), width))
			}
			args := [][]byte{[]byte("TokenName"), []byte("TOKEN")}
			family := core.FungibleESDT
			supply := int64(0)
			switch method {
			case "issue":
				args = append(args, []byte{7}, decimals.Bytes())
				supply = 7
			case "registerMetaESDT":
				args = append(args, decimals.Bytes())
				family = core.MetaESDT
			case "registerAndSetAllRoles":
				args = append(args, []byte("FNG"), decimals.Bytes())
			default:
				t.Fatal("unknown fixture method")
			}
			in := qualTransitionInput(method, args, true)
			in.GasProvided = 1000
			in.GasPrice = 9
			before, err := f.db.RootHash()
			require.NoError(t, err)
			out, err := f.call(in)
			require.NoError(t, err)
			if width > 0 {
				require.Equal(t, vmcommon.UserError, out.ReturnCode)
				require.Contains(t, out.ReturnMessage, "provided: "+decimals.String())
				require.Empty(t, out.OutputAccounts)
				require.Empty(t, out.Logs)
				require.Empty(t, out.ReturnData)
				require.Zero(t, out.GasRemaining)
				after, e := f.db.RootHash()
				require.NoError(t, e)
				require.Equal(t, before, after)
				require.Empty(t, qualNativeRegistrationValue(t, f.db, core.ESDTSCAddress, id))
				return
			}
			require.Equal(t, vmcommon.Ok, out.ReturnCode)
			require.Empty(t, out.ReturnMessage)
			require.Equal(t, uint64(990), out.GasRemaining)
			require.Equal(t, []*vmcommon.LogEntry{{Identifier: []byte(upgradeProperties), Address: owner, Topics: [][]byte{id, {}, []byte(upgradable), []byte("true"), []byte(canAddSpecialRoles), []byte("true")}}, {Identifier: []byte(method), Address: owner, Topics: [][]byte{id, []byte("TokenName"), []byte("TOKEN"), []byte(family), {18}}}}, out.Logs)
			token := &ESDTDataV2{OwnerAddress: owner, TokenName: []byte("TokenName"), TickerName: []byte("TOKEN"), TokenType: []byte(family), NumDecimals: 18, MintedValue: big.NewInt(supply), BurntValue: big.NewInt(0), Upgradable: true, CanAddSpecialRoles: true}
			var recipients, payloads [][]byte
			if method == "issue" {
				require.Empty(t, out.ReturnData)
				recipients = [][]byte{owner}
				payloads = [][]byte{[]byte(core.BuiltInFunctionESDTTransfer + "@" + hex.EncodeToString(id) + "@07")}
			} else {
				require.Equal(t, [][]byte{id}, out.ReturnData)
			}
			if method == "registerAndSetAllRoles" {
				roles := [][]byte{[]byte(core.ESDTRoleLocalMint), []byte(core.ESDTRoleLocalBurn)}
				token.SpecialRoles = []*ESDTRoles{{Address: owner, Roles: roles}}
				recipients = [][]byte{owner}
				payloads = [][]byte{[]byte(core.BuiltInFunctionSetESDTRole + "@" + hex.EncodeToString(id) + "@" + hex.EncodeToString(roles[0]) + "@" + hex.EncodeToString(roles[1]))}
			}
			expected, err := (&marshal.GogoProtoMarshalizer{}).Marshal(token)
			require.NoError(t, err)
			qualPartialsConsumeSystemOutput(t, f, in, out, id, expected, recipients, payloads)
		})
	}
}

func TestQualPartialsR03IssueComposition(t *testing.T) { qualPartialsCreationComposition(t, "issue") }
