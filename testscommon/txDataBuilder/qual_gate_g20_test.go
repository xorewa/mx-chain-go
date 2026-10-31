package txDataBuilder

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-core-go/marshal"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/multiversx/mx-chain-vm-common-go/mock"
	"github.com/multiversx/mx-chain-vm-common-go/parsers"
	datafield "github.com/multiversx/mx-chain-vm-common-go/parsers/dataField"
	builder "github.com/multiversx/mx-chain-vm-common-go/txDataBuilder"
	"github.com/stretchr/testify/require"
)

// TestQualGateG20 uses the integrated public parsers and builder with literal wire expectations.
// Values here are experimental test coordinates, never a deployed profile.
func TestQualGateG20(t *testing.T) {
	sender, receiver := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	p, err := datafield.NewOperationDataFieldParser(&datafield.ArgsOperationDataFieldParser{
		AddressLength: 32, Marshalizer: &marshal.GogoProtoMarshalizer{}, RelayedTransactionsV1V2DisableEpoch: 10,
	})
	require.NoError(t, err)
	t.Run("native_freeze_log_to_decoder", func(t *testing.T) {
		marshaller := &marshal.GogoProtoMarshalizer{}
		freeze, err := builtInFunctions.NewESDTFreezeWipeFunc(&mock.ESDTNFTStorageHandlerStub{}, &mock.EnableEpochsHandlerStub{}, marshaller, true, false)
		require.NoError(t, err)
		arg := append([]byte("TEST-123456"), 1, 0x2d)
		key := append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), arg...)
		account := mock.NewUserAccount(receiver)
		stored, err := marshaller.Marshal(&esdt.ESDigitalToken{Value: big.NewInt(7)})
		require.NoError(t, err)
		require.NoError(t, account.SaveKeyValue(key, stored))
		output, err := freeze.ProcessBuiltinFunction(nil, account, &vmcommon.ContractCallInput{
			VMInput:       vmcommon.VMInput{CallerAddr: core.ESDTSCAddress, CallValue: big.NewInt(0), Arguments: [][]byte{arg}},
			RecipientAddr: receiver, Function: core.BuiltInFunctionESDTFreeze,
		})
		require.NoError(t, err)
		require.Equal(t, vmcommon.Ok, output.ReturnCode)
		require.Equal(t, []*vmcommon.LogEntry{{Identifier: []byte(core.BuiltInFunctionESDTFreeze), Address: core.ESDTSCAddress,
			Topics: [][]byte{[]byte("TEST-123456"), {1, 0x2d}, {7}, receiver}, Data: nil}}, output.Logs)
		raw, _, err := account.RetrieveValue(key)
		require.NoError(t, err)
		var token esdt.ESDigitalToken
		require.NoError(t, marshaller.Unmarshal(&token, raw))
		require.True(t, builtInFunctions.ESDTUserMetadataFromBytes(token.Properties).Frozen)
		require.Equal(t, big.NewInt(7), token.Value)
		decoded := p.Parse(builder.NewBuilder().Func(string(output.Logs[0].Identifier)).Bytes(arg).ToBytes(), core.ESDTSCAddress, receiver, 3, 0)
		require.Equal(t, core.BuiltInFunctionESDTFreeze, decoded.Operation)
		require.Equal(t, []string{"TEST-123456-012d"}, decoded.Tokens)
	})
	t.Run("relayed_null_and_malformed", func(t *testing.T) {
		for _, payload := range []string{"null", "{"} {
			require.NotPanics(t, func() {
				data := builder.NewBuilder().Func(core.RelayedTransaction).Str(payload).ToBytes()
				r := p.Parse(data, sender, receiver, 3, 0)
				require.Equal(t, &datafield.ResponseParseData{IsRelayed: true}, r)
			})
		}
	})
	t.Run("modify_arity", func(t *testing.T) {
		for _, tc := range []struct {
			function string
			args     int
			tokens   []string
		}{
			{core.ESDTModifyCreator, 1, nil}, {core.ESDTModifyCreator, 2, []string{"TEST-123456-01"}},
			{core.ESDTModifyRoyalties, 2, nil}, {core.ESDTModifyRoyalties, 3, []string{"TEST-123456-01"}},
		} {
			b := builder.NewBuilder().Func(tc.function).Str("TEST-123456")
			if tc.args > 1 {
				b.Int(1)
			}
			if tc.args > 2 {
				b.Int(7)
			}
			r := p.Parse(b.ToBytes(), sender, receiver, 3, 0)
			require.Equal(t, tc.function, r.Operation)
			require.Equal(t, tc.tokens, r.Tokens)
		}
	})
	t.Run("complete_nonce_suffix", func(t *testing.T) {
		for _, tc := range []struct {
			suffix []byte
			token  string
		}{
			{nil, "TEST-123456"}, {[]byte{0x2d}, "TEST-123456-2d"},
			{[]byte{1, 0x2d}, "TEST-123456-012d"}, {[]byte{0x2d, 1}, "TEST-123456-2d01"},
		} {
			arg := append([]byte("TEST-123456"), tc.suffix...)
			r := p.Parse(builder.NewBuilder().Func(core.BuiltInFunctionESDTWipe).Bytes(arg).ToBytes(), sender, receiver, 3, 0)
			require.Equal(t, []string{tc.token}, r.Tokens)
		}
	})
	t.Run("bounded_count_both_routes", func(t *testing.T) {
		ep, err := parsers.NewESDTTransferParser(&marshal.GogoProtoMarshalizer{})
		require.NoError(t, err)
		for _, atSender := range []bool{false, true} {
			for _, tc := range []struct {
				count []byte
				want  error
			}{
				{new(big.Int).Lsh(big.NewInt(1), 64).Bytes(), parsers.ErrTooManyTransfers},
				{big.NewInt(10001).Bytes(), parsers.ErrTooManyTransfers}, {nil, parsers.ErrNotEnoughArguments},
				{[]byte{2}, parsers.ErrNotEnoughArguments},
			} {
				args := [][]byte{tc.count, []byte("TEST-123456"), nil, []byte{7}}
				if atSender {
					args = append([][]byte{receiver}, args...)
				}
				r, err := ep.ParseESDTTransfers(sender, receiver, core.BuiltInFunctionMultiESDTNFTTransfer, args)
				require.Nil(t, r)
				require.ErrorIs(t, err, tc.want)
			}
			args := [][]byte{{1}, []byte("TEST-123456"), nil, {7}, []byte("callback"), {0, 1}}
			if atSender {
				args = append([][]byte{receiver}, args...)
			}
			r, err := ep.ParseESDTTransfers(sender, receiver, core.BuiltInFunctionMultiESDTNFTTransfer, args)
			require.NoError(t, err)
			require.Equal(t, receiver, r.RcvAddr)
			require.Len(t, r.ESDTTransfers, 1)
			require.Equal(t, []byte("TEST-123456"), r.ESDTTransfers[0].ESDTTokenName)
			require.Equal(t, big.NewInt(7), r.ESDTTransfers[0].ESDTValue)
			require.Equal(t, uint64(0), r.ESDTTransfers[0].ESDTTokenNonce)
			require.Equal(t, "callback", r.CallFunction)
			require.Equal(t, [][]byte{{0, 1}}, r.CallArgs)
		}
	})
	t.Run("builder_literal_bytes", func(t *testing.T) {
		for _, tc := range []struct {
			function string
			args     [][]byte
			want     string
		}{
			{"", nil, ""}, {"f", nil, "f"}, {"", [][]byte{{1}}, "@01"},
			{"f", [][]byte{nil}, "f@"}, {"f", [][]byte{{1}}, "f@01"},
			{"f", [][]byte{nil, {0, 1}, nil}, "f@@0001@"},
		} {
			b := builder.NewBuilder().Func(tc.function)
			for _, arg := range tc.args {
				b.Bytes(arg)
			}
			require.Equal(t, tc.want, b.ToString())
			require.Equal(t, []byte(tc.want), b.ToBytes())
			require.Equal(t, "", b.Clear().ToString())
		}
	})
}
