package drwa

import (
	"bytes"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	nativeBuiltins "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
)

// SP2-25, F.5 D17, Plan L435: the admission of public built-in calls. The real
// pinned built-in container supplies the functions and the native transfer
// parse. Inert local fixtures only.

type qualSP225Classifier struct {
	regulated map[string]bool
	err       error
	asked     [][]byte
}

func (c *qualSP225Classifier) ClassifyToken(tokenID []byte) (bool, error) {
	c.asked = append(c.asked, bytes.Clone(tokenID))
	if c.err != nil {
		return false, c.err
	}
	return c.regulated[string(tokenID)], nil
}
func (c *qualSP225Classifier) IsInterfaceNil() bool { return c == nil }

const qualSP225Regulated, qualSP225Ordinary = "REGULATED-abcdef", "ORDINARY-abcdef"

func qualSP225Container(t *testing.T) vmcommon.BuiltInFunctionContainer {
	t.Helper()
	f := routeOperationFixture(t)
	creator, err := nativeBuiltins.NewBuiltInFunctionsCreator(f.args)
	require.NoError(t, err)
	require.NoError(t, creator.CreateBuiltInFunctionContainer())
	return creator.BuiltInFunctionContainer()
}

func qualSP225Admission(t *testing.T) (*BuiltInAdmission, *qualSP225Classifier) {
	t.Helper()
	classifier := &qualSP225Classifier{regulated: map[string]bool{qualSP225Regulated: true}}
	admission := NewBuiltInAdmission(classifier)
	require.NotNil(t, admission)
	return admission, classifier
}

func qualSP225Call(function string, arguments ...[]byte) *vmcommon.ContractCallInput {
	return &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: bytes.Repeat([]byte{1}, 32),
		CallValue: big.NewInt(0), GasProvided: 100000, Arguments: arguments}, RecipientAddr: bytes.Repeat([]byte{2}, 32), Function: function}
}

// The gate's two tables are exactly the loaded container and agree with the
// reviewed P17 direct inventory: account-only built-ins are the OUT_OF_SCOPE
// rows, every other row carries a token identifier.
func TestQualSP225BuiltInTablesMatchInventoryAndContainer(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testscommon", "testdata", "drwa", "t10", "inventory_01.json"))
	require.NoError(t, err)
	var inventory struct {
		Rows []struct {
			Layer     string `json:"layer"`
			Operation string `json:"operation_name"`
			Class     string `json:"normalized_class"`
		} `json:"rows"`
	}
	require.NoError(t, json.Unmarshal(raw, &inventory))
	transfers := map[string]bool{core.BuiltInFunctionESDTTransfer: true, core.BuiltInFunctionESDTNFTTransfer: true, core.BuiltInFunctionMultiESDTNFTTransfer: true}
	container := qualSP225Container(t)
	rows := 0
	for _, row := range inventory.Rows {
		if row.Layer != "builtin_factory" {
			continue
		}
		rows++
		_, accountOnly := builtInAccountFunctions[row.Operation]
		_, tokenBearing := builtInTokenFunctions[row.Operation]
		require.Equal(t, row.Class == "OUT_OF_SCOPE", accountOnly, row.Operation)
		require.Equal(t, row.Class != "OUT_OF_SCOPE", tokenBearing || transfers[row.Operation], row.Operation)
		require.Equal(t, row.Class == "GATE", transfers[row.Operation], row.Operation)
		require.False(t, accountOnly && tokenBearing)
		_, err = container.Get(row.Operation)
		require.NoError(t, err, row.Operation)
	}
	require.Equal(t, 42, rows)
	require.Equal(t, rows, len(builtInAccountFunctions)+len(builtInTokenFunctions)+len(transfers))
	require.Equal(t, rows, container.Len())
	for name := range container.Keys() {
		_, accountOnly := builtInAccountFunctions[name]
		_, tokenBearing := builtInTokenFunctions[name]
		require.True(t, accountOnly || tokenBearing || transfers[name], name)
	}
}

func TestQualSP225BuiltInAdmissionEveryLoadedFunction(t *testing.T) {
	container := qualSP225Container(t)
	for name := range container.Keys() {
		function, err := container.Get(name)
		require.NoError(t, err)
		_, accountOnly := builtInAccountFunctions[name]
		for _, token := range []string{qualSP225Regulated, qualSP225Ordinary} {
			t.Run(name+"/"+token, func(t *testing.T) {
				admission, classifier := qualSP225Admission(t)
				input := qualSP225Call(name, []byte(token), []byte{1}, []byte{1}, []byte{1})
				if name == core.BuiltInFunctionMultiESDTNFTTransfer {
					// Destination-side form: count, then (identifier, nonce, value).
					input = qualSP225Call(name, []byte{1}, []byte(token), []byte{0}, []byte{1})
				}
				before := qualSP225CloneInput(input)
				err := admission.AdmitBuiltIn(function, input)
				require.Equal(t, before, input, "the native input is not changed")
				if accountOnly {
					require.NoError(t, err)
					require.Empty(t, classifier.asked, "no token, no classification")
					return
				}
				require.NotEmpty(t, classifier.asked)
				if token == qualSP225Regulated {
					require.ErrorIs(t, err, ErrRegulatedTokenOperation)
					require.NotErrorIs(t, err, vm.ErrDRWAExecution, "a deterministic operation error, not a node failure")
				} else {
					require.NoError(t, err)
				}

				unresolved := &qualSP225Classifier{err: ErrClassificationUnresolved}
				err = NewBuiltInAdmission(unresolved).AdmitBuiltIn(function, input)
				require.ErrorIs(t, err, vm.ErrDRWAExecution, "unresolved is never ordinary")
				require.ErrorIs(t, err, ErrClassificationUnresolved)
			})
		}
	}
}

func qualSP225CloneInput(input *vmcommon.ContractCallInput) *vmcommon.ContractCallInput {
	clone := *input
	clone.CallerAddr, clone.RecipientAddr = bytes.Clone(input.CallerAddr), bytes.Clone(input.RecipientAddr)
	clone.CallValue = new(big.Int).Set(input.CallValue)
	clone.Arguments = make([][]byte, len(input.Arguments))
	for i := range input.Arguments {
		clone.Arguments[i] = bytes.Clone(input.Arguments[i])
	}
	return &clone
}

func TestQualSP225BuiltInAdmissionIdentifierShapes(t *testing.T) {
	container := qualSP225Container(t)
	get := func(name string) vmcommon.BuiltinFunction {
		function, err := container.Get(name)
		require.NoError(t, err)
		return function
	}
	regulated, ordinary, destination := []byte(qualSP225Regulated), []byte(qualSP225Ordinary), bytes.Repeat([]byte{2}, 32)
	for _, tc := range []struct {
		name   string
		input  *vmcommon.ContractCallInput
		denied bool
		asked  int
	}{
		{"multi_all_ordinary", qualSP225Call(core.BuiltInFunctionMultiESDTNFTTransfer, []byte{2}, ordinary, []byte{0}, []byte{1}, ordinary, []byte{0}, []byte{1}), false, 2},
		{"multi_second_regulated", qualSP225Call(core.BuiltInFunctionMultiESDTNFTTransfer, []byte{2}, ordinary, []byte{0}, []byte{1}, regulated, []byte{0}, []byte{1}), true, 2},
		{"multi_first_regulated", qualSP225Call(core.BuiltInFunctionMultiESDTNFTTransfer, []byte{2}, regulated, []byte{0}, []byte{1}, ordinary, []byte{0}, []byte{1}), true, 1},
		{"multi_too_short_is_native", qualSP225Call(core.BuiltInFunctionMultiESDTNFTTransfer, []byte{9}, regulated), false, 0},
		{"transfer_without_arguments_is_native", qualSP225Call(core.BuiltInFunctionESDTTransfer), false, 0},
		{"token_function_without_arguments_is_native", qualSP225Call(core.BuiltInFunctionESDTLocalMint), false, 0},
		{"wipe_single_nft_regulated", qualSP225Call(core.BuiltInFunctionESDTWipe, append(bytes.Clone(regulated), 0x07)), true, 2},
		{"freeze_single_nft_ordinary", qualSP225Call(core.BuiltInFunctionESDTFreeze, append(bytes.Clone(ordinary), 0x07)), false, 2},
		{"unfreeze_fungible_regulated", qualSP225Call(core.BuiltInFunctionESDTUnFreeze, regulated), true, 1},
		{"delete_metadata_second_token_regulated", qualSP225Call(vmcommon.ESDTDeleteMetadata, ordinary, []byte{1}, []byte{1}, []byte{2}, regulated, []byte{1}, []byte{3}, []byte{4}), true, 2},
		{"add_metadata_ordinary", qualSP225Call(vmcommon.ESDTAddMetadata, ordinary, []byte{1}, []byte("metadata")), false, 1},
		{"add_metadata_second_token_regulated", qualSP225Call(vmcommon.ESDTAddMetadata, ordinary, []byte{1}, []byte("metadata"), regulated, []byte{2}, []byte("metadata")), true, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			admission, classifier := qualSP225Admission(t)
			err := admission.AdmitBuiltIn(get(tc.input.Function), tc.input)
			if tc.denied {
				require.ErrorIs(t, err, ErrRegulatedTokenOperation)
			} else {
				require.NoError(t, err)
			}
			require.Len(t, classifier.asked, tc.asked)
		})
	}

	t.Run("multi_self_call_form", func(t *testing.T) {
		admission, classifier := qualSP225Admission(t)
		input := qualSP225Call(core.BuiltInFunctionMultiESDTNFTTransfer, destination, []byte{1}, regulated, []byte{0}, []byte{1})
		input.RecipientAddr = bytes.Clone(input.CallerAddr)
		require.ErrorIs(t, admission.AdmitBuiltIn(get(input.Function), input), ErrRegulatedTokenOperation)
		require.Equal(t, [][]byte{regulated}, classifier.asked)
	})
}

type qualSP225PlainFunction struct{ vmcommon.BuiltinFunction }

type qualSP225LeakyTransfer struct {
	vmcommon.BuiltinFunction
	skipGate bool
}

func (f *qualSP225LeakyTransfer) ProcessBuiltinFunctionWithESDTTransferGate(input *vmcommon.ContractCallInput,
	_ vmcommon.ESDTTransferAccountResolver, gate vmcommon.ESDTTransferGate) (*vmcommon.VMOutput, *vmcommon.ParsedESDTTransfers, error) {
	if !f.skipGate {
		_, _ = gate.Classify(input.Function, [][]byte{[]byte(qualSP225Ordinary)})
	}
	return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil, nil
}

// Anything the gate cannot place fails closed as a node-level error.
func TestQualSP225BuiltInAdmissionFailsClosed(t *testing.T) {
	container := qualSP225Container(t)
	transfer, err := container.Get(core.BuiltInFunctionESDTTransfer)
	require.NoError(t, err)
	admission, classifier := qualSP225Admission(t)

	require.Nil(t, NewBuiltInAdmission(nil))
	require.Nil(t, NewBuiltInAdmission((*qualSP225Classifier)(nil)))
	require.False(t, admission.IsInterfaceNil())

	for name, call := range map[string]func() error{
		"nil_admission": func() error {
			return (*BuiltInAdmission)(nil).AdmitBuiltIn(transfer, qualSP225Call(core.BuiltInFunctionESDTTransfer))
		},
		"nil_function": func() error { return admission.AdmitBuiltIn(nil, qualSP225Call(core.BuiltInFunctionESDTTransfer)) },
		"nil_input":    func() error { return admission.AdmitBuiltIn(transfer, nil) },
		"unknown_function": func() error {
			return admission.AdmitBuiltIn(transfer, qualSP225Call("ESDTFutureFunction", []byte(qualSP225Ordinary)))
		},
		"transfer_without_native_parse": func() error {
			return admission.AdmitBuiltIn(&qualSP225PlainFunction{transfer}, qualSP225Call(core.BuiltInFunctionESDTTransfer, []byte(qualSP225Ordinary), []byte{1}))
		},
		"native_entry_ignores_the_probe": func() error {
			return admission.AdmitBuiltIn(&qualSP225LeakyTransfer{BuiltinFunction: transfer}, qualSP225Call(core.BuiltInFunctionESDTTransfer, []byte(qualSP225Ordinary), []byte{1}))
		},
		"native_entry_skips_classification": func() error {
			return admission.AdmitBuiltIn(&qualSP225LeakyTransfer{BuiltinFunction: transfer, skipGate: true}, qualSP225Call(core.BuiltInFunctionESDTTransfer, []byte(qualSP225Ordinary), []byte{1}))
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := call()
			require.ErrorIs(t, err, vm.ErrDRWAExecution)
			require.NotErrorIs(t, err, ErrRegulatedTokenOperation)
		})
	}
	require.Empty(t, classifier.asked)

	probe := &builtInIdentifierProbe{}
	require.ErrorIs(t, probe.CheckTransfer("", nil, nil, nil), errRouteNativeGuard, "the probe admits nothing")
	require.False(t, probe.IsInterfaceNil())
}

// The shard classifier without a registry source answers nothing.
func TestQualSP225ShardClassificationUnresolvedWithoutSource(t *testing.T) {
	for name, classifier := range map[string]*ShardClassification{
		"no_source": NewShardClassification(nil), "typed_nil_source": NewShardClassification((*qualSP225Classifier)(nil)), "nil": nil,
	} {
		t.Run(name, func(t *testing.T) {
			regulated, err := classifier.ClassifyToken([]byte(qualSP225Ordinary))
			require.ErrorIs(t, err, ErrClassificationUnresolved)
			require.False(t, regulated)
		})
	}
	source := &qualSP225Classifier{regulated: map[string]bool{qualSP225Regulated: true}}
	resolved := NewShardClassification(source)
	require.False(t, resolved.IsInterfaceNil())
	for token, expected := range map[string]bool{qualSP225Regulated: true, qualSP225Ordinary: false} {
		regulated, err := resolved.ClassifyToken([]byte(token))
		require.NoError(t, err)
		require.Equal(t, expected, regulated)
	}
	source.err = errors.New("inert source read failure")
	_, err := resolved.ClassifyToken([]byte(qualSP225Ordinary))
	require.ErrorIs(t, err, source.err, "a read failure is an error, never ordinary")
	require.True(t, reflect.DeepEqual(source.asked[len(source.asked)-1], []byte(qualSP225Ordinary)))
}
