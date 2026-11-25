package processorV2

import (
	"bytes"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/stretchr/testify/require"
)

func TestQualSP281CLaneCSaveKeyValueGasBoundary(t *testing.T) {
	args := createMockSmartContractProcessorArguments()
	args.ArgsParser = &testscommon.ArgumentParserMock{
		ParseCallDataCalled: func(string) (string, [][]byte, error) {
			return core.BuiltInFunctionSaveKeyValue, [][]byte{[]byte("ab"), []byte("value"), []byte("extra")}, nil
		},
	}
	processor, err := NewSmartContractProcessorV2(args)
	require.NoError(t, err)
	processor.persistPerByte = 3
	processor.storePerByte = 7
	processor.builtInGasCosts = map[string]uint64{core.BuiltInFunctionSaveKeyValue: 11}

	sender := bytes.Repeat([]byte{1}, 32)
	other := bytes.Repeat([]byte{2}, 32)
	existing := bytes.Repeat([]byte{3}, 32)
	empty := make([]byte, 32)
	// The exact charge is 11 + 3*(2+5) + 7*5.
	cases := []struct {
		name     string
		gas      uint64
		receiver []byte
		root     []byte
		want     []byte
	}{
		{name: "below", gas: 66, receiver: sender},
		{name: "exact", gas: 67, receiver: sender, want: empty},
		{name: "above", gas: 68, receiver: sender, want: empty},
		{name: "existing root", gas: 68, receiver: sender, root: existing, want: existing},
		{name: "different receiver", gas: 68, receiver: other},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			account := createAccount(sender)
			account.SetRootHash(tc.root)
			scr := &smartContractResult.SmartContractResult{
				SndAddr: sender, RcvAddr: tc.receiver, GasLimit: tc.gas,
			}
			processor.setEmptyRoothashOnErrorIfSaveKeyValue(scr, account)
			require.Equal(t, tc.want, account.GetRootHash())
		})
	}
}
