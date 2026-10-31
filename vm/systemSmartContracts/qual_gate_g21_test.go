package systemSmartContracts

import (
	"bytes"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/vm/mock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// This file is also executed unchanged on the untouched candidate in bounded scratch.
func TestQualGateG21Native(t *testing.T) {
	t.Logf("G21_TRANSCRIPT %s", qualGateG21Transcript(t, nil))
}

func qualGateG21Transcript(t *testing.T, configure func(*VMContextArgs)) []byte {
	t.Helper()
	args := createMockArgumentsForESDT()
	contextArgs := createDefaultEeiArgs()
	contextArgs.BlockChainHook = &mock.BlockChainHookStub{
		GetStorageDataCalled:    func([]byte, []byte) ([]byte, uint32, error) { return nil, 0, nil },
		CurrentRandomSeedCalled: func() []byte { return []byte("gate-g21-ordinary") },
		NumberOfShardsCalled:    func() uint32 { return 3 },
	}
	if configure != nil {
		configure(&contextArgs)
	}
	context, err := NewVMContext(contextArgs)
	require.NoError(t, err)
	context.SetSCAddress(core.ESDTSCAddress)
	args.Eei = context
	contract, err := NewESDTSmartContract(args)
	require.NoError(t, err)
	owner := bytes.Repeat([]byte{1}, 32)
	var transcript []json.RawMessage
	call := func(function string, arguments [][]byte, value *big.Int, want vmcommon.ReturnCode) {
		context.gasRemaining = 1000000 // Experimental fixture budget only.
		context.returnMessage = ""
		input := getDefaultVmInputForFunc(function, arguments)
		input.CallerAddr, input.RecipientAddr, input.CallValue = owner, core.ESDTSCAddress, value
		code := contract.Execute(input)
		require.Equal(t, want, code, "%s: %s", function, context.returnMessage)
		snapshot, err := json.Marshal(struct {
			Function string
			Code     vmcommon.ReturnCode
			Output   *vmcommon.VMOutput
			Storage  map[string]map[string][]byte
		}{function, code, context.CreateVMOutput(), context.storageUpdate})
		require.NoError(t, err)
		transcript = append(transcript, snapshot)
	}
	call("issueNonFungible", [][]byte{[]byte("TokenName"), []byte("TOKEN"), []byte(canPause), []byte("true")}, new(big.Int).Set(contract.baseIssuingCost), vmcommon.Ok)
	require.Len(t, context.output, 1)
	id := bytes.Clone(context.output[0])
	call("pause", [][]byte{id}, big.NewInt(0), vmcommon.Ok)
	call("pause", [][]byte{id}, big.NewInt(0), vmcommon.UserError)
	call("unPause", [][]byte{id}, big.NewInt(0), vmcommon.Ok)
	call("pause", nil, big.NewInt(0), vmcommon.FunctionWrongSignature)
	call("unknownGateMethod", nil, big.NewInt(0), vmcommon.FunctionNotFound)
	result, err := json.Marshal(transcript)
	require.NoError(t, err)
	return result
}
