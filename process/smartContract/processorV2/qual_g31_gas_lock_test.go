package processorV2

import (
	"bytes"
	"testing"
	"time"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/stretchr/testify/require"
)

func TestQualG31GasCostReadWaitsForWriter(t *testing.T) {
	entered := make(chan struct{})
	args := createMockSmartContractProcessorArguments()
	args.ArgsParser = &testscommon.ArgumentParserMock{ParseCallDataCalled: func(string) (string, [][]byte, error) {
		close(entered)
		return core.BuiltInFunctionSaveKeyValue, [][]byte{[]byte("key"), []byte("value"), []byte("extra")}, nil
	}}
	sc, err := NewSmartContractProcessorV2(args)
	require.NoError(t, err)
	sc.persistPerByte, sc.storePerByte = 0, 0
	sc.builtInGasCosts = map[string]uint64{core.BuiltInFunctionSaveKeyValue: 0}
	address := bytes.Repeat([]byte{1}, 32)
	account := createAccount(address)
	account.SetRootHash(nil)
	tx := &smartContractResult.SmartContractResult{SndAddr: address, RcvAddr: address}
	sc.mutGasLock.Lock()
	locked := true
	t.Cleanup(func() { if locked { sc.mutGasLock.Unlock() } })
	done := make(chan struct{})
	go func() { sc.setEmptyRoothashOnErrorIfSaveKeyValue(tx, account); close(done) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("saveKeyValue parser was not reached")
	}
	select {
	case <-done:
		t.Error("gas-cost read completed while writer lock was held")
	case <-time.After(100 * time.Millisecond):
		require.Nil(t, account.GetRootHash())
	}
	sc.mutGasLock.Unlock()
	locked = false
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("gas-cost read did not continue after writer released")
	}
	require.Equal(t, make([]byte, 32), account.GetRootHash())
}
