package systemSmartContracts

import (
	"bytes"
	"encoding/json"
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	processMock "github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

func TestQualD20NativeContextMissingOperationSource(t *testing.T) {
	for _, configured := range []bool{false, true} {
		args := createDefaultEeiArgs()
		if configured {
			args.DRWAClassifier = &publicOwner{publicClassifier: &publicClassifier{}}
		}
		host, err := NewVMContext(args)
		require.NoError(t, err)
		host.SetSCAddress([]byte("prior-context"))
		host.storageUpdate = map[string]map[string][]byte{"prior-context": {"key": []byte("prior-value")}}
		host.outputAccounts = map[string]*vmcommon.OutputAccount{"prior-context": {Address: []byte("prior-context"), Balance: big.NewInt(11), BalanceDelta: big.NewInt(13)}}
		host.SetGasProvided(37)
		host.returnMessage = "prior-message"
		host.output = [][]byte{[]byte("prior-output")}
		host.logs = []*vmcommon.LogEntry{nil}
		host.crtTransferIndex = 9
		snapshot := func() []byte {
			out, failure := json.Marshal(map[string]any{"address": host.scAddress, "storage": host.storageUpdate, "accounts": host.outputAccounts, "gas": host.gasRemaining, "message": host.returnMessage, "output": host.output, "logs": host.logs, "transferIndex": host.crtTransferIndex})
			require.NoError(t, failure)
			return out
		}
		before := snapshot()
		entered := 0
		tx := &transaction.Transaction{RcvAddr: bytes.Clone(core.ESDTSCAddress), Data: []byte("DRWARegisterToken")}
		_, err = host.WithDRWANativeCall(tx, struct{}{}, host.userAccountsDB, &processMock.VMExecutionHandlerStub{}, func(vm.DRWANativeCallLease) (vmcommon.ReturnCode, error) { entered++; return vmcommon.Ok, nil })
		require.ErrorIs(t, err, vm.ErrDRWAExecution)
		require.Zero(t, entered)
		require.Equal(t, before, snapshot())
	}
}
