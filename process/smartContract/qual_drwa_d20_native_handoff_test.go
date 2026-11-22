package smartContract

import (
	"bytes"
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/process/mock"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
	"sync"
	"testing"
)

func TestQualD20NativeHandoffBeforePayment(t *testing.T) {
	reads := 0
	accounts := &stateMock.AccountsStub{}
	sc := &scProcessor{accounts: accounts, wasmVMChangeLocker: &sync.RWMutex{}, vmContainer: &mock.VMContainerMock{GetCalled: func([]byte) (vmcommon.VMExecutionHandler, error) { reads++; return &mock.VMExecutionHandlerStub{}, nil }}}
	for _, name := range []string{"DRWARegisterBootstrapIntent", "DRWARegisterToken", "ordinary"} {
		tx := &transaction.Transaction{RcvAddr: bytes.Clone(core.ESDTSCAddress), Data: []byte(name)}
		_, err := sc.ExecuteSmartContractTransactionWithDRWA(tx, nil, nil, struct{}{})
		require.ErrorIs(t, err, vm.ErrDRWAExecution)
	}
	require.Equal(t, 3, reads)
	// No initialized payment/gas/output collaborators exist: any effect before
	// missing-source denial would panic. Ordinary existing entry is separate.
}
