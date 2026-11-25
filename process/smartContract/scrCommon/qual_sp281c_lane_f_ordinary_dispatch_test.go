package scrCommon

import (
	"errors"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/process/mock"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

type qualSP281CLaneFUnconfiguredPhysical struct {
	*mock.VMExecutionHandlerStub
	qualD20CommonRefusalPhysical
}

func (*qualSP281CLaneFUnconfiguredPhysical) DRWANativeCallConfigured() bool { return false }

func TestQualSP281CLaneFOrdinaryDispatchAndLookupRefusal(t *testing.T) {
	recipient := core.ESDTSCAddress
	vmType, err := vmcommon.ParseVMTypeFromContractAddress(recipient)
	require.NoError(t, err)
	_, shortAddressErr := vmcommon.ParseVMTypeFromContractAddress(recipient[:1])
	require.Error(t, shortAddressErr)

	lookupErr := errors.New("inert VM lookup refusal")
	ordinaryErr := errors.New("inert ordinary dispatch error")
	cases := []struct {
		name       string
		recipient  []byte
		lookupErr  error
		bodyCode   vmcommon.ReturnCode
		bodyErr    error
		wantCode   vmcommon.ReturnCode
		wantErr    error
		wantLookup int
		wantBody   int
	}{
		{name: "ordinary result", recipient: recipient, bodyCode: vmcommon.Ok, wantCode: vmcommon.Ok, wantLookup: 1, wantBody: 1},
		{name: "ordinary error", recipient: recipient, bodyCode: vmcommon.UserError, bodyErr: ordinaryErr, wantCode: vmcommon.UserError, wantErr: ordinaryErr, wantLookup: 1, wantBody: 1},
		{name: "container refusal", recipient: recipient, lookupErr: lookupErr, wantCode: vmcommon.ExecutionFailed, wantErr: lookupErr, wantLookup: 1},
		{name: "address parse refusal", recipient: recipient[:1], wantCode: vmcommon.ExecutionFailed, wantErr: shortAddressErr},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			locker := &sync.RWMutex{}
			physical := &qualSP281CLaneFUnconfiguredPhysical{VMExecutionHandlerStub: &mock.VMExecutionHandlerStub{}}
			lookups, bodies := 0, 0
			container := &mock.VMContainerMock{GetCalled: func(key []byte) (vmcommon.VMExecutionHandler, error) {
				lookups++
				require.Equal(t, vmType, key)
				if tc.lookupErr != nil {
					return nil, tc.lookupErr
				}
				return physical, nil
			}}
			tx := &transaction.Transaction{RcvAddr: tc.recipient}
			code, err := WithDRWANativeCall(container, locker, &stateMock.AccountsStub{}, tx, nil, func(call *DRWANativeCall) (vmcommon.ReturnCode, error) {
				bodies++
				require.Nil(t, call)
				require.True(t, locker.TryLock(), "ordinary continuation must get its own VM-change lock")
				locker.Unlock()
				return tc.bodyCode, tc.bodyErr
			})
			require.Equal(t, tc.wantCode, code)
			require.True(t, err == tc.wantErr, "expected the original error %v, got %v", tc.wantErr, err)
			require.Equal(t, tc.wantLookup, lookups)
			require.Equal(t, tc.wantBody, bodies)
			require.True(t, locker.TryLock(), "the preliminary VM-change read lock must be released")
			locker.Unlock()
		})
	}
}
