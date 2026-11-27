package metachain

import (
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/vm"
	vmMock "github.com/multiversx/mx-chain-go/vm/mock"
	"github.com/stretchr/testify/require"
)

// A presence marker only: no classification or account operation is part of
// this constructor lifecycle check. Any such call would fail the test.
type lifecycleClassifierMarker struct {
	vm.DRWATokenClassifier
}

func TestFinalizeSystemVMCreationRegistersLifecycleHandler(t *testing.T) {
	gas := testscommon.NewGasScheduleNotifierMock(map[string]map[string]uint64{
		common.BaseOpsAPICost: {
			common.AsyncCallStepField:        1,
			common.AsyncCallbackGasLockField: 1,
		},
	})
	var subscribers []core.GasScheduleSubscribeHandler
	gas.RegisterNotifyHandlerCalled = func(handler core.GasScheduleSubscribeHandler) {
		subscribers = append(subscribers, handler)
	}
	factory := &vmContainerFactory{
		drwaClassifier:  &lifecycleClassifierMarker{},
		systemContracts: &vmMock.SystemSCContainerStub{},
		gasSchedule:     gas,
	}
	require.Nil(t, factory.drwaDeletionGuard)

	created, err := factory.finalizeSystemVMCreation(&vmMock.SystemEIStub{})
	require.NoError(t, err)
	require.NotNil(t, created)
	require.Same(t, created, factory.drwaDeletionGuard)
	require.NotEmpty(t, subscribers)
	for _, subscriber := range subscribers {
		require.Same(t, created, subscriber)
	}
}

type lifecycleContainerErrorStub struct {
	vmMock.SystemEIStub
	err error
}

func (s *lifecycleContainerErrorStub) SetSystemSCContainer(_ vm.SystemSCContainer) error {
	return s.err
}

func TestFinalizeSystemVMCreationReturnsContainerSetupError(t *testing.T) {
	wantErr := errors.New("container setup failed")
	gas := testscommon.NewGasScheduleNotifierMock(nil)
	registered := false
	gas.RegisterNotifyHandlerCalled = func(_ core.GasScheduleSubscribeHandler) {
		registered = true
	}
	factory := &vmContainerFactory{
		systemContracts: &vmMock.SystemSCContainerStub{},
		gasSchedule:     gas,
	}
	created, err := factory.finalizeSystemVMCreation(&lifecycleContainerErrorStub{err: wantErr})
	require.ErrorIs(t, err, wantErr)
	require.Nil(t, created)
	require.False(t, registered)
}

func TestFinalizeSystemVMCreationReturnsConstructorError(t *testing.T) {
	gas := testscommon.NewGasScheduleNotifierMock(nil)
	registered := false
	gas.RegisterNotifyHandlerCalled = func(_ core.GasScheduleSubscribeHandler) {
		registered = true
	}
	factory := &vmContainerFactory{
		systemContracts: &vmMock.SystemSCContainerStub{},
		gasSchedule:     gas,
	}
	created, err := factory.finalizeSystemVMCreation(&vmMock.SystemEIStub{})
	require.ErrorIs(t, err, vm.ErrNilGasSchedule)
	require.Nil(t, created)
	require.False(t, registered)
}
