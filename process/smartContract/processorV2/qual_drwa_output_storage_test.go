package processorV2

import (
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/process"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Part A 3.1/P20: test the real V2 storage-output consumer separately from
// public SaveKeyValue. No DRWA namespace, VM execution or commit is modeled.
func TestQualDRWAV2OutputStorageBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, key string
		allowed   bool
	}{
		{"ordinary", "qual-key", true},
		{"protocol", core.ProtectedKeyPrefix + "qual-probe", false},
		{"bare_vm_prefix", core.ProtectedKeyPrefix + process.VMStoragePrefix, false},
		{"vm_child", core.ProtectedKeyPrefix + process.VMStoragePrefix + "qual-probe", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			account := &stateMock.UserAccountStub{SaveKeyValueCalled: func(key, value []byte) error {
				calls++
				require.Equal(t, []byte(tc.key), key)
				require.Equal(t, []byte("value"), value)
				return nil
			}}
			output := &vmcommon.OutputAccount{StorageUpdates: map[string]*vmcommon.StorageUpdate{
				tc.key: {Offset: []byte(tc.key), Data: []byte("value")},
			}}
			processor := &VMOutputAccountsProcessor{}
			err := processor.processStorageUpdatesStep(account, output)
			if tc.allowed {
				require.NoError(t, err)
				require.Equal(t, 1, calls)
			} else {
				require.ErrorIs(t, err, process.ErrNotAllowedToWriteUnderProtectedKey)
				require.Zero(t, calls)
			}
		})
	}
}

func TestQualDRWAV2OutputStorageWriteErrorIsPropagated(t *testing.T) {
	injected := errors.New("injected data write failure")
	calls := 0
	account := &stateMock.UserAccountStub{SaveKeyValueCalled: func(_, _ []byte) error { calls++; return injected }}
	output := &vmcommon.OutputAccount{StorageUpdates: map[string]*vmcommon.StorageUpdate{
		"qual-key": {Offset: []byte("qual-key"), Data: []byte("value")},
	}}
	processor := &VMOutputAccountsProcessor{}
	require.ErrorIs(t, processor.processStorageUpdatesStep(account, output), injected)
	require.Equal(t, 1, calls)
}
