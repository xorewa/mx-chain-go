package builtInFunctions_test

import (
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/process"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	native "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/multiversx/mx-chain-vm-common-go/mock"
	"github.com/stretchr/testify/require"
)

// Part A 3.1/P20 and Part B 17.2 require a protocol-owned namespace, not
// a new reservation in valid user keys. This observes existing key rules;
// the synthetic suffixes below allocate no DRWA storage format or namespace.
func TestQualDRWANativeStorageKeyBoundaries(t *testing.T) {
	protected := core.ProtectedKeyPrefix
	vmPrefix := protected + process.VMStoragePrefix
	for _, tc := range []struct {
		name, key                  string
		publicWrite, vmOutputWrite bool
	}{
		{"ordinary", "qual-key", true, true},
		{"truncated_prefix", protected[:len(protected)-1], true, true},
		{"embedded_prefix", "qual-" + protected, true, true},
		{"exact_protected_prefix", protected, false, false},
		{"protocol_child", protected + "qual-probe", false, false},
		{"protocol_binary_child", protected + "\x00", false, false},
		{"exact_vm_prefix", vmPrefix, false, false},
		{"vm_child", vmPrefix + "qual-probe", false, true},
		{"vm_binary_child", vmPrefix + "\x00", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := []byte(tc.key)
			require.Equal(t, tc.publicWrite, vmcommon.IsAllowedToSaveUnderKey(key))
			require.Equal(t, tc.vmOutputWrite, process.IsAllowedToSaveUnderKey(key))
			fn, err := native.NewSaveKeyValueStorageFunc(vmcommon.BaseOperationCost{PersistPerByte: 1, StorePerByte: 1}, 1, &mock.EnableEpochsHandlerStub{})
			require.NoError(t, err)
			address := []byte("qual-owner-address")
			account := mock.NewUserAccount(address)
			input := &vmcommon.ContractCallInput{RecipientAddr: address, VMInput: vmcommon.VMInput{
				CallerAddr: address, CallValue: big.NewInt(0), GasProvided: 1000, Arguments: [][]byte{key, []byte("value")},
			}}
			output, err := fn.ProcessBuiltinFunction(account, account, input)
			if tc.publicWrite {
				require.NoError(t, err)
				require.NotNil(t, output)
				require.Equal(t, []byte("value"), account.Storage[tc.key])
			} else {
				require.ErrorIs(t, err, native.ErrOperationNotPermitted)
				require.Nil(t, output)
				require.Empty(t, account.Storage)
			}
		})
	}
}

// A direct built-in call is below the node journal boundary. Earlier ordinary
// writes can exist when a later reserved key rejects. This is evidence of the
// caller's rollback obligation, not a committed-state exploit or P20 closure.
func TestQualDRWASaveKeyValuePartialBatchRequiresCallerRollback(t *testing.T) {
	for _, protectedFirst := range []bool{true, false} {
		name := "protected_last"
		if protectedFirst {
			name = "protected_first"
		}
		t.Run(name, func(t *testing.T) {
			fn, err := native.NewSaveKeyValueStorageFunc(vmcommon.BaseOperationCost{PersistPerByte: 1, StorePerByte: 1}, 1, &mock.EnableEpochsHandlerStub{})
			require.NoError(t, err)
			address := []byte("qual-owner-address")
			account := mock.NewUserAccount(address)
			protected := []byte(core.ProtectedKeyPrefix + "qual-probe")
			ordinary := []byte("qual-key")
			args := [][]byte{ordinary, []byte("value"), protected, []byte("forbidden")}
			if protectedFirst {
				args = [][]byte{protected, []byte("forbidden"), ordinary, []byte("value")}
			}
			output, err := fn.ProcessBuiltinFunction(account, account, &vmcommon.ContractCallInput{RecipientAddr: address, VMInput: vmcommon.VMInput{
				CallerAddr: address, CallValue: big.NewInt(0), GasProvided: 1000, Arguments: args,
			}})
			require.ErrorIs(t, err, native.ErrOperationNotPermitted)
			require.Nil(t, output)
			require.NotContains(t, account.Storage, string(protected))
			if protectedFirst {
				require.Empty(t, account.Storage)
			} else {
				require.Equal(t, []byte("value"), account.Storage[string(ordinary)])
			}
		})
	}
}
