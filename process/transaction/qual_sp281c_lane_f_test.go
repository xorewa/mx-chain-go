package transaction

import (
	"bytes"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	native "github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/marshallerMock"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"

	"github.com/stretchr/testify/require"
)

func TestQualSP281CLaneFReceiptOwnsCopiedBytes(t *testing.T) {
	var absent *NativeValidationReceipt
	require.Nil(t, absent.OriginalBytes())
	require.Nil(t, absent.InnerBytes())
	require.Nil(t, absent.Hash())
	require.Zero(t, absent.RetainedSize())

	receipt := &NativeValidationReceipt{
		original: []byte("original"),
		inner:    []byte("inner"),
		hash:     []byte("digest"),
		source:   NativeValidationSource{ChainID: "A"},
	}
	for _, field := range []struct {
		read func() []byte
		want string
	}{
		{receipt.OriginalBytes, "original"},
		{receipt.InnerBytes, "inner"},
		{receipt.Hash, "digest"},
	} {
		raw := field.read()
		require.Equal(t, field.want, string(raw))
		raw[0] ^= 1
		require.Equal(t, field.want, string(field.read()))
	}
	empty := &NativeValidationReceipt{}
	require.Equal(t, int64(len("original")+len("inner")+len("digest")+len("A")), receipt.RetainedSize()-empty.RetainedSize())
}

func TestQualSP281CLaneFReceiptDependencyIdentity(t *testing.T) {
	type provider struct{ value int }
	first, other := &provider{1}, &provider{1}
	var absent *provider
	require.True(t, sameNativeValidationDependency(first, first))
	require.False(t, sameNativeValidationDependency(first, other))
	require.False(t, sameNativeValidationDependency(first, absent))
	require.False(t, sameNativeValidationDependency(absent, absent))
	require.False(t, sameNativeValidationDependency(nil, first))
	require.False(t, sameNativeValidationDependency(first, "other type"))
	require.False(t, sameNativeValidationDependency([]int{1}, []int{1}))
}

type qualSP281CLaneFMetaSource struct {
	*testscommon.SCProcessorMock
	executed bool
}

func (s *qualSP281CLaneFMetaSource) WithDRWANativeTransaction(_ data.TransactionHandler, _ any,
	body func(vm.DRWANativeSCExecutor) (vmcommon.ReturnCode, error)) (vmcommon.ReturnCode, error) {
	return body(func(data.TransactionHandler, state.UserAccountHandler, state.UserAccountHandler) (vmcommon.ReturnCode, error) {
		s.executed = true
		return vmcommon.Ok, nil
	})
}

func TestQualSP281CLaneFMetaSourcePreservesNativeAccountReadFailure(t *testing.T) {
	refusal := errors.New("inert account lookup failure")
	reads := 0
	source := &qualSP281CLaneFMetaSource{SCProcessorMock: &testscommon.SCProcessorMock{}}
	processor := &metaTxProcessor{baseTxProcessor: &baseTxProcessor{
		scProcessor: source,
		shardCoordinator: &testscommon.ShardsCoordinatorMock{
			NoShards: 1, ComputeIdCalled: func([]byte) uint32 { return 0 },
		},
		accounts: &stateMock.AccountsStub{LoadAccountCalled: func([]byte) (vmcommon.AccountHandler, error) {
			reads++
			return nil, refusal
		}},
	}}
	tx := &native.Transaction{SndAddr: bytes.Repeat([]byte{1}, 32), RcvAddr: core.ESDTSCAddress, Data: []byte("DRWARegisterToken")}
	_, err := processor.ProcessTransactionWithDRWA(tx, &NativeValidationReceipt{})
	require.ErrorIs(t, err, refusal)
	require.Equal(t, 1, reads)
	require.False(t, source.executed)
}

func TestQualSP281CLaneFMetaSourceRefusesUnhashableTransaction(t *testing.T) {
	refusal := errors.New("inert canonical serialization failure")
	source := &qualSP281CLaneFMetaSource{SCProcessorMock: &testscommon.SCProcessorMock{}}
	tx := &native.Transaction{SndAddr: bytes.Repeat([]byte{1}, 32), RcvAddr: core.ESDTSCAddress, Data: []byte("DRWARegisterToken")}
	processor := &metaTxProcessor{baseTxProcessor: &baseTxProcessor{
		scProcessor: source,
		shardCoordinator: &testscommon.ShardsCoordinatorMock{
			NoShards: 2, ComputeIdCalled: func([]byte) uint32 { return 1 },
		},
		accounts: &stateMock.AccountsStub{
			LoadAccountCalled: func([]byte) (vmcommon.AccountHandler, error) {
				t.Fatal("nonlocal accounts must not be read")
				return nil, nil
			},
		},
		marshalizer: &marshallerMock.MarshalizerStub{MarshalCalled: func(actual interface{}) ([]byte, error) {
			require.Same(t, tx, actual)
			return nil, refusal
		}},
		hasher: blake2b.NewBlake2b(),
	}}
	_, err := processor.ProcessTransactionWithDRWA(tx, &NativeValidationReceipt{})
	require.ErrorIs(t, err, refusal)
	require.False(t, source.executed)
}
