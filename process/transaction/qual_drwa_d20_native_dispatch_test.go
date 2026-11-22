package transaction

import (
	"bytes"
	"errors"
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	native "github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/testscommon"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
	"testing"
)

// This fixture always refuses the native source; it never supplies a lease,
// issuer or an accepting authority/default and is not installed by a factory.
type qualD20RefuseMetaSource struct {
	*testscommon.SCProcessorMock
	tx         data.TransactionHandler
	validation any
	refusal    error
	calls      int
}

func (s *qualD20RefuseMetaSource) WithDRWANativeTransaction(tx data.TransactionHandler, validation any, _ func(vm.DRWANativeSCExecutor) (vmcommon.ReturnCode, error)) (vmcommon.ReturnCode, error) {
	s.calls++
	s.tx = tx
	s.validation = validation
	return vmcommon.ExecutionFailed, s.refusal
}
func TestQualD20MetaNativeSourceBeforeAccounts(t *testing.T) {
	for _, name := range []string{"DRWARegisterBootstrapIntent", "DRWARegisterToken"} {
		t.Run(name, func(t *testing.T) {
			sentinel := errors.New("synthetic missing qualified native owner")
			source := &qualD20RefuseMetaSource{SCProcessorMock: &testscommon.SCProcessorMock{}, refusal: sentinel}
			p := &metaTxProcessor{baseTxProcessor: &baseTxProcessor{scProcessor: source}}
			tx := &native.Transaction{SndAddr: bytes.Repeat([]byte{1}, 32), RcvAddr: bytes.Clone(core.ESDTSCAddress), Data: []byte(name + "@00")}
			observation := &NativeValidationReceipt{} // explicitly invalid/unvalidated hostile metadata
			code, err := p.ProcessTransactionWithDRWA(tx, observation)
			require.ErrorIs(t, err, sentinel)
			require.Equal(t, vmcommon.ExecutionFailed, code)
			require.Same(t, tx, source.tx)
			require.Same(t, observation, source.validation)
			require.Equal(t, 1, source.calls)
			// The native accounts/fee/hash dependencies deliberately remain unavailable;
			// reaching them before this source refusal would panic.
		})
	}
}

func TestQualD20MetaMissingNativeSourceDoesNotFallBack(t *testing.T) {
	for _, name := range []string{"DRWARegisterBootstrapIntent", "DRWARegisterToken"} {
		t.Run(name, func(t *testing.T) {
			accountError := errors.New("ordinary account path reached")
			reads := 0
			p := &metaTxProcessor{baseTxProcessor: &baseTxProcessor{
				scProcessor: &testscommon.SCProcessorMock{},
				accounts: &stateMock.AccountsStub{LoadAccountCalled: func([]byte) (vmcommon.AccountHandler, error) {
					reads++
					return nil, accountError
				}},
				shardCoordinator: &testscommon.ShardsCoordinatorMock{
					NoShards: 1, CurrentShard: 0, ComputeIdCalled: func([]byte) uint32 { return 0 },
				},
			}}
			tx := &native.Transaction{SndAddr: bytes.Repeat([]byte{1}, 32),
				RcvAddr: bytes.Clone(core.ESDTSCAddress), Data: []byte(name + "@00")}
			for _, receipt := range []*NativeValidationReceipt{nil, {}} {
				code, err := p.ProcessTransactionWithDRWA(tx, receipt)
				require.ErrorIs(t, err, vm.ErrDRWAExecution)
				require.NotErrorIs(t, err, accountError)
				require.Equal(t, vmcommon.ExecutionFailed, code)
				require.Zero(t, reads)
			}
			// An ordinary transaction reaches the same account path. The
			// sentinel makes a fallback observable without a panic or store.
			tx.Data = []byte("ordinary")
			_, err := p.ProcessTransactionWithDRWA(tx, nil)
			require.ErrorIs(t, err, accountError)
			require.Equal(t, 1, reads)
		})
	}
}

func TestQualD20MetaOrdinaryDispatchPreservation(t *testing.T) {
	for _, kind := range []string{"nil", "ordinary-name", "foreign-recipient"} {
		run := func(withMetadata bool) (vmcommon.ReturnCode, error, int) {
			reads := 0
			sentinel := errors.New("native account read unavailable")
			source := &qualD20RefuseMetaSource{SCProcessorMock: &testscommon.SCProcessorMock{}, refusal: vm.ErrDRWAExecution}
			p := &metaTxProcessor{baseTxProcessor: &baseTxProcessor{scProcessor: source, accounts: &stateMock.AccountsStub{LoadAccountCalled: func([]byte) (vmcommon.AccountHandler, error) { reads++; return nil, sentinel }}, shardCoordinator: &testscommon.ShardsCoordinatorMock{NoShards: 1, CurrentShard: 0, ComputeIdCalled: func([]byte) uint32 { return 0 }}}}
			tx := &native.Transaction{SndAddr: bytes.Repeat([]byte{1}, 32), RcvAddr: bytes.Clone(core.ESDTSCAddress), Data: []byte("ordinary")}
			if kind == "nil" {
				tx = nil
			}
			if kind == "foreign-recipient" {
				tx.RcvAddr = bytes.Repeat([]byte{2}, 32)
				tx.Data = []byte("DRWARegisterToken@00")
			}
			var code vmcommon.ReturnCode
			var err error
			if withMetadata {
				code, err = p.ProcessTransactionWithDRWA(tx, nil)
			} else {
				code, err = p.ProcessTransaction(tx)
			}
			require.Zero(t, source.calls)
			return code, err, reads
		}
		t.Run(kind, func(t *testing.T) {
			a, e, n := run(false)
			b, f, m := run(true)
			require.Equal(t, a, b)
			require.Equal(t, e.Error(), f.Error())
			require.Equal(t, n, m)
		})
	}
}
