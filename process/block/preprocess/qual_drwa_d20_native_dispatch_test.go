package preprocess

import (
	"bytes"
	"errors"
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/dataRetriever"
	"github.com/multiversx/mx-chain-go/process"
	nativeValidation "github.com/multiversx/mx-chain-go/process/transaction"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
	"testing"
)

// Compare the untouched native callsite, not an accepting DRWA source. The
// enhanced fixture always refuses and must be unreachable when unconfigured.
func TestQualD20PreprocessUnconfiguredUsesOriginalConsumer(t *testing.T) {
	for _, name := range []string{"DRWARegisterBootstrapIntent", "DRWARegisterToken"} {
		for _, absent := range []bool{false, true} {
			configuration := "disabled"
			if absent {
				configuration = "absent"
			}
			t.Run(name+"/"+configuration, func(t *testing.T) {
				sentinel := errors.New("synthetic native consumer refusal")
				legacy := &qualD20LegacyProcessor{failure: sentinel}
				enhanced := &qualD20NativeProcessor{qualD20LegacyProcessor: legacy}
				pool := &qualD20ReceiptRoute{enabled: false}
				p := &transactions{txProcessor: enhanced, txPool: pool}
				if absent {
					p.txPool = nil
				}
				tx := &transaction.Transaction{RcvAddr: bytes.Clone(core.ESDTSCAddress), Data: []byte(name + "@00")}
				expectedCode, expectedErr := enhanced.ProcessTransaction(tx)
				legacy.ordinary = 0
				code, err := p.processNativeTransaction([]byte("synthetic-native-key"), tx, 0, 4294967295)
				require.Equal(t, expectedCode, code)
				require.ErrorIs(t, err, expectedErr)
				require.Equal(t, 1, legacy.ordinary)
				require.Zero(t, enhanced.calls)
				require.Zero(t, pool.calls)
			})
		}
	}
}

type qualD20LegacyProcessor struct {
	process.TransactionProcessor
	ordinary int
	failure  error
}

func (p *qualD20LegacyProcessor) ProcessTransaction(*transaction.Transaction) (vmcommon.ReturnCode, error) {
	p.ordinary++
	return vmcommon.UserError, p.failure
}

type qualD20NativeProcessor struct {
	*qualD20LegacyProcessor
	calls   int
	seen    *transaction.Transaction
	receipt *nativeValidation.NativeValidationReceipt
}

func (p *qualD20NativeProcessor) ProcessTransactionWithDRWA(tx *transaction.Transaction, r *nativeValidation.NativeValidationReceipt) (vmcommon.ReturnCode, error) {
	p.calls++
	p.seen = tx
	p.receipt = r
	return vmcommon.ExecutionFailed, p.failure
}

// Hostile/static metadata lookup only; this fixture supplies no authenticated
// receipt or native operation. Actual cryptographic pool transport is covered
// by the retained D19/D20 real-signature consumers, not this routing fixture.
type qualD20ReceiptRoute struct {
	dataRetriever.ShardedDataCacherNotifier
	enabled bool
	calls   int
	hash    []byte
	route   string
	tx      *transaction.Transaction
}

func (p *qualD20ReceiptRoute) NativeValidationReceiptEnabled() bool { return p.enabled }
func (p *qualD20ReceiptRoute) NativeValidationReceiptFor(h []byte, r string, tx *transaction.Transaction) *nativeValidation.NativeValidationReceipt {
	p.calls++
	p.hash = bytes.Clone(h)
	p.route = r
	p.tx = tx
	return nil
}
func TestQualD20PreprocessNativeReceiptRoute(t *testing.T) {
	for _, mode := range []string{"legacy", "disabled", "cross", "same", "missing-route"} {
		t.Run(mode, func(t *testing.T) {
			sentinel := errors.New("synthetic native operation unavailable")
			legacy := &qualD20LegacyProcessor{failure: sentinel}
			native := &qualD20NativeProcessor{qualD20LegacyProcessor: legacy}
			pool := &qualD20ReceiptRoute{enabled: mode != "disabled"}
			p := &transactions{txProcessor: native, txPool: pool}
			if mode == "legacy" {
				p.txProcessor = legacy
			}
			tx := &transaction.Transaction{}
			hash := []byte("synthetic-key")
			ids := []uint32{0, 4294967295}
			if mode == "same" {
				ids = []uint32{2, 2}
			}
			if mode == "missing-route" {
				ids = nil
			}
			_, err := p.processNativeTransaction(hash, tx, ids...)
			if mode == "missing-route" {
				require.ErrorIs(t, err, vm.ErrDRWAExecution)
				require.Zero(t, native.calls)
				require.Zero(t, pool.calls)
				return
			}
			require.ErrorIs(t, err, sentinel)
			if mode == "legacy" || mode == "disabled" {
				require.Equal(t, 1, legacy.ordinary)
				require.Zero(t, native.calls)
				require.Zero(t, pool.calls)
				return
			}
			require.Zero(t, legacy.ordinary)
			require.Equal(t, 1, native.calls)
			require.Same(t, tx, native.seen)
			require.Nil(t, native.receipt)
			require.Equal(t, 1, pool.calls)
			require.Equal(t, hash, pool.hash)
			require.Same(t, tx, pool.tx)
			expected := "0_4294967295"
			if mode == "same" {
				expected = "2"
			}
			require.Equal(t, expected, pool.route)
		})
	}
}
