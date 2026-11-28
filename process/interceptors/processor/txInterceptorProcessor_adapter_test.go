package processor_test

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-go/p2p"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/interceptors/processor"
	"github.com/multiversx/mx-chain-go/process/mock"
	nativeValidation "github.com/multiversx/mx-chain-go/process/transaction"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/stretchr/testify/require"
)

// These test doubles model interface dispatch only. They do not construct a
// native validation receipt or store or validate any transaction.
type saveAdapterTransaction struct {
	data.TransactionHandler
}

func (*saveAdapterTransaction) Size() int { return 17 }

type saveAdapterProducer struct {
	testscommon.InterceptedDataStub
	mock.InterceptedTxHandlerStub
	required     bool
	receiptCalls int
}

func (p *saveAdapterProducer) RequiresDRWANativeValidationReceipt() bool { return p.required }

func (p *saveAdapterProducer) NativeValidationReceipt() *nativeValidation.NativeValidationReceipt {
	p.receiptCalls++
	return nil // No receipt object is needed for this isolated dispatch test.
}

type saveAdapterPool struct {
	*testscommon.ShardedDataStub
	enabled   bool
	addNative func([]byte, interface{}, int, string, *nativeValidation.NativeValidationReceipt)
}

func (p *saveAdapterPool) NativeValidationReceiptEnabled() bool { return p.enabled }

func (p *saveAdapterPool) AddDataWithNativeValidationReceipt(key []byte, value interface{}, size int, id string, receipt *nativeValidation.NativeValidationReceipt) {
	p.addNative(key, value, size, id, receipt)
}

func TestTxInterceptorProcessor_SaveAdapterDispatch(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name          string
		enabled       bool
		required      bool
		wantNativeAdd int
		wantPlainAdd  int
	}{
		{name: "configured interface", enabled: true, required: true, wantNativeAdd: 1},
		{name: "disabled interface", enabled: false, required: true, wantPlainAdd: 1},
		{name: "ordinary interface", enabled: true, required: false, wantPlainAdd: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := &saveAdapterTransaction{}
			hash := []byte("adapter-test-key")
			producer := &saveAdapterProducer{
				InterceptedDataStub: testscommon.InterceptedDataStub{
					HashCalled: func() []byte { return hash },
				},
				InterceptedTxHandlerStub: mock.InterceptedTxHandlerStub{
					SenderShardIdCalled:   func() uint32 { return 0 },
					ReceiverShardIdCalled: func() uint32 { return 0 },
					TransactionCalled:     func() data.TransactionHandler { return tx },
				},
				required: tc.required,
			}

			checkArgs := func(key []byte, value interface{}, size int, id string) {
				t.Helper()
				require.Equal(t, hash, key)
				require.Same(t, tx, value)
				require.Equal(t, 17, size)
				require.Equal(t, "0", id)
			}
			plainAdds, nativeAdds, whitelistCalls := 0, 0, 0
			pool := &saveAdapterPool{
				ShardedDataStub: &testscommon.ShardedDataStub{
					AddDataCalled: func(key []byte, value interface{}, size int, id string) {
						plainAdds++
						checkArgs(key, value, size, id)
					},
				},
				enabled: tc.enabled,
				addNative: func(key []byte, value interface{}, size int, id string, receipt *nativeValidation.NativeValidationReceipt) {
					nativeAdds++
					checkArgs(key, value, size, id)
					require.Nil(t, receipt)
				},
			}
			arg := createMockTxArgument()
			arg.ShardedDataCache = pool
			arg.TxValidator = &mock.TxValidatorStub{
				CheckTxWhiteListCalled: func(got process.InterceptedData) error {
					whitelistCalls++
					require.Same(t, producer, got)
					return nil
				},
			}
			txip, err := processor.NewTxInterceptorProcessor(arg)
			require.NoError(t, err)

			saved, err := txip.Save(producer, "", "", p2p.Broadcast)
			require.NoError(t, err)
			require.True(t, saved)
			require.Equal(t, 1, whitelistCalls)
			require.Equal(t, tc.wantPlainAdd, plainAdds)
			require.Equal(t, tc.wantNativeAdd, nativeAdds)
			require.Equal(t, tc.wantNativeAdd, producer.receiptCalls)
		})
	}
}
