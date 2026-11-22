package counters

import (
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/assert"
)

func generateMapsOfValues(value uint64) map[string]uint64 {
	return map[string]uint64{
		maxTrieReads:    value,
		maxTransfers:    value,
		maxBuiltinCalls: value,
	}
}

func TestNewUsageCounter(t *testing.T) {
	t.Parallel()

	t.Run("nil esdt transfer parser should error", func(t *testing.T) {
		t.Parallel()

		counter, err := NewUsageCounter(nil, enableEpochsHandlerMock.NewEnableEpochsHandlerStub())
		assert.True(t, check.IfNil(counter))
		assert.Equal(t, process.ErrNilESDTTransferParser, err)
	})
	t.Run("nil enable epochs handler should error", func(t *testing.T) {
		t.Parallel()

		counter, err := NewUsageCounter(&testscommon.ESDTTransferParserStub{}, nil)
		assert.True(t, check.IfNil(counter))
		assert.Equal(t, process.ErrNilEnableEpochsHandler, err)
	})
	t.Run("valid parameters should work", func(t *testing.T) {
		t.Parallel()

		counter, err := NewUsageCounter(&testscommon.ESDTTransferParserStub{}, enableEpochsHandlerMock.NewEnableEpochsHandlerStub())
		assert.False(t, check.IfNil(counter))
		assert.Nil(t, err)
	})
}

func TestUsageCounter_ProcessCrtNumberOfTrieReadsCounter(t *testing.T) {
	t.Parallel()

	counter, _ := NewUsageCounter(&testscommon.ESDTTransferParserStub{}, enableEpochsHandlerMock.NewEnableEpochsHandlerStub())
	counter.SetMaximumValues(generateMapsOfValues(3))

	assert.Nil(t, counter.ProcessCrtNumberOfTrieReadsCounter())                                 // counter is now 1
	assert.Nil(t, counter.ProcessCrtNumberOfTrieReadsCounter())                                 // counter is now 2
	assert.Nil(t, counter.ProcessCrtNumberOfTrieReadsCounter())                                 // counter is now 3
	assert.ErrorIs(t, counter.ProcessCrtNumberOfTrieReadsCounter(), process.ErrMaxCallsReached) // counter is now 4, error signalled
	err := counter.ProcessCrtNumberOfTrieReadsCounter()                                         // counter is now 5, error signalled
	assert.ErrorIs(t, err, process.ErrMaxCallsReached)
	t.Run("backwards compatibility on error message string", func(t *testing.T) {
		assert.Equal(t, "max calls reached: too many reads from trie", err.Error())
	})

	countersMap := counter.GetCounterValues()
	expectedMap := map[string]uint64{
		crtBuiltinCalls: 0,
		crtTransfers:    0,
		crtTrieReads:    5,
	}
	assert.Equal(t, expectedMap, countersMap)

	counter.ResetCounters()

	assert.Nil(t, counter.ProcessCrtNumberOfTrieReadsCounter()) // counter is now 1
	countersMap = counter.GetCounterValues()
	expectedMap = map[string]uint64{
		crtBuiltinCalls: 0,
		crtTransfers:    0,
		crtTrieReads:    1,
	}
	assert.Equal(t, expectedMap, countersMap)
}

func TestUsageCounter_ProcessMaxBuiltInCounters(t *testing.T) {
	t.Parallel()

	t.Run("builtin functions exceeded", func(t *testing.T) {
		t.Parallel()

		counter, _ := NewUsageCounter(&testscommon.ESDTTransferParserStub{}, enableEpochsHandlerMock.NewEnableEpochsHandlerStub())
		counter.SetMaximumValues(generateMapsOfValues(3))

		vmInput := &vmcommon.ContractCallInput{}

		assert.Nil(t, counter.ProcessMaxBuiltInCounters(vmInput))                                 // counter is now 1
		assert.Nil(t, counter.ProcessMaxBuiltInCounters(vmInput))                                 // counter is now 2
		assert.Nil(t, counter.ProcessMaxBuiltInCounters(vmInput))                                 // counter is now 3
		assert.ErrorIs(t, counter.ProcessMaxBuiltInCounters(vmInput), process.ErrMaxCallsReached) // counter is now 4, error signalled
		err := counter.ProcessMaxBuiltInCounters(vmInput)                                         // counter is now 5, error signalled
		assert.ErrorIs(t, err, process.ErrMaxCallsReached)
		t.Run("backwards compatibility on error message string", func(t *testing.T) {
			assert.Equal(t, "max calls reached: too many built-in functions calls", err.Error())
		})

		countersMap := counter.GetCounterValues()
		expectedMap := map[string]uint64{
			crtBuiltinCalls: 5,
			crtTransfers:    0,
			crtTrieReads:    0,
		}
		assert.Equal(t, expectedMap, countersMap)

		counter.ResetCounters()

		assert.Nil(t, counter.ProcessMaxBuiltInCounters(vmInput)) // counter is now 1
		countersMap = counter.GetCounterValues()
		expectedMap = map[string]uint64{
			crtBuiltinCalls: 1,
			crtTransfers:    0,
			crtTrieReads:    0,
		}
		assert.Equal(t, expectedMap, countersMap)
	})
	t.Run("number of transfers exceeded", func(t *testing.T) {
		t.Parallel()

		counter, _ := NewUsageCounter(
			&testscommon.ESDTTransferParserStub{
				ParseESDTTransfersCalled: func(sndAddr []byte, rcvAddr []byte, function string, args [][]byte) (*vmcommon.ParsedESDTTransfers, error) {
					return &vmcommon.ParsedESDTTransfers{
						ESDTTransfers: make([]*vmcommon.ESDTTransfer, 2),
					}, nil
				},
			},
			enableEpochsHandlerMock.NewEnableEpochsHandlerStub(),
		)
		values := generateMapsOfValues(6)
		values[maxBuiltinCalls] = 1000
		counter.SetMaximumValues(values)

		vmInput := &vmcommon.ContractCallInput{}

		assert.Nil(t, counter.ProcessMaxBuiltInCounters(vmInput))                                 // counter is now 2
		assert.Nil(t, counter.ProcessMaxBuiltInCounters(vmInput))                                 // counter is now 4
		assert.Nil(t, counter.ProcessMaxBuiltInCounters(vmInput))                                 // counter is now 6
		assert.ErrorIs(t, counter.ProcessMaxBuiltInCounters(vmInput), process.ErrMaxCallsReached) // counter is now 8, error signalled
		err := counter.ProcessMaxBuiltInCounters(vmInput)                                         // counter is now 10, error signalled
		assert.ErrorIs(t, err, process.ErrMaxCallsReached)
		t.Run("backwards compatibility on error message string", func(t *testing.T) {
			assert.Equal(t, "max calls reached: too many ESDT transfers", err.Error())
		})

		countersMap := counter.GetCounterValues()
		expectedMap := map[string]uint64{
			crtBuiltinCalls: 5,
			crtTransfers:    10,
			crtTrieReads:    0,
		}
		assert.Equal(t, expectedMap, countersMap)

		counter.ResetCounters()

		assert.Nil(t, counter.ProcessMaxBuiltInCounters(vmInput)) // counter is now 2
		countersMap = counter.GetCounterValues()
		expectedMap = map[string]uint64{
			crtBuiltinCalls: 1,
			crtTransfers:    2,
			crtTrieReads:    0,
		}
		assert.Equal(t, expectedMap, countersMap)
	})
	t.Run("parser error on transfer function propagates error when flag enabled", func(t *testing.T) {
		t.Parallel()

		expectedErr := errors.New("malformed transfer arguments")
		counter, _ := NewUsageCounter(
			&testscommon.ESDTTransferParserStub{
				ParseESDTTransfersCalled: func(sndAddr []byte, rcvAddr []byte, function string, args [][]byte) (*vmcommon.ParsedESDTTransfers, error) {
					return nil, expectedErr
				},
			},
			enableEpochsHandlerMock.NewEnableEpochsHandlerStub(common.FixCorrectSmallIntAndGasLimitsFlag),
		)
		values := generateMapsOfValues(10)
		counter.SetMaximumValues(values)

		vmInput := &vmcommon.ContractCallInput{
			Function: core.BuiltInFunctionMultiESDTNFTTransfer,
		}

		err := counter.ProcessMaxBuiltInCounters(vmInput)
		assert.Equal(t, expectedErr, err)

		vmInputSingle := &vmcommon.ContractCallInput{
			Function: core.BuiltInFunctionESDTTransfer,
		}
		err = counter.ProcessMaxBuiltInCounters(vmInputSingle)
		assert.Equal(t, expectedErr, err)

		vmInputNFT := &vmcommon.ContractCallInput{
			Function: core.BuiltInFunctionESDTNFTTransfer,
		}
		err = counter.ProcessMaxBuiltInCounters(vmInputNFT)
		assert.Equal(t, expectedErr, err)
	})
	t.Run("parser error on transfer function is ignored when flag disabled", func(t *testing.T) {
		t.Parallel()

		counter, _ := NewUsageCounter(
			&testscommon.ESDTTransferParserStub{
				ParseESDTTransfersCalled: func(sndAddr []byte, rcvAddr []byte, function string, args [][]byte) (*vmcommon.ParsedESDTTransfers, error) {
					return nil, errors.New("malformed transfer arguments")
				},
			},
			enableEpochsHandlerMock.NewEnableEpochsHandlerStub(),
		)
		values := generateMapsOfValues(10)
		counter.SetMaximumValues(values)

		vmInput := &vmcommon.ContractCallInput{
			Function: core.BuiltInFunctionMultiESDTNFTTransfer,
		}

		err := counter.ProcessMaxBuiltInCounters(vmInput)
		assert.Nil(t, err)

		vmInputSingle := &vmcommon.ContractCallInput{
			Function: core.BuiltInFunctionESDTTransfer,
		}
		err = counter.ProcessMaxBuiltInCounters(vmInputSingle)
		assert.Nil(t, err)

		vmInputNFT := &vmcommon.ContractCallInput{
			Function: core.BuiltInFunctionESDTNFTTransfer,
		}
		err = counter.ProcessMaxBuiltInCounters(vmInputNFT)
		assert.Nil(t, err)
	})
	t.Run("parser error on non-transfer function is ignored", func(t *testing.T) {
		t.Parallel()

		counter, _ := NewUsageCounter(
			&testscommon.ESDTTransferParserStub{
				ParseESDTTransfersCalled: func(sndAddr []byte, rcvAddr []byte, function string, args [][]byte) (*vmcommon.ParsedESDTTransfers, error) {
					return nil, errors.New("not an ESDT transfer")
				},
			},
			enableEpochsHandlerMock.NewEnableEpochsHandlerStub(),
		)
		values := generateMapsOfValues(10)
		counter.SetMaximumValues(values)

		vmInput := &vmcommon.ContractCallInput{
			Function: "someCustomFunction",
		}

		err := counter.ProcessMaxBuiltInCounters(vmInput)
		assert.Nil(t, err)
	})
}

func TestUsageCounterSharedPreparedVectorDoesNotReparse(t *testing.T) {
	parserCalls := 0
	counter, err := NewUsageCounter(&testscommon.ESDTTransferParserStub{ParseESDTTransfersCalled: func([]byte, []byte, string, [][]byte) (*vmcommon.ParsedESDTTransfers, error) {
		parserCalls++
		return nil, errors.New("raw parser must not run")
	}}, enableEpochsHandlerMock.NewEnableEpochsHandlerStub())
	assert.NoError(t, err)
	// EXPERIMENTAL native counter limits, not production defaults.
	limits := generateMapsOfValues(6)
	limits[maxBuiltinCalls] = 3
	counter.SetMaximumValues(limits)
	input := &vmcommon.ContractCallInput{Function: core.BuiltInFunctionMultiESDTNFTTransfer}
	prepared := &vmcommon.ParsedESDTTransfers{ESDTTransfers: []*vmcommon.ESDTTransfer{{ESDTTokenName: []byte("TOKEN-abcdef")}, {ESDTTokenName: []byte(vmcommon.EGLDIdentifier)}}}
	for i := 0; i < 3; i++ {
		assert.NoError(t, counter.ProcessMaxBuiltInCountersWithESDTTransfers(input, prepared))
	}
	assert.Equal(t, uint64(3), counter.GetCounterValues()[crtBuiltinCalls])
	assert.Equal(t, uint64(6), counter.GetCounterValues()[crtTransfers])
	assert.Zero(t, parserCalls)
	assert.ErrorIs(t, counter.ProcessMaxBuiltInCountersWithESDTTransfers(input, prepared), process.ErrMaxCallsReached)
	assert.Equal(t, uint64(4), counter.GetCounterValues()[crtBuiltinCalls])
	assert.Equal(t, uint64(6), counter.GetCounterValues()[crtTransfers])
	assert.Zero(t, parserCalls)
	counter.ResetCounters()
	assert.Zero(t, counter.GetCounterValues()[crtBuiltinCalls])
	assert.Zero(t, counter.GetCounterValues()[crtTransfers])
}

func TestUsageCounterSharedPreparedRejectsMissingResult(t *testing.T) {
	counter, err := NewUsageCounter(&testscommon.ESDTTransferParserStub{}, enableEpochsHandlerMock.NewEnableEpochsHandlerStub())
	assert.NoError(t, err)
	counter.SetMaximumValues(generateMapsOfValues(3))
	input := &vmcommon.ContractCallInput{Function: core.BuiltInFunctionESDTTransfer}
	one := &vmcommon.ParsedESDTTransfers{ESDTTransfers: []*vmcommon.ESDTTransfer{{}}}
	assert.Error(t, counter.ProcessMaxBuiltInCountersWithESDTTransfers(nil, one))
	assert.Error(t, counter.ProcessMaxBuiltInCountersWithESDTTransfers(input, nil))
	assert.Error(t, counter.ProcessMaxBuiltInCountersWithESDTTransfers(input, &vmcommon.ParsedESDTTransfers{}))
	assert.Error(t, counter.ProcessMaxBuiltInCountersWithESDTTransfers(&vmcommon.ContractCallInput{Function: "ordinaryCustomFunction"}, one))
	assert.Zero(t, counter.GetCounterValues()[crtBuiltinCalls])
	assert.Zero(t, counter.GetCounterValues()[crtTransfers])
}

func TestUsageCounterSharedPreparedPreservesLimitErrorsAndRejectsWrap(t *testing.T) {
	counter, err := NewUsageCounter(&testscommon.ESDTTransferParserStub{}, enableEpochsHandlerMock.NewEnableEpochsHandlerStub())
	assert.NoError(t, err)
	limits := generateMapsOfValues(3)
	limits[maxTransfers] = 1
	counter.SetMaximumValues(limits)
	input := &vmcommon.ContractCallInput{Function: core.BuiltInFunctionMultiESDTNFTTransfer}
	two := &vmcommon.ParsedESDTTransfers{ESDTTransfers: []*vmcommon.ESDTTransfer{{}, {}}}
	err = counter.ProcessMaxBuiltInCountersWithESDTTransfers(input, two)
	assert.ErrorIs(t, err, process.ErrMaxCallsReached)
	if err != nil {
		assert.Equal(t, "max calls reached: too many ESDT transfers", err.Error())
	}
	assert.Equal(t, uint64(2), counter.GetCounterValues()[crtTransfers])
	counter.ResetCounters()
	counter.SetMaximumValues(generateMapsOfValues(^uint64(0)))
	counter.crtNumberOfTransfers = ^uint64(0)
	assert.ErrorIs(t, counter.ProcessMaxBuiltInCountersWithESDTTransfers(input, two), process.ErrMaxCallsReached)
	assert.Equal(t, ^uint64(0), counter.GetCounterValues()[crtTransfers])
	counter.crtNumberOfBuiltInFunctionCalls = ^uint64(0)
	assert.ErrorIs(t, counter.ProcessMaxBuiltInCountersWithESDTTransfers(input, two), process.ErrMaxCallsReached)
	assert.Equal(t, ^uint64(0), counter.GetCounterValues()[crtBuiltinCalls])
}
