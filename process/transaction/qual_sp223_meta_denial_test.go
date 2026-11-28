package transaction

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	native "github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// SP2-23, audit finding TA-SP2-23-1-1: the branches of the metachain
// transaction processor around an owner that refuses a reserved registration
// request. The owner is a labelled synthetic source; the processor is the
// production one. The composition with the installed owner is
// TestQualSP223ReservedRegistrationRequestIsAPlainDenial in factory/processing.
type qualSP223Source struct {
	*testscommon.SCProcessorMock
	refusal error
	enter   bool
}

func (s *qualSP223Source) WithDRWANativeTransaction(_ data.TransactionHandler, _ any,
	execute func(vm.DRWANativeSCExecutor) (vmcommon.ReturnCode, error)) (vmcommon.ReturnCode, error) {
	if s.enter {
		_, _ = execute(nil)
	}
	return vmcommon.UserError, s.refusal
}

type qualSP223FailingMarshaller struct{ marshal.Marshalizer }

func (qualSP223FailingMarshaller) Marshal(interface{}) ([]byte, error) {
	return nil, errors.New("synthetic encoding failure")
}

func TestQualSP223MetaAnswersARefusedReservedRequest(t *testing.T) {
	refused := fmt.Errorf("%w: synthetic owner refusal", process.ErrTransactionNotExecutable)
	type denial struct {
		sender   state.UserAccountHandler
		hash     []byte
		tx       data.TransactionHandler
		message  string
		snapshot int
		locked   uint64
	}
	for _, tc := range []struct {
		name          string
		refusal       error
		enter         bool
		selfSender    bool
		resultFailure error
		encodeFailure bool
		code          vmcommon.ReturnCode
		failure       error
		denied        bool
	}{
		{name: "request of another shard is answered", refusal: refused, code: vmcommon.UserError, denied: true},
		{name: "sender of this shard keeps the refusal", refusal: refused, selfSender: true, code: vmcommon.UserError, failure: process.ErrTransactionNotExecutable},
		{name: "refusal from inside the operation is kept", refusal: refused, enter: true, code: vmcommon.UserError, failure: process.ErrTransactionNotExecutable},
		{name: "unavailable context stays fatal", refusal: vm.ErrDRWAExecution, code: vmcommon.UserError, failure: vm.ErrDRWAExecution},
		{name: "unrelated error is kept", refusal: process.ErrInsufficientFee, code: vmcommon.UserError, failure: process.ErrInsufficientFee},
		{name: "no error is kept", code: vmcommon.UserError},
		{name: "answer cannot be recorded", refusal: refused, resultFailure: errors.New("synthetic result failure"), denied: true},
		{name: "hash cannot be computed", refusal: refused, encodeFailure: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var answers []denial
			accountError := errors.New("ordinary account path reached")
			source := &qualSP223Source{refusal: tc.refusal, enter: tc.enter, SCProcessorMock: &testscommon.SCProcessorMock{
				ProcessIfErrorCalled: func(sender state.UserAccountHandler, hash []byte, tx data.TransactionHandler, message string, _ []byte, snapshot int, locked uint64) error {
					answers = append(answers, denial{sender, bytes.Clone(hash), tx, message, snapshot, locked})
					return tc.resultFailure
				}}}
			var codec marshal.Marshalizer = &marshal.GogoProtoMarshalizer{}
			if tc.encodeFailure {
				codec = qualSP223FailingMarshaller{codec}
			}
			self := core.MetachainShardId
			p := &metaTxProcessor{baseTxProcessor: &baseTxProcessor{scProcessor: source, marshalizer: codec, hasher: blake2b.NewBlake2b(),
				accounts: &stateMock.AccountsStub{JournalLenCalled: func() int { return 7 },
					LoadAccountCalled: func([]byte) (vmcommon.AccountHandler, error) { return nil, accountError }},
				shardCoordinator: &testscommon.ShardsCoordinatorMock{NoShards: 3, CurrentShard: self, ComputeIdCalled: func(address []byte) uint32 {
					if tc.selfSender || bytes.Equal(address, core.ESDTSCAddress) {
						return self
					}
					return 1
				}}}}
			tx := &native.Transaction{SndAddr: bytes.Repeat([]byte{1}, 32), RcvAddr: bytes.Clone(core.ESDTSCAddress), Data: []byte("DRWARegisterToken@00")}
			code, err := p.ProcessTransactionWithDRWA(tx, nil)
			if !tc.denied {
				require.Empty(t, answers)
			}
			switch {
			case tc.encodeFailure:
				require.ErrorContains(t, err, "synthetic encoding failure")
				require.Zero(t, code)
			case tc.resultFailure != nil:
				require.ErrorIs(t, err, tc.resultFailure)
				require.Zero(t, code)
			case tc.failure != nil:
				require.ErrorIs(t, err, tc.failure)
				require.Equal(t, tc.code, code)
			default:
				require.NoError(t, err)
				require.Equal(t, tc.code, code)
			}
			if !tc.denied {
				return
			}
			require.Len(t, answers, 1)
			encoded, encodeErr := (&marshal.GogoProtoMarshalizer{}).Marshal(tx)
			require.NoError(t, encodeErr)
			require.Nil(t, answers[0].sender, "the sender is an account of another shard")
			require.Equal(t, blake2b.NewBlake2b().Compute(string(encoded)), answers[0].hash)
			require.Same(t, tx, answers[0].tx)
			require.Equal(t, refused.Error(), answers[0].message)
			require.Equal(t, 7, answers[0].snapshot)
			require.Zero(t, answers[0].locked)
		})
	}
}
