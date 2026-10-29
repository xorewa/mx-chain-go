package hooks

import (
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	ht "github.com/multiversx/mx-chain-go/process/drwa/headertime"
	epochs "github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/marshallerMock"
	"github.com/stretchr/testify/require"
)

// Internal unit setup isolates the native owner's validation, without claiming
// successful real installation, canonical lineage or factory admission.
func sp1HeaderOperation(t *testing.T) (*BlockChainHookImpl, *evaluatedHeaderOperation, *ht.HeaderTimeContext) {
	t.Helper()
	flags := epochs.NewEnableEpochsHandlerStub()
	flags.IsFlagEnabledInEpochCalled = func(flag core.EnableEpochFlag, epoch uint32) bool { return flag == common.SupernovaFlag && epoch >= 10 }
	bh := &BlockChainHookImpl{enableEpochsHandler: flags, marshalizer: &marshal.GogoProtoMarshalizer{}, currentHdr: &block.HeaderV3{Epoch: 10, ShardID: 1, TimestampMs: 1234567}}
	require.NoError(t, bh.initializeEvaluatedHeaderTime(blake2b.NewBlake2b()))
	bh.drwaTime.enabled = func() bool { return true }
	_, end, err := bh.BeginDRWAHeaderEvaluation()
	require.NoError(t, err)
	t.Cleanup(end)
	op := bh.drwaTime.active.Load()
	var context *ht.HeaderTimeContext
	context, err = bh.drwaTime.clock.BeginBound(bh.currentHdr, func() (func(), error) { return op.acquire(context) }, func() error { return op.validateLocked(context) })
	require.NoError(t, err)
	op.context = context
	op.identity, _ = context.HeaderIdentity()
	op.milliseconds = 1234567
	require.NoError(t, op.validateLocked(context))
	return bh, op, context
}
func TestSP1CoverageHookHeaderValidation(t *testing.T) {
	for _, mode := range []string{"disabled", "time error", "nil header", "nil marshaller", "nil hasher", "nil flags", "legacy header", "lost activation", "marshal error", "changed timestamp"} {
		t.Run(mode, func(t *testing.T) {
			bh, op, context := sp1HeaderOperation(t)
			sentinel := errors.New("native time/hash dependency unavailable")
			switch mode {
			case "disabled":
				bh.drwaTime.enabled = func() bool { return false }
			case "time error":
				op.timeError = sentinel
			case "nil header":
				bh.currentHdr = nil
			case "nil marshaller":
				bh.marshalizer = nil
			case "nil hasher":
				bh.drwaTime.hasher = nil
			case "nil flags":
				bh.enableEpochsHandler = nil
			case "legacy header":
				bh.currentHdr = &block.Header{Epoch: 10, TimeStamp: 1234}
			case "lost activation":
				bh.enableEpochsHandler.(*epochs.EnableEpochsHandlerStub).IsFlagEnabledInEpochCalled = func(core.EnableEpochFlag, uint32) bool { return false }
			case "marshal error":
				bh.marshalizer = &marshallerMock.MarshalizerStub{MarshalCalled: func(interface{}) ([]byte, error) { return nil, sentinel }}
			case "changed timestamp":
				bh.currentHdr = &block.HeaderV3{Epoch: 10, ShardID: 1, TimestampMs: 1234568}
			}
			err := op.validateLocked(context)
			require.Error(t, err)
			current, err := bh.EvaluatedHeaderTimeContext()
			require.Error(t, err)
			require.Nil(t, current)
			if mode == "time error" || mode == "marshal error" {
				require.ErrorIs(t, err, sentinel)
			}
		})
	}
}
func TestSP1CoverageHookEvaluationAdmission(t *testing.T) {
	var absent *BlockChainHookImpl
	install, end, err := absent.BeginDRWAHeaderEvaluation()
	require.ErrorIs(t, err, ht.ErrUnavailableHeaderTime)
	require.Nil(t, install)
	require.Nil(t, end)
	ordinary := &BlockChainHookImpl{}
	install, end, err = ordinary.BeginDRWAHeaderEvaluation()
	require.NoError(t, err)
	require.NotNil(t, install)
	end()
	require.NoError(t, ordinary.initializeEvaluatedHeaderTime(nil))
	require.Nil(t, ordinary.drwaTime)
	require.Error(t, ordinary.initializeEvaluatedHeaderTime(blake2b.NewBlake2b()))
	require.Nil(t, ordinary.drwaTime)
	bh, op, _ := sp1HeaderOperation(t)
	_, _, err = bh.BeginDRWAHeaderEvaluation()
	require.ErrorIs(t, err, ht.ErrInactiveHeaderTime)
	op.end()
	bh.drwaTime.closed.Store(true)
	_, _, err = bh.BeginDRWAHeaderEvaluation()
	require.ErrorIs(t, err, ht.ErrInactiveHeaderTime)
	bh.drwaTime.closed.Store(false)
	bh.drwaTime.enabled = func() bool { return false }
	install, end, err = bh.BeginDRWAHeaderEvaluation()
	require.NoError(t, err)
	require.NotNil(t, install)
	end()
}
func TestSP1CoverageHookOutstandingLease(t *testing.T) {
	bh, op, context := sp1HeaderOperation(t)
	_, _, release, err := context.Lease()
	require.NoError(t, err)
	defer release()
	op.end()
	_, _, err = bh.BeginDRWAHeaderEvaluation()
	require.ErrorIs(t, err, ht.ErrInactiveHeaderTime)
}
