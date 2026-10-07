package drwa

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/process"
	nativeBlock "github.com/multiversx/mx-chain-go/process/block"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/processMocks"
	"github.com/stretchr/testify/require"
)

// Ledger L28/L33; Part A L4886-4888. This exercises the native result
// verifier and destination-miniblock map before the DRWA anchor selector.
// It proves neither header signatures nor registration/T19 atomicity.
func TestQualDRWAMetaFanoutAnchor(t *testing.T) {
	for _, name := range []string{"fanout_and_root", "stale_last_root", "unexecuted_fanout", "retained_result"} {
		t.Run(name, func(t *testing.T) {
			f := qualNativeMetaContext(t)
			previous, current := f.references[0], f.references[1]
			fanout := block.MiniBlockHeader{Hash: []byte("registration-fanout"),
				SenderShardID: core.MetachainShardId, ReceiverShardID: f.candidate.ShardID}
			current.ExecutionResults[0].MiniBlockHeaders = []block.MiniBlockHeader{fanout}
			// Freeze the independent native executed-result input before corrupting
			// the candidate. A shared result pointer would hide the mismatch.
			raw, err := f.c.marshaller.Marshal(current.ExecutionResults[0])
			require.NoError(t, err)
			executed := &block.MetaExecutionResult{}
			require.NoError(t, f.c.marshaller.Unmarshal(executed, raw))
			pending := []data.BaseExecutionResultHandler{executed}
			switch name {
			case "stale_last_root":
				current.LastExecutionResult = previous.LastExecutionResult
			case "unexecuted_fanout":
				executed.MiniBlockHeaders = nil
			case "retained_result":
				current.ExecutionResults = nil
				current.LastExecutionResult = previous.LastExecutionResult
				pending = nil
			}
			// Full callback sweep: constructor -> both IsInterfaceNil methods;
			// Verify -> current header/hash, then pending results. Genesis is
			// unreachable with these nonempty current inputs, and bound explicitly.
			chain := &testscommon.ChainHandlerStub{
				GetCurrentBlockHeaderCalled:     func() data.HeaderHandler { return previous },
				GetCurrentBlockHeaderHashCalled: func() []byte { return []byte("previous-meta") },
				GetGenesisHeaderCalled:          func() data.HeaderHandler { return f.predecessor },
				GetGenesisHeaderHashCalled:      func() []byte { return f.predecessorHash },
			}
			manager := &processMocks.ExecutionManagerMock{
				GetPendingExecutionResultsCalled: func() ([]data.BaseExecutionResultHandler, error) { return pending, nil },
			}
			verifier, err := nativeBlock.NewExecutionResultsVerifier(chain, manager)
			require.NoError(t, err)
			err = verifier.VerifyHeaderExecutionResults(current)
			if name == "stale_last_root" || name == "unexecuted_fanout" {
				require.ErrorIs(t, err, process.ErrExecutionResultDoesNotMatch)
				return
			}
			require.NoError(t, err)
			f.encode(t)
			anchor, err := f.read()
			require.NoError(t, err)
			if name == "retained_result" {
				require.Empty(t, current.GetMiniBlockHeadersWithDst(f.candidate.ShardID))
				require.Equal(t, []byte("first-root"), anchor.root)
			} else {
				require.Equal(t, core.MetachainShardId, current.GetMiniBlockHeadersWithDst(f.candidate.ShardID)[string(fanout.Hash)])
				require.Contains(t, current.GetMiniBlockHeadersWithDst(f.candidate.ShardID), string(fanout.Hash))
				require.Equal(t, []byte("latest-root"), anchor.root)
				require.Equal(t, executed.GetHeaderHash(), anchor.executedHash)
			}
		})
	}
}
