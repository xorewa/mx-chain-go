package smartContract

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	stateMocks "github.com/multiversx/mx-chain-go/testscommon/state"
)

// SP2-24 open point D-2, evidence only. The upstream query service installs a
// header in its hook only when it has a root hash for the queried block. On a
// node whose chain has no committed block yet it has none, and the query still
// runs: the hook then holds whatever header it held before, initially the
// empty one. With a committed block the header is installed before the VM runs.
func TestQualSP224QueryInstallsAHeaderOnlyWithACommittedBlock(t *testing.T) {
	for _, committed := range []bool{false, true} {
		name := map[bool]string{false: "no_committed_block", true: "committed_block"}[committed]
		t.Run(name, func(t *testing.T) {
			var installed, epochStart, ran int
			var order []string
			args := createMockArgumentsForSCQuery()
			args.BlockChainHook = &testscommon.BlockChainHookStub{
				GetAccountsAdapterCalled: func() state.AccountsAdapter {
					return &stateMocks.AccountsStub{RecreateTrieCalled: func(common.RootHashHolder) error { return nil }}
				},
				SetCurrentHeaderCalled: func(data.HeaderHandler) error {
					installed++
					order = append(order, "header")
					return nil
				},
				SetEpochStartHeaderCalled: func(data.HeaderHandler) error { epochStart++; return nil },
			}
			chain := &testscommon.ChainHandlerStub{}
			if committed {
				header := &block.Header{Epoch: 0, Round: 7, Nonce: 7}
				chain.GetCurrentBlockHeaderCalled = func() data.HeaderHandler { return header }
				chain.GetCurrentBlockRootHashCalled = func() []byte { return []byte("committed root hash") }
				chain.GetCurrentBlockHeaderHashCalled = func() []byte { return []byte("committed header hash") }
				chain.GetGenesisHeaderCalled = func() data.HeaderHandler { return &block.Header{} }
			}
			args.MainBlockChain = chain
			args.VmContainer = &mock.VMContainerMock{GetCalled: func([]byte) (vmcommon.VMExecutionHandler, error) {
				return &mock.VMExecutionHandlerStub{RunSmartContractCallCalled: func(*vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
					ran++
					order = append(order, "vm")
					return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
				}}, nil
			}}
			service, err := NewSCQueryService(args)
			require.NoError(t, err)
			output, _, err := service.ExecuteQuery(&process.SCQuery{ScAddress: []byte(DummyScAddress), FuncName: "function"})
			require.NoError(t, err)
			require.Equal(t, vmcommon.Ok, output.ReturnCode)
			require.Equal(t, 1, ran)
			if committed {
				require.Equal(t, 1, installed)
				require.Equal(t, 1, epochStart)
				require.Equal(t, []string{"header", "vm"}, order)
				return
			}
			require.Zero(t, installed, "the query ran in a hook in which this service installed no header")
			require.Zero(t, epochStart)
			require.Equal(t, []string{"vm"}, order)
		})
	}
}
