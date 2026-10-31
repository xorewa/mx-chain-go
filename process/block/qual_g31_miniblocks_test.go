package block_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/common"
	processBlock "github.com/multiversx/mx-chain-go/process/block"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/stretchr/testify/require"
)

type qualG31ShardHeader struct {
	*block.Header
	minis []data.MiniBlockHeaderHandler
}
func (h *qualG31ShardHeader) GetMiniBlockHeaderHandlers() []data.MiniBlockHeaderHandler { return h.minis }

func TestQualG31MetaInterfaceMiniblocks(t *testing.T) {
	for _,scheduled:=range []bool{false,true} {
		t.Run(fmt.Sprint(scheduled),func(t *testing.T){
			coreC,dataC,bootstrapC,statusC:=createMockComponentHolders()
			flags:=coreC.EnableEpochsHandlerField.(*enableEpochsHandlerMock.EnableEpochsHandlerStub)
			flags.IsFlagEnabledCalled=func(flag core.EnableEpochFlag) bool {return scheduled && flag==common.ScheduledMiniBlocksFlag}
			mp,err:=processBlock.NewMetaProcessor(createMockMetaArguments(coreC,dataC,bootstrapC,statusC));require.NoError(t,err)
			final:=&block.MiniBlockHeader{Hash:[]byte("final"),SenderShardID:1,ReceiverShardID:2,TxCount:3,Type:block.TxBlock}
			partial:=&block.MiniBlockHeader{Hash:[]byte("partial"),SenderShardID:2,ReceiverShardID:1,TxCount:4,Type:block.SmartContractResultBlock}
			require.NoError(t,final.SetConstructionState(int32(block.Final)))
			require.NoError(t,partial.SetConstructionState(int32(block.PartialExecuted)))
			header:=&qualG31ShardHeader{Header:&block.Header{AccumulatedFees:big.NewInt(0),DeveloperFees:big.NewInt(0)},minis:[]data.MiniBlockHeaderHandler{final,partial}}
			got:=mp.BuildShardDataFromHeader(header,[]byte("header"))
			want:=[]block.MiniBlockHeader{{Hash:[]byte("final"),SenderShardID:1,ReceiverShardID:2,TxCount:3,Type:block.TxBlock}}
			if !scheduled {want=append(want,block.MiniBlockHeader{Hash:[]byte("partial"),SenderShardID:2,ReceiverShardID:1,TxCount:4,Type:block.SmartContractResultBlock})}
			require.Equal(t,want,got.ShardMiniBlockHeaders)
		})
	}
}
