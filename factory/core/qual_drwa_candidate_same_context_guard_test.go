package core

import (
	"fmt"
	"math/big"
	"testing"

	nativeFactory "github.com/multiversx/mx-chain-go/process/factory"
	"github.com/multiversx/mx-chain-go/process/factory/shard"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-go/vmhost"
	"github.com/stretchr/testify/require"
)

// T09-M14 exercises the actual native host's pre-effect guard. The matching
// crawler input is deliberately synthetic; it is not authenticated execution.
func TestQualDRWACandidateSameContextCrawlerGuard(t *testing.T) {
	for _, shardID := range []uint32{0, 1, 2} {
		for _, crawlerID := range []int{0, 1, 2} {
			for _, epoch := range []uint32{1, 3} {
				for _, function := range []string{vmcommon.ESDTAddMetadata, vmcommon.ESDTDeleteMetadata} {
					t.Run(fmt.Sprintf("shard_%d_crawler_%d_epoch_%d_%s", shardID, crawlerID, epoch, function), func(t *testing.T) {
						args := qualDRWACandidateVMFactoryArgs(t, shardID, epoch, false)
						// Reuse the exact candidate loader; no address is fabricated.
						_, cfg, _, _ := qualDRWACandidateBuiltInArgs(t, shardID)
						crawler, err := args.PubKeyConverter.Decode(cfg.BuiltInFunctions.AutomaticCrawlerAddresses[crawlerID])
						require.NoError(t, err)
						hostFactory, err := shard.NewVMContainerFactory(args)
						require.NoError(t, err)
						container, err := hostFactory.Create()
						require.NoError(t, err)
						t.Cleanup(func() { require.NoError(t, hostFactory.Close()) })
						machine, err := container.Get(nativeFactory.WasmVirtualMachine)
						require.NoError(t, err)
						host := machine.(vmhost.VMHost)
						require.True(t, host.IsBuiltinFunctionName(function), "active native name is required for this guard")
						require.False(t, host.IsBuiltinFunctionName("not-a-native-builtin"))
						before := host.Runtime().GetVMInput()
						input := &vmcommon.ContractCallInput{
							VMInput:       vmcommon.VMInput{CallerAddr: append([]byte(nil), crawler...), CallValue: big.NewInt(0)},
							RecipientAddr: append([]byte(nil), crawler...), Function: function,
						}
						require.ErrorIs(t, host.ExecuteOnSameContext(input), vmhost.ErrBuiltinCallOnSameContextDisallowed)
						require.Same(t, before, host.Runtime().GetVMInput(), "guard precedes runtime replacement")
						require.Equal(t, crawler, input.CallerAddr)
						require.Equal(t, crawler, input.RecipientAddr, "guard precedes recipient rewrite")
						require.Nil(t, host.Runtime().GetAllErrors(), "guard returns directly, before execution")
					})
				}
			}
		}
	}
}
