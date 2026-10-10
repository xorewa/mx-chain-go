package core

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"

	nativeFactory "github.com/multiversx/mx-chain-go/process/factory"
	"github.com/multiversx/mx-chain-go/process/factory/shard"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/vmcommonMocks"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-go/vmhost"
	"github.com/stretchr/testify/require"
)

// Independently encoded input modules, not VM-generated fixtures. The parent
// imports native executeOnSameContext(i64, seven i32)->i32 and finish(i32,i32).
// It calls the import with zero value/arguments, then finishes "ok". The child
// exports a no-op "child" function. No compiler or production codec is added.
func qualDRWASameContextModule(function string, destination []byte) []byte {
	uleb := func(value int) []byte {
		var out []byte
		for {
			b := byte(value & 127)
			value >>= 7
			if value != 0 {
				b |= 128
			}
			out = append(out, b)
			if value == 0 {
				return out
			}
		}
	}
	name := func(s string) []byte { return append(uleb(len(s)), []byte(s)...) }
	module := []byte{0, 97, 115, 109, 1, 0, 0, 0}
	section := func(id byte, payload []byte) {
		module = append(module, id)
		module = append(module, uleb(len(payload))...)
		module = append(module, payload...)
	}
	if destination == nil {
		section(1, []byte{1, 0x60, 0, 0}) // () -> ()
		section(3, []byte{1, 0})
		section(5, []byte{1, 0, 1})
		exports := append(append([]byte{2}, name("child")...), 0, 0)
		exports = append(exports, name("memory")...)
		section(7, append(exports, 2, 0))
		section(10, []byte{1, 2, 0, 0x0b})
		return module
	}
	section(1, []byte{3,
		0x60, 8, 0x7e, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f,
		0x60, 2, 0x7f, 0x7f, 0,
		0x60, 0, 0})
	imports := []byte{2}
	for index, imported := range []string{"executeOnSameContext", "finish"} {
		imports = append(imports, name("env")...)
		imports = append(imports, name(imported)...)
		imports = append(imports, 0, byte(index))
	}
	section(2, imports)
	section(3, []byte{1, 2})
	section(5, []byte{1, 0, 1}) // one page of memory
	exports := append(append([]byte{2}, name("run")...), 0, 2)
	exports = append(exports, name("memory")...)
	exports = append(exports, 2, 0)
	section(7, exports)
	// SLEB constants: 2000000=80 89 fa 00; 64=c0 00; 96=e0 00.
	// Candidate gasScheduleV9 GetCode alone costs 1000000 for the child.
	body := []byte{0, 0x42, 0x80, 0x89, 0xfa, 0x00,
		0x41, 0, 0x41, 32, 0x41, 0xc0, 0, 0x41, byte(len(function)),
		0x41, 0, 0x41, 0, 0x41, 0, 0x10, 0, 0x1a,
		0x41, 0xe0, 0, 0x41, 2, 0x10, 1, 0x0b}
	section(10, append(append([]byte{1}, uleb(len(body))...), body...))
	data := make([]byte, 98)
	copy(data, destination)
	copy(data[64:], function)
	copy(data[96:], "ok")
	segment := append([]byte{1, 0, 0x41, 0, 0x0b}, uleb(len(data))...)
	section(11, append(segment, data...))
	return module
}

// T09-M27: actual Wasmer/import execution with deliberately synthetic code and
// account hooks. Loaded crawler identities are test contexts, not authenticated
// callers or lawful crawler deployments. No returned output is applied to state.
func TestQualDRWACandidateExecutingSameContext(t *testing.T) {
	for _, shardID := range []uint32{0, 1, 2} {
		for _, crawlerID := range []int{0, 1, 2} {
			for _, epoch := range []uint32{1, 3} {
				for _, function := range []string{"child", vmcommon.ESDTAddMetadata, vmcommon.ESDTDeleteMetadata} {
					t.Run(fmt.Sprintf("shard_%d_crawler_%d_epoch_%d_%s", shardID, crawlerID, epoch, function), func(t *testing.T) {
						args := qualDRWACandidateVMFactoryArgs(t, shardID, epoch, false)
						_, cfg, _, _ := qualDRWACandidateBuiltInArgs(t, shardID)
						crawler, err := args.PubKeyConverter.Decode(cfg.BuiltInFunctions.AutomaticCrawlerAddresses[crawlerID])
						require.NoError(t, err)
						child := bytes.Repeat([]byte{7}, 32) // synthetic library, same-shard hook below
						parentCode := qualDRWASameContextModule(function, child)
						childCode := qualDRWASameContextModule("", nil)
						childReads, builtinCalls := 0, 0
						hook := args.BlockChainHook.(*testscommon.BlockChainHookStub)
						hook.CurrentEpochCalled = func() uint32 { return epoch }
						hook.GetShardOfAddressCalled = func([]byte) uint32 { return shardID }
						hook.IsSmartContractCalled = func([]byte) bool { return true }
						hook.GetUserAccountCalled = func(address []byte) (vmcommon.UserAccountHandler, error) {
							require.True(t, bytes.Equal(address, crawler) || bytes.Equal(address, child))
							code := parentCode
							if bytes.Equal(address, child) {
								code = childCode
								childReads++
								if function != "child" {
									t.Error("builtin rejection must precede child account/code access")
								}
							}
							return &vmcommonMocks.UserAccountStub{
								AddressBytesCalled: func() []byte { return address },
								GetCodeHashCalled:  func() []byte { return args.Hasher.Compute(string(code)) },
								GetBalanceCalled:   func() *big.Int { return big.NewInt(0) },
							}, nil
						}
						hook.GetCodeCalled = func(account vmcommon.UserAccountHandler) []byte {
							if bytes.Equal(account.AddressBytes(), crawler) {
								return parentCode
							}
							return childCode
						}
						hook.ProcessBuiltInFunctionCalled = func(*vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
							builtinCalls++
							return nil, fmt.Errorf("unexpected builtin dispatch")
						}
						factory, err := shard.NewVMContainerFactory(args)
						require.NoError(t, err)
						container, err := factory.Create()
						require.NoError(t, err)
						t.Cleanup(func() { require.NoError(t, factory.Close()) })
						machine, err := container.Get(nativeFactory.WasmVirtualMachine)
						require.NoError(t, err)
						output, err := machine.RunSmartContractCall(&vmcommon.ContractCallInput{
							VMInput:       vmcommon.VMInput{CallerAddr: crawler, CallValue: big.NewInt(0), GasProvided: 10000000},
							RecipientAddr: crawler, Function: "run",
						})
						require.NoError(t, err)
						require.NotNil(t, output)
						require.Zero(t, builtinCalls)
						if function == "child" {
							require.Equal(t, vmcommon.Ok, output.ReturnCode, output.ReturnMessage)
							require.Equal(t, [][]byte{[]byte("ok")}, output.ReturnData)
							require.Positive(t, childReads)
						} else {
							require.Equal(t, vmcommon.ExecutionFailed, output.ReturnCode)
							require.Contains(t, output.ReturnMessage, vmhost.ErrInvalidBuiltInFunctionCall.Error())
							require.Empty(t, output.ReturnData)
							require.Zero(t, childReads)
						}
						for _, account := range output.OutputAccounts {
							require.Empty(t, account.StorageUpdates)
							require.Empty(t, account.OutputTransfers)
							if account.BalanceDelta != nil {
								require.Zero(t, account.BalanceDelta.Sign())
							}
						}
					})
				}
			}
		}
	}
}
