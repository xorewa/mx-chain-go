package process

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/vm"
	"github.com/multiversx/mx-chain-go/vm/mock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

type qualStep1CallContext struct {
	*mock.SystemEIStub
	output *vmcommon.VMOutput
	err    error
	calls  int
}

func (c *qualStep1CallContext) ExecuteDRWASystemCall(_ *vmcommon.ContractCallInput, _ func() (*vmcommon.VMOutput, error)) (*vmcommon.VMOutput, error) {
	c.calls++
	return c.output, c.err
}

// The shared policy and real VM context are exercised in systemSmartContracts.
// This spy checks the physical entry points' handling of the two result channels.
func TestQualDRWAStep1ValueRejectedBeforePhysicalPrelude(t *testing.T) {
	for _, path := range []string{"native", "owned"} {
		for _, result := range []string{"user-rejection", "owner-failure", "lease-failure"} {
			if path == "native" && result == "lease-failure" {
				continue
			}
			t.Run(path+"/"+result, func(t *testing.T) {
				effects := 0
				args := createMockArguments()
				ei := &mock.SystemEIStub{
					CleanCacheCalled:                func() { effects++ },
					AddTxValueToSmartContractCalled: func(*big.Int, []byte) { effects++ },
				}
				failure := errors.Join(vm.ErrDRWAExecution, errors.New("synthetic containment failure"))
				context := &qualStep1CallContext{SystemEIStub: ei}
				if result == "owner-failure" {
					context.err = failure
				} else {
					context.output = &vmcommon.VMOutput{ReturnCode: vmcommon.UserError, GasRefund: big.NewInt(0)}
				}
				args.SystemEI = context
				s, err := NewSystemVM(args)
				require.NoError(t, err)
				in := &vmcommon.ContractCallInput{
					RecipientAddr: bytes.Clone(core.ESDTSCAddress), Function: "DRWARegisterBootstrapIntent",
					VMInput: vmcommon.VMInput{CallValue: big.NewInt(1)},
				}
				var out *vmcommon.VMOutput
				lease := &qualD20CallLease{expected: in}
				if result == "lease-failure" {
					lease.denial = failure
				}
				if path == "owned" {
					token := &drwaNativeCall{vm: s, active: true, validated: true, prepared: in, lease: lease}
					out, err = s.RunSmartContractCallWithDRWA(in, token)
					require.True(t, token.used)
					require.Equal(t, err, token.failure)
				} else {
					out, err = s.RunSmartContractCall(in)
				}
				require.Zero(t, effects)
				switch result {
				case "lease-failure":
					require.ErrorIs(t, err, failure)
					require.Nil(t, out)
					require.Zero(t, context.calls)
				case "owner-failure":
					require.ErrorIs(t, err, failure)
					require.Nil(t, out)
					require.Equal(t, 1, context.calls)
				default:
					require.NoError(t, err)
					require.Same(t, context.output, out)
					require.Equal(t, 1, context.calls)
				}
			})
		}
	}
}
