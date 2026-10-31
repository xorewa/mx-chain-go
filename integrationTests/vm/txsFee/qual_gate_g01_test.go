package txsFee

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/integrationTests/vm"
	"github.com/multiversx/mx-chain-go/integrationTests/vm/txsFee/utils"
	"github.com/multiversx/mx-chain-go/integrationTests/vm/wasm"
	"github.com/multiversx/mx-chain-go/process/factory"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-go/vmhost/verifier"
	"github.com/stretchr/testify/require"
)

type qualGateG01Verifier struct {
	target []byte
	shape  string
	calls  int
	err    error
}

func (v *qualGateG01Verifier) IsInterfaceNil() bool { return v == nil }

func (v *qualGateG01Verifier) Verify(in *verifier.VerificationInput, out *vmcommon.VMOutput) error {
	v.calls++
	if out.OutputAccounts == nil {
		out.OutputAccounts = make(map[string]*vmcommon.OutputAccount)
	}
	acc := out.OutputAccounts[string(v.target)]
	if acc == nil {
		acc = &vmcommon.OutputAccount{Address: bytes.Clone(v.target), BalanceDelta: big.NewInt(0)}
		out.OutputAccounts[string(v.target)] = acc
	}
	acc.StorageUpdates = map[string]*vmcommon.StorageUpdate{
		"gate": {Offset: []byte("gate"), Data: []byte("after"), Written: true},
	}
	switch v.shape {
	case "identity":
		acc.Address = bytes.Clone(v.target)
		acc.Address[31] ^= 1
	case "negative_balance":
		acc.Balance = big.NewInt(-1)
	case "negative_transfer":
		acc.OutputTransfers = []vmcommon.OutputTransfer{{Value: big.NewInt(-1)}}
	case "native_outflow":
		acc.BalanceDelta = big.NewInt(1)
	case "token_outflow":
		receiver := bytes.Repeat([]byte{2}, 32)
		out.OutputAccounts[string(receiver)] = &vmcommon.OutputAccount{
			Address: receiver, BalanceDelta: big.NewInt(0),
			OutputTransfers: []vmcommon.OutputTransfer{{Value: big.NewInt(0), Data: []byte("ESDTTransfer@544f4b454e2d616263646566@01")}},
		}
	case "gas":
		out.GasRemaining = in.GasProvided + 1
	case "readonly":
		in.IsReadOnly = true
	}
	v.err = verifier.NewVMOutputVerifier().Verify(in, out)
	return v.err
}

// Existing public exit-verifier injection changes an actual native WASM result.
// Node transaction processing and its account journal are real. This does not
// qualify System-SC outputs, live readonly ingress or spontaneous VM corruption.
// Amounts, marker bytes and gas are experimental test coordinates.
func TestQualGateG01NodeExitJournal(t *testing.T) {
	cases := []struct {
		shape string
		err   error
	}{
		{"valid", nil},
		{"identity", verifier.ErrAddressKeyMismatch},
		{"negative_balance", verifier.ErrNegativeBalanceInOutput},
		{"negative_transfer", verifier.ErrNegativeOutputTransferValue},
		{"native_outflow", verifier.ErrNativeTokenConservationViolated},
		{"token_outflow", verifier.ErrTokenConservationViolated},
		{"gas", verifier.ErrGasRemainingExceedsProvided},
		{"readonly", verifier.ErrReadOnlyStateChange},
	}
	for _, route := range []string{"call", "create"} {
		for _, tc := range cases {
			t.Run(route+"/"+tc.shape, func(t *testing.T) {
				ctx, err := vm.CreatePreparedTxProcessorWithVMs(config.EnableEpochs{}, 1)
				require.NoError(t, err)
				t.Cleanup(ctx.Close)
				var owner, target []byte
				if route == "call" {
					target, owner = utils.DoDeployWithCustomParams(t, ctx, "../wasm/testdata/hello-v1/output/answer.wasm", big.NewInt(1000000000), 1000000, nil)
					a, e := ctx.Accounts.GetExistingAccount(target)
					require.NoError(t, e)
					require.NoError(t, a.(state.UserAccountHandler).SaveKeyValue([]byte("gate"), []byte("before")))
					require.NoError(t, ctx.Accounts.SaveAccount(a))
				} else {
					owner = bytes.Repeat([]byte{1}, 32)
					owner[31] = 0
					_, e := vm.CreateAccount(ctx.Accounts, owner, 0, big.NewInt(1000000000))
					require.NoError(t, e)
					target, err = ctx.BlockchainHook.NewAddress(owner, 0, factory.WasmVirtualMachine)
					require.NoError(t, err)
				}
				_, err = ctx.Accounts.Commit()
				require.NoError(t, err)
				host, err := ctx.VMContainer.Get(factory.WasmVirtualMachine)
				require.NoError(t, err)
				injected := &qualGateG01Verifier{target: target, shape: tc.shape}
				setter, ok := host.(interface{ SetOutputVerifier(verifier.OutputVerifier) })
				require.True(t, ok)
				setter.SetOutputVerifier(injected)
				sender, err := ctx.Accounts.GetExistingAccount(owner)
				require.NoError(t, err)
				receiver, data := target, []byte("getUltimateAnswer")
				if route == "create" {
					receiver = vm.CreateEmptyAddress()
					data = []byte(wasm.CreateDeployTxData(wasm.GetSCCode("../wasm/testdata/hello-v1/output/answer.wasm")))
				}
				tx := vm.CreateTransaction(sender.GetNonce(), big.NewInt(0), owner, receiver, 10, 1000000, data)
				code, processErr := ctx.TxProcessor.ProcessTransaction(tx)
				require.NoError(t, processErr)
				require.Equal(t, 1, injected.calls, "must reach the real create/call exit")
				if tc.err == nil {
					require.NoError(t, injected.err)
					require.Equal(t, vmcommon.Ok, code)
				} else {
					require.ErrorIs(t, injected.err, tc.err)
					require.Equal(t, vmcommon.UserError, code)
				}
				_, err = ctx.Accounts.Commit()
				require.NoError(t, err)
				a, err := ctx.Accounts.GetExistingAccount(target)
				if route == "create" && tc.err != nil {
					require.ErrorIs(t, err, state.ErrAccNotFound)
					return
				}
				require.NoError(t, err)
				value, _, err := a.(state.UserAccountHandler).RetrieveValue([]byte("gate"))
				require.NoError(t, err)
				want := []byte("before")
				if tc.err == nil {
					want = []byte("after")
				}
				require.Equal(t, want, value, "node journal excludes rejected output and applies valid output")
			})
		}
	}
}
