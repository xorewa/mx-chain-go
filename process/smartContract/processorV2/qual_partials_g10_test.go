package processorV2

import (
	"crypto/elliptic"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-vm-go/config"
	"github.com/multiversx/mx-chain-vm-go/executor"
	contextmock "github.com/multiversx/mx-chain-vm-go/mock/context"
	"github.com/multiversx/mx-chain-vm-go/vmhost"
	"github.com/multiversx/mx-chain-vm-go/vmhost/contexts"
	"github.com/multiversx/mx-chain-vm-go/vmhost/vmhooks"
	"github.com/stretchr/testify/require"
)

type qualG10Runtime struct {
	contextmock.RuntimeContextMock
	err error
}

func (r *qualG10Runtime) FailExecution(err error) { r.err = err }

type qualG10Memory struct {
	executor.Instance
	data  []byte
	loads int
}

func (m *qualG10Memory) IsInterfaceNil() bool { return m == nil }
func (m *qualG10Memory) MemLoad(_ executor.MemPtr, length executor.MemLength) ([]byte, error) {
	m.loads++
	if length < 0 || int(length) > len(m.data) {
		return nil, executor.ErrMemoryBadBounds
	}
	return m.data[:length], nil
}

// Experimental scalar fixtures exercise all four public raw/managed scalar
// routes with the real managed context and curve arithmetic. No guest WASM,
// native executor, factory or network execution is represented by this host.
func TestQualPartialsG10ScalarRoutes(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P224(), elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		for _, managed := range []bool{false, true} {
			for _, base := range []bool{false, true} {
				for _, mode := range []string{"one", "zero", "missing_curve", "missing_result", "invalid_input", "negative_length"} {
					if mode == "negative_length" && managed || mode == "invalid_input" && base {
						continue
					}
					t.Run(fmt.Sprintf("%s/managed_%t/base_%t/%s", curve.Params().Name, managed, base, mode), func(t *testing.T) {
						memory := &qualG10Memory{data: []byte{1}}
						runtime := &qualG10Runtime{RuntimeContextMock: contextmock.RuntimeContextMock{Instance: memory}}
						// Experimental positive gas-left keeps zero-cost scalar fixtures
						// beyond MeteringContextMock's inclusive exhaustion check.
						host := &contextmock.VMHostMock{RuntimeContext: runtime, MeteringContext: &contextmock.MeteringContextMock{GasLeftMock: 1, GasCost: &config.GasCost{}}}
						values, err := contexts.NewManagedTypesContext(host)
						require.NoError(t, err)
						host.ManagedTypesContext = values
						hooks := vmhooks.NewVMHooksImpl(host)
						ec := values.PutEllipticCurve(curve.Params())
						xOut, yOut := values.NewBigIntFromInt64(17), values.NewBigIntFromInt64(19)
						xIn, yIn := values.NewBigInt(new(big.Int).Set(curve.Params().Gx)), values.NewBigInt(new(big.Int).Set(curve.Params().Gy))
						if mode == "zero" {
							memory.data[0] = 0
						}
						data := values.NewManagedBufferFromBytes(memory.data)
						result := xOut
						if mode == "missing_curve" {
							ec = -1
						}
						if mode == "missing_result" {
							result = -1
						}
						if mode == "invalid_input" {
							xIn = values.NewBigIntFromInt64(0)
							yIn = values.NewBigIntFromInt64(0)
						}
						length := int32(1)
						if mode == "negative_length" {
							length = -1
						}
						var rc int32
						if managed && base {
							rc = hooks.ManagedScalarBaseMultEC(result, yOut, ec, data)
						} else if managed {
							rc = hooks.ManagedScalarMultEC(result, yOut, ec, xIn, yIn, data)
						} else if base {
							rc = hooks.ScalarBaseMultEC(result, yOut, ec, 0, length)
						} else {
							rc = hooks.ScalarMultEC(result, yOut, ec, xIn, yIn, 0, length)
						}
						x, err := values.GetBigInt(xOut)
						require.NoError(t, err)
						y, err := values.GetBigInt(yOut)
						require.NoError(t, err)
						if mode == "one" {
							require.Zero(t, rc, "scalar one succeeds")
							require.Nil(t, runtime.err)
							require.Equal(t, curve.Params().Gx, x)
							require.Equal(t, curve.Params().Gy, y)
							return
						}
						require.Equal(t, int32(1), rc, "scalar rejection code")
						wantErr := vmhost.ErrPointNotOnCurve
						switch mode {
						case "missing_curve":
							wantErr = vmhost.ErrNoEllipticCurveUnderThisHandle
						case "missing_result":
							wantErr = vmhost.ErrNoBigIntUnderThisHandle
						case "negative_length":
							wantErr = vmhost.ErrNegativeLength
						}
						require.ErrorIs(t, runtime.err, wantErr, "scalar rejection cause")
						require.Equal(t, big.NewInt(17), x, "rejected scalar preserves x")
						require.Equal(t, big.NewInt(19), y, "rejected scalar preserves y")
						if mode == "missing_curve" || mode == "negative_length" {
							require.Zero(t, memory.loads, "early rejection precedes scalar memory load")
						}
					})
				}
			}
		}
	}
}
