package processorV2

import (
	"crypto/elliptic"
	"errors"
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

// These literals are experimental qualification inputs, never an installed gas
// schedule or production profile. The host uses real managed state/curve math;
// memory and metering are controlled collaborators, without a guest executor.
var qualG10Injected = errors.New("experimental G10 collaborator failure")

type qualG10Meter struct {
	contextmock.MeteringContextMock
	charges []uint64
	fail    bool
}

func (m *qualG10Meter) UseGasBounded(gas uint64) error {
	m.charges = append(m.charges, gas)
	if m.fail {
		return qualG10Injected
	}
	return nil
}

type qualG10FaultMemory struct {
	qualG10Memory
	fail bool
}

func (m *qualG10FaultMemory) MemLoad(p executor.MemPtr, n executor.MemLength) ([]byte, error) {
	if m.fail {
		m.loads++
		return nil, qualG10Injected
	}
	return m.qualG10Memory.MemLoad(p, n)
}

// Inject an error only after the public multiplier check has used the real
// managed context. That redundant lookup is otherwise inseparable from it.
type qualG10FaultManaged struct {
	vmhost.ManagedTypesContext
	curveError, copyError bool
	copyCalls             int
}

func (m *qualG10FaultManaged) GetEllipticCurve(h int32) (*elliptic.CurveParams, error) {
	if m.curveError {
		return nil, qualG10Injected
	}
	return m.ManagedTypesContext.GetEllipticCurve(h)
}
func (m *qualG10FaultManaged) ConsumeGasForBigIntCopy(v ...*big.Int) error {
	m.copyCalls++
	if m.copyError {
		return qualG10Injected
	}
	return m.ManagedTypesContext.ConsumeGasForBigIntCopy(v...)
}

func TestQualPartialsG10ScalarGuardInventory(t *testing.T) {
	curves := []elliptic.Curve{elliptic.P224(), elliptic.P256(), elliptic.P384(), elliptic.P521()}
	// Independent fixture table: pinned managedType.go constants L38–41.
	multipliers := []uint64{100, 110, 150, 190}
	for ci, curve := range curves {
		for _, managed := range []bool{false, true} {
			for _, base := range []bool{false, true} {
				for _, mode := range []string{"one", "empty", "order", "order_plus_one", "missing_curve", "missing_buffer", "missing_x", "missing_y", "missing_point_x", "missing_point_y", "invalid_point", "gas", "memory", "copy", "curve_lookup", "negative"} {
					if (managed && (mode == "memory" || mode == "negative")) || (!managed && mode == "missing_buffer") || (base && (mode == "missing_point_x" || mode == "missing_point_y" || mode == "invalid_point")) {
						continue
					}
					t.Run(fmt.Sprintf("%s/managed_%t/base_%t/%s", curve.Params().Name, managed, base, mode), func(t *testing.T) {
						scalar := []byte{1}
						if mode == "empty" {
							scalar = nil
						}
						if mode == "order" {
							scalar = curve.Params().N.Bytes()
						}
						if mode == "order_plus_one" {
							scalar = new(big.Int).Add(curve.Params().N, big.NewInt(1)).Bytes()
						}
						memory := &qualG10FaultMemory{qualG10Memory: qualG10Memory{data: scalar}, fail: mode == "memory"}
						runtime := &qualG10Runtime{RuntimeContextMock: contextmock.RuntimeContextMock{Instance: memory}}
						meter := &qualG10Meter{MeteringContextMock: contextmock.MeteringContextMock{GasCost: &config.GasCost{}}, fail: mode == "gas"}
						meter.GasCost.CryptoAPICost.ScalarMultECC = 100
						host := &contextmock.VMHostMock{RuntimeContext: runtime, MeteringContext: meter}
						values, err := contexts.NewManagedTypesContext(host)
						require.NoError(t, err)
						faults := &qualG10FaultManaged{ManagedTypesContext: values, curveError: mode == "curve_lookup", copyError: mode == "copy"}
						host.ManagedTypesContext = faults
						hooks := vmhooks.NewVMHooksImpl(host)
						ec := values.PutEllipticCurve(curve.Params())
						xOut, yOut := values.NewBigIntFromInt64(17), values.NewBigIntFromInt64(19)
						xIn, yIn := values.NewBigInt(new(big.Int).Set(curve.Params().Gx)), values.NewBigInt(new(big.Int).Set(curve.Params().Gy))
						buffer := values.NewManagedBufferFromBytes(scalar)
						xh, yh := xOut, yOut
						switch mode {
						case "missing_curve":
							ec = -1
						case "missing_buffer":
							buffer = -1
						case "missing_x":
							xh = -1
						case "missing_y":
							yh = -1
						case "missing_point_x":
							xIn = -1
						case "missing_point_y":
							yIn = -1
						case "invalid_point":
							xIn = values.NewBigIntFromInt64(0)
							yIn = values.NewBigIntFromInt64(0)
						}
						n := int32(len(scalar))
						if mode == "negative" {
							n = -1
						}
						var rc int32
						if managed && base {
							rc = hooks.ManagedScalarBaseMultEC(xh, yh, ec, buffer)
						} else if managed {
							rc = hooks.ManagedScalarMultEC(xh, yh, ec, xIn, yIn, buffer)
						} else if base {
							rc = hooks.ScalarBaseMultEC(xh, yh, ec, 0, n)
						} else {
							rc = hooks.ScalarMultEC(xh, yh, ec, xIn, yIn, 0, n)
						}
						x, err := values.GetBigInt(xOut)
						require.NoError(t, err)
						y, err := values.GetBigInt(yOut)
						require.NoError(t, err)
						if mode == "one" || mode == "order_plus_one" {
							require.Zero(t, rc, "scalar healthy code")
							require.NoError(t, runtime.err)
							require.Equal(t, curve.Params().Gx, x)
							require.Equal(t, curve.Params().Gy, y)
						} else {
							wantCode := int32(1)
							wantErr := qualG10Injected
							switch mode {
							case "gas":
								wantCode = -1
							case "empty", "order", "invalid_point":
								wantErr = vmhost.ErrPointNotOnCurve
							case "missing_curve":
								wantErr = vmhost.ErrNoEllipticCurveUnderThisHandle
							case "missing_buffer":
								wantErr = vmhost.ErrNoManagedBufferUnderThisHandle
							case "missing_x", "missing_y", "missing_point_x", "missing_point_y":
								wantErr = vmhost.ErrNoBigIntUnderThisHandle
							case "negative":
								wantErr = vmhost.ErrNegativeLength
							}
							require.Equal(t, wantCode, rc, "scalar guard return")
							require.ErrorIs(t, runtime.err, wantErr, "scalar guard error")
							require.Equal(t, big.NewInt(17), x, "scalar guard preserves x")
							require.Equal(t, big.NewInt(19), y, "scalar guard preserves y")
						}
						var wantCharges []uint64
						if mode == "negative" || mode == "missing_curve" || mode == "missing_buffer" {
							require.Zero(t, memory.loads)
						} else {
							wantCharges = append(wantCharges, multipliers[ci]*uint64(1+len(scalar)))
						}
						if ci >= 2 && (mode == "one" || mode == "empty" || mode == "order" || mode == "order_plus_one") {
							copies := 5
							if !base {
								copies += 2
							}
							for i := 0; i < copies; i++ {
								wantCharges = append(wantCharges, 0)
							}
						}
						if mode != "one" && mode != "order_plus_one" {
							wantCharges = append(wantCharges, 0) // FailExecution gas drain.
						}
						require.Equal(t, wantCharges, meter.charges, "exact scalar charge sequence")
						if mode == "gas" {
							require.Zero(t, memory.loads, "gas denial precedes memory")
						}
						if managed {
							require.Zero(t, memory.loads, "managed scalar does not read guest memory")
						}
					})
				}
			}
		}
	}
}
