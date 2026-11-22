package processorV2

import (
	"crypto/elliptic"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-vm-go/config"
	vmcrypto "github.com/multiversx/mx-chain-vm-go/crypto"
	"github.com/multiversx/mx-chain-vm-go/executor"
	contextmock "github.com/multiversx/mx-chain-vm-go/mock/context"
	"github.com/multiversx/mx-chain-vm-go/vmhost"
	"github.com/multiversx/mx-chain-vm-go/vmhost/contexts"
	"github.com/multiversx/mx-chain-vm-go/vmhost/vmhooks"
	"github.com/stretchr/testify/require"
)

type qualG10ABIMemory struct {
	executor.Instance
	data        []byte
	loads       int
	shortHeader bool
}

func (m *qualG10ABIMemory) IsInterfaceNil() bool { return m == nil }
func (m *qualG10ABIMemory) MemLoad(p executor.MemPtr, n executor.MemLength) ([]byte, error) {
	m.loads++
	if m.shortHeader && p == 128 && n == 2 {
		return []byte{0x30}, nil
	}
	if p < 0 || n < 0 || int64(p)+int64(n) > int64(len(m.data)) {
		return nil, executor.ErrMemoryBadBounds
	}
	return m.data[p : int64(p)+int64(n)], nil
}

type qualG10ABICrypto struct {
	vmcrypto.VMCrypto
	calls int
}

func (c *qualG10ABICrypto) VerifySecp256k1(_, _, _ []byte, _ uint8) error     { c.calls++; return nil }
func (c *qualG10ABICrypto) VerifyAggregatedSig(_ [][]byte, _, _ []byte) error { c.calls++; return nil }

// Experimental offsets/lengths and collaborator returns test only ABI admission;
// successful crypto stubs do not prove signature validity or native execution.
func TestQualPartialsG10ABILengths(t *testing.T) {
	for _, n := range []int32{-1, 0, 1, 32, 33, 34, 64, 65, 66} {
		for _, short := range []bool{false, true} {
			t.Run(fmt.Sprintf("secp/key_%d/short_%t", n, short), func(t *testing.T) {
				memory := &qualG10ABIMemory{data: make([]byte, 256), shortHeader: short}
				memory.data[128] = 0x30
				runtime := &qualG10Runtime{RuntimeContextMock: contextmock.RuntimeContextMock{Instance: memory}}
				crypto := &qualG10ABICrypto{}
				hooks := vmhooks.NewVMHooksImpl(&contextmock.VMHostMock{RuntimeContext: runtime, CryptoHook: crypto, MeteringContext: &contextmock.MeteringContextMock{GasLeftMock: 1, GasCost: &config.GasCost{}}})
				rc := hooks.VerifyCustomSecp256k1(0, n, 96, 0, 128, 0)
				if n != 33 && n != 65 {
					require.Equal(t, int32(1), rc, "ABI key denial code")
					require.ErrorIs(t, runtime.err, vmhost.ErrInvalidPublicKeySize, "ABI key denial cause")
					require.Zero(t, memory.loads)
					require.Zero(t, crypto.calls)
				} else if short {
					require.Equal(t, int32(1), rc, "ABI header denial code")
					require.ErrorIs(t, runtime.err, executor.ErrMemoryBadBounds, "ABI header denial cause")
					require.Zero(t, crypto.calls)
				} else {
					require.Zero(t, rc)
					require.NoError(t, runtime.err)
					require.Equal(t, 1, crypto.calls)
				}
			})
		}
	}
	for _, curve := range []elliptic.Curve{elliptic.P224(), elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		for _, managed := range []bool{false, true} {
			for _, compressed := range []bool{false, true} {
				for _, delta := range []int{-1, 0, 1} {
					t.Run(fmt.Sprintf("unmarshal/%s/managed_%t/compressed_%t/delta_%d", curve.Params().Name, managed, compressed, delta), func(t *testing.T) {
						data := elliptic.Marshal(curve, curve.Params().Gx, curve.Params().Gy)
						if compressed {
							data = elliptic.MarshalCompressed(curve, curve.Params().Gx, curve.Params().Gy)
						}
						if delta < 0 {
							data = data[:len(data)-1]
						} else if delta > 0 {
							data = append(data, 0)
						}
						memory := &qualG10ABIMemory{data: data}
						runtime := &qualG10Runtime{RuntimeContextMock: contextmock.RuntimeContextMock{Instance: memory}}
						host := &contextmock.VMHostMock{RuntimeContext: runtime, MeteringContext: &contextmock.MeteringContextMock{GasLeftMock: 1, GasCost: &config.GasCost{}}}
						values, err := contexts.NewManagedTypesContext(host)
						require.NoError(t, err)
						host.ManagedTypesContext = values
						hooks := vmhooks.NewVMHooksImpl(host)
						ec := values.PutEllipticCurve(curve.Params())
						xh, yh := values.NewBigIntFromInt64(17), values.NewBigIntFromInt64(19)
						buffer := values.NewManagedBufferFromBytes(data)
						var rc int32
						if managed && compressed {
							rc = hooks.ManagedUnmarshalCompressedEC(xh, yh, ec, buffer)
						} else if managed {
							rc = hooks.ManagedUnmarshalEC(xh, yh, ec, buffer)
						} else if compressed {
							rc = hooks.UnmarshalCompressedEC(xh, yh, ec, 0, int32(len(data)))
						} else {
							rc = hooks.UnmarshalEC(xh, yh, ec, 0, int32(len(data)))
						}
						x, err := values.GetBigInt(xh)
						require.NoError(t, err)
						y, err := values.GetBigInt(yh)
						require.NoError(t, err)
						if delta == 0 {
							require.Zero(t, rc)
							require.NoError(t, runtime.err)
							require.Equal(t, curve.Params().Gx, x)
							require.Equal(t, curve.Params().Gy, y)
						} else {
							require.Equal(t, int32(1), rc, "ABI curve length code")
							require.ErrorIs(t, runtime.err, vmhost.ErrLengthOfBufferNotCorrect, "ABI curve length cause")
							require.Equal(t, big.NewInt(17), x)
							require.Equal(t, big.NewInt(19), y)
						}
					})
				}
			}
		}
	}
	for _, n := range []int32{-1, 0, 3, 4, 5} {
		t.Run(fmt.Sprintf("create/length_%d", n), func(t *testing.T) {
			memory := &qualG10ABIMemory{data: []byte("p256x")}
			runtime := &qualG10Runtime{RuntimeContextMock: contextmock.RuntimeContextMock{Instance: memory}}
			host := &contextmock.VMHostMock{RuntimeContext: runtime, MeteringContext: &contextmock.MeteringContextMock{GasLeftMock: 1, GasCost: &config.GasCost{}}}
			values, err := contexts.NewManagedTypesContext(host)
			require.NoError(t, err)
			host.ManagedTypesContext = values
			rc := vmhooks.NewVMHooksImpl(host).CreateEC(0, n)
			if n == 4 {
				require.GreaterOrEqual(t, rc, int32(0))
				require.NoError(t, runtime.err)
				c, err := values.GetEllipticCurve(rc)
				require.NoError(t, err)
				require.Equal(t, elliptic.P256().Params(), c)
			} else {
				require.Equal(t, int32(-1), rc, "ABI curve name code")
				require.ErrorIs(t, runtime.err, vmhost.ErrBadBounds, "ABI curve name cause")
				require.Zero(t, memory.loads)
			}
		})
	}
	for _, flag := range []bool{false, true} {
		for _, count := range []int{0, 1, 2, 400, 401} {
			for _, keyLen := range []int{95, 96, 97} {
				t.Run(fmt.Sprintf("aggregate/flag_%t/count_%d/key_%d", flag, count, keyLen), func(t *testing.T) {
					runtime := &qualG10Runtime{RuntimeContextMock: contextmock.RuntimeContextMock{FixCorrectSmallIntAndGasLimitsFunc: func() bool { return flag }}}
					crypto := &qualG10ABICrypto{}
					host := &contextmock.VMHostMock{RuntimeContext: runtime, CryptoHook: crypto, MeteringContext: &contextmock.MeteringContextMock{GasLeftMock: 1, GasCost: &config.GasCost{}}}
					values, err := contexts.NewManagedTypesContext(host)
					require.NoError(t, err)
					host.ManagedTypesContext = values
					keys := make([][]byte, count)
					for i := range keys {
						keys[i] = make([]byte, keyLen)
					}
					kh, mh, sh := values.NewManagedBuffer(), values.NewManagedBufferFromBytes([]byte("message")), values.NewManagedBufferFromBytes([]byte("signature"))
					require.NoError(t, values.WriteManagedVecOfManagedBuffers(keys, kh))
					rc := vmhooks.NewVMHooksImpl(host).ManagedVerifyBLSAggregatedSignature(kh, mh, sh)
					var want error
					if flag {
						if count == 0 {
							want = vmhost.ErrInvalidArgument
						} else if count > 400 {
							want = vmhost.ErrArgOutOfRange
						} else if keyLen != 96 {
							want = vmhost.ErrLengthOfBufferNotCorrect
						}
					}
					if want != nil {
						require.Equal(t, int32(1), rc, "ABI aggregate denial code")
						require.ErrorIs(t, runtime.err, want, "ABI aggregate denial cause")
						require.Zero(t, crypto.calls, "ABI aggregate denial precedes crypto")
					} else {
						require.Zero(t, rc)
						require.NoError(t, runtime.err)
						require.Equal(t, 1, crypto.calls)
					}
				})
			}
		}
	}
}
