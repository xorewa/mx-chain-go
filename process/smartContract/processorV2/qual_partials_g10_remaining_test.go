package processorV2

import (
	"crypto/elliptic"
	"fmt"
	"io"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-vm-go/config"
	vmcrypto "github.com/multiversx/mx-chain-vm-go/crypto"
	"github.com/multiversx/mx-chain-vm-go/executor"
	contextmock "github.com/multiversx/mx-chain-vm-go/mock/context"
	"github.com/multiversx/mx-chain-vm-go/vmhost"
	"github.com/multiversx/mx-chain-vm-go/vmhost/contexts"
	"github.com/multiversx/mx-chain-vm-go/vmhost/vmhooks"
	"github.com/stretchr/testify/require"
)

// Experimental host collaborators. Errors are injected at ABI boundaries, not
// evidence of an installed guest/native failure. Source oracle: cryptoei.go in
// pinned VM f5259136, enumerated before code in G10_INVENTORY.json.
type qualG10ABIFault struct {
	target    string
	nth, seen int
}

func (f *qualG10ABIFault) hit(s string) bool {
	if s != f.target {
		return false
	}
	f.seen++
	return f.seen == f.nth
}

type qualG10AllMeter struct {
	contextmock.MeteringContextMock
	f       *qualG10ABIFault
	charges []uint64
}

func (m *qualG10AllMeter) UseGasBounded(n uint64) error {
	m.charges = append(m.charges, n)
	if m.f.hit("gas") {
		return qualG10Injected
	}
	return nil
}
func (m *qualG10AllMeter) UseGasBoundedAndAddTracedGas(_ string, n uint64) error {
	return m.UseGasBounded(n)
}

type qualG10AllMemory struct {
	qualG10ABIMemory
	f      *qualG10ABIFault
	stored []byte
}

func (m *qualG10AllMemory) MemLoad(p executor.MemPtr, n executor.MemLength) ([]byte, error) {
	if m.f.hit("load") {
		return nil, qualG10Injected
	}
	return m.qualG10ABIMemory.MemLoad(p, n)
}
func (m *qualG10AllMemory) MemStore(_ executor.MemPtr, b []byte) error {
	if m.f.hit("store") {
		return qualG10Injected
	}
	m.stored = append([]byte(nil), b...)
	return nil
}

type qualG10AllRuntime struct {
	qualG10Runtime
	bounded bool
}

func (r *qualG10AllRuntime) UseGasBoundedShouldFailExecution() bool { return r.bounded }

type qualG10Flags struct {
	contextmock.DefaultEnableEpochsHandlerStub
	mask bool
}

func (f *qualG10Flags) IsFlagEnabled(flag core.EnableEpochFlag) bool {
	return f.mask && flag == vmhost.MaskInternalDependenciesErrorsFlag
}

type qualG10AllCrypto struct {
	vmcrypto.VMCrypto
	f     *qualG10ABIFault
	calls int
}

func (c *qualG10AllCrypto) hash() ([]byte, error) {
	c.calls++
	if c.f.hit("crypto") {
		return nil, qualG10Injected
	}
	return []byte{7, 8, 9}, nil
}
func (c *qualG10AllCrypto) Sha256([]byte) ([]byte, error)                       { return c.hash() }
func (c *qualG10AllCrypto) Keccak256([]byte) ([]byte, error)                    { return c.hash() }
func (c *qualG10AllCrypto) Ripemd160([]byte) ([]byte, error)                    { return c.hash() }
func (c *qualG10AllCrypto) verify() error                                       { _, e := c.hash(); return e }
func (c *qualG10AllCrypto) VerifyBLS([]byte, []byte, []byte) error              { return c.verify() }
func (c *qualG10AllCrypto) VerifySignatureShare([]byte, []byte, []byte) error   { return c.verify() }
func (c *qualG10AllCrypto) VerifyAggregatedSig([][]byte, []byte, []byte) error  { return c.verify() }
func (c *qualG10AllCrypto) VerifyEd25519([]byte, []byte, []byte) error          { return c.verify() }
func (c *qualG10AllCrypto) VerifySecp256k1([]byte, []byte, []byte, uint8) error { return c.verify() }
func (c *qualG10AllCrypto) VerifySecp256r1([]byte, []byte, []byte) error        { return c.verify() }
func (c *qualG10AllCrypto) EncodeSecp256k1DERSignature([]byte, []byte) []byte {
	c.calls++
	return []byte{7, 8, 9}
}

type qualG10Reader struct{ fail bool }

func (r qualG10Reader) Read(p []byte) (int, error) {
	if r.fail {
		return 0, qualG10Injected
	}
	clear(p)
	return len(p), nil
}

type qualG10AllManaged struct {
	vmhost.ManagedTypesContext
	f             *qualG10ABIFault
	tiny, nilInts bool
	multiplier    int32
}

func (m *qualG10AllManaged) GetBytes(h int32) ([]byte, error) {
	if m.f.hit("bytes") {
		return nil, qualG10Injected
	}
	return m.ManagedTypesContext.GetBytes(h)
}
func (m *qualG10AllManaged) ConsumeGasForBytes([]byte) error {
	if m.f.hit("bytecopy") {
		return qualG10Injected
	}
	return nil
}
func (m *qualG10AllManaged) GetEllipticCurve(h int32) (*elliptic.CurveParams, error) {
	if m.f.hit("curve") {
		return nil, qualG10Injected
	}
	c, e := m.ManagedTypesContext.GetEllipticCurve(h)
	if e == nil && m.tiny {
		v := *c
		v.BitSize = 1
		c = &v
	}
	return c, e
}
func (m *qualG10AllManaged) GetTwoBigInt(a, b int32) (*big.Int, *big.Int, error) {
	if m.f.hit("ints") {
		return nil, nil, qualG10Injected
	}
	if m.nilInts {
		return nil, nil, nil
	}
	return m.ManagedTypesContext.GetTwoBigInt(a, b)
}
func (m *qualG10AllManaged) GetBigInt(h int32) (*big.Int, error) {
	if m.f.hit("int") {
		return nil, qualG10Injected
	}
	return m.ManagedTypesContext.GetBigInt(h)
}
func (m *qualG10AllManaged) ConsumeGasForBigIntCopy(...*big.Int) error {
	if m.f.hit("intcopy") {
		return qualG10Injected
	}
	return nil
}
func (m *qualG10AllManaged) GetRandReader() io.Reader { return qualG10Reader{fail: m.f.hit("random")} }
func (m *qualG10AllManaged) Get100xCurveGasCostMultiplier(h int32) int32 {
	if m.multiplier != 0 {
		return m.multiplier
	}
	return m.ManagedTypesContext.Get100xCurveGasCostMultiplier(h)
}
func (m *qualG10AllManaged) ReadManagedVecOfManagedBuffers(h int32) ([][]byte, uint64, error) {
	if m.f.hit("vector") {
		return nil, 0, qualG10Injected
	}
	return m.ManagedTypesContext.ReadManagedVecOfManagedBuffers(h)
}

type qualG10ABIHost struct {
	host    *contextmock.VMHostMock
	hooks   *vmhooks.VMHooksImpl
	runtime *qualG10AllRuntime
	meter   *qualG10AllMeter
	memory  *qualG10AllMemory
	crypto  *qualG10AllCrypto
	values  vmhost.ManagedTypesContext
	faults  *qualG10AllManaged
	flags   *qualG10Flags
}

func qualG10NewABIHost(t *testing.T, f *qualG10ABIFault) *qualG10ABIHost {
	memory := &qualG10AllMemory{qualG10ABIMemory: qualG10ABIMemory{data: make([]byte, 512)}, f: f}
	runtime := &qualG10AllRuntime{qualG10Runtime: qualG10Runtime{RuntimeContextMock: contextmock.RuntimeContextMock{Instance: memory, FixCorrectSmallIntAndGasLimitsFunc: func() bool { return false }}}, bounded: true}
	meter := &qualG10AllMeter{MeteringContextMock: contextmock.MeteringContextMock{GasCost: &config.GasCost{}}, f: f}
	crypto := &qualG10AllCrypto{f: f}
	flags := &qualG10Flags{}
	host := &contextmock.VMHostMock{RuntimeContext: runtime, MeteringContext: meter, CryptoHook: crypto, EnableEpochsHandlerField: flags}
	values, e := contexts.NewManagedTypesContext(host)
	require.NoError(t, e)
	faults := &qualG10AllManaged{ManagedTypesContext: values, f: f}
	host.ManagedTypesContext = faults
	return &qualG10ABIHost{host, vmhooks.NewVMHooksImpl(host), runtime, meter, memory, crypto, values, faults, flags}
}

func TestQualPartialsG10HashAndSignatureGuards(t *testing.T) {
	for _, name := range []string{"sha", "keccak", "ripemd", "bls", "share", "aggregate", "ed", "secp", "secp_default", "r1", "der"} {
		for _, managed := range []bool{false, true} {
			if !managed && (name == "share" || name == "aggregate" || name == "r1") {
				continue
			}
			hash := name == "sha" || name == "keccak" || name == "ripemd"
			targets := []string{"healthy", "gas1"}
			if managed {
				targets = append(targets, "bytes1")
				if hash {
					targets = append(targets, "bytecopy1")
				} else if name == "der" {
					targets = append(targets, "bytes2")
				} else {
					targets = append(targets, "bytes2", "bytes3", "bytecopy1", "bytecopy2", "bytecopy3")
				}
			} else {
				targets = append(targets, "load1")
				if !hash {
					targets = append(targets, "load2")
					if name != "der" {
						targets = append(targets, "gas2", "load3")
						if name == "secp" || name == "secp_default" {
							targets = append(targets, "load4")
						}
					}
				}
				if hash || name == "der" {
					targets = append(targets, "store1")
				}
			}
			if name != "der" {
				targets = append(targets, "crypto1")
			}
			if name == "aggregate" {
				targets = append(targets, "vector1", "gas5")
			}
			for _, target := range targets {
				for _, mask := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/managed_%t/%s/mask_%t", name, managed, target, mask), func(t *testing.T) {
						f := &qualG10ABIFault{nth: 1}
						if target != "healthy" {
							f.target = target[:len(target)-1]
							f.nth = int(target[len(target)-1] - '0')
						}
						armed := f.target
						f.target = ""
						h := qualG10NewABIHost(t, f)
						h.flags.mask = mask
						h.meter.GasCost.CryptoAPICost.VerifyBLS = 11
						h.meter.GasCost.CryptoAPICost.VerifyBLSSignatureShare = 13
						h.meter.GasCost.CryptoAPICost.VerifyBLSMultiSig = 17
						h.meter.GasCost.CryptoAPICost.VerifySecp256k1 = 19
						h.meter.GasCost.CryptoAPICost.VerifySecp256r1 = 23
						h.meter.GasCost.CryptoAPICost.VerifyEd25519 = 29
						kh := h.values.NewManagedBufferFromBytes(make([]byte, 96))
						mh := h.values.NewManagedBufferFromBytes([]byte("m"))
						sh := h.values.NewManagedBufferFromBytes([]byte("s"))
						out := h.values.NewManagedBufferFromBytes([]byte("sentinel"))
						if name == "aggregate" {
							require.NoError(t, h.values.WriteManagedVecOfManagedBuffers([][]byte{make([]byte, 96), make([]byte, 96)}, kh))
							h.runtime.FixCorrectSmallIntAndGasLimitsFunc = func() bool { return true }
						}
						h.memory.data[256] = 0x30
						h.memory.data[257] = 2
						// Fixture construction must not consume the injected failure counter.
						f.seen = 0
						f.target = armed
						h.meter.charges = nil
						var rc int32
						if managed {
							switch name {
							case "sha":
								rc = h.hooks.ManagedSha256(kh, out)
							case "keccak":
								rc = h.hooks.ManagedKeccak256(kh, out)
							case "ripemd":
								rc = h.hooks.ManagedRipemd160(kh, out)
							case "bls":
								rc = h.hooks.ManagedVerifyBLS(kh, mh, sh)
							case "share":
								rc = h.hooks.ManagedVerifyBLSSignatureShare(kh, mh, sh)
							case "aggregate":
								rc = h.hooks.ManagedVerifyBLSAggregatedSignature(kh, mh, sh)
							case "ed":
								rc = h.hooks.ManagedVerifyEd25519(kh, mh, sh)
							case "secp":
								rc = h.hooks.ManagedVerifyCustomSecp256k1(kh, mh, sh, 0)
							case "secp_default":
								rc = h.hooks.ManagedVerifySecp256k1(kh, mh, sh)
							case "r1":
								rc = h.hooks.ManagedVerifySecp256r1(kh, mh, sh)
							case "der":
								rc = h.hooks.ManagedEncodeSecp256k1DerSignature(kh, mh, out)
							}
						} else {
							switch name {
							case "sha":
								rc = h.hooks.Sha256(0, 1, 384)
							case "keccak":
								rc = h.hooks.Keccak256(0, 1, 384)
							case "ripemd":
								rc = h.hooks.Ripemd160(0, 1, 384)
							case "bls":
								rc = h.hooks.VerifyBLS(0, 128, 1, 256)
							case "ed":
								rc = h.hooks.VerifyEd25519(0, 128, 1, 256)
							case "secp":
								rc = h.hooks.VerifyCustomSecp256k1(0, 33, 128, 1, 256, 0)
							case "secp_default":
								rc = h.hooks.VerifySecp256k1(0, 33, 128, 1, 256)
							case "der":
								rc = h.hooks.EncodeSecp256k1DerSignature(0, 1, 128, 1, 384)
							}
						}
						if target == "healthy" {
							require.Zero(t, rc)
							require.NoError(t, h.runtime.err)
							require.Equal(t, 1, h.crypto.calls)
							if hash || name == "der" {
								b := h.memory.stored
								if managed {
									var e error
									b, e = h.values.GetBytes(out)
									require.NoError(t, e)
								}
								require.Equal(t, []byte{7, 8, 9}, b)
							}
							if !hash && name != "der" {
								want := uint64(11)
								switch name {
								case "share":
									want = 13
								case "aggregate":
									want = 17
								case "secp", "secp_default":
									want = 19
								case "r1":
									want = 23
								case "ed":
									want = 29
								}
								require.Equal(t, want, h.meter.charges[0], "signature entry tariff")
							}
							return
						}
						code := int32(1)
						if !hash && (f.target == "crypto" || f.target == "vector") {
							code = -1
						}
						want := qualG10Injected
						if mask && (f.target == "crypto" || f.target == "vector") {
							switch name {
							case "sha":
								want = vmhost.ErrSha256Hash
							case "keccak":
								want = vmhost.ErrKeccak256Hash
							case "ripemd":
								want = vmhost.ErrRipemd160Hash
							case "bls", "share", "aggregate":
								want = vmhost.ErrBlsVerify
							case "ed":
								want = vmhost.ErrEd25519Verify
							default:
								want = vmhost.ErrSecp256k1Verify
							}
						}
						require.Equal(t, code, rc, "ABI guard code")
						require.ErrorIs(t, h.runtime.err, want, "ABI guard cause")
						require.GreaterOrEqual(t, f.seen, f.nth, "injection reached")
						if f.target == "store" {
							require.Equal(t, 1, h.crypto.calls, "store follows crypto")
						} else if f.target != "crypto" {
							require.Zero(t, h.crypto.calls, "denial precedes crypto")
						}
						require.Empty(t, h.memory.stored)
					})
				}
			}
		}
	}
}

func TestQualPartialsG10SelectorAndGasBranches(t *testing.T) {
	for _, name := range []string{"bls", "secp", "r1"} {
		t.Run("gas_continue/"+name, func(t *testing.T) {
			f := &qualG10ABIFault{target: "gas", nth: 1}
			h := qualG10NewABIHost(t, f)
			h.runtime.bounded = false
			a := h.values.NewManagedBufferFromBytes([]byte("a"))
			b := h.values.NewManagedBufferFromBytes([]byte("b"))
			c := h.values.NewManagedBufferFromBytes([]byte("c"))
			var rc int32
			switch name {
			case "bls":
				rc = h.hooks.ManagedVerifyBLS(a, b, c)
			case "secp":
				rc = h.hooks.ManagedVerifyCustomSecp256k1(a, b, c, 0)
			case "r1":
				rc = h.hooks.ManagedVerifySecp256r1(a, b, c)
			}
			require.Zero(t, rc, "legacy bounded gas continuation")
			require.NoError(t, h.runtime.err)
			require.Equal(t, 1, h.crypto.calls)
			require.Equal(t, 1, f.seen)
		})
	}
	for _, bls := range []bool{false, true} {
		for _, mask := range []bool{false, true} {
			t.Run(fmt.Sprintf("selector/bls_%t/mask_%t", bls, mask), func(t *testing.T) {
				h := qualG10NewABIHost(t, &qualG10ABIFault{})
				h.flags.mask = mask
				a := h.values.NewManagedBufferFromBytes(nil)
				var rc int32
				if bls {
					rc = vmhooks.ManagedVerifyBLSWithHost(h.host, a, a, a, "experimental_unknown_selector")
				} else {
					rc = vmhooks.ManagedVerifyCustomSecp256k1WithHost(h.host, a, a, a, 0, "experimental_unknown_selector")
				}
				want := vmhost.ErrInvalidArgument
				if mask {
					want = vmhost.ErrSecp256k1Verify
					if bls {
						want = vmhost.ErrBlsVerify
					}
				}
				require.Equal(t, int32(-1), rc)
				require.ErrorIs(t, h.runtime.err, want)
				require.Zero(t, h.crypto.calls)
			})
		}
	}
	for _, fallback := range []bool{false, true} {
		for _, count := range []int{1, 2, 3} {
			t.Run(fmt.Sprintf("aggregate_tariff/fallback_%t/count_%d", fallback, count), func(t *testing.T) {
				h := qualG10NewABIHost(t, &qualG10ABIFault{})
				h.runtime.FixCorrectSmallIntAndGasLimitsFunc = func() bool { return true }
				h.meter.GasCost.CryptoAPICost.VerifyBLSMultiSig = 17
				h.meter.GasCost.CryptoAPICost.VerifyBLSSignatureShare = 7
				h.meter.GasCost.CryptoAPICost.VerifyBLS = 11
				if fallback {
					h.meter.GasCost.CryptoAPICost.VerifyBLSSignatureShare = 0
				}
				keys := make([][]byte, count)
				for i := range keys {
					keys[i] = make([]byte, 96)
				}
				a := h.values.NewManagedBuffer()
				require.NoError(t, h.values.WriteManagedVecOfManagedBuffers(keys, a))
				b := h.values.NewManagedBufferFromBytes(nil)
				h.meter.charges = nil
				require.Zero(t, h.hooks.ManagedVerifyBLSAggregatedSignature(a, b, b))
				require.NoError(t, h.runtime.err)
				want := []uint64{17}
				for i := 0; i <= count; i++ {
					want = append(want, 0)
				}
				if count > 1 {
					per := uint64(7)
					if fallback {
						per = 11
					}
					want = append(want, uint64(count-1)*per)
				}
				require.Equal(t, want, h.meter.charges, "aggregate exact gas calls")
			})
		}
	}
}

func TestQualPartialsG10ECRemainingGuards(t *testing.T) {
	for _, name := range []string{"add", "double", "ison", "marshal", "marshal_compressed", "unmarshal", "unmarshal_compressed", "generate", "create", "length", "private_length", "values"} {
		for _, managed := range []bool{false, true} {
			if managed && (name == "add" || name == "double" || name == "ison" || name == "length" || name == "private_length" || name == "values") {
				continue
			}
			modes := []string{"healthy", "gas", "missing_curve"}
			switch name {
			case "create":
				modes = append(modes, "input", "unsupported", "p224", "p384", "p521")
			case "length", "private_length":
			case "values":
				modes = append(modes, "curve", "ints1", "ints2", "int1")
			default:
				modes = append(modes, "curve", "ints1", "intcopy")
				if name == "add" {
					modes = append(modes, "ints2", "ints3", "invalid1", "invalid2")
				}
				if name == "double" {
					modes = append(modes, "ints2", "invalid1")
				}
				if name == "ison" {
					modes = append(modes, "invalid1", "nilints")
				}
				if name == "marshal" || name == "marshal_compressed" {
					modes = append(modes, "invalid1", "tiny")
					if !managed {
						modes = append(modes, "store")
					}
					if name == "marshal_compressed" {
						modes = append(modes, "nilints")
					}
				}
				if name == "unmarshal" || name == "unmarshal_compressed" {
					modes = append(modes, "input", "bad_length", "invalid_encoding")
				}
				if name == "generate" {
					modes = append(modes, "random", "multiplier250")
					if !managed {
						modes = append(modes, "store")
					}
				}
			}
			for _, mode := range modes {
				t.Run(fmt.Sprintf("%s/managed_%t/%s", name, managed, mode), func(t *testing.T) {
					f := &qualG10ABIFault{nth: 1}
					h := qualG10NewABIHost(t, f)
					curve := elliptic.P256().Params()
					ec := h.values.PutEllipticCurve(curve)
					x := h.values.NewBigInt(new(big.Int).Set(curve.Gx))
					y := h.values.NewBigInt(new(big.Int).Set(curve.Gy))
					x2 := h.values.NewBigInt(new(big.Int).Set(curve.Gx))
					y2 := h.values.NewBigInt(new(big.Int).Set(curve.Gy))
					xo := h.values.NewBigIntFromInt64(17)
					yo := h.values.NewBigIntFromInt64(19)
					v2 := h.values.NewBigIntFromInt64(23)
					v3 := h.values.NewBigIntFromInt64(29)
					v4 := h.values.NewBigIntFromInt64(31)
					data := elliptic.Marshal(curve, curve.Gx, curve.Gy)
					if name == "unmarshal_compressed" {
						data = elliptic.MarshalCompressed(curve, curve.Gx, curve.Gy)
					}
					if name == "create" {
						data = []byte("p256")
						if mode == "unsupported" {
							data = []byte("nope")
						}
						if mode == "p224" || mode == "p384" || mode == "p521" {
							data = []byte(mode)
						}
					}
					if mode == "bad_length" {
						data = data[:len(data)-1]
					}
					if mode == "invalid_encoding" {
						data[0] = 0
					}
					copy(h.memory.data, data)
					in := h.values.NewManagedBufferFromBytes(data)
					out := h.values.NewManagedBufferFromBytes([]byte("sentinel"))
					if mode == "missing_curve" {
						ec = -1
					}
					if name == "create" && mode == "missing_curve" {
						data = []byte("none")
						copy(h.memory.data, data)
						h.values.SetBytes(in, data)
						h.runtime.FixCorrectSmallIntAndGasLimitsFunc = func() bool { return true }
					}
					switch mode {
					case "gas":
						f.target = "gas"
					case "curve":
						f.target = "curve"
					case "ints1", "ints2", "ints3":
						f.target = "ints"
						f.nth = int(mode[len(mode)-1] - '0')
					case "int1":
						f.target = "int"
					case "intcopy":
						f.target = "intcopy"
					case "input":
						if managed {
							f.target = "bytes"
						} else {
							f.target = "load"
						}
					case "store":
						f.target = "store"
					case "random":
						f.target = "random"
					case "invalid1":
						a, _ := h.values.GetBigInt(x)
						a.SetInt64(0)
						a, _ = h.values.GetBigInt(y)
						a.SetInt64(0)
					case "invalid2":
						a, _ := h.values.GetBigInt(x2)
						a.SetInt64(0)
						a, _ = h.values.GetBigInt(y2)
						a.SetInt64(0)
					case "tiny":
						h.faults.tiny = true
					case "nilints":
						h.faults.nilInts = true
					case "multiplier250":
						h.faults.multiplier = 250
						h.meter.GasCost.CryptoAPICost.GenerateKeyECC = 100
					}
					f.seen = 0
					var rc int32
					void := false
					switch name {
					case "add":
						void = true
						h.hooks.AddEC(xo, yo, ec, x, y, x2, y2)
					case "double":
						void = true
						h.hooks.DoubleEC(xo, yo, ec, x, y)
					case "ison":
						rc = h.hooks.IsOnCurveEC(ec, x, y)
					case "marshal":
						if managed {
							rc = h.hooks.ManagedMarshalEC(x, y, ec, out)
						} else {
							rc = h.hooks.MarshalEC(x, y, ec, 256)
						}
					case "marshal_compressed":
						if managed {
							rc = h.hooks.ManagedMarshalCompressedEC(x, y, ec, out)
						} else {
							rc = h.hooks.MarshalCompressedEC(x, y, ec, 256)
						}
					case "unmarshal":
						if managed {
							rc = h.hooks.ManagedUnmarshalEC(xo, yo, ec, in)
						} else {
							rc = h.hooks.UnmarshalEC(xo, yo, ec, 0, int32(len(data)))
						}
					case "unmarshal_compressed":
						if managed {
							rc = h.hooks.ManagedUnmarshalCompressedEC(xo, yo, ec, in)
						} else {
							rc = h.hooks.UnmarshalCompressedEC(xo, yo, ec, 0, int32(len(data)))
						}
					case "generate":
						if managed {
							rc = h.hooks.ManagedGenerateKeyEC(xo, yo, ec, out)
						} else {
							rc = h.hooks.GenerateKeyEC(xo, yo, ec, 256)
						}
					case "create":
						if managed {
							rc = h.hooks.ManagedCreateEC(in)
						} else {
							rc = h.hooks.CreateEC(0, int32(len(data)))
						}
					case "length":
						rc = h.hooks.GetCurveLengthEC(ec)
					case "private_length":
						rc = h.hooks.GetPrivKeyByteLengthEC(ec)
					case "values":
						rc = h.hooks.EllipticCurveGetValues(ec, xo, yo, v2, v3, v4)
					}
					success := mode == "healthy" || mode == "multiplier250" || mode == "p224" || mode == "p384" || mode == "p521"
					if name == "ison" && mode == "invalid1" {
						require.Zero(t, rc)
						require.NoError(t, h.runtime.err)
						return
					}
					if name == "create" && mode == "unsupported" && !managed {
						require.Equal(t, int32(-1), rc)
						require.NoError(t, h.runtime.err)
						return
					}
					if success {
						require.NoError(t, h.runtime.err)
						switch name {
						case "ison":
							require.Equal(t, int32(1), rc)
						case "length":
							require.Equal(t, int32(256), rc)
						case "private_length":
							require.Equal(t, int32(32), rc)
						case "create":
							c, e := h.values.GetEllipticCurve(rc)
							require.NoError(t, e)
							want := curve
							if mode == "p224" {
								want = elliptic.P224().Params()
							}
							if mode == "p384" {
								want = elliptic.P384().Params()
							}
							if mode == "p521" {
								want = elliptic.P521().Params()
							}
							require.Equal(t, want, c)
						case "marshal", "marshal_compressed":
							b := h.memory.stored
							if managed {
								var e error
								b, e = h.values.GetBytes(out)
								require.NoError(t, e)
							}
							want := elliptic.Marshal(curve, curve.Gx, curve.Gy)
							if name == "marshal_compressed" {
								want = elliptic.MarshalCompressed(curve, curve.Gx, curve.Gy)
							}
							require.Equal(t, int32(len(want)), rc)
							require.Equal(t, want, b)
						case "values":
							require.Equal(t, ec, rc)
							for i, handle := range []int32{xo, yo, v2, v3, v4} {
								v, e := h.values.GetBigInt(handle)
								require.NoError(t, e)
								require.Equal(t, []*big.Int{curve.P, curve.N, curve.B, curve.Gx, curve.Gy}[i], v)
							}
						case "generate":
							require.Zero(t, rc)
							xx, _ := h.values.GetBigInt(xo)
							yy, _ := h.values.GetBigInt(yo)
							priv := h.memory.stored
							if managed {
								priv, _ = h.values.GetBytes(out)
							}
							require.Len(t, priv, 32)
							wx, wy := curve.ScalarBaseMult(priv)
							require.Equal(t, wx, xx)
							require.Equal(t, wy, yy)
							if mode == "multiplier250" {
								require.Equal(t, uint64(500), h.meter.charges[0])
							}
						default:
							require.Zero(t, rc)
							xx, _ := h.values.GetBigInt(xo)
							yy, _ := h.values.GetBigInt(yo)
							wx, wy := curve.Gx, curve.Gy
							if name == "add" || name == "double" {
								wx, wy = curve.Double(curve.Gx, curve.Gy)
							}
							require.Equal(t, wx, xx)
							require.Equal(t, wy, yy)
						}
						return
					}
					want := qualG10Injected
					code := int32(1)
					if name == "marshal" || name == "marshal_compressed" || name == "create" || name == "length" || name == "private_length" || name == "values" {
						code = -1
					}
					if name == "ison" && mode != "missing_curve" {
						code = -1
					}
					if (name == "unmarshal" || name == "unmarshal_compressed") && mode == "gas" {
						code = -1
					}
					if name == "unmarshal_compressed" && mode == "input" {
						code = 0
					}
					if name == "generate" && mode == "store" {
						code = 32
					}
					if mode == "missing_curve" {
						want = vmhost.ErrNoEllipticCurveUnderThisHandle
						if name == "create" {
							want = vmhost.ErrBadBounds
						}
					}
					if mode == "unsupported" {
						want = vmhost.ErrBadBounds
					}
					if mode == "nilints" || ((name == "add" || name == "double" || name == "ison" || name == "marshal_compressed") && f.target == "ints") {
						want = vmhost.ErrNoBigIntUnderThisHandle
					}
					if mode == "invalid1" || mode == "invalid2" || mode == "invalid_encoding" {
						want = vmhost.ErrPointNotOnCurve
					}
					if mode == "bad_length" || mode == "tiny" {
						want = vmhost.ErrLengthOfBufferNotCorrect
					}
					if !void {
						require.Equal(t, code, rc, "EC ABI guard code")
					}
					require.ErrorIs(t, h.runtime.err, want, "EC ABI guard cause")
					if f.target != "" {
						require.GreaterOrEqual(t, f.seen, f.nth, "EC injection reached")
					}
					if !(name == "generate" && mode == "store") && name != "create" {
						xx, _ := h.values.GetBigInt(xo)
						yy, _ := h.values.GetBigInt(yo)
						require.Equal(t, big.NewInt(17), xx, "EC denial preserves x")
						require.Equal(t, big.NewInt(19), yy, "EC denial preserves y")
					}
				})
			}
		}
	}
}
