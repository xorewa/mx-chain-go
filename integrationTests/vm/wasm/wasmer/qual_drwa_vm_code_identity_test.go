package wasmer

import (
	"bytes"
	"os"
	"testing"

	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	vmconfig "github.com/multiversx/mx-chain-vm-go/config"
	"github.com/multiversx/mx-chain-vm-go/executor"
	contextmock "github.com/multiversx/mx-chain-vm-go/mock/context"
	"github.com/multiversx/mx-chain-vm-go/vmhost"
	"github.com/multiversx/mx-chain-vm-go/vmhost/contexts"
	"github.com/multiversx/mx-chain-vm-go/vmhost/vmhooks"
	"github.com/multiversx/mx-chain-vm-go/wasmer2"
	"github.com/stretchr/testify/require"
)

// AT-04, SQ-04/05 and V263-Q18: native instance identity at the runtime/cache
// boundary. Real Wasmer compilation, compiled-code loading and warm instances
// are used; accounts/compiled storage use the upstream hook stub. These tests
// do not execute an upgrade transaction, a VM callback or a network replay.
// Expected exports come from the upstream counter WAT and hello-v2 C source.
type qualDRWACacheExecutor struct {
	executor.Executor
	compiled, loaded int
}

func (e *qualDRWACacheExecutor) NewInstanceWithOptions(code []byte, options executor.CompilationOptions) (executor.Instance, error) {
	e.compiled++
	return e.Executor.NewInstanceWithOptions(code, options)
}

func (e *qualDRWACacheExecutor) NewInstanceFromCompiledCodeWithOptions(code []byte, options executor.CompilationOptions) (executor.Instance, error) {
	e.loaded++
	return e.Executor.NewInstanceFromCompiledCodeWithOptions(code, options)
}

type qualDRWACacheHarness struct {
	runtime                    vmhost.RuntimeContext
	output                     vmhost.OutputContext
	exec                       *qualDRWACacheExecutor
	codeA, codeB, hashA, hashB []byte
	compiled                   map[string][]byte
	reads, writes              [][]byte
}

func qualDRWANewCacheHarness(t *testing.T) *qualDRWACacheHarness {
	t.Helper()
	h := &qualDRWACacheHarness{compiled: make(map[string][]byte)}
	var err error
	h.codeA, err = os.ReadFile("../testdata/counter/output/counter.wasm")
	require.NoError(t, err)
	h.codeB, err = os.ReadFile("../testdata/hello-v2/output/answer.wasm")
	require.NoError(t, err)
	hasher := blake2b.NewBlake2b()
	h.hashA = hasher.Compute(string(h.codeA))
	h.hashB = hasher.Compute(string(h.codeB))
	require.NotEqual(t, h.hashA, h.hashB)
	host := &contextmock.VMHostMock{}
	metering := &contextmock.MeteringContextMock{}
	metering.SetGasSchedule(vmconfig.MakeGasMapForTests())
	host.MeteringContext = metering
	hook := &contextmock.BlockchainHookStub{
		GetUserAccountCalled: func(address []byte) (vmcommon.UserAccountHandler, error) {
			// Both accounts have the original committed code. A pending code
			// update exists only in the real output context, not this stub.
			return &contextmock.StubAccount{Address: bytes.Clone(address), CodeHash: bytes.Clone(h.hashA)}, nil
		},
		GetCodeCalled: func(_ vmcommon.UserAccountHandler) []byte { return bytes.Clone(h.codeA) },
		GetCompiledCodeCalled: func(hash []byte) (bool, []byte) {
			h.reads = append(h.reads, bytes.Clone(hash))
			code, ok := h.compiled[string(hash)]
			return ok, bytes.Clone(code)
		},
		SaveCompiledCodeCalled: func(hash, code []byte) {
			h.writes = append(h.writes, bytes.Clone(hash))
			h.compiled[string(hash)] = bytes.Clone(code)
		},
	}
	host.BlockchainContext, err = contexts.NewBlockchainContext(host, hook)
	require.NoError(t, err)
	host.OutputContext, err = contexts.NewOutputContext(host)
	require.NoError(t, err)
	h.output = host.OutputContext
	native, err := wasmer2.ExecutorFactory().CreateExecutor(executor.ExecutorFactoryArgs{
		VMHooks: vmhooks.NewVMHooksImpl(host), OpcodeCosts: metering.GasSchedule().WASMOpcodeCost,
	})
	require.NoError(t, err)
	h.exec = &qualDRWACacheExecutor{Executor: native}
	h.runtime, err = contexts.NewRuntimeContext(host, []byte("type"), builtInFunctions.NewBuiltInFunctionContainer(), h.exec, hasher)
	require.NoError(t, err)
	host.RuntimeContext = h.runtime
	h.runtime.SetMaxInstanceStackSize(8)
	t.Cleanup(h.runtime.ClearWarmInstanceCache)
	return h
}

func (h *qualDRWACacheHarness) selectCode(t *testing.T, address string, code []byte) {
	t.Helper()
	h.runtime.SetCodeAddress([]byte(address))
	if code != nil {
		account, _ := h.output.GetOutputAccount([]byte(address))
		account.Code = bytes.Clone(code)
	}
	actual, err := h.runtime.GetSCCode()
	require.NoError(t, err)
	if code == nil {
		code = h.codeA
	}
	require.Equal(t, code, actual)
	require.NoError(t, h.runtime.StartWasmerInstance(actual, 100000000, false))
}

func (h *qualDRWACacheHarness) assertCode(t *testing.T, wantB bool) {
	t.Helper()
	require.Equal(t, wantB, h.runtime.HasFunction("getUltimateAnswer"), "selected native instance must match requested bytes")
	require.Equal(t, !wantB, h.runtime.HasFunction("increment"), "old and new native export sets must remain distinct")
}

func TestQualDRWACacheIdentityPendingOutput(t *testing.T) {
	for _, tc := range []struct {
		name                                     string
		seedA, seedB, clearWarm, invalidCompiled bool
		compiled, loaded                         int
	}{
		{name: "cold", compiled: 1},
		{name: "old_warm", seedA: true, compiled: 1},
		{name: "old_compiled", seedA: true, clearWarm: true, compiled: 1},
		{name: "new_warm", seedB: true},
		{name: "new_compiled", seedB: true, clearWarm: true, loaded: 1},
		{name: "invalid_new_compiled_falls_back", invalidCompiled: true, compiled: 1, loaded: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := qualDRWANewCacheHarness(t)
			if tc.seedA {
				h.selectCode(t, "seed-A", nil)
				h.assertCode(t, false)
			}
			if tc.seedB {
				h.selectCode(t, "seed-B", h.codeB)
				h.assertCode(t, true)
			}
			if tc.clearWarm {
				h.runtime.ClearWarmInstanceCache()
			}
			if tc.invalidCompiled {
				h.compiled[string(h.hashB)] = []byte("invalid compiled code")
			}
			h.output.InitState()
			oldCache, oldPresent := h.compiled[string(h.hashA)]
			oldCache = bytes.Clone(oldCache)
			compiled, loaded := h.exec.compiled, h.exec.loaded
			h.reads, h.writes = nil, nil
			h.selectCode(t, "changed-account", h.codeB)
			h.assertCode(t, true)
			require.Equal(t, tc.compiled, h.exec.compiled-compiled)
			require.Equal(t, tc.loaded, h.exec.loaded-loaded)
			for _, hash := range append(h.reads, h.writes...) {
				require.Equal(t, h.hashB, hash)
			}
			now, present := h.compiled[string(h.hashA)]
			require.Equal(t, oldPresent, present, "pending code must not create an old-hash entry")
			require.Equal(t, oldCache, now, "pending code must not overwrite an old-hash entry")
			// Independent account with the same committed original hash must
			// still select the original instance after the pending-code call.
			h.selectCode(t, "original-account", nil)
			h.assertCode(t, false)
		})
	}
}

func TestQualDRWABytecodeCompilationRebindsIdentity(t *testing.T) {
	h := qualDRWANewCacheHarness(t)
	h.runtime.SetCodeAddress([]byte("stale-hash-fixture"))
	// Deliberately bypass GetSCCode to isolate the post-compilation safeguard.
	// This is a runtime-boundary negative fixture, not a reachable transaction.
	require.NoError(t, h.runtime.StartWasmerInstance(h.codeB, 100000000, false))
	h.assertCode(t, true)
	require.Equal(t, [][]byte{h.hashB}, h.writes, "compilation must store under the actual byte hash")
	_, oldPresent := h.compiled[string(h.hashA)]
	require.False(t, oldPresent)
}

func TestQualDRWACacheIdentityOutputRollbackAndStack(t *testing.T) {
	h := qualDRWANewCacheHarness(t)
	h.selectCode(t, "same-account", nil)
	original := h.runtime.GetInstance()
	h.output.PushState()
	h.runtime.PushState()
	h.selectCode(t, "same-account", h.codeB)
	h.assertCode(t, true)
	h.runtime.PopSetActiveState()
	h.output.PopSetActiveState()
	require.Same(t, original, h.runtime.GetInstance())
	h.assertCode(t, false)
	require.Zero(t, h.runtime.GetInstanceStackSize())
	code, err := h.runtime.GetSCCode()
	require.NoError(t, err)
	require.Equal(t, h.codeA, code, "output rollback must restore original code")
	// Compiled pending bytes may remain cached, but never under the old hash.
	h.runtime.ClearWarmInstanceCache()
	h.selectCode(t, "same-account", nil)
	h.assertCode(t, false)
}
