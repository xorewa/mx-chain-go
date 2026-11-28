package drwa

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/sharding"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func sp232Mutated(w *sp232World, transfer vmcommon.OutputTransfer, mutate func(*adminEffectEnvelope)) vmcommon.OutputTransfer {
	e := w.envelope(transfer)
	mutate(&e)
	return sp232With(transfer, sp232Frame(sp232Domain, e))
}

// recall changes the inner call of an envelope consistently: payload,
// discriminator and normalized digest.
func (w *sp232World) recall(e *adminEffectEnvelope, function string, arguments ...[]byte) {
	e.payload, e.discriminator = sp232Payload(function, arguments...), []byte(function)
	e.normalizedDigest = w.normalized(function, arguments...)
}

// Part A L3242-3246: "User-supplied bytes cannot set this context. Copying an
// envelope into an ordinary transaction or arbitrary SCR therefore does not
// authorize the inner admin built-in". The same canonical envelope, byte for
// byte, arrives by every call that is not the protected metachain result.
func TestQualSP232CopiedEnvelopeCreatesNoVerifiedContext(t *testing.T) {
	w := sp232New(t)
	shard := w.shards[1]
	_, transfers := w.open(w.grant(1, core.ESDTRoleLocalMint))
	system := registryDeltaSystemAddress(1)
	user := sp232Holder(1, 9)
	contract := make([]byte, 32)
	contract[20], contract[31] = 5, 1
	require.True(t, core.IsSmartContractAddress(contract))

	cases := []struct {
		name   string
		mutate func(*vmcommon.ContractCallInput)
	}{
		{"user transaction", func(in *vmcommon.ContractCallInput) { in.CallerAddr, in.CallType = user, vmData.DirectCall }},
		{"user transaction claiming the asynchronous type", func(in *vmcommon.ContractCallInput) { in.CallerAddr = user }},
		{"user transaction of the role holder", func(in *vmcommon.ContractCallInput) { in.CallerAddr, in.CallType = shard.holder, vmData.DirectCall }},
		{"contract result, asynchronous call", func(in *vmcommon.ContractCallInput) { in.CallerAddr = contract }},
		{"contract result, direct call", func(in *vmcommon.ContractCallInput) { in.CallerAddr, in.CallType = contract, vmData.DirectCall }},
		{"contract result, transfer and execute", func(in *vmcommon.ContractCallInput) {
			in.CallerAddr, in.CallType = contract, vmData.ESDTTransferAndExecute
		}},
		{"contract execution on destination context", func(in *vmcommon.ContractCallInput) {
			in.CallerAddr, in.CallType = contract, vmData.ExecOnDestByCaller
		}},
		{"another system contract as sender", func(in *vmcommon.ContractCallInput) {
			in.CallerAddr = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 255, 255}
		}},
		{"the shard system account as sender", func(in *vmcommon.ContractCallInput) { in.CallerAddr = system }},
		{"ESDT system contract, direct call", func(in *vmcommon.ContractCallInput) { in.CallType = vmData.DirectCall }},
		{"ESDT system contract, callback", func(in *vmcommon.ContractCallInput) { in.CallType = vmData.AsynchronousCallBack }},
		{"sent to the role holder instead of the system account", func(in *vmcommon.ContractCallInput) { in.RecipientAddr = shard.holder }},
		{"sent to another shard's system account", func(in *vmcommon.ContractCallInput) { in.RecipientAddr = registryDeltaSystemAddress(2) }},
		{"sent to the bare system account address", func(in *vmcommon.ContractCallInput) { in.RecipientAddr = bytes.Clone(core.SystemAccountAddress) }},
		{"with value", func(in *vmcommon.ContractCallInput) { in.CallValue = big.NewInt(1) }},
		{"without value field", func(in *vmcommon.ContractCallInput) { in.CallValue = nil }},
		{"without a result hash", func(in *vmcommon.ContractCallInput) { in.CurrentTxHash = nil }},
		{"with a second argument", func(in *vmcommon.ContractCallInput) { in.Arguments = append(in.Arguments, []byte{1}) }},
		// R01.08: a result whose data was lost carries no envelope.
		{"without data", func(in *vmcommon.ContractCallInput) { in.Arguments = nil }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := sp232Input(t, system, transfers[0], "leg result hash")
			c.mutate(in)
			calls := shard.binding.calls
			shard.refused(c.name, in)
			require.Equal(t, calls, shard.binding.calls, "refused before the envelope is read")
			require.Empty(t, shard.roles())
		})
	}
	t.Run("nil input", func(t *testing.T) {
		_, err := shard.function.ProcessBuiltinFunction(nil, nil, nil)
		require.ErrorIs(t, err, ErrInvalidAdminEffect)
	})
	// The native role built-in itself stays refused for the regulated token on
	// the public path, whoever sends it.
	admission := NewBuiltInAdmission(shard.registry)
	for _, function := range []string{core.BuiltInFunctionSetESDTRole, core.BuiltInFunctionUnSetESDTRole,
		core.BuiltInFunctionESDTSetLimitedTransfer, core.ESDTSetTokenType} {
		builtIn, err := shard.builtIns.Get(function)
		require.NoError(t, err)
		err = admission.AdmitBuiltIn(builtIn, &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: core.ESDTSCAddress,
			CallValue: big.NewInt(0), Arguments: [][]byte{[]byte(sp232Token), []byte(core.ESDTRoleLocalMint)}},
			RecipientAddr: shard.holder, Function: function})
		require.ErrorIs(t, err, ErrRegulatedTokenOperation, function)
	}
	// The protected function has no identifier of its own to classify.
	require.NoError(t, admission.AdmitBuiltIn(shard.function, sp232Input(t, system, transfers[0], "leg result hash")))

	// The canonical leg still applies afterwards.
	_, err := shard.deliver(transfers[0])
	require.NoError(t, err)
	require.Equal(t, sp232Roles(core.ESDTRoleLocalMint), shard.roles())
}

// Part A section 13 item 6: "wrong origin, target shard, plan step, CEB/GAS
// binding, predecessor/result hash or normalized inner payload denies."
func TestQualSP232WrongEnvelopeIsRefusedWithNoState(t *testing.T) {
	w := sp232New(t)
	shard := w.shards[1]
	_, transfers := w.open(w.grant(1, core.ESDTRoleLocalMint))
	system := registryDeltaSystemAddress(1)
	token, role := []byte(sp232Token), []byte(core.ESDTRoleLocalMint)
	contract := make([]byte, 32)
	contract[20], contract[31] = 5, 1
	step := make([]byte, 8)

	cases := []struct {
		name   string
		mutate func(*adminEffectEnvelope)
	}{
		{"target shard: leg of another shard", func(e *adminEffectEnvelope) { e.targetShard = 2 }},
		{"target shard: the metachain", func(e *adminEffectEnvelope) { e.targetShard = core.MetachainShardId }},
		{"inner payload: changed, digest kept", func(e *adminEffectEnvelope) {
			e.payload = sp232Payload(core.BuiltInFunctionSetESDTRole, token, []byte(core.ESDTRoleLocalBurn))
		}},
		{"inner payload: digest changed, payload kept", func(e *adminEffectEnvelope) { e.normalizedDigest = w.hash("other digest") }},
		{"inner payload: discriminator of another function", func(e *adminEffectEnvelope) {
			e.discriminator = []byte(core.BuiltInFunctionUnSetESDTRole)
		}},
		{"inner payload: not a call", func(e *adminEffectEnvelope) { e.payload = []byte("@@") }},
		{"inner payload: empty", func(e *adminEffectEnvelope) { e.payload = nil }},
		{"inner payload: token other than the envelope's", func(e *adminEffectEnvelope) {
			w.recall(e, core.BuiltInFunctionSetESDTRole, []byte("OTHER-0a1b2c"), role)
		}},
		{"inner payload: no token argument", func(e *adminEffectEnvelope) { w.recall(e, core.BuiltInFunctionSetESDTRole) }},
		{"predecessor hash", func(e *adminEffectEnvelope) { e.predecessor = w.hash("other predecessor") }},
		{"predecessor hash: already the result", func(e *adminEffectEnvelope) { e.predecessor = e.result }},
		{"result hash", func(e *adminEffectEnvelope) { e.result = w.hash("other result") }},
		{"result hash: the predecessor", func(e *adminEffectEnvelope) { e.result = e.predecessor }},
		{"CEB binding: prepared, not held", func(e *adminEffectEnvelope) { e.binding = []byte("PREPARED_CEB") }},
		{"CEB binding: terminal, not held", func(e *adminEffectEnvelope) { e.binding = []byte("TERMINAL") }},
		{"CEB binding: unknown kind", func(e *adminEffectEnvelope) { e.binding = []byte("NEXT_CEB") }},
		{"CEB binding: another epoch", func(e *adminEffectEnvelope) { e.cebEpoch = 3 }},
		{"GAS binding: an action the shard does not hold", func(e *adminEffectEnvelope) { e.actionID = w.hash("other action") }},
		{"GAS binding: action of wrong size", func(e *adminEffectEnvelope) { e.actionID = []byte("short") }},
		{"plan step: a plan the shard does not hold", func(e *adminEffectEnvelope) {
			e.planDigest, e.planStep = w.hash("other plan"), step
		}},
		{"plan step: step without a plan", func(e *adminEffectEnvelope) { e.planStep = step }},
		{"plan step: plan without a step", func(e *adminEffectEnvelope) { e.planDigest = w.hash("other plan") }},
		{"work limit above the carrier's gas", func(e *adminEffectEnvelope) { e.workLimit = sp232LegGas + 1 }},
		{"work limit zero", func(e *adminEffectEnvelope) { e.workLimit = 0 }},
		{"no pricing identity", func(e *adminEffectEnvelope) { e.gasVersion = nil }},
		{"target: a contract", func(e *adminEffectEnvelope) { e.targetKey = contract }},
		{"target: an account of another shard", func(e *adminEffectEnvelope) { e.targetKey = sp232Holder(2, 7) }},
		{"target: the system account, for a role", func(e *adminEffectEnvelope) { e.targetKey = bytes.Clone(core.SystemAccountAddress) }},
		{"target: a shard system address, for a role", func(e *adminEffectEnvelope) { e.targetKey = system }},
		{"target: short address", func(e *adminEffectEnvelope) { e.targetKey = []byte("short") }},
		{"target: none", func(e *adminEffectEnvelope) { e.targetKey = nil }},
		{"target: an account, for a global setting", func(e *adminEffectEnvelope) {
			w.recall(e, core.BuiltInFunctionESDTSetLimitedTransfer, token)
		}},
		{"operation: metadata", func(e *adminEffectEnvelope) { e.operation = []byte("DRWAMetadataMutation") }},
		{"operation: unknown", func(e *adminEffectEnvelope) { e.operation = []byte("DRWAOther") }},
		{"operation: requalification without action and plan", func(e *adminEffectEnvelope) {
			e.operation = []byte("DRWAApplyRequalificationAdmin")
		}},
		{"token: not a token identifier", func(e *adminEffectEnvelope) { e.tokenID = []byte("x") }},
		{"token type: unknown", func(e *adminEffectEnvelope) { e.tokenType = []byte("Other") }},
		{"effect identifier of wrong size", func(e *adminEffectEnvelope) { e.effectID = []byte("short") }},
		{"leg identifier of wrong size", func(e *adminEffectEnvelope) { e.legID = nil }},
		{"origin identity of wrong size", func(e *adminEffectEnvelope) { e.origin = nil }},
		{"open effect commitment of wrong size", func(e *adminEffectEnvelope) { e.openCommitment = []byte("short") }},
	}
	// Inner effects outside the closed set (Part A L3185 and the inventory).
	for _, function := range []string{core.BuiltInFunctionESDTPause, core.BuiltInFunctionESDTUnPause,
		core.BuiltInFunctionESDTFreeze, core.BuiltInFunctionESDTUnFreeze, core.BuiltInFunctionESDTWipe,
		vmcommon.BuiltInFunctionESDTSetBurnRoleForAll, core.BuiltInFunctionESDTNFTCreateRoleTransfer,
		core.BuiltInFunctionESDTTransfer, core.BuiltInFunctionESDTLocalMint, core.BuiltInFunctionESDTLocalBurn,
		core.ESDTMetaDataUpdate, core.BuiltInFunctionSaveKeyValue, RegistryDeltaFunctionName, AdminEffectFunctionName, "unknownFunction"} {
		cases = append(cases, struct {
			name   string
			mutate func(*adminEffectEnvelope)
		}{"inner effect not admitted: " + function, func(e *adminEffectEnvelope) { w.recall(e, function, token, role) }})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			calls := shard.binding.calls
			shard.refused(c.name, sp232Input(t, system, sp232Mutated(w, transfers[0], c.mutate), "leg result hash"))
			require.Empty(t, shard.roles())
			if c.name == "work limit above the carrier's gas" {
				require.Equal(t, calls, shard.binding.calls, "refused before the binding is consulted and before any effect")
			}
		})
	}
	// The same refusals with every hash of the envelope consistent with what
	// it asks for, so that only the rule named refuses it.
	limitedKey := append([]byte(adminTokenKeyPrefix), sp232Token...)
	consistent := []struct {
		name   string
		mutate func(*adminEffectEnvelope)
	}{
		{"role for a contract, hashes of that contract", func(e *adminEffectEnvelope) {
			e.targetKey, e.predecessor, e.result = contract, w.rolesHash(contract), w.rolesHash(contract, core.ESDTRoleLocalMint)
		}},
		{"role for an account of another shard, hashes of that account", func(e *adminEffectEnvelope) {
			other := sp232Holder(2, 7)
			e.targetKey, e.predecessor, e.result = other, w.rolesHash(other), w.rolesHash(other, core.ESDTRoleLocalMint)
		}},
		{"role for a shard system address, hashes of that address", func(e *adminEffectEnvelope) {
			e.targetKey, e.predecessor, e.result = system, w.rolesHash(system), w.rolesHash(system, core.ESDTRoleLocalMint)
		}},
		{"role for an address of another length, hashes of that address", func(e *adminEffectEnvelope) {
			odd := []byte{9, 9, 9, 9, 1}
			e.targetKey, e.predecessor, e.result = odd, w.rolesHash(odd), w.rolesHash(odd, core.ESDTRoleLocalMint)
		}},
		{"global setting declared on an account that it does not change", func(e *adminEffectEnvelope) {
			w.recall(e, core.BuiltInFunctionESDTSetLimitedTransfer, token)
			e.predecessor = w.stateHash(shard.holder, limitedKey, nil)
			e.result = e.predecessor
		}},
		{"role of another token, the envelope's token unchanged", func(e *adminEffectEnvelope) {
			w.recall(e, core.BuiltInFunctionSetESDTRole, []byte("OTHER-0a1b2c"), role)
			e.result = e.predecessor
		}},
	}
	for _, c := range consistent {
		t.Run(c.name, func(t *testing.T) {
			shard.refused(c.name, sp232Input(t, system, sp232Mutated(w, transfers[0], c.mutate), "leg result hash"))
			require.Empty(t, shard.roles())
			require.Empty(t, shard.value(shard.holder, append([]byte(adminRolesKeyPrefix), "OTHER-0a1b2c"...)))
			require.Empty(t, shard.value(core.SystemAccountAddress, limitedKey))
		})
	}
	raw := w.envelope(transfers[0])
	canonical := sp232Frame(sp232Domain, raw)
	_, arguments := sp232Input(t, system, transfers[0], "h").Function, sp232Input(t, system, transfers[0], "h").Arguments
	require.Equal(t, canonical, arguments[0], "the independent wire form is the emitted envelope")
	for name, envelope := range map[string][]byte{
		"another network domain": sp232Frame([]byte("another network"), raw),
		"truncated":              canonical[:len(canonical)-1],
		"trailing byte":          append(bytes.Clone(canonical), 0),
		"one field less":         qualRecordFrame([]byte("DRWA/ADMIN_ENVELOPE/candidate1"), sp232Domain),
		"another tag":            bytes.Replace(canonical, []byte("ADMIN_ENVELOPE"), []byte("ADMIN_ENVELOPF"), 1),
		"empty":                  {},
		"oversized":              bytes.Repeat([]byte{1}, 5000),
	} {
		t.Run("envelope: "+name, func(t *testing.T) {
			shard.refused(name, sp232Input(t, system, sp232With(transfers[0], envelope), "leg result hash"))
		})
	}
	// Wrong origin: an envelope that names another origin execution has
	// another effect identity on the metachain. Were it ever applied, its item
	// is not the retained leg's and acknowledges nothing (see the origin tests).
	_, err := shard.deliver(transfers[0])
	require.NoError(t, err)
	require.Equal(t, sp232Roles(core.ESDTRoleLocalMint), shard.roles())
}

// The destination's own dependencies: an unregulated token, no binding source,
// a failing binding source, no network domain, an unresolved registry.
func TestQualSP232DestinationDependencies(t *testing.T) {
	w := sp232New(t)
	shard := w.shards[1]
	_, transfers := w.open(w.grant(1, core.ESDTRoleLocalMint))
	system := registryDeltaSystemAddress(1)
	input := func() *vmcommon.ContractCallInput { return sp232Input(t, system, transfers[0], "leg result hash") }

	t.Run("token not in this shard's registry", func(t *testing.T) {
		other := []byte("OTHER-0a1b2c")
		shard.refused("unregulated", sp232Input(t, system, sp232Mutated(w, transfers[0], func(e *adminEffectEnvelope) {
			e.tokenID = other
			w.recall(e, core.BuiltInFunctionSetESDTRole, other, []byte(core.ESDTRoleLocalMint))
		}), "leg result hash"))
	})
	t.Run("binding source refuses", func(t *testing.T) {
		shard.binding.err = errSP232
		calls := shard.binding.calls
		before := shard.root()
		_, err := shard.call(input())
		require.ErrorIs(t, err, errSP232)
		require.ErrorIs(t, err, ErrInvalidAdminEffect)
		require.Equal(t, before, shard.root())
		require.Equal(t, calls+1, shard.binding.calls)
		shard.binding.err = nil
	})
	t.Run("no network domain", func(t *testing.T) {
		shard.domain = nil
		shard.refused("no domain", input())
		shard.domain = bytes.Repeat([]byte{1}, 5000)
		shard.refused("oversized domain", input())
		shard.domain = sp232Domain
	})

	coordinator, err := sharding.NewMultiShardCoordinator(3, 1)
	require.NoError(t, err)
	args := ArgsAdminEffectFunction{Accounts: shard.store, Marshaller: &marshal.GogoProtoMarshalizer{},
		Hasher: shard.f.reader.accounts.args.Hasher, Classifier: shard.registry, BuiltIns: shard.builtIns, Shard: 1,
		ShardOf: coordinator.ComputeId, Domain: func() []byte { return sp232Domain }, RecordBytes: 4096}
	run := func(function *AdminEffectFunction) error {
		before, snapshot := shard.root(), shard.store.JournalLen()
		_, callErr := function.ProcessBuiltinFunction(nil, nil, input())
		require.Equal(t, snapshot, shard.store.JournalLen())
		require.Equal(t, before, shard.root())
		return callErr
	}
	t.Run("no binding source installed", func(t *testing.T) {
		function, e := NewAdminEffectFunction(args)
		require.NoError(t, e)
		require.ErrorIs(t, run(function), ErrInvalidAdminEffect)
		require.Error(t, function.SetBindingSource(nil))
		require.Error(t, function.SetBindingSource((*sp232Binding)(nil)))
		require.NoError(t, function.SetBindingSource(shard.binding))
		require.Error(t, function.SetBindingSource(shard.binding), "installed once")
	})
	t.Run("registry unresolved", func(t *testing.T) {
		unresolved := args
		unresolved.Classifier = NewShardClassification(nil)
		function, e := NewAdminEffectFunction(unresolved)
		require.NoError(t, e)
		require.NoError(t, function.SetBindingSource(shard.binding))
		require.ErrorIs(t, run(function), ErrClassificationUnresolved)
	})
	t.Run("construction", func(t *testing.T) {
		for name, mutate := range map[string]func(*ArgsAdminEffectFunction){
			"no classifier":      func(a *ArgsAdminEffectFunction) { a.Classifier = nil },
			"no built-ins":       func(a *ArgsAdminEffectFunction) { a.BuiltIns = nil },
			"no shard rule":      func(a *ArgsAdminEffectFunction) { a.ShardOf = nil },
			"no domain source":   func(a *ArgsAdminEffectFunction) { a.Domain = nil },
			"metachain":          func(a *ArgsAdminEffectFunction) { a.Shard = core.MetachainShardId },
			"shard out of range": func(a *ArgsAdminEffectFunction) { a.Shard = 256 },
			"no accounts":        func(a *ArgsAdminEffectFunction) { a.Accounts = nil },
			"no hasher":          func(a *ArgsAdminEffectFunction) { a.Hasher = nil },
			"no record bound":    func(a *ArgsAdminEffectFunction) { a.RecordBytes = 0 },
		} {
			bad := args
			mutate(&bad)
			function, e := NewAdminEffectFunction(bad)
			require.Error(t, e, name)
			require.Nil(t, function, name)
		}
		require.True(t, (*AdminEffectFunction)(nil).IsInterfaceNil())
		require.True(t, (*verifiedAdminEffectContext)(nil).IsInterfaceNil())
	})

	_, err = shard.deliver(transfers[0])
	require.NoError(t, err)
}

// A requalification plan leg applies only under the exact prepared binding,
// action, plan and step this shard holds; the binding source receives the
// decoded leg.
func TestQualSP232RequalificationPlanLegNeedsItsExactBinding(t *testing.T) {
	w := sp232New(t)
	shard := w.shards[1]
	step, other := uint64(4), uint64(5)
	request := w.grant(1, core.ESDTRoleLocalBurn)
	request.Operation, request.Binding, request.Epoch = "DRWAApplyRequalificationAdmin", "PREPARED_CEB", 9
	request.ActionID, request.PlanDigest, request.PlanStep = w.hash("governed action"), w.hash("requalification plan"), &step
	_, transfers := w.open(request)
	system := registryDeltaSystemAddress(1)

	shard.refused("prepared binding not held", sp232Input(t, system, transfers[0], "leg result hash"))
	shard.binding.held[sp232Context("PREPARED_CEB", 9, request.ActionID, request.PlanDigest, &other)] = struct{}{}
	shard.refused("another step of the plan held", sp232Input(t, system, transfers[0], "leg result hash"))
	shard.binding.held[sp232Context("CURRENT_CEB", 9, request.ActionID, request.PlanDigest, &step)] = struct{}{}
	shard.refused("held as current, not prepared", sp232Input(t, system, transfers[0], "leg result hash"))

	shard.binding.held[sp232Context("PREPARED_CEB", 9, request.ActionID, request.PlanDigest, &step)] = struct{}{}
	_, err := shard.deliver(transfers[0])
	require.NoError(t, err)
	require.Equal(t, sp232Roles(core.ESDTRoleLocalBurn), shard.roles())
	seen := shard.binding.last
	require.Equal(t, "DRWAApplyRequalificationAdmin", seen.Operation)
	require.Equal(t, core.BuiltInFunctionSetESDTRole, seen.Function)
	require.Equal(t, [][]byte{[]byte(sp232Token), []byte(core.ESDTRoleLocalBurn)}, seen.Arguments)
	require.Equal(t, step, *seen.PlanStep)
	require.Equal(t, shard.holder, seen.Target)
	require.Equal(t, uint32(1), seen.TargetShard)
	require.Equal(t, w.effectID(request), seen.EffectID)
	require.Equal(t, request.Origin, seen.Origin)
	require.Equal(t, []byte(sp232Token), seen.TokenID)
	require.Equal(t, []byte(core.FungibleESDT), seen.TokenType)
}
