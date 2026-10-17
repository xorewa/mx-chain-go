package drwa

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"sync"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
)

// E10 option b adaptation: Part A L2257-2266/L2355-2373/L6388-6393
// (SHA d2f6ea1d4036c32e8778da53f135961de91cf0d8576c930fb0dd76651e1c7831).
// Reuses vm-common v1.7.2, commit 9893aa9005d4f47741fa41f9b09db4ec8728d355,
// builtInFunctions/esdtGlobalSettings.go L41-146/L184-190, SHA
// 94828a725d38b9455d0c82e1886b97f557f64029b88bfbb2f89898cd4d5cb6c4.
// Approved unwired construction: T16_E10_Construction_Proposal_02.json,
// SHA a48b5ee10bef02307e12bb374bc3fb2122bb6433be11c539ab579a833442813c.
// No ordinary dispatcher, public endpoint, ACK or production configuration is
// installed. T44 must bind canonical native context and install the guard before
// effects in every route; T45 owns ACK/profile readiness and manager admission.

var errBurnForAllDenied = errors.New("DRWA registered token global burn setting denied")

// ArgsBurnForAllAbsence supplies the existing native ownership/dependencies.
// It selects no epoch, address, numeric bound or production profile. Candidate
// and predecessor identities MUST already be authenticated by the native owner,
// as in T08; hashing supplied headers does not establish canonical finality.
// Accounts is exclusively owned, committed, and has the existing provisioned
// system account/data trie. Reader uses a separate native proof cache. Stable
// input ownership and native epoch/root retention are required throughout use.
type ArgsBurnForAllAbsence struct {
	Accounts                                               state.AccountsAdapter
	Reader                                                 *ResultAccountReader
	Marshaller                                             marshal.Marshalizer
	Hasher                                                 hashing.Hasher
	Validator                                              process.HeaderConstructionValidator
	EnableEpochsHandler                                    common.EnableEpochsHandler
	CandidateHash, Candidate, PredecessorHash, Predecessor []byte
	References                                             [][]byte
	MaxEver                                                uint64
	ProofByteLimit, RecordByteLimit                        int
}

// BurnForAllMemberWitness is untrusted native proof transport, not authority.
type BurnForAllMemberWitness struct {
	TokenID []byte
	Proof   AccountItemWitness
}

// BurnForAllAbsence is DRWA-defined E10 startup/reconstruction ownership of the
// existing T08 materialization plus native global-burn effects. It is not a new
// registry or protocol. Its mutex serializes all local operations; account
// aliases outside this owner remain forbidden by T04's exclusive-owner contract.
type BurnForAllAbsence struct {
	mut          sync.Mutex
	material     *registryMaterialization
	transport    *registryTransport
	records      *registrationRecords
	set, unset   vmcommon.BuiltinFunction
	protected    vmcommon.BuiltinFunction
	metadata     vmcommon.GlobalMetadataHandler
	tokenType    vmcommon.BuiltinFunction
	ordinaryType vmcommon.BuiltinFunction
	flags        common.EnableEpochsHandler
	normalizing  bool
}

func NewBurnForAllAbsence(a ArgsBurnForAllAbsence) (*BurnForAllAbsence, error) {
	if check.IfNil(a.EnableEpochsHandler) {
		return nil, builtInFunctions.ErrNilEnableEpochsHandler
	}
	c, err := newNativeMetaContext(a.Marshaller, a.Hasher, a.Validator)
	if err != nil {
		return nil, err
	}
	anchor, err := c.selectAnchor(a.CandidateHash, a.Candidate, a.PredecessorHash, a.Predecessor, a.References)
	if err != nil {
		return nil, err
	}
	t, err := newRegistryTransport(a.Reader, a.MaxEver, a.ProofByteLimit)
	if err != nil {
		return nil, err
	}
	m, err := newRegistryMaterialization(a.Accounts, anchor)
	if err != nil {
		return nil, err
	}
	r, err := newRegistrationRecords(a.Accounts, a.Marshaller, a.Hasher, a.RecordByteLimit)
	if err != nil {
		return nil, err
	}
	b := &BurnForAllAbsence{material: m, transport: t, records: r, flags: a.EnableEpochsHandler}
	active := func() bool { return a.EnableEpochsHandler.IsFlagEnabled(common.SendAlwaysFlag) }
	b.set, err = builtInFunctions.NewESDTGlobalSettingsFunc(a.Accounts, a.Marshaller, true, vmcommon.BuiltInFunctionESDTSetBurnRoleForAll, active)
	if err != nil {
		return nil, err
	}
	b.unset, err = builtInFunctions.NewESDTGlobalSettingsFunc(a.Accounts, a.Marshaller, false, vmcommon.BuiltInFunctionESDTUnSetBurnRoleForAll, active)
	if err != nil {
		return nil, err
	}
	// This instance is private. Eligibility is derived only after exact proof
	// authentication inside Normalize, never from a raw UNSET or caller flag.
	// SendAlways is off before cleanup's epoch; it cannot supply this path.
	setter, err := builtInFunctions.NewESDTGlobalSettingsFunc(a.Accounts, a.Marshaller, false,
		vmcommon.BuiltInFunctionESDTUnSetBurnRoleForAll, func() bool { return b.normalizing })
	if err != nil {
		return nil, err
	}
	b.protected, b.metadata = setter, setter
	b.tokenType, err = builtInFunctions.NewESDTSetTokenTypeFunc(a.Accounts, setter, a.Marshaller,
		func() bool { return b.normalizing && a.EnableEpochsHandler.IsFlagEnabled(common.DynamicESDTFlag) })
	if err != nil {
		return nil, err
	}
	b.ordinaryType, err = builtInFunctions.NewESDTSetTokenTypeFunc(a.Accounts, setter, a.Marshaller,
		func() bool { return a.EnableEpochsHandler.IsFlagEnabled(common.DynamicESDTFlag) })
	if err != nil {
		return nil, err
	}
	return b, nil
}

// BuiltinFunction supplies the SAME before-first-effect guard to the native
// container, so transaction/SCR/VM/callback paths cannot choose different
// classification logic. The native owner must install these three entries in
// its actual container before consumers and bind this exact candidate; obtaining
// the wrapper alone is not canonical/configuration admission. Native flags and
// gas configuration are delegated to the exact underlying native function.
func (b *BurnForAllAbsence) BuiltinFunction(function string) (vmcommon.BuiltinFunction, error) {
	if b == nil {
		return nil, errInvalidRegistrationRecord
	}
	var native vmcommon.BuiltinFunction
	switch function {
	case vmcommon.BuiltInFunctionESDTSetBurnRoleForAll:
		native = b.set
	case vmcommon.BuiltInFunctionESDTUnSetBurnRoleForAll:
		native = b.unset
	case core.ESDTSetTokenType:
		native = b.ordinaryType
	default:
		return nil, builtInFunctions.ErrInvalidArguments
	}
	return &registrationBuiltin{owner: b, function: function, native: native}, nil
}

// BindBuiltinFunctions is the native owner's pre-consumer binding step. It
// wraps the actual existing native container entries, preserving their exact
// flags/gas/ordinary implementation. It must run with exclusive configuration
// ownership BEFORE dispatchers/VMs retain function pointers, after canonical
// preparation of this candidate. No running-network installation is implied.
// On an error, the container is restored; a restoration error denies admission.
func (b *BurnForAllAbsence) BindBuiltinFunctions(container vmcommon.BuiltInFunctionContainer,
	accounts state.AccountsAdapter, flags common.EnableEpochsHandler) error {
	if b == nil || check.IfNil(container) || accounts != b.material.state.accounts || flags != b.flags {
		return errInvalidRegistrationRecord
	}
	b.mut.Lock()
	defer b.mut.Unlock()
	if b.material.members == nil {
		return errInvalidRegistryTransport
	}
	b.material.owner.mut.Lock()
	err := b.material.owner.checkAvailable()
	b.material.owner.mut.Unlock()
	if err != nil {
		return err
	}
	names := []string{vmcommon.BuiltInFunctionESDTSetBurnRoleForAll, vmcommon.BuiltInFunctionESDTUnSetBurnRoleForAll, core.ESDTSetTokenType}
	old := make([]vmcommon.BuiltinFunction, len(names))
	for i, name := range names {
		old[i], err = container.Get(name)
		if err != nil {
			return err
		}
		if check.IfNil(old[i]) {
			return errInvalidRegistrationRecord
		}
		if wrapped, exists := old[i].(*registrationBuiltin); exists {
			if wrapped.owner != b || wrapped.function != name {
				return errInvalidRegistrationRecord
			}
		}
	}
	for i, name := range names {
		if _, exists := old[i].(*registrationBuiltin); exists {
			continue
		}
		err = container.Replace(name, &registrationBuiltin{owner: b, function: name, native: old[i]})
		if err == nil {
			continue
		}
		failures := []error{err}
		// Include the failing entry: an implementation might replace then fail.
		for j := i; j >= 0; j-- {
			if restore := container.Replace(names[j], old[j]); restore != nil {
				failures = append(failures, restore)
			}
		}
		return errors.Join(failures...)
	}
	return nil
}

type registrationBuiltin struct {
	owner    *BurnForAllAbsence
	function string
	native   vmcommon.BuiltinFunction
}

func (f *registrationBuiltin) IsInterfaceNil() bool                   { return f == nil }
func (f *registrationBuiltin) IsActive() bool                         { return f.native.IsActive() }
func (f *registrationBuiltin) SetNewGasConfig(cost *vmcommon.GasCost) { f.native.SetNewGasConfig(cost) }
func (f *registrationBuiltin) ProcessBuiltinFunction(_, _ vmcommon.UserAccountHandler, input *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
	if input != nil && input.Function != f.function {
		return nil, builtInFunctions.ErrInvalidArguments
	}
	f.owner.mut.Lock()
	defer f.owner.mut.Unlock()
	return f.owner.processBuiltinFunction(input, f.native)
}

// Prepare is the existing T08 bounded full-set startup/integrity operation, not
// a per-block crawler. Partial/authentication failures publish no ordinary view.
func (b *BurnForAllAbsence) Prepare(ctx context.Context, count AccountItemWitness, members []BurnForAllMemberWitness) error {
	b.mut.Lock()
	defer b.mut.Unlock()
	if uint64(len(members)) > b.transport.maxEver {
		return errInvalidRegistryTransport
	}
	items := make([]registryMemberWitness, len(members))
	for i, w := range members {
		items[i] = registryMemberWitness{tokenID: w.TokenID, proof: w.Proof}
	}
	view, err := b.transport.reconstruct(&b.material.required, count, items)
	if err != nil {
		return err
	}
	return b.material.prepare(ctx, view)
}

// ProcessBuiltinFunction is an UNWIRED SET/UNSET guard construction. It denies
// both raw operations for every authenticated permanent member, even before
// normalization and after hostile reorder/replay. Protected disable authority
// comes solely from Normalize's registration proofs, never this transport.
// Ordinary inputs pass to the unchanged matching native implementation.
// Native route eligibility (IsActive/SendAlways) remains the ordinary caller's
// dispatch obligation; this method does not enable a previously inactive route.
func (b *BurnForAllAbsence) ProcessBuiltinFunction(input *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
	b.mut.Lock()
	defer b.mut.Unlock()
	return b.processBuiltinFunction(input, nil)
}

func (b *BurnForAllAbsence) processBuiltinFunction(input *vmcommon.ContractCallInput, selected vmcommon.BuiltinFunction) (*vmcommon.VMOutput, error) {
	if input == nil {
		return nil, builtInFunctions.ErrNilVmInput
	}
	var native vmcommon.BuiltinFunction
	arity := 1
	switch input.Function {
	case vmcommon.BuiltInFunctionESDTSetBurnRoleForAll:
		native = b.set
	case vmcommon.BuiltInFunctionESDTUnSetBurnRoleForAll:
		native = b.unset
	case core.ESDTSetTokenType:
		native, arity = b.ordinaryType, 2
	default:
		return nil, builtInFunctions.ErrInvalidArguments
	}
	if selected != nil {
		native = selected
	}
	// Only a single argument supplies the native setting target. For malformed
	// arity, delegate validation to native code: it checks CallValue first and
	// rejects before any setting effect (vm-common v1.7.2 L94-107; INV-0).
	// An unavailable classifier for a valid target is never ordinary absence.
	if len(input.Arguments) != arity {
		return native.ProcessBuiltinFunction(nil, nil, input)
	}
	regulated, err := b.material.classify(b.material.required.candidateHash, input.Arguments[0])
	if err != nil {
		return nil, err
	}
	if regulated {
		if arity == 2 {
			return nil, errInvalidRegistrationRecord
		}
		return nil, errBurnForAllDenied
	}
	return native.ProcessBuiltinFunction(nil, nil, input)
}

// Normalize authenticates exact immutable registration at the same native
// anchor as the complete classifier. It creates a positively present native
// false record; a missing record's IsBurnForAll=false is never its oracle.
func (b *BurnForAllAbsence) Normalize(tokenID []byte, w BurnForAllRegistrationWitness) error {
	return b.normalize(tokenID, w, false)
}

// MaterializeRegistration is T44's receiving bootstrap construction: classify
// FIRST and authenticate the exact consumed registration/profile, then reuse
// native type installation and false-burn normalization in the SAME journal.
// A source set/type/unset fan-out, sender address, raw call or ACK does not
// authenticate this path. All public raw setting replay remains denied.
// Native DynamicESDTFlag eligibility is preserved, with no invented type map.
func (b *BurnForAllAbsence) MaterializeRegistration(tokenID []byte, w BurnForAllRegistrationWitness) error {
	return b.normalize(tokenID, w, true)
}

func (b *BurnForAllAbsence) normalize(tokenID []byte, w BurnForAllRegistrationWitness, installType bool) error {
	b.mut.Lock()
	defer b.mut.Unlock()
	regulated, err := b.material.classify(b.material.required.candidateHash, tokenID)
	if err != nil {
		return err
	}
	if !regulated {
		return errInvalidRegistrationRecord
	}
	body, err := b.authenticateRegistration(tokenID, w)
	if err != nil {
		return err
	}
	tokenID = bytes.Clone(tokenID)
	key := append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), tokenID...)
	return b.material.owner.Execute(func() (*vmcommon.VMOutput, error) {
		account, e := b.material.state.systemAccount()
		if e != nil {
			return nil, e
		}
		prior, _, e := account.RetrieveValue(key)
		if e != nil {
			return nil, e
		}
		meta := builtInFunctions.ESDTGlobalMetadataFromBytes(prior)
		if len(prior) != 0 && (len(prior) != 2 || !bytes.Equal(meta.ToBytes(), prior)) {
			return nil, errInvalidRegistrationRecord
		}
		if len(prior) == 2 && meta.TokenType != 0 {
			actual, e := b.metadata.GetTokenType(key)
			if e != nil {
				return nil, e
			}
			want, e := core.ConvertESDTTypeToUint32(string(body.requestedTokenFamily))
			if e != nil {
				return nil, e
			}
			if actual != want {
				return nil, errInvalidRegistrationRecord
			}
		}
		// Part B L441-443: shared native internal reuse only after authenticated
		// preparation. No manager CallerAddr is forged; no public input reaches it.
		b.normalizing = true
		defer func() { b.normalizing = false }()
		if installType {
			if !b.tokenType.IsActive() {
				return nil, errBurnForAllDenied
			}
			output, e := b.tokenType.ProcessBuiltinFunction(nil, nil, &vmcommon.ContractCallInput{
				VMInput: vmcommon.VMInput{CallerAddr: bytes.Clone(core.ESDTSCAddress), CallValue: big.NewInt(0),
					Arguments: [][]byte{bytes.Clone(tokenID), bytes.Clone(body.requestedTokenFamily)}},
				RecipientAddr: bytes.Clone(vmcommon.SystemAccountAddress), Function: core.ESDTSetTokenType})
			if e != nil {
				return nil, e
			}
			if output == nil || output.ReturnCode != vmcommon.Ok {
				return nil, errInvalidRegistrationRecord
			}
			// Reload the real native result. Preserve every unrelated native bit
			// and require the actual native type reader to agree with the profile.
			account, e = b.material.state.systemAccount()
			if e != nil {
				return nil, e
			}
			stored, _, e := account.RetrieveValue(key)
			if e != nil {
				return nil, e
			}
			meta = builtInFunctions.ESDTGlobalMetadataFromBytes(stored)
			actual, e := b.metadata.GetTokenType(key)
			if e != nil {
				return nil, e
			}
			want, e := core.ConvertESDTTypeToUint32(string(body.requestedTokenFamily))
			if e != nil || len(stored) != 2 || !bytes.Equal(meta.ToBytes(), stored) || actual != want {
				return nil, errInvalidRegistrationRecord
			}
		}
		if !b.protected.IsActive() {
			return nil, errBurnForAllDenied
		}
		out, e := b.protected.ProcessBuiltinFunction(nil, nil, &vmcommon.ContractCallInput{
			VMInput:       vmcommon.VMInput{CallerAddr: bytes.Clone(core.ESDTSCAddress), CallValue: big.NewInt(0), Arguments: [][]byte{tokenID}},
			RecipientAddr: bytes.Clone(vmcommon.SystemAccountAddress), Function: vmcommon.BuiltInFunctionESDTUnSetBurnRoleForAll})
		if e != nil {
			return nil, e
		}
		account, e = b.material.state.systemAccount()
		if e != nil {
			return nil, e
		}
		stored, _, e := account.RetrieveValue(key)
		if e != nil {
			return nil, e
		}
		meta.BurnRoleForAll = false
		if out == nil || out.ReturnCode != vmcommon.Ok || len(stored) != 2 || !bytes.Equal(stored, meta.ToBytes()) || b.metadata.IsBurnForAll(key) {
			return nil, errInvalidRegistrationRecord
		}
		return out, nil
	})
}

// Commit/Abort/Recover share the existing native journal and invalidate this
// handle. Roots/local outputs are not canonical ACKs or activation readiness.
func (b *BurnForAllAbsence) Commit() ([][]byte, []*vmcommon.VMOutput, error) {
	b.mut.Lock()
	defer b.mut.Unlock()
	if b.material.members == nil {
		return nil, nil, errInvalidRegistryTransport
	}
	return b.material.owner.Commit()
}
func (b *BurnForAllAbsence) Abort() error {
	b.mut.Lock()
	defer b.mut.Unlock()
	return b.material.abort()
}
func (b *BurnForAllAbsence) Recover() error {
	b.mut.Lock()
	defer b.mut.Unlock()
	return b.material.owner.Recover()
}
