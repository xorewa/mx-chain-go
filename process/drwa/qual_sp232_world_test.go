package drwa

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/state/accounts"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	nativeBuiltins "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/multiversx/mx-chain-vm-common-go/parsers"
	"github.com/stretchr/testify/require"
)

// SP2-32 test world. The metachain side is a real account store with the
// production funding owner, the production convergence host as evidence
// reader and the origin owner of this row. Each execution shard is a real
// account store with the real shard registry, the complete native built-in
// container and the destination function of this row. Legs travel as the
// output transfers the origin produced; acknowledgements as canonical-final
// evidence of the shard's own item, read through SP2-22's result reader.
//
// Two things are fixtures because another row owns their production form:
// the price entries (owner decision 25.1) and the shard's local binding
// source (SP2-38 and SP2-52).

const sp232Token = "REGUL-0a1b2c"

var sp232Domain = []byte("sp232 network domain")

var errSP232 = errors.New("selected SP2-32 fault")

type sp232Prices struct {
	price CarrierPrice
	err   error
	// flip makes every second answer another price.
	flip  bool
	calls int
}

func (p *sp232Prices) IsInterfaceNil() bool { return p == nil }
func (p *sp232Prices) CarrierPrice(class string) (CarrierPrice, error) {
	if class != AdminEffectCarrierClass {
		return CarrierPrice{}, ErrCarrierFunding
	}
	p.calls++
	if p.flip && p.calls%2 == 0 {
		other := p.price
		other.Completion++
		return other, p.err
	}
	return p.price, p.err
}

// sp232Binding stands for a shard's locally installed bindings: the exact
// (kind, epoch, action, plan, step) contexts it holds for the token.
type sp232Binding struct {
	held  map[string]struct{}
	err   error
	calls int
	last  AdminEffect
}

func sp232Context(kind string, epoch uint64, action, plan []byte, step *uint64) string {
	s := "none"
	if step != nil {
		s = fmt.Sprint(*step)
	}
	return fmt.Sprintf("%s/%d/%x/%x/%s", kind, epoch, action, plan, s)
}

func (b *sp232Binding) IsInterfaceNil() bool { return b == nil }
func (b *sp232Binding) VerifyAdminEffect(e AdminEffect) error {
	b.calls++
	b.last = e
	if b.err != nil {
		return b.err
	}
	if _, held := b.held[sp232Context(e.Binding, e.Epoch, e.ActionID, e.PlanDigest, e.PlanStep)]; !held {
		return errSP232
	}
	return nil
}

type sp232Shard struct {
	t        *testing.T
	id       uint32
	f        *canonicalTestFixture
	store    *qualNativeStore
	registry *ShardRegistry
	builtIns vmcommon.BuiltInFunctionContainer
	function *AdminEffectFunction
	binding  *sp232Binding
	holder   []byte
	domain   []byte
	nonce    uint64
}

func sp232Holder(shard uint32, seed byte) []byte {
	address := bytes.Repeat([]byte{seed}, 32)
	address[31] = uint8(shard)
	return address
}

func sp232ShardNew(t *testing.T, id uint32) *sp232Shard {
	t.Helper()
	s := &sp232Shard{t: t, id: id, f: newCanonicalTestFixture(t, id, core.MetachainShardId), holder: sp232Holder(id, 7),
		domain: sp232Domain, nonce: 11,
		binding: &sp232Binding{held: map[string]struct{}{sp232Context("CURRENT_CEB", 2, nil, nil, nil): {}}}}
	// The fixture's fault-injecting wrapper is not used: the native store.
	s.store = s.f.s.qualNativeStore
	coordinator, err := sharding.NewMultiShardCoordinator(3, id)
	require.NoError(t, err)
	require.Equal(t, id, coordinator.ComputeId(s.holder))
	creator, err := nativeBuiltins.NewBuiltInFunctionsCreator(routeBuiltinArgs(s.store, coordinator, s.holder))
	require.NoError(t, err)
	require.NoError(t, creator.CreateBuiltInFunctionContainer())
	s.builtIns = creator.BuiltInFunctionContainer()
	s.registry, err = NewShardRegistry(s.store, id)
	require.NoError(t, err)
	require.NoError(t, s.builtIns.Add(RegistryDeltaFunctionName, s.registry.DeltaFunction()))
	s.function, err = NewAdminEffectFunction(ArgsAdminEffectFunction{Accounts: s.store, Marshaller: &marshal.GogoProtoMarshalizer{},
		Hasher: s.f.reader.accounts.args.Hasher, Classifier: s.registry, BuiltIns: s.builtIns, Shard: id,
		ShardOf: coordinator.ComputeId, Domain: func() []byte { return s.domain }, RecordBytes: 4096})
	require.NoError(t, err)
	require.False(t, s.function.IsInterfaceNil())
	require.True(t, s.function.IsActive())
	s.function.SetNewGasConfig(nil)
	require.NoError(t, s.builtIns.Add(AdminEffectFunctionName, s.function))
	require.NoError(t, s.function.SetBindingSource(s.binding))
	// The token is a member of this shard's registry, as the metachain's delta
	// made it.
	require.NoError(t, s.registry.BeginExecution())
	_, err = s.registry.DeltaFunction().ProcessBuiltinFunction(nil, nil, &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{CallerAddr: core.ESDTSCAddress, CallValue: big.NewInt(0), CallType: vmData.AsynchronousCall,
			Arguments: [][]byte{[]byte(sp232Token), make([]byte, 8)}},
		RecipientAddr: registryDeltaSystemAddress(id), Function: RegistryDeltaFunctionName})
	require.NoError(t, err)
	s.commit()
	return s
}

func (s *sp232Shard) commit() []byte {
	s.t.Helper()
	root, err := s.store.Commit()
	require.NoError(s.t, err)
	require.NoError(s.t, s.registry.Committed())
	return root
}

func (s *sp232Shard) root() []byte {
	s.t.Helper()
	root, err := s.store.RootHash()
	require.NoError(s.t, err)
	return root
}

// input is the call the shard's result processor makes of one transfer.
func sp232Input(t *testing.T, destination []byte, transfer vmcommon.OutputTransfer, hash string) *vmcommon.ContractCallInput {
	t.Helper()
	function, arguments, err := parsers.NewCallArgsParser().ParseData(string(transfer.Data))
	require.NoError(t, err)
	return &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: bytes.Clone(transfer.SenderAddress),
		CallValue: big.NewInt(0), CallType: transfer.CallType, GasProvided: transfer.GasLimit, Arguments: arguments,
		CurrentTxHash: []byte(hash)}, RecipientAddr: bytes.Clone(destination), Function: function}
}

// call runs one built-in call as the result processor does: through the
// container, and with everything the call wrote reverted when it fails.
func (s *sp232Shard) call(input *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
	s.t.Helper()
	builtIn, err := s.builtIns.Get(input.Function)
	require.NoError(s.t, err)
	snapshot := s.store.JournalLen()
	output, err := builtIn.ProcessBuiltinFunction(nil, nil, input)
	if err != nil {
		require.NoError(s.t, s.store.RevertToSnapshot(snapshot))
		require.Nil(s.t, output)
	}
	return output, err
}

func (s *sp232Shard) deliver(transfer vmcommon.OutputTransfer) (*vmcommon.VMOutput, error) {
	s.t.Helper()
	return s.call(sp232Input(s.t, registryDeltaSystemAddress(s.id), transfer, "leg result hash"))
}

// refused requires an error and no state: the root after the processor's
// revert is the root before.
func (s *sp232Shard) refused(label string, input *vmcommon.ContractCallInput) {
	s.t.Helper()
	before, journal := s.root(), s.store.JournalLen()
	output, err := s.call(input)
	require.ErrorIs(s.t, err, ErrInvalidAdminEffect, label)
	require.Nil(s.t, output, label)
	require.Equal(s.t, before, s.root(), label)
	require.Equal(s.t, journal, s.store.JournalLen(), label)
}

func (s *sp232Shard) value(address, key []byte) []byte {
	s.t.Helper()
	a, err := s.store.LoadAccount(address)
	require.NoError(s.t, err)
	value, err := shardRegistryValue(a.(vmcommon.UserAccountHandler), key)
	require.NoError(s.t, err)
	return value
}

func (s *sp232Shard) roles() []byte {
	return s.value(s.holder, append([]byte(adminRolesKeyPrefix), sp232Token...))
}

// settle commits the shard and makes that state the result of an executed
// block, carried by a header that is settled below a consuming metachain
// block.
func (s *sp232Shard) settle() {
	s.t.Helper()
	root := s.commit()
	s.nonce++
	f := s.f
	executed := &block.HeaderV3{Nonce: s.nonce, Round: 21, Epoch: 3, ShardID: s.id, ChainID: []byte("unit-chain")}
	f.w.Account.ExecutedHeader = f.encode(s.t, executed)
	origin := f.hash(f.w.Account.ExecutedHeader)
	carrying := &block.HeaderV3{Nonce: 15, Round: 25, Epoch: 4, ShardID: s.id, ChainID: []byte("unit-chain"),
		ExecutionResults: []*block.ExecutionResult{{BaseExecutionResult: &block.BaseExecutionResult{
			HeaderHash: origin, HeaderNonce: s.nonce, HeaderRound: 21, HeaderEpoch: 3, RootHash: root}}}}
	f.w.Account.Header = f.encode(s.t, carrying)
	f.w.HeaderProof = f.proof(s.t, carrying, f.w.Account.Header)
	f.metas[0].ShardInfoProposal[0].HeaderHash = f.hash(f.w.Account.Header)
	f.metas[0].ShardInfo[0].HeaderHash, f.metas[0].ShardInfo[0].Nonce = origin, s.nonce
	f.rechain(s.t)
}

// witness is the canonical witness of one item of this shard's system account.
func (s *sp232Shard) witness(key []byte) canonicalResultWitness {
	s.t.Helper()
	w := cloneCanonicalResultWitness(s.f.w)
	var err error
	w.Account, err = s.f.reader.accounts.BuildNativeWitness(s.store, s.f.hash(s.f.w.Account.Header), s.id,
		core.SystemAccountAddress, key, s.f.w.Account, 1<<20)
	require.NoError(s.t, err)
	return w
}

// restart rebuilds the shard's projection from its committed store.
func (s *sp232Shard) restart() {
	s.t.Helper()
	root := s.commit()
	require.NoError(s.t, s.store.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
	require.NoError(s.t, s.registry.BeginExecution())
}

type sp232World struct {
	t       *testing.T
	meta    *sp223World
	prices  *sp232Prices
	funding *CarrierFunding
	effects *AdminEffects
	shards  []*sp232Shard
	domain  []byte
	limits  RegistrationResourceLimits
	// accounts is the store the metachain owners are built over: the native
	// store, or a fault-injecting view of it.
	accounts state.AccountsAdapter
	// genesisRoot is the committed metachain root before any effect.
	genesisRoot []byte
}

func sp232Price() CarrierPrice {
	return CarrierPrice{Source: 100, Destination: 40, Success: 7, Refund: 9, Completion: 30}
}

// sp232LegGas is the gas of one leg under sp232Price: destination work, the
// larger outcome and completion.
const sp232LegGas = 40 + 9 + 30

func sp232New(t *testing.T) *sp232World {
	t.Helper()
	w := &sp232World{t: t, meta: sp223New(t, sp223Ample()), prices: &sp232Prices{price: sp232Price()}, domain: sp232Domain,
		limits: sp223Ample()}
	w.genesisRoot, w.accounts = w.meta.root(), w.meta.store
	w.build()
	for id := uint32(0); id < 3; id++ {
		w.shards = append(w.shards, sp232ShardNew(t, id))
	}
	return w
}

// build constructs the metachain owners from the store and configured inputs.
func (w *sp232World) build() {
	w.t.Helper()
	var err error
	w.funding, err = NewCarrierFunding(ArgsCarrierFunding{Accounts: w.accounts, Marshaller: &marshal.GogoProtoMarshalizer{},
		Hasher: w.meta.hasher, Block: w.meta.block, Prices: w.prices, Limits: w.limits, RecordBytes: 4096})
	require.NoError(w.t, err)
	w.effects, err = NewAdminEffects(ArgsAdminEffects{Accounts: w.accounts, Marshaller: &marshal.GogoProtoMarshalizer{},
		Hasher: w.meta.hasher, Domain: func() []byte { return w.domain }, Funding: w.funding, Block: w.meta.block,
		Evidence: w.meta.host, Limits: w.limits, RecordBytes: 4096, Shards: 3})
	require.NoError(w.t, err)
	require.False(w.t, w.effects.IsInterfaceNil())
}

// restart commits the metachain store, reopens it at that root and rebuilds
// every owner.
func (w *sp232World) restart() {
	w.t.Helper()
	w.meta.restart()
	w.build()
}

func (w *sp232World) hash(seed string) []byte { return w.meta.hasher.Compute(seed) }

// stateHash is the independently computed state hash of one locus: the
// framed tag, domain, target and each key with its value.
func (w *sp232World) stateHash(target []byte, items ...[]byte) []byte {
	fields := append([][]byte{[]byte("DRWA/ADMIN/STATE/candidate1"), sp232Domain, target}, items...)
	return w.meta.hasher.Compute(string(qualRecordFrame(fields...)))
}

func sp232Roles(roles ...string) []byte {
	// Independent ESDTRoles protobuf: repeated bytes field 1.
	var out []byte
	for _, role := range roles {
		out = append(append(out, 0x0a, byte(len(role))), role...)
	}
	return out
}

func (w *sp232World) rolesHash(holder []byte, roles ...string) []byte {
	return w.stateHash(holder, append([]byte(adminRolesKeyPrefix), sp232Token...), sp232Roles(roles...),
		append([]byte(adminNonceKeyPrefix), sp232Token...), nil)
}

func sp232Payload(function string, arguments ...[]byte) []byte {
	out := function
	for _, argument := range arguments {
		out += "@" + hex.EncodeToString(argument)
	}
	return []byte(out)
}

// grant is the request of a role grant to the holder of one shard, from no
// roles to exactly role.
func (w *sp232World) grant(shard uint32, role string) AdminEffectRequest {
	holder := w.shards[shard].holder
	return AdminEffectRequest{Operation: "DRWAApplyTokenAdmin", Origin: w.hash("protected origin execution"),
		TokenID: []byte(sp232Token), TokenType: []byte(core.FungibleESDT), Binding: "CURRENT_CEB", Epoch: 2,
		Payload: sp232Payload(core.BuiltInFunctionSetESDTRole, []byte(sp232Token), []byte(role)),
		Legs:    []AdminEffectLeg{{Shard: shard, Target: holder, Predecessor: w.rolesHash(holder), Result: w.rolesHash(holder, role)}}}
}

// tokenItem is the independent encoding of the token's global item: the two
// bytes of ESDTGlobalMetadata with the limited-transfer bit.
func sp232TokenItem(limited bool) []byte {
	if !limited {
		return nil
	}
	return []byte{2, 0}
}

// limited is the request that sets limited transfer on every shard.
func (w *sp232World) limited() AdminEffectRequest {
	key := append([]byte(adminTokenKeyPrefix), sp232Token...)
	r := AdminEffectRequest{Operation: "DRWAApplyTokenAdmin", Origin: w.hash("protected origin execution"),
		TokenID: []byte(sp232Token), TokenType: []byte(core.FungibleESDT), Binding: "CURRENT_CEB", Epoch: 2,
		Payload: sp232Payload(core.BuiltInFunctionESDTSetLimitedTransfer, []byte(sp232Token))}
	for shard := uint32(0); shard < 3; shard++ {
		value := w.shards[shard].value(core.SystemAccountAddress, key)
		r.Legs = append(r.Legs, AdminEffectLeg{Shard: shard, Target: core.SystemAccountAddress,
			Predecessor: w.stateHash(core.SystemAccountAddress, key, value),
			Result:      w.stateHash(core.SystemAccountAddress, key, sp232TokenItem(true))})
	}
	return r
}

// transfers returns the output's transfers in result order.
func sp232Transfers(output *vmcommon.VMOutput) []vmcommon.OutputTransfer {
	var out []vmcommon.OutputTransfer
	for index := uint32(0); ; index++ {
		found := false
		for _, account := range output.OutputAccounts {
			for _, transfer := range account.OutputTransfers {
				if transfer.Index == index {
					out, found = append(out, transfer), true
				}
			}
		}
		if !found {
			return out
		}
	}
}

// open opens an effect with ample gas and returns its identifier and legs.
func (w *sp232World) open(request AdminEffectRequest) ([]byte, []vmcommon.OutputTransfer) {
	w.t.Helper()
	output := &vmcommon.VMOutput{}
	available := uint64(100 + len(request.Legs)*sp232LegGas + 5)
	id, remaining, err := w.effects.Open(output, request, available)
	require.NoError(w.t, err)
	require.Equal(w.t, uint64(5), remaining)
	transfers := sp232Transfers(output)
	require.Len(w.t, transfers, len(request.Legs))
	return id, transfers
}

func (w *sp232World) metaRoot() []byte { return w.meta.root() }

// denied requires an error from a metachain request and no write at all.
func (w *sp232World) denied(label string, run func() error) {
	w.t.Helper()
	w.meta.denied(label, run)
}

// appliedKey is the independently derived applied-leg item key of one leg.
func (w *sp232World) appliedKey(effectID []byte, leg uint32) []byte {
	legID := w.meta.hasher.Compute(string(qualRecordFrame([]byte("DRWA/ADMIN/LEG/candidate1"), sp232Domain, effectID,
		binary.BigEndian.AppendUint32(nil, leg))))
	return append([]byte(adminAppliedPrefix), w.meta.hasher.Compute(string(qualRecordFrame(
		[]byte("DRWA/ADMIN/APPLIED_ID/candidate1"), sp232Domain, effectID, legID)))...)
}

// evidence is the canonical-final evidence of one leg's applied item on its
// shard, and makes that shard's consuming block the block in execution.
func (w *sp232World) evidence(shard *sp232Shard, effectID []byte, leg uint32) []byte {
	w.t.Helper()
	w.meta.block.hash, w.meta.block.header = shard.f.bHash, shard.f.w.Consumer
	return sp223Evidence(w.t, shard.witness(w.appliedKey(effectID, leg)))
}

func (w *sp232World) acknowledge(shard *sp232Shard, effectID []byte, leg uint32) (AdminEffectProgress, error) {
	w.t.Helper()
	return w.effects.Acknowledge(effectID, leg, w.evidence(shard, effectID, leg), 35)
}

func (w *sp232World) fundingState(effectID []byte) *CarrierFundingState {
	w.t.Helper()
	s, err := w.funding.Read(AdminEffectCarrierClass, effectID)
	require.NoError(w.t, err)
	return s
}

// carrier is the envelope codec with the network domain, for decoding what
// the origin emitted.
func (w *sp232World) carrier() *adminCarrier {
	w.t.Helper()
	codec, err := newRegistrationRecords(w.meta.store, &marshal.GogoProtoMarshalizer{}, w.meta.hasher, 4096)
	require.NoError(w.t, err)
	return &adminCarrier{codec: codec, domain: sp232Domain}
}

// envelope decodes the envelope a transfer carries.
func (w *sp232World) envelope(transfer vmcommon.OutputTransfer) adminEffectEnvelope {
	w.t.Helper()
	_, arguments, err := parsers.NewCallArgsParser().ParseData(string(transfer.Data))
	require.NoError(w.t, err)
	e, err := w.carrier().decode(arguments[0])
	require.NoError(w.t, err)
	return e
}

// sp232Frame is the independent wire form of an envelope: the 23 framed
// fields in the order of Part A's DRWAAdminEffectEnvelope, with no check.
func sp232Frame(domain []byte, e adminEffectEnvelope) []byte {
	return qualRecordFrame([]byte("DRWA/ADMIN_ENVELOPE/candidate1"), domain,
		e.effectID, e.legID, e.operation, e.origin, e.openCommitment, e.tokenID, e.tokenType, e.binding,
		binary.BigEndian.AppendUint64(nil, e.cebEpoch), e.actionID, e.planDigest, e.planStep,
		e.normalizedDigest, e.discriminator, e.payload, binary.BigEndian.AppendUint32(nil, e.targetShard),
		e.targetKey, e.predecessor, e.result, e.gasVersion, binary.BigEndian.AppendUint64(nil, e.workLimit))
}

// with returns the transfer carrying other envelope bytes.
func sp232With(transfer vmcommon.OutputTransfer, envelope []byte) vmcommon.OutputTransfer {
	transfer.Data = []byte(AdminEffectFunctionName + "@" + hex.EncodeToString(envelope))
	return transfer
}

// normalized is the independently derived normalized digest of a call.
func (w *sp232World) normalized(function string, arguments ...[]byte) []byte {
	fields := append([][]byte{[]byte("DRWA/ADMIN/NORMALIZED/candidate1"), sp232Domain, []byte(function)}, arguments...)
	return w.meta.hasher.Compute(string(qualRecordFrame(fields...)))
}

// effectID is the independently derived identifier of an effect (Part A
// 4.7.1, TOKEN_ADMIN grammar).
func (w *sp232World) effectID(request AdminEffectRequest) []byte {
	function, arguments, err := parsers.NewCallArgsParser().ParseData(string(request.Payload))
	require.NoError(w.t, err)
	return w.meta.hasher.Compute(string(qualRecordFrame([]byte("DRWA/EFFECT/ADMINOP/v1"), sp232Domain, request.Origin,
		w.normalized(function, arguments...), binary.BigEndian.AppendUint64(nil, request.Epoch), request.ActionID)))
}

// native runs a native built-in on this shard as the metachain ESDT system
// contract's call, outside this row's code: the oracle of an inner effect.
func (s *sp232Shard) native(function string, recipient []byte, arguments ...[]byte) {
	s.t.Helper()
	builtIn, err := s.builtIns.Get(function)
	require.NoError(s.t, err)
	input := &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: core.ESDTSCAddress, CallValue: big.NewInt(0),
		Arguments: arguments}, RecipientAddr: recipient, Function: function}
	var account vmcommon.UserAccountHandler
	if !bytes.Equal(recipient, core.SystemAccountAddress) {
		loaded, loadErr := s.store.LoadAccount(recipient)
		require.NoError(s.t, loadErr)
		account = loaded.(vmcommon.UserAccountHandler)
	}
	_, err = builtIn.ProcessBuiltinFunction(nil, account, input)
	require.NoError(s.t, err)
	if account != nil {
		require.NoError(s.t, s.store.SaveAccount(account))
	}
}

// sp232Faults is a view of an account store that fails the at-th native
// operation (account load, account save, item read, item write) with
// errSP232, or returns an account of another kind at that load.
type sp232Faults struct {
	state.AccountsAdapter
	at, calls int
	peer      bool
	hit       bool
	onSave    func()
}

// sp232Account is the native user account under both of its interfaces.
type sp232Account interface {
	state.UserAccountHandler
	vmcommon.UserAccountHandler
}

type sp232FaultAccount struct {
	sp232Account
	faults *sp232Faults
}

func (s *sp232Faults) fail() bool {
	s.calls++
	if s.calls == s.at {
		s.hit = true
	}
	return s.calls == s.at
}

func (a *sp232FaultAccount) RetrieveValue(key []byte) ([]byte, uint32, error) {
	if a.faults.fail() {
		return nil, 0, errSP232
	}
	return a.sp232Account.RetrieveValue(key)
}

func (a *sp232FaultAccount) SaveKeyValue(key, value []byte) error {
	if a.faults.fail() {
		return errSP232
	}
	return a.sp232Account.SaveKeyValue(key, value)
}

func (s *sp232Faults) wrap(account vmcommon.AccountHandler, err error) (vmcommon.AccountHandler, error) {
	if err != nil {
		return nil, err
	}
	if s.fail() {
		if s.peer {
			return accounts.NewPeerAccount(account.AddressBytes())
		}
		return nil, errSP232
	}
	return &sp232FaultAccount{account.(sp232Account), s}, nil
}

func (s *sp232Faults) GetExistingAccount(address []byte) (vmcommon.AccountHandler, error) {
	return s.wrap(s.AccountsAdapter.GetExistingAccount(address))
}

func (s *sp232Faults) LoadAccount(address []byte) (vmcommon.AccountHandler, error) {
	return s.wrap(s.AccountsAdapter.LoadAccount(address))
}

func (s *sp232Faults) SaveAccount(account vmcommon.AccountHandler) error {
	if s.onSave != nil {
		s.onSave()
	}
	if s.fail() {
		return errSP232
	}
	if wrapped, ok := account.(*sp232FaultAccount); ok {
		account = wrapped.sp232Account
	}
	return s.AccountsAdapter.SaveAccount(account)
}
