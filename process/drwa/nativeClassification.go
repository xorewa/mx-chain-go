package drwa

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	nativeValidation "github.com/multiversx/mx-chain-go/process/transaction"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// ErrClassificationUnresolved reports that the registry projection required by
// the block in execution is not available on this node. It is never read as
// "ordinary token" (Part A 5.1 rule 5); callers wrap it in vm.ErrDRWAExecution.
var ErrClassificationUnresolved = errors.New("DRWA classification is unresolved")

// ErrRegulatedTokenOperation is the deterministic refusal of a public native
// operation on a regulated token. It is an ordinary operation error.
var ErrRegulatedTokenOperation = errors.New("DRWA regulated token: public native operation denied")

// TokenClassifier answers permanent-registry membership for the store and the
// block in execution. An error is never membership absence.
type TokenClassifier interface {
	ClassifyToken(tokenID []byte) (bool, error)
	IsInterfaceNil() bool
}

// classifierHost is the installed native System VM (vm/process systemVM).
type classifierHost interface {
	ReplaceDRWAClassifier(vm.DRWATokenClassifier) error
}

// ArgsMetaClassification names the metachain processing stores. They are the
// same instances the System VM and the block processor use.
type ArgsMetaClassification struct {
	Accounts     state.AccountsAdapter
	PeerAccounts state.AccountsAdapter
	Coordinator  sharding.Coordinator
}

// MetaClassification is the native block owner of the metachain classifier
// (Part A 5.1 rules 1-5). It drives the existing committedRegistry and
// registrationCandidate through block execution: reconstruction from the
// committed store, one open candidate per execution, handoff through the
// System VM, exact advance on commit. It persists, reverts and commits nothing;
// the block processor remains the only owner of the stores.
type MetaClassification struct {
	mut           sync.Mutex
	state         *protectedState
	stores        []state.AccountsAdapter
	coordinator   sharding.Coordinator
	registry      *committedRegistry
	current       *registrationCandidate
	host          classifierHost
	native        *registrationNativeExecution
	maxEver       uint64
	funding       *CarrierFunding
	reconstructed bool
	snapshot      atomic.Pointer[map[string]struct{}]
}

// NewMetaClassification captures the stores only. The store need not yet be at
// a committed DRWA root (a restarting node loads its state later), so the first
// candidate is not ready: it refuses every classification until the first
// BeginExecution reconstructs the projection.
func NewMetaClassification(args ArgsMetaClassification) (*MetaClassification, error) {
	if check.IfNil(args.Accounts) || check.IfNil(args.PeerAccounts) {
		return nil, state.ErrNilAccountsAdapter
	}
	if check.IfNil(args.Coordinator) || args.Coordinator.SelfId() != core.MetachainShardId {
		return nil, ErrInvalidRegistryRegistration
	}
	writer, owner, err := NewRegistryRegistration(args.Accounts, args.Coordinator, 0, args.PeerAccounts)
	if err != nil {
		return nil, err
	}
	placeholder := rootRegistryAnchor(owner.roots[0])
	registry := &committedRegistry{anchor: placeholder, members: make(map[string]struct{})}
	first := attachRegistrationCandidate(writer, owner, registry, &placeholder)
	first.view.ready = false
	return &MetaClassification{state: writer.state, stores: []state.AccountsAdapter{args.Accounts, args.PeerAccounts},
		coordinator: args.Coordinator, registry: registry, current: first}, nil
}

// rebase replaces the projection with one the native block owner reconstructed
// from its committed store at another root (startup, state sync, rollback to
// an earlier block). old is the last candidate of this registry; it must have
// been closed healthy. Only its successor, begun at the reconstructed anchor,
// can then be handed off. No store is read or written here.
func (c *committedRegistry) rebase(old *registrationCandidate, anchor *metaRegistryAnchor, members map[string]struct{}) error {
	if c == nil || old == nil || old.view == nil || old.view.parent != c || old.writer == nil ||
		old.writer.boundary == nil || !validRegistrationAnchor(anchor) || members == nil {
		return errInvalidMetaContext
	}
	if !c.mut.TryLock() {
		return ErrExecutionBusy
	}
	defer c.mut.Unlock()
	owner := old.writer.boundary
	owner.mut.Lock()
	defer owner.mut.Unlock()
	if owner.failure != nil {
		return owner.failure
	}
	if c.active != nil || !owner.closed || owner.running || owner.recovered || old.view.ready || old.view.added != nil {
		return errInvalidMetaContext
	}
	c.members = members
	c.anchor = copyRegistryAnchor(anchor)
	old.rebased = true
	return nil
}

// rootRegistryAnchor identifies the metachain's own registry state by the
// committed user-store root. On the metachain the local committed store is the
// authority, so the root is the complete identity of the projection.
func rootRegistryAnchor(root []byte) metaRegistryAnchor {
	id := root
	if len(id) == 0 {
		id = []byte{0}
	}
	return metaRegistryAnchor{candidateHash: bytes.Clone(id), metaHash: bytes.Clone(id),
		executedHash: bytes.Clone(id), root: bytes.Clone(id)}
}

// Classifier is the candidate to give to the metachain VM factory.
func (m *MetaClassification) Classifier() vm.DRWATokenClassifier {
	m.mut.Lock()
	defer m.mut.Unlock()
	return m.current
}

// BindNative completes construction once the System VM exists. physical is that
// VM; headers is its block-chain hook; source holds the provider instances the
// transaction pool was configured with. Without it no execution can begin.
func (m *MetaClassification) BindNative(physical vmcommon.VMExecutionHandler, headers HeaderTimeSource,
	source *nativeValidation.NativeValidationSource) error {
	m.mut.Lock()
	defer m.mut.Unlock()
	host, ok := physical.(classifierHost)
	if m.host != nil || !ok || check.IfNil(physical) || check.IfNil(headers) || source == nil ||
		headers.GetAccountsAdapter() != m.stores[0] {
		return vm.ErrDRWAExecution
	}
	m.host = host
	m.native = &registrationNativeExecution{source: *source, headers: headers, physical: physical}
	m.current.native = m.native
	return nil
}

func (m *MetaClassification) committedRoots() ([][]byte, error) {
	roots := make([][]byte, len(m.stores))
	for i, store := range m.stores {
		if store.JournalLen() != 0 {
			return nil, ErrUncommittedState
		}
		root, err := store.RootHash()
		if err != nil {
			return nil, err
		}
		roots[i] = bytes.Clone(root)
	}
	return roots, nil
}

// BeginExecution is called by the block processor before the first native
// effect of every block execution, with every store committed. It verifies the
// projection against the store root, reconstructs it when the store moved, and
// leaves an open, ready candidate installed in the System VM.
func (m *MetaClassification) BeginExecution() error {
	m.mut.Lock()
	defer m.mut.Unlock()
	if err := m.beginLocked(); err != nil {
		return fmt.Errorf("%w: %w", vm.ErrDRWAExecution, err)
	}
	return nil
}

func (m *MetaClassification) beginLocked() error {
	if m.host == nil {
		return errInvalidMetaContext
	}
	roots, err := m.committedRoots()
	if err != nil {
		return err
	}
	moved := !m.reconstructed || !bytes.Equal(m.registry.anchor.root, roots[0])
	if !moved {
		reusable, reuseErr := m.current.nativeReusable(roots)
		if reuseErr != nil {
			return reuseErr
		}
		if reusable {
			return nil
		}
	}
	if err = m.current.closeNative(); err != nil {
		return err
	}
	if moved {
		members, maxEver, readErr := m.readCommittedRegistry()
		if readErr != nil {
			return readErr
		}
		anchor := rootRegistryAnchor(roots[0])
		if err = m.registry.rebase(m.current, &anchor, members); err != nil {
			return err
		}
		m.maxEver, m.reconstructed = maxEver, true
		m.publish(members)
	}
	return m.installNext()
}

// SetRegistrationCarrierFunding installs, once, the funding owner every later
// registration candidate of this node uses for its registry delta
// (RegistryRegistration.SetCarrierFunding). It is a construction step of the
// row that opens the registration ingress, together with the owner of the
// withheld effects: until then a registration is funded by nobody and its
// delta is not acknowledged.
func (m *MetaClassification) SetRegistrationCarrierFunding(funding *CarrierFunding) error {
	m.mut.Lock()
	defer m.mut.Unlock()
	if funding == nil || m.funding != nil || funding.codec.state.accounts != m.stores[0] {
		return ErrInvalidRegistryRegistration
	}
	m.funding = funding
	if m.current != nil && m.current.writer != nil {
		m.current.writer.funding = funding
	}
	return nil
}

// installNext begins the next candidate at the committed projection and hands
// it to the System VM. No registry or owner lock is held across the handoff.
func (m *MetaClassification) installNext() error {
	before := copyRegistryAnchor(&m.registry.anchor)
	next, err := m.registry.beginRegistration(m.stores[0], m.coordinator, m.maxEver, &before, &before, m.stores[1:]...)
	if err != nil {
		m.reconstructed = false
		return err
	}
	next.native = m.native
	// Checked against this owner's store by SetRegistrationCarrierFunding.
	next.writer.funding = m.funding
	if err = m.host.ReplaceDRWAClassifier(next); err != nil {
		m.reconstructed = false
		return errors.Join(err, next.closeNative())
	}
	m.current = next
	return nil
}

// readCommittedRegistry enumerates exactly count members through the ordinal
// index, at the committed root the store is at. It is the startup/state-sync
// reconstruction, bounded by the genesis max_ever_regulated_tokens; it is not
// run per block. A missing, malformed or inconsistent record is an error.
func (m *MetaClassification) readCommittedRegistry() (map[string]struct{}, uint64, error) {
	minimum, err := m.state.readMinimumGenesis()
	if err != nil {
		return nil, 0, err
	}
	account, err := m.state.systemAccount()
	if err != nil {
		return nil, 0, err
	}
	count, err := registrationCount(account)
	if err != nil {
		return nil, 0, err
	}
	if count > minimum.maxEverTokens {
		return nil, 0, ErrInvalidRegistryRegistration
	}
	members := make(map[string]struct{}, count)
	for ordinal := uint64(0); ordinal < count; ordinal++ {
		id, _, readErr := account.RetrieveValue(registryEntryKey(ordinal))
		if readErr != nil {
			return nil, 0, readErr
		}
		if _, duplicate := members[string(id)]; duplicate || !vmcommon.ValidateToken(id) {
			return nil, 0, ErrInvalidRegistryRegistration
		}
		marker, _, readErr := account.RetrieveValue(append([]byte(registryMemberKeyPrefix), id...))
		if readErr != nil {
			return nil, 0, readErr
		}
		if !bytes.Equal(marker, []byte{1}) {
			return nil, 0, ErrInvalidRegistryRegistration
		}
		members[string(id)] = struct{}{}
	}
	return members, minimum.maxEverTokens, nil
}

func (m *MetaClassification) publish(members map[string]struct{}) {
	published := make(map[string]struct{}, len(members))
	for id := range members {
		published[id] = struct{}{}
	}
	m.snapshot.Store(&published)
}

// Committed is called by the block processor right after its successful commit
// of every participating store. The projection advances by exactly the
// committed block's additions and the next candidate is installed at once, so
// the System VM never keeps a closed candidate. On an error the projection is
// marked for reconstruction; the committed stores are not affected.
func (m *MetaClassification) Committed() error {
	m.mut.Lock()
	defer m.mut.Unlock()
	if err := m.committedLocked(); err != nil {
		m.reconstructed = false
		return fmt.Errorf("%w: %w", vm.ErrDRWAExecution, err)
	}
	return nil
}

func (m *MetaClassification) committedLocked() error {
	if m.host == nil || !m.reconstructed {
		// Nothing was executed under a reconstructed projection; the next
		// BeginExecution reconstructs from the committed store.
		return nil
	}
	roots, err := m.committedRoots()
	if err != nil {
		return err
	}
	anchor := rootRegistryAnchor(roots[0])
	added, err := m.current.commitNative(&anchor)
	if err != nil {
		return err
	}
	if added != 0 {
		// The exact delta must equal the committed registry. An addition whose
		// native write was reverted by an outer snapshot would differ here.
		account, readErr := m.state.systemAccount()
		if readErr != nil {
			return readErr
		}
		count, readErr := registrationCount(account)
		if readErr != nil {
			return readErr
		}
		if count != uint64(len(m.registry.members)) {
			return ErrInvalidRegistryRegistration
		}
		m.publish(m.registry.members)
	}
	return m.installNext()
}

// ClassifyToken serves the metachain's native built-in dispatch from the
// installed candidate, including this block's own registrations.
func (m *MetaClassification) ClassifyToken(tokenID []byte) (bool, error) {
	m.mut.Lock()
	current := m.current
	m.mut.Unlock()
	return current.classifyOwn(tokenID)
}

// IsInterfaceNil returns true if there is no value under the interface
func (m *MetaClassification) IsInterfaceNil() bool { return m == nil }

// ReadOnlyClassifier is for the metachain VMs that never commit: the API query
// VM and the transaction simulator. It reads the published committed
// membership only, takes no registry lock, and has no registration, handoff or
// native-call capability. Membership is permanent, so a snapshot newer than
// the simulated root can only be stricter. Before the first reconstruction it
// is unavailable, never "ordinary".
// It is bound to the two adapters of that VM; with any other adapter, or a nil
// one, it validates and classifies nothing.
func (m *MetaClassification) ReadOnlyClassifier(user, validator state.AccountsAdapter) ReadOnlyTokenClassifier {
	return &readOnlyClassifier{owner: m, user: user, validator: validator}
}

// ReadOnlyTokenClassifier classifies both the System-SC calls and the
// built-in calls of a VM that never commits.
type ReadOnlyTokenClassifier interface {
	vm.DRWATokenClassifier
	ClassifyToken(tokenID []byte) (bool, error)
}

type readOnlyClassifier struct {
	owner           *MetaClassification
	user, validator state.AccountsAdapter
}

func (r *readOnlyClassifier) IsInterfaceNil() bool { return r == nil }

func (r *readOnlyClassifier) ValidateAccounts(user, validator state.AccountsAdapter) error {
	if r == nil || check.IfNil(r.user) || check.IfNil(r.validator) || user != r.user || validator != r.validator {
		return errInvalidMetaContext
	}
	return nil
}

func (r *readOnlyClassifier) ClassifyToken(tokenID []byte) (bool, error) {
	if r == nil {
		return false, errInvalidMetaContext
	}
	members := r.owner.snapshot.Load()
	if members == nil {
		return false, ErrClassificationUnresolved
	}
	_, regulated := (*members)[string(tokenID)]
	return regulated, nil
}

func (r *readOnlyClassifier) WithTokenClassification(accounts state.AccountsAdapter, tokenID []byte,
	execute func(bool) (*vmcommon.VMOutput, error)) (*vmcommon.VMOutput, error) {
	if r == nil || accounts != r.user || execute == nil {
		return nil, errInvalidMetaContext
	}
	regulated, err := r.ClassifyToken(tokenID)
	if err != nil {
		return nil, vm.NewDRWAClassificationUnavailable(err)
	}
	return execute(regulated)
}

// WithDRWAAccountProtection keeps the protected-account refusal of the native
// deletion guard for simulated execution; it owns no view to hold.
func (r *readOnlyClassifier) WithDRWAAccountProtection(accounts state.AccountsAdapter, execute func() error) error {
	if r == nil || accounts != r.user || execute == nil {
		return errInvalidMetaContext
	}
	return execute()
}

// ShardRegistrySource is the boundary to the finalized-registry import
// (tracker row SP2-22). Its implementation must answer membership at the
// metachain registry anchor required by the shard block in execution, from an
// authenticated, locally applied projection (committedRegistry.prepareDelta and
// registryCandidate.stage in this package). No production implementation
// exists yet.
type ShardRegistrySource interface {
	TokenClassifier
}

// ShardClassification is the execution-shard classifier. Without a registry
// source every classification is unresolved; it is never ordinary by default.
type ShardClassification struct {
	source ShardRegistrySource
}

// NewShardClassification accepts a nil source: the node then refuses every
// dependent native effect while DRWA is enforced.
func NewShardClassification(source ShardRegistrySource) *ShardClassification {
	if check.IfNil(source) {
		source = nil
	}
	return &ShardClassification{source: source}
}

// ClassifyToken returns the source's answer, or the unresolved error.
func (s *ShardClassification) ClassifyToken(tokenID []byte) (bool, error) {
	if s == nil || s.source == nil {
		return false, ErrClassificationUnresolved
	}
	return s.source.ClassifyToken(tokenID)
}

// IsInterfaceNil returns true if there is no value under the interface
func (s *ShardClassification) IsInterfaceNil() bool { return s == nil }

// builtInTokenFunctions is the closed set of loaded built-ins that carry a
// token identifier in their first argument (P17 direct inventory: every
// built-in except the nine account-only ones and the three transfers, whose
// identifiers come from the native transfer parse).
var builtInTokenFunctions = map[string]struct{}{
	core.BuiltInFunctionESDTPause: {}, core.BuiltInFunctionESDTUnPause: {},
	core.BuiltInFunctionSetESDTRole: {}, core.BuiltInFunctionUnSetESDTRole: {},
	core.BuiltInFunctionESDTBurn: {}, core.BuiltInFunctionESDTLocalBurn: {}, core.BuiltInFunctionESDTLocalMint: {},
	core.BuiltInFunctionESDTNFTAddQuantity: {}, core.BuiltInFunctionESDTNFTBurn: {}, core.BuiltInFunctionESDTNFTCreate: {},
	core.BuiltInFunctionESDTFreeze: {}, core.BuiltInFunctionESDTUnFreeze: {}, core.BuiltInFunctionESDTWipe: {},
	core.BuiltInFunctionESDTNFTCreateRoleTransfer: {}, core.BuiltInFunctionESDTNFTUpdateAttributes: {},
	core.BuiltInFunctionESDTNFTAddURI:          {},
	core.BuiltInFunctionESDTSetLimitedTransfer: {}, core.BuiltInFunctionESDTUnSetLimitedTransfer: {},
	vmcommon.ESDTDeleteMetadata: {}, vmcommon.ESDTAddMetadata: {},
	vmcommon.BuiltInFunctionESDTSetBurnRoleForAll: {}, vmcommon.BuiltInFunctionESDTUnSetBurnRoleForAll: {},
	vmcommon.BuiltInFunctionESDTTransferRoleDeleteAddress: {}, vmcommon.BuiltInFunctionESDTTransferRoleAddAddress: {},
	core.ESDTSetTokenType: {}, core.ESDTMetaDataRecreate: {}, core.ESDTMetaDataUpdate: {},
	core.ESDTSetNewURIs: {}, core.ESDTModifyRoyalties: {}, core.ESDTModifyCreator: {},
}

// builtInAccountFunctions carry no token identifier.
var builtInAccountFunctions = map[string]struct{}{
	core.BuiltInFunctionClaimDeveloperRewards: {}, core.BuiltInFunctionChangeOwnerAddress: {},
	core.BuiltInFunctionSetUserName: {}, "DeleteUserName": {},
	core.BuiltInFunctionSaveKeyValue: {}, core.BuiltInFunctionSetGuardian: {},
	core.BuiltInFunctionGuardAccount: {}, core.BuiltInFunctionUnGuardAccount: {},
	core.BuiltInFunctionMigrateDataTrie: {},
}

// BuiltInAdmission classifies the token identifiers of a public built-in call
// before its first native effect (Part A 5.1, F.5 D17). An ordinary call is
// returned to the untouched native dispatch. A regulated identifier is refused
// on this public path: the regulated transfer, supply and administration routes
// are separate DRWA operations. An unresolved classification, an unknown
// built-in or a transfer without the native parse seam is a DRWA execution
// error, so the block is not processed on this node.
type BuiltInAdmission struct {
	classifier TokenClassifier
}

// NewBuiltInAdmission requires the classifier of the store the built-ins
// write. Without a classifier there is no admission: it returns nil.
func NewBuiltInAdmission(classifier TokenClassifier) *BuiltInAdmission {
	if check.IfNil(classifier) {
		return nil
	}
	return &BuiltInAdmission{classifier: classifier}
}

// IsInterfaceNil returns true if there is no value under the interface
func (a *BuiltInAdmission) IsInterfaceNil() bool { return a == nil }

// esdtRandomSequenceLength is the length of the random part of an ESDT
// identifier (TICKER-xxxxxx), as the native freeze/wipe parse uses it.
const esdtRandomSequenceLength = 6

var errBuiltInIdentifiers = errors.New("DRWA built-in identifiers observed")
var errUnknownBuiltIn = errors.New("built-in function is not in the DRWA route inventory")

// builtInIdentifierProbe stops the native gated entry right after its own
// identifier parse, before account resolution and before any effect.
type builtInIdentifierProbe struct {
	identifiers [][]byte
	observed    bool
}

func (p *builtInIdentifierProbe) Classify(_ string, identifiers [][]byte) (bool, error) {
	p.identifiers, p.observed = identifiers, true
	return false, errBuiltInIdentifiers
}

func (p *builtInIdentifierProbe) CheckTransfer(string, []byte, *vmcommon.ParsedESDTTransfers, *vmcommon.ContractCallInput) error {
	return errRouteNativeGuard
}

func (p *builtInIdentifierProbe) IsInterfaceNil() bool { return p == nil }

// AdmitBuiltIn returns nil only for a call none of whose identifiers is
// regulated. It reads no account and changes no state or input.
func (a *BuiltInAdmission) AdmitBuiltIn(function vmcommon.BuiltinFunction, input *vmcommon.ContractCallInput) error {
	if a == nil || check.IfNil(function) || input == nil {
		return vm.ErrDRWAExecution
	}
	identifiers, err := builtInIdentifiers(function, input)
	if err != nil {
		return err
	}
	for _, identifier := range identifiers {
		regulated, classifyErr := a.classifier.ClassifyToken(identifier)
		if classifyErr != nil {
			return fmt.Errorf("%w: %w", vm.ErrDRWAExecution, classifyErr)
		}
		if regulated {
			return fmt.Errorf("%w: %s", ErrRegulatedTokenOperation, input.Function)
		}
	}
	return nil
}

func builtInIdentifiers(function vmcommon.BuiltinFunction, input *vmcommon.ContractCallInput) ([][]byte, error) {
	switch input.Function {
	case core.BuiltInFunctionESDTTransfer, core.BuiltInFunctionESDTNFTTransfer, core.BuiltInFunctionMultiESDTNFTTransfer:
		native, ok := function.(vmcommon.BuiltinFunctionWithESDTTransferGate)
		if !ok {
			return nil, vm.ErrDRWAExecution
		}
		probe := &builtInIdentifierProbe{}
		_, _, err := native.ProcessBuiltinFunctionWithESDTTransferGate(input,
			func(*vmcommon.ContractCallInput, bool) (vmcommon.UserAccountHandler, vmcommon.UserAccountHandler, error) {
				return nil, nil, errRouteNativeGuard
			}, probe)
		if probe.observed && errors.Is(err, errBuiltInIdentifiers) {
			return probe.identifiers, nil
		}
		if err == nil || probe.observed {
			// The native entry went past the probe: never continue.
			return nil, vm.ErrDRWAExecution
		}
		// The native parse refused the input before classification. The
		// untouched native call owns that validation and its error.
		return nil, nil
	}
	if _, tokenBearing := builtInTokenFunctions[input.Function]; tokenBearing {
		if len(input.Arguments) == 0 {
			return nil, nil
		}
		switch input.Function {
		case vmcommon.ESDTDeleteMetadata, vmcommon.ESDTAddMetadata:
			// These carry several identifiers at data-dependent positions. The
			// native parse requires each to be a valid identifier, and no
			// interval, nonce or metadata argument of theirs can equal a
			// registered identifier, so every valid identifier is classified.
			var identifiers [][]byte
			for _, argument := range input.Arguments {
				if vmcommon.ValidateToken(argument) {
					identifiers = append(identifiers, argument)
				}
			}
			return identifiers, nil
		case core.BuiltInFunctionESDTFreeze, core.BuiltInFunctionESDTUnFreeze, core.BuiltInFunctionESDTWipe:
			// The native argument is the identifier, optionally followed by the
			// nonce bytes of one NFT. Classify it both ways.
			first := input.Arguments[0]
			if dash := bytes.IndexByte(first, '-'); dash >= 0 && len(first) > dash+1+esdtRandomSequenceLength {
				return [][]byte{first, first[:dash+1+esdtRandomSequenceLength]}, nil
			}
			return [][]byte{first}, nil
		}
		return [][]byte{input.Arguments[0]}, nil
	}
	if _, accountOnly := builtInAccountFunctions[input.Function]; accountOnly {
		return nil, nil
	}
	if input.Function == RegistryDeltaFunctionName {
		// The registry writer itself: it creates the membership that every
		// other call is classified by, and admits only the metachain ESDT
		// system contract as its caller.
		return nil, nil
	}
	if input.Function == AdminEffectFunctionName {
		// The protected admin leg: its identifier is inside the envelope, which
		// the function itself authenticates together with its sender, the
		// metachain ESDT system contract.
		return nil, nil
	}
	return nil, fmt.Errorf("%w: %w: %s", vm.ErrDRWAExecution, errUnknownBuiltIn, input.Function)
}
