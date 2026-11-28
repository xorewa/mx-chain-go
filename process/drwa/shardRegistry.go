package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"
	"sync"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// RegistryDeltaFunctionName is the protected built-in call by which the
// metachain registration delivers one new registry member to every execution
// shard, as an ordinary metachain-to-shard result (owner decision of
// 27 November 2026, option A). It is the first result the registration emits,
// and the only one it releases once the metachain half of the acknowledged
// registration is installed (RegistrationEffects, option 1 of the same day).
const RegistryDeltaFunctionName = "DRWARegistryDelta"

// ErrInvalidRegistryDelta refuses a delta call that is not the next member
// sent by the metachain ESDT system contract to this shard's system account.
var ErrInvalidRegistryDelta = errors.New("invalid DRWA registry delta")

// registryDeltaSystemAddress is the per-shard system account address that the
// native all-shard fan-out uses (vm/systemSmartContracts/eei.go,
// SendGlobalSettingToAll).
func registryDeltaSystemAddress(shard uint32) []byte {
	address := bytes.Clone(core.SystemAccountAddress)
	address[len(address)-1] = uint8(shard)
	return address
}

// emitRegistryDelta adds, for every execution shard, one delta call to the
// registration's native output, ahead of every transfer still in it: results
// are created in transfer-index order
// (process/smartContract/processorV2/vmOutputAccountsProcessor.go, sortIndexedScrs).
// ordinal is the member's position in the registry.
//
// Each delta is a native asynchronous call. The shard's acknowledgment is then
// the native callback of that call, which the result processor of the shard
// creates itself from the outcome of the delta
// (process/smartContract/processorV2, createAsyncCallBackSCRFromVMOutput) and
// which carries the gas the delta did not use. A result for the metachain
// that has neither value nor gas is dropped by that processor
// (deleteSCRsWithValueZeroGoingToMeta): a delta emitted with no gas is applied
// by the shard and never acknowledged.
func emitRegistryDelta(output *vmcommon.VMOutput, tokenID []byte, ordinal uint64, shards uint32, gas uint64) error {
	if output == nil || shards > 255 || !vmcommon.ValidateToken(tokenID) {
		return ErrInvalidRegistryDelta
	}
	lowest, found := uint32(0), false
	for _, account := range output.OutputAccounts {
		if account == nil {
			return ErrInvalidRegistryDelta
		}
		for _, transfer := range account.OutputTransfers {
			if bytes.HasPrefix(transfer.Data, []byte(RegistryDeltaFunctionName+"@")) {
				return ErrInvalidRegistryDelta
			}
			if !found || transfer.Index < lowest {
				lowest, found = transfer.Index, true
			}
		}
	}
	for _, account := range output.OutputAccounts {
		for i := range account.OutputTransfers {
			if account.OutputTransfers[i].Index > ^uint32(0)-shards {
				return ErrInvalidRegistryDelta
			}
			account.OutputTransfers[i].Index += shards
		}
	}
	if output.OutputAccounts == nil {
		output.OutputAccounts = make(map[string]*vmcommon.OutputAccount, shards)
	}
	member := binary.BigEndian.AppendUint64(bytes.Clone(tokenID), ordinal)
	data := []byte(RegistryDeltaFunctionName + "@" + hexEncode(tokenID) + "@" + hexEncode(member[len(tokenID):]))
	for shard := uint32(0); shard < shards; shard++ {
		address := registryDeltaSystemAddress(shard)
		account, exists := output.OutputAccounts[string(address)]
		if !exists {
			account = &vmcommon.OutputAccount{Address: address, BalanceDelta: big.NewInt(0)}
			output.OutputAccounts[string(address)] = account
		}
		// The native identifiers of an asynchronous call: this delivery, and
		// the member it belongs to. The callback returns both.
		delivery := append(bytes.Clone(member), uint8(shard))
		account.OutputTransfers = append(account.OutputTransfers, vmcommon.OutputTransfer{
			Index: lowest + shard, Value: big.NewInt(0), GasLimit: gas, Data: bytes.Clone(data),
			AsyncData: []byte("@" + hexEncode(delivery) + "@" + hexEncode(member)),
			CallType:  vmData.AsynchronousCall, SenderAddress: bytes.Clone(core.ESDTSCAddress),
		})
	}
	return nil
}

// RegistryAcknowledgmentFunctionName is the function under which the native
// processor delivers the callback of an asynchronous call to its caller
// (process/smartContract/processorV2/vmInputV2.go).
const RegistryAcknowledgmentFunctionName = "callBack"

// ErrInvalidRegistryAcknowledgment refuses a call that is not the
// acknowledgment of an execution shard.
var ErrInvalidRegistryAcknowledgment = errors.New("invalid DRWA registry acknowledgment")

// RegistryAcknowledgment is one shard's statement that it holds member
// Ordinal, TokenID, in the registry it commits with its blocks.
type RegistryAcknowledgment struct {
	Shard   uint32
	TokenID []byte
	Ordinal uint64
}

// ParseRegistryAcknowledgment is the metachain's reading of the callback of a
// delta, as the native processor hands it to the metachain ESDT system
// contract: a callback whose caller is the system account address of an
// execution shard, which names the shard, with the return code of the delta
// and what an applied delta returns, the token identifier and the eight-byte
// ordinal. The callback of a refused delta carries another return code and is
// not an acknowledgment. This authenticates the form of the call only; that no
// other producer on that shard can emit a callback with this sender is an
// obligation of the metachain half (Part A, hostile producer requirement).
func ParseRegistryAcknowledgment(input *vmcommon.ContractCallInput, shards uint32) (*RegistryAcknowledgment, error) {
	if input == nil || shards > 255 || input.CallType != vmData.AsynchronousCallBack ||
		input.Function != RegistryAcknowledgmentFunctionName || !bytes.Equal(input.RecipientAddr, core.ESDTSCAddress) ||
		input.CallValue == nil || input.CallValue.Sign() != 0 ||
		len(input.CallerAddr) != len(core.SystemAccountAddress) || len(input.Arguments) != 3 ||
		!bytes.Equal(input.Arguments[0], []byte{byte(vmcommon.Ok)}) ||
		len(input.Arguments[2]) != 8 || !vmcommon.ValidateToken(input.Arguments[1]) {
		return nil, ErrInvalidRegistryAcknowledgment
	}
	shard := uint32(input.CallerAddr[len(input.CallerAddr)-1])
	if shard >= shards || !bytes.Equal(input.CallerAddr, registryDeltaSystemAddress(shard)) {
		return nil, ErrInvalidRegistryAcknowledgment
	}
	return &RegistryAcknowledgment{Shard: shard, TokenID: bytes.Clone(input.Arguments[1]),
		Ordinal: binary.BigEndian.Uint64(input.Arguments[2])}, nil
}

// acknowledged is the outcome of a delta this shard holds: the member, and
// all the gas the delta was given, which the delta call does not use. The
// native processor turns it into the callback. A delta delivered without gas
// is applied, but its callback does not leave the shard (see
// emitRegistryDelta); the metachain then never counts this shard, and the
// member can be delivered again with gas.
func acknowledged(input *vmcommon.ContractCallInput) *vmcommon.VMOutput {
	return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: input.GasProvided,
		ReturnData: [][]byte{bytes.Clone(input.Arguments[0]), bytes.Clone(input.Arguments[1])}}
}

func hexEncode(raw []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(raw))
	for _, b := range raw {
		out = append(out, digits[b>>4], digits[b&15])
	}
	return string(out)
}

// ShardRegistry is the execution-shard registry projection behind
// ShardRegistrySource (Part A 5.1 rules 1-5). Membership is the set of
// identifiers this shard has applied from metachain registry deltas; it is
// kept in the shard's own system account, so it is journaled, rolled back and
// committed with the block that applied it, and reconstructed from the
// committed store at startup. Classification is an in-memory lookup. The block
// processor calls BeginExecution before every execution and Committed after
// every native commit (process.DRWAClassificationHandler).
type ShardRegistry struct {
	mut       sync.RWMutex
	accounts  state.AccountsAdapter
	shard     uint32
	ready     bool
	root      []byte
	committed map[string]struct{}
	local     map[string]struct{}
}

// NewShardRegistry creates the projection of the processing store of one
// execution shard. It reads no state; until the first BeginExecution every
// classification is unresolved.
func NewShardRegistry(accounts state.AccountsAdapter, shard uint32) (*ShardRegistry, error) {
	if check.IfNil(accounts) || shard == core.MetachainShardId || shard > 255 {
		return nil, ErrInvalidRegistryDelta
	}
	return &ShardRegistry{accounts: accounts, shard: shard}, nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (r *ShardRegistry) IsInterfaceNil() bool { return r == nil }

// ClassifyToken answers from memory: the committed members and the members
// applied by the block in execution. Before the projection matches the store
// it is unresolved, never ordinary.
func (r *ShardRegistry) ClassifyToken(tokenID []byte) (bool, error) {
	r.mut.RLock()
	defer r.mut.RUnlock()
	if !r.ready {
		return false, ErrClassificationUnresolved
	}
	if _, regulated := r.committed[string(tokenID)]; regulated {
		return true, nil
	}
	_, regulated := r.local[string(tokenID)]
	return regulated, nil
}

// BeginExecution verifies that the projection is the one of the store's
// committed root and rebuilds it from the store otherwise (startup, state
// sync, a rollback to another block). Members applied by an execution that
// did not commit are dropped.
func (r *ShardRegistry) BeginExecution() error {
	r.mut.Lock()
	defer r.mut.Unlock()
	r.local = nil
	root, err := r.accounts.RootHash()
	if err != nil {
		r.ready = false
		return err
	}
	if r.ready && bytes.Equal(root, r.root) {
		return nil
	}
	return r.reconstruct(root)
}

// Committed follows the native commit. The members the block applied join the
// committed set; if the store disagrees with the result the projection is
// rebuilt from the store.
func (r *ShardRegistry) Committed() error {
	r.mut.Lock()
	defer r.mut.Unlock()
	root, err := r.accounts.RootHash()
	if err != nil {
		r.ready = false
		return err
	}
	if !r.ready {
		return r.reconstruct(root)
	}
	if len(r.local) == 0 {
		r.root = bytes.Clone(root)
		return nil
	}
	count, err := r.storedCount()
	if err != nil {
		r.ready = false
		return err
	}
	if count != uint64(len(r.committed)+len(r.local)) {
		return r.reconstruct(root)
	}
	for member := range r.local {
		r.committed[member] = struct{}{}
	}
	r.local, r.root = nil, bytes.Clone(root)
	return nil
}

// systemAccount returns nil when the system account is absent from the
// account trie: no delta was ever applied here. Members are kept where the
// native global settings of a shard are kept, in the system account itself.
func (r *ShardRegistry) systemAccount() (vmcommon.UserAccountHandler, error) {
	a, err := r.accounts.GetExistingAccount(bytes.Clone(core.SystemAccountAddress))
	if errors.Is(err, state.ErrAccNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u, ok := a.(vmcommon.UserAccountHandler)
	if !ok || check.IfNil(u) {
		return nil, ErrInvalidRegistryDelta
	}
	return u, nil
}

func shardRegistryValue(u vmcommon.UserAccountHandler, key []byte) ([]byte, error) {
	value, _, err := u.AccountDataHandler().RetrieveValue(key)
	if errors.Is(err, state.ErrNilTrie) && len(u.GetRootHash()) == 0 {
		// The account has no data trie in this state: the key is absent.
		return nil, nil
	}
	return value, err
}

func shardRegistryCount(u vmcommon.UserAccountHandler) (uint64, error) {
	value, err := shardRegistryValue(u, []byte(localMembershipCountKey))
	if err != nil || len(value) == 0 {
		return 0, err
	}
	if len(value) != 8 {
		return 0, ErrInvalidRegistryDelta
	}
	return binary.BigEndian.Uint64(value), nil
}

func (r *ShardRegistry) storedCount() (uint64, error) {
	u, err := r.systemAccount()
	if err != nil || u == nil {
		return 0, err
	}
	return shardRegistryCount(u)
}

func (r *ShardRegistry) reconstruct(root []byte) error {
	r.ready, r.local = false, nil
	members := make(map[string]struct{})
	u, err := r.systemAccount()
	if err != nil {
		return err
	}
	if u != nil {
		count, countErr := shardRegistryCount(u)
		if countErr != nil {
			return countErr
		}
		for ordinal := uint64(0); ordinal < count; ordinal++ {
			member, readErr := shardRegistryValue(u, localMembershipEntryKey(ordinal))
			if readErr != nil {
				return readErr
			}
			marker, readErr := shardRegistryMarker(u, member)
			if readErr != nil {
				return readErr
			}
			if _, duplicate := members[string(member)]; duplicate || !marker {
				return ErrInvalidRegistryDelta
			}
			members[string(member)] = struct{}{}
		}
	}
	r.committed, r.root, r.ready = members, bytes.Clone(root), true
	return nil
}

// shardMemberKey is membershipKey for an identifier already validated as a
// native token identifier, hence never empty.
func shardMemberKey(tokenID []byte) []byte {
	return append([]byte(membershipKeyPrefix), tokenID...)
}

func shardRegistryMarker(u vmcommon.UserAccountHandler, tokenID []byte) (bool, error) {
	if !vmcommon.ValidateToken(tokenID) {
		return false, ErrInvalidRegistryDelta
	}
	value, err := shardRegistryValue(u, shardMemberKey(tokenID))
	if err != nil || len(value) == 0 {
		return false, err
	}
	if len(value) != 1 || value[0] != 1 {
		return false, ErrInvalidRegistryDelta
	}
	return true, nil
}

// DeltaFunction returns the built-in that applies a delivered member to the
// store this projection follows. It belongs in that store's processing
// container only.
func (r *ShardRegistry) DeltaFunction() vmcommon.BuiltinFunction {
	return &registryDeltaFunction{registry: r}
}

type registryDeltaFunction struct {
	registry *ShardRegistry
}

// SetNewGasConfig does nothing: the call consumes no gas of its own, like the
// native global-setting calls of the ESDT system contract; what it is given
// stays for the acknowledgment.
func (f *registryDeltaFunction) SetNewGasConfig(*vmcommon.GasCost) {}

// IsActive always returns true
func (f *registryDeltaFunction) IsActive() bool { return true }

// IsInterfaceNil returns true if there is no value under the interface
func (f *registryDeltaFunction) IsInterfaceNil() bool { return f == nil }

// ProcessBuiltinFunction applies member number ordinal. Only the metachain
// ESDT system contract can be its caller, only by an asynchronous call, and
// only this shard's system account address its destination; members are
// applied in registry order, each exactly once. Its outcome is what the
// native processor returns to the metachain as the callback of that call: the
// shard's acknowledgment. A member this shard already holds at that ordinal
// is not applied again and has the same outcome, so that the metachain can
// deliver a member again without a second mutation. A refused delta has an
// error outcome.
func (f *registryDeltaFunction) ProcessBuiltinFunction(_, _ vmcommon.UserAccountHandler,
	input *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
	r := f.registry
	if input == nil || input.CallValue == nil || input.CallValue.Sign() != 0 ||
		input.CallType != vmData.AsynchronousCall || len(input.Arguments) != 2 || len(input.Arguments[1]) != 8 ||
		!bytes.Equal(input.CallerAddr, core.ESDTSCAddress) ||
		!bytes.Equal(input.RecipientAddr, registryDeltaSystemAddress(r.shard)) {
		return nil, ErrInvalidRegistryDelta
	}
	tokenID, ordinal := input.Arguments[0], binary.BigEndian.Uint64(input.Arguments[1])
	loaded, err := r.accounts.LoadAccount(bytes.Clone(core.SystemAccountAddress))
	if err != nil {
		return nil, err
	}
	account, ok := loaded.(vmcommon.UserAccountHandler)
	if !ok || check.IfNil(account) {
		return nil, ErrInvalidRegistryDelta
	}
	present, err := shardRegistryMarker(account, tokenID)
	if err != nil {
		return nil, err
	}
	count, err := shardRegistryCount(account)
	if err != nil {
		return nil, err
	}
	if present && ordinal < count {
		held, readErr := shardRegistryValue(account, localMembershipEntryKey(ordinal))
		if readErr != nil {
			return nil, readErr
		}
		if bytes.Equal(held, tokenID) {
			return acknowledged(input), nil
		}
	}
	if present || ordinal != count || count == ^uint64(0) {
		return nil, ErrInvalidRegistryDelta
	}
	data := account.AccountDataHandler()
	if err = data.SaveKeyValue(shardMemberKey(tokenID), []byte{1}); err != nil {
		return nil, err
	}
	if err = data.SaveKeyValue(localMembershipEntryKey(count), bytes.Clone(tokenID)); err != nil {
		return nil, err
	}
	if err = data.SaveKeyValue([]byte(localMembershipCountKey), binary.BigEndian.AppendUint64(nil, count+1)); err != nil {
		return nil, err
	}
	if err = r.accounts.SaveAccount(account); err != nil {
		return nil, err
	}
	r.mut.Lock()
	if r.local == nil {
		r.local = make(map[string]struct{})
	}
	r.local[string(tokenID)] = struct{}{}
	r.mut.Unlock()
	return acknowledged(input), nil
}
