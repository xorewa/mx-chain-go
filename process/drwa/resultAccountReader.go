package drwa

import (
	"bytes"
	"errors"
	"sync"

	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	stateDisabled "github.com/multiversx/mx-chain-go/state/disabled"
	"github.com/multiversx/mx-chain-go/state/factory"
	"github.com/multiversx/mx-chain-go/trie"
)

// ErrInvalidAccountWitness is DRWA-defined: the supplied result/account/item
// witness does not authenticate the caller's requested locus.
var ErrInvalidAccountWitness = errors.New("invalid DRWA result account witness")

// ArgsResultAccountReader supplies native dependencies, not a DRWA codec or gas
// profile. Storage must be a dedicated proof cache, never execution-state storage.
// Its lifecycle and bounded retention belong to the eventual consumer (T43).
type ArgsResultAccountReader struct {
	StorageManager       common.StorageManager
	Marshaller           marshal.Marshalizer
	Hasher               hashing.Hasher
	EnableEpochsHandler  common.EnableEpochsHandler
	MaxTrieLevelInMemory uint
}

// AccountItemWitness is DRWA-defined. H commits S's complete native execution
// result; its root authenticates account bytes and that account's data-trie item.
// No untrusted parallel API value, address or item key is accepted in the witness.
type AccountItemWitness struct {
	Header, ExecutedHeader  []byte
	AccountProof, DataProof [][]byte
}

// ResultAccountReader is an unwired DRWA-owned byte reader (Part A 6.1,
// L5251-5285). It does NOT establish canonical finality, select a protected
// namespace or write consumer progress. T43 must authenticate committedH and
// bind the returned item and complete result to the route's M/B predicate.
// Native account creation and RetrieveValue preserve both native data-trie
// encodings; no custom account or leaf decoder is introduced.
type ResultAccountReader struct {
	mut            sync.Mutex
	args           ArgsResultAccountReader
	proofTrie      common.Trie
	accountFactory state.AccountFactory
}

// NewResultAccountReader creates a reader using pinned native trie and account
// semantics. Dependencies must remain configured for the witness's epoch during
// Read; epoch ownership/activation and real consumer wiring are T43 obligations.
func NewResultAccountReader(args ArgsResultAccountReader) (*ResultAccountReader, error) {
	tr, err := trie.NewTrie(args.StorageManager, args.Marshaller, args.Hasher,
		args.EnableEpochsHandler, args.MaxTrieLevelInMemory)
	if err != nil {
		return nil, err
	}
	af, err := factory.NewAccountCreator(factory.ArgsAccountCreator{
		Hasher: args.Hasher, Marshaller: args.Marshaller,
		EnableEpochsHandler:    args.EnableEpochsHandler,
		StateAccessesCollector: stateDisabled.NewDisabledStateAccessesCollector(),
	})
	if err != nil {
		return nil, err
	}
	return &ResultAccountReader{args: args, proofTrie: tr, accountFactory: af}, nil
}

// Read returns only the native value at the caller-owned address/logical key.
// committedH, producingShard, address and itemKey are trusted owning-caller
// inputs, not facts learned from the witness. proofByteLimit is an explicit
// caller bound across BOTH proofs, not an invented production profile/default.
// The caller must not concurrently mutate input bytes or native dependencies.
func (r *ResultAccountReader) Read(committedH []byte, producingShard uint32,
	address, itemKey []byte, w AccountItemWitness, proofByteLimit int) ([]byte, error) {
	r.mut.Lock()
	defer r.mut.Unlock()
	if len(committedH) == 0 || len(address) == 0 || len(itemKey) == 0 ||
		!bytes.Equal(r.args.Hasher.Compute(string(w.Header)), committedH) {
		return nil, ErrInvalidAccountWitness
	}
	used := 0
	for _, nodes := range [][][]byte{w.AccountProof, w.DataProof} {
		if len(nodes) == 0 {
			return nil, ErrInvalidAccountWitness
		}
		for _, node := range nodes {
			if len(node) == 0 || used > proofByteLimit || len(node) > proofByteLimit-used {
				return nil, ErrInvalidAccountWitness
			}
			used += len(node)
		}
	}
	h, s := &block.HeaderV3{}, &block.HeaderV3{}
	if r.args.Marshaller.Unmarshal(h, w.Header) != nil ||
		r.args.Marshaller.Unmarshal(s, w.ExecutedHeader) != nil ||
		h.ShardID != producingShard || s.ShardID != producingShard {
		return nil, ErrInvalidAccountWitness
	}
	sHash := r.args.Hasher.Compute(string(w.ExecutedHeader))
	var result *block.ExecutionResult
	for _, candidate := range h.ExecutionResults {
		if candidate == nil || candidate.BaseExecutionResult == nil {
			return nil, ErrInvalidAccountWitness
		}
		if bytes.Equal(candidate.BaseExecutionResult.HeaderHash, sHash) {
			if result != nil {
				return nil, ErrInvalidAccountWitness
			}
			result = candidate
		}
	}
	if result == nil || result.BaseExecutionResult.HeaderNonce != s.Nonce ||
		result.BaseExecutionResult.HeaderRound != s.Round || result.BaseExecutionResult.HeaderEpoch != s.Epoch {
		return nil, ErrInvalidAccountWitness
	}
	root := result.BaseExecutionResult.RootHash
	valid, err := r.proofTrie.VerifyProof(root, address, w.AccountProof)
	if err != nil || !valid {
		return nil, ErrInvalidAccountWitness
	}
	if err = r.cacheProof(w.AccountProof); err != nil {
		return nil, err
	}
	mainTrie, err := r.proofTrie.Recreate(holders.NewDefaultRootHashesHolder(root))
	if err != nil {
		return nil, err
	}
	accountBytes, _, err := mainTrie.Get(address)
	if err != nil || len(accountBytes) == 0 {
		return nil, ErrInvalidAccountWitness
	}
	a, err := r.accountFactory.CreateAccount(address)
	if err != nil {
		return nil, err
	}
	user, ok := a.(state.UserAccountHandler)
	if !ok || r.args.Marshaller.Unmarshal(user, accountBytes) != nil ||
		!bytes.Equal(user.AddressBytes(), address) || len(user.GetRootHash()) == 0 {
		return nil, ErrInvalidAccountWitness
	}
	valid, err = r.proofTrie.VerifyProof(user.GetRootHash(), itemKey, w.DataProof)
	if err != nil || !valid {
		return nil, ErrInvalidAccountWitness
	}
	if err = r.cacheProof(w.DataProof); err != nil {
		return nil, err
	}
	dataTrie, err := r.proofTrie.Recreate(holders.NewDefaultRootHashesHolder(user.GetRootHash()))
	if err != nil {
		return nil, err
	}
	user.SetDataTrie(dataTrie)
	value, _, err := user.RetrieveValue(itemKey)
	if err != nil || len(value) == 0 {
		return nil, ErrInvalidAccountWitness
	}
	return bytes.Clone(value), nil
}

func (r *ResultAccountReader) cacheProof(nodes [][]byte) error {
	for _, node := range nodes {
		// The cache key is derived exclusively from authenticated node bytes.
		if err := r.args.StorageManager.Put(r.args.Hasher.Compute(string(node)), bytes.Clone(node)); err != nil {
			return err
		}
	}
	return nil
}
