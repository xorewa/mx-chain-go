package drwa

import (
	"bytes"
	"errors"
	"sync"

	"github.com/multiversx/mx-chain-core-go/core"
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
// It supports HeaderV3/ExecutionResult for execution shards and
// MetaBlockV3/MetaExecutionResult for the metachain. The trusted producingShard
// selects the native header family; neither family establishes canonical
// finality or selects the candidate's required metachain context.
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
	root, err := r.executionRoot(producingShard, w)
	if err != nil {
		return nil, err
	}
	return r.readAccountItem(root, address, itemKey, w)
}

// readRegistryItem consumes a root selected from the caller-validated native
// candidate context, including a retained LastExecutionResult. It is private to
// the T08 registry construction and fixes the account to the L26 system account.
// It cannot select its authority from the witness. Native ownership/finality,
// epoch configuration and stable inputs remain the selecting caller's duties.
func (r *ResultAccountReader) readRegistryItem(anchor *metaRegistryAnchor,
	itemKey []byte, w AccountItemWitness, proofByteLimit int) ([]byte, error) {
	r.mut.Lock()
	defer r.mut.Unlock()
	if anchor == nil || len(anchor.candidateHash) == 0 || len(anchor.metaHash) == 0 ||
		len(anchor.executedHash) == 0 || len(anchor.root) == 0 || len(itemKey) == 0 ||
		len(w.Header) != 0 || len(w.ExecutedHeader) != 0 {
		return nil, ErrInvalidAccountWitness
	}
	if _, err := registryProofBytes(w, proofByteLimit); err != nil {
		return nil, err
	}
	return r.readAccountItem(anchor.root, bytes.Clone(core.SystemAccountAddress), itemKey, w)
}

// readAccountItem requires the reader mutex and validated native root/proof
// bounds. Both native result paths reuse exactly the same proof/account decoder.
func (r *ResultAccountReader) readAccountItem(root, address, itemKey []byte,
	w AccountItemWitness) ([]byte, error) {
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

// executionRoot adopts the native result wrappers. A meta header's own
// GetRootHash is nil: only the result for the exact executed header supplies
// the account root (Part A L5263; native core metaBlockV3.go L211-219).
func (r *ResultAccountReader) executionRoot(producingShard uint32, w AccountItemWitness) ([]byte, error) {
	var nonce, round uint64
	var epoch uint32
	var results []*block.BaseExecutionResult
	if producingShard == core.MetachainShardId {
		h, s := &block.MetaBlockV3{}, &block.MetaBlockV3{}
		if r.args.Marshaller.Unmarshal(h, w.Header) != nil ||
			r.args.Marshaller.Unmarshal(s, w.ExecutedHeader) != nil {
			return nil, ErrInvalidAccountWitness
		}
		nonce, round, epoch = s.Nonce, s.Round, s.Epoch
		for _, result := range h.ExecutionResults {
			if result == nil || result.ExecutionResult == nil || result.ExecutionResult.BaseExecutionResult == nil {
				return nil, ErrInvalidAccountWitness
			}
			results = append(results, result.ExecutionResult.BaseExecutionResult)
		}
	} else {
		h, s := &block.HeaderV3{}, &block.HeaderV3{}
		if r.args.Marshaller.Unmarshal(h, w.Header) != nil ||
			r.args.Marshaller.Unmarshal(s, w.ExecutedHeader) != nil ||
			h.ShardID != producingShard || s.ShardID != producingShard {
			return nil, ErrInvalidAccountWitness
		}
		nonce, round, epoch = s.Nonce, s.Round, s.Epoch
		for _, result := range h.ExecutionResults {
			if result == nil || result.BaseExecutionResult == nil {
				return nil, ErrInvalidAccountWitness
			}
			results = append(results, result.BaseExecutionResult)
		}
	}
	sHash := r.args.Hasher.Compute(string(w.ExecutedHeader))
	var result *block.BaseExecutionResult
	for _, candidate := range results {
		if bytes.Equal(candidate.HeaderHash, sHash) {
			if result != nil {
				return nil, ErrInvalidAccountWitness
			}
			result = candidate
		}
	}
	if result == nil || result.HeaderNonce != nonce ||
		result.HeaderRound != round || result.HeaderEpoch != epoch {
		return nil, ErrInvalidAccountWitness
	}
	return result.RootHash, nil
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
