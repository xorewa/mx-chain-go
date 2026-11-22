package drwa

import (
	"bytes"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/trie"
)

// resultWitnessStorage restricts native lookup to the supplied node bytes.
// It has no fallback to the caller's proof cache and publishes no stored nodes.
type resultWitnessStorage struct {
	common.StorageManager
	nodes map[string][]byte
}

func (s *resultWitnessStorage) Get(key []byte) ([]byte, error) {
	node, found := s.nodes[string(key)]
	if !found {
		return nil, ErrInvalidAccountWitness
	}
	return bytes.Clone(node), nil
}

func (s *resultWitnessStorage) GetFromCurrentEpoch(key []byte) ([]byte, error) {
	return s.Get(key)
}

func (s *resultWitnessStorage) Put(_ []byte, _ []byte) error {
	return ErrInvalidAccountWitness
}

func (s *resultWitnessStorage) IsInterfaceNil() bool {
	return s == nil
}

// readAbsent establishes only a native account/item absence fact at the exact
// result root selected by H for S. It does not establish canonical finality,
// complete class applicability, no-work permission, first eligibility or funding.
// The owning caller must independently admit those facts and the source-epoch
// configuration. No current-epoch configuration fallback is selected here.
//
// Native lookup distinguishes a missing key from a missing storage node. Every
// node it can read is frozen and content-addressed from this witness; a warm
// local cache cannot complete an unavailable path. Native account creation and
// RetrieveValue retain the existing account/data-trie encodings. A bare empty
// main-state root is deliberately unsupported rather than a header-only negative.
func (r *ResultAccountReader) readAbsent(committedH []byte, producingShard uint32,
	address, itemKey []byte, w AccountItemWitness, proofByteLimit int) error {
	r.mut.Lock()
	defer r.mut.Unlock()

	if len(committedH) == 0 || len(address) == 0 || len(itemKey) == 0 ||
		proofByteLimit <= 0 || len(w.AccountProof) == 0 {
		return ErrInvalidAccountWitness
	}
	w.Header = bytes.Clone(w.Header)
	w.ExecutedHeader = bytes.Clone(w.ExecutedHeader)
	address, itemKey = bytes.Clone(address), bytes.Clone(itemKey)
	if !bytes.Equal(r.args.Hasher.Compute(string(w.Header)), committedH) {
		return ErrInvalidAccountWitness
	}

	view := &resultWitnessStorage{StorageManager: r.args.StorageManager, nodes: make(map[string][]byte)}
	used := 0
	for _, proof := range [][][]byte{w.AccountProof, w.DataProof} {
		for _, raw := range proof {
			if len(raw) == 0 || len(raw) > proofByteLimit-used {
				return ErrInvalidAccountWitness
			}
			node := bytes.Clone(raw)
			view.nodes[string(r.args.Hasher.Compute(string(node)))] = node
			used += len(raw)
		}
	}
	root, err := r.executionRoot(producingShard, w)
	if err != nil {
		return err
	}
	if common.IsEmptyTrie(root) {
		return ErrInvalidAccountWitness
	}
	native, err := trie.NewTrie(view, r.args.Marshaller, r.args.Hasher,
		r.args.EnableEpochsHandler, r.args.MaxTrieLevelInMemory)
	if err != nil {
		return err
	}
	mainTrie, err := native.Recreate(holders.NewDefaultRootHashesHolder(root))
	if err != nil {
		return ErrInvalidAccountWitness
	}
	accountBytes, _, err := mainTrie.Get(address)
	if err != nil {
		return ErrInvalidAccountWitness
	}
	if len(accountBytes) == 0 {
		return nil
	}
	account, err := r.accountFactory.CreateAccount(address)
	if err != nil {
		return err
	}
	user, valid := account.(state.UserAccountHandler)
	if !valid || r.args.Marshaller.Unmarshal(user, accountBytes) != nil ||
		!bytes.Equal(user.AddressBytes(), address) {
		return ErrInvalidAccountWitness
	}
	dataTrie, err := native.Recreate(holders.NewDefaultRootHashesHolder(user.GetRootHash()))
	if err != nil {
		return ErrInvalidAccountWitness
	}
	user.SetDataTrie(dataTrie)
	value, _, err := user.RetrieveValue(itemKey)
	if err != nil || len(value) != 0 {
		return ErrInvalidAccountWitness
	}
	return nil
}
