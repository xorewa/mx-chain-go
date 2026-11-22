package drwa

import (
	"bytes"

	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
)

// BuildNativeWitness constructs the existing witness carrier from the actual
// source accounts' committed trie root. nativeDataKey is the native physical
// key, derived by the caller's admitted source-era storage profile.
// It preserves a native query error with its bounded proof prefix. Neither an
// error nor a prefix is a no-work/canonicality decision. Source-era codec,
// historical service and original-source work funding remain first-use gates.
func (r *ResultAccountReader) BuildNativeWitness(source state.AccountsAdapter,
	committedH []byte, producingShard uint32, address, nativeDataKey []byte,
	template AccountItemWitness, proofByteLimit int,
) (AccountItemWitness, error) {
	var w AccountItemWitness
	if source == nil || source.IsInterfaceNil() || proofByteLimit <= 0 ||
		len(committedH) == 0 || len(address) == 0 || len(nativeDataKey) == 0 ||
		len(address) > proofByteLimit || len(nativeDataKey) > proofByteLimit ||
		len(template.Header) == 0 || len(template.Header) > proofByteLimit ||
		len(template.ExecutedHeader) > proofByteLimit {
		return w, ErrInvalidAccountWitness
	}
	w.Header = bytes.Clone(template.Header)
	w.ExecutedHeader = bytes.Clone(template.ExecutedHeader)
	address = bytes.Clone(address)
	nativeDataKey = bytes.Clone(nativeDataKey)
	committedH = bytes.Clone(committedH)

	r.mut.Lock()
	defer r.mut.Unlock()
	if !bytes.Equal(r.args.Hasher.Compute(string(w.Header)), committedH) {
		return w, ErrInvalidAccountWitness
	}
	root, err := r.executionRoot(producingShard, w)
	if err != nil {
		return w, err
	}
	main, err := source.GetTrie(root)
	if err != nil {
		return w, err
	}
	if main == nil || main.IsInterfaceNil() {
		return w, ErrInvalidAccountWitness
	}
	actualRoot, err := main.RootHash()
	if err != nil {
		return w, err
	}
	if !bytes.Equal(actualRoot, root) {
		return w, ErrInvalidAccountWitness
	}
	type nativeQuery interface {
		GetProofForQuery([]byte) ([][]byte, []byte, error)
	}
	query, supported := main.(nativeQuery)
	if !supported {
		return w, state.ErrFunctionalityNotImplemented
	}
	remaining := proofByteLimit
	copyProof := func(nodes [][]byte) ([][]byte, error) {
		if nodes == nil {
			return nil, nil
		}
		out := make([][]byte, len(nodes))
		for i, node := range nodes {
			if len(node) > remaining {
				return nil, ErrInvalidAccountWitness
			}
			remaining -= len(node)
			out[i] = bytes.Clone(node)
		}
		return out, nil
	}
	nodes, accountBytes, queryErr := query.GetProofForQuery(address)
	w.AccountProof, err = copyProof(nodes)
	if err != nil {
		return w, err
	}
	if queryErr != nil {
		return w, queryErr
	}
	if len(accountBytes) == 0 || len(w.AccountProof) == 0 {
		return w, ErrInvalidAccountWitness
	}
	accountBytes = bytes.Clone(accountBytes)
	account, err := r.accountFactory.CreateAccount(address)
	if err != nil {
		return w, err
	}
	user, supported := account.(state.UserAccountHandler)
	if !supported || r.args.Marshaller.Unmarshal(user, accountBytes) != nil ||
		!bytes.Equal(user.AddressBytes(), address) || len(user.GetRootHash()) == 0 {
		return w, ErrInvalidAccountWitness
	}
	data, err := main.Recreate(holders.NewDefaultRootHashesHolder(user.GetRootHash()))
	if err != nil {
		return w, err
	}
	if data == nil || data.IsInterfaceNil() {
		return w, ErrInvalidAccountWitness
	}
	actualRoot, err = data.RootHash()
	if err != nil {
		return w, err
	}
	if !bytes.Equal(actualRoot, user.GetRootHash()) {
		return w, ErrInvalidAccountWitness
	}
	query, supported = data.(nativeQuery)
	if !supported {
		return w, state.ErrFunctionalityNotImplemented
	}
	nodes, _, queryErr = query.GetProofForQuery(nativeDataKey)
	w.DataProof, err = copyProof(nodes)
	if err != nil {
		return w, err
	}
	return w, queryErr
}
