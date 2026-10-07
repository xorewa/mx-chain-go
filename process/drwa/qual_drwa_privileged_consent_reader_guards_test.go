package drwa

import (
	"bytes"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/integrationTests"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Deliberate hostile state-origin fixtures, not successful actions and never
// eligibility evidence. Native AccountsDB and native membership proofs expose
// invalid records so that an overlapping tuple comparison cannot hide a guard.
func TestQualDRWAPrivilegedConsentHostileSelectedEvidence(t *testing.T) {
	for _, name := range []string{"empty_field", "over_bound", "domain", "short_address", "sc_address", "system_prefix", "reserved", "meta"} {
		t.Run(name, func(t *testing.T) {
			ctx := qualConsentContext(t)
			c, _ := qualConsentInstall(t, ctx, 0)
			s := qualConsentScope()
			switch name {
			case "empty_field":
				s.Program = nil
			case "over_bound":
				s.Program = bytes.Repeat([]byte{1}, 257)
			case "domain":
				s.Domain = []byte("foreign domain with a matching authenticated slot")
			case "short_address":
				s.Address = []byte{1}
			case "sc_address":
				s.Address = make([]byte, 32)
				s.Address[31] = 1
			case "system_prefix":
				s.Address = bytes.Clone(core.SystemAccountAddress)
				s.Address[31] = 1
			case "reserved":
				c.reserved = [][]byte{bytes.Clone(s.Address)}
			}
			a, err := ctx.Accounts.LoadAccount(s.Address)
			require.NoError(t, err)
			u := a.(state.UserAccountHandler)
			require.NoError(t, ctx.Accounts.SaveAccount(a))
			require.NoError(t, savePrivilegedConsent(ctx.Accounts, s.Address, s.Token, s.Program, encodeExperimentalConsent(s, u.GetNonce(), 0)))
			h, w, budget := qualConsentWitnessScope(t, ctx, 0, s)
			shard := uint32(1)
			if name == "meta" {
				old := &block.HeaderV3{}
				require.NoError(t, ctx.Marshalizer.Unmarshal(old, w.Header))
				s := &block.MetaBlockV3{Nonce: 11, Round: 21, Epoch: 0}
				w.ExecutedHeader, err = ctx.Marshalizer.Marshal(s)
				require.NoError(t, err)
				meta := &block.MetaBlockV3{Nonce: 15, Round: 25, Epoch: 0, ExecutionResults: []*block.MetaExecutionResult{{ExecutionResult: &block.BaseMetaExecutionResult{BaseExecutionResult: &block.BaseExecutionResult{
					HeaderHash: integrationTests.TestHasher.Compute(string(w.ExecutedHeader)), HeaderNonce: 11, HeaderRound: 21, HeaderEpoch: 0, RootHash: old.ExecutionResults[0].BaseExecutionResult.RootHash}}}}}
				w.Header, err = ctx.Marshalizer.Marshal(meta)
				require.NoError(t, err)
				h = integrationTests.TestHasher.Compute(string(w.Header))
				shard = core.MetachainShardId
			}
			require.ErrorIs(t, c.ReadEvidence(qualConsentReader(t, ctx), h, shard, s, w, budget), ErrPrivilegedConsent)
		})
	}
}

type qualConsentProofTrie struct {
	common.Trie
	calls    int
	boundary func(common.Trie) (common.Trie, error)
}

func (p *qualConsentProofTrie) Recreate(root common.RootHashHolder) (common.Trie, error) {
	tr, err := p.Trie.Recreate(root)
	p.calls++
	if err == nil && p.calls == 3 {
		return p.boundary(tr)
	}
	return tr, err
}

type qualConsentReadFailureTrie struct {
	common.Trie
	failure error
}

func (p *qualConsentReadFailureTrie) Get(key []byte) ([]byte, uint32, error) {
	raw, depth, err := p.Trie.Get(key)
	if err != nil {
		return raw, depth, err
	}
	return raw, depth, p.failure
}

type qualConsentProofFactory struct {
	state.AccountFactory
	calls    int
	boundary func(vmcommon.AccountHandler) (vmcommon.AccountHandler, error)
}

func (f *qualConsentProofFactory) CreateAccount(address []byte) (vmcommon.AccountHandler, error) {
	a, err := f.AccountFactory.CreateAccount(address)
	f.calls++
	if err == nil && f.calls == 2 {
		return f.boundary(a)
	}
	return a, err
}

type qualConsentReadMarshal struct {
	marshal.Marshalizer
	unmarshal func(interface{}, []byte) error
}

func (m *qualConsentReadMarshal) Unmarshal(v interface{}, b []byte) error { return m.unmarshal(v, b) }

func TestQualDRWAPrivilegedConsentReaderFaults(t *testing.T) {
	for _, name := range []string{"T06_error", "root_error", "recreate_error", "get_error", "factory_error", "account_type", "account_decode", "header_decode"} {
		t.Run(name, func(t *testing.T) {
			ctx := qualConsentContext(t)
			c, owner := qualConsentInstall(t, ctx, 0)
			s := qualConsentScope()
			qualConsentProcess(t, ctx, qualConsentData(s), nil)
			_, _, err := owner.Commit()
			require.NoError(t, err)
			h, w, budget := qualConsentWitness(t, ctx, 0)
			r := qualConsentReader(t, ctx)
			failure := errors.New("qualification native reader boundary")
			expected := error(failure)
			originalMarshal := r.args.Marshaller
			var observedProof *qualConsentEOAProofBoundary
			switch name {
			case "T06_error":
				h = []byte("unselected H")
				expected = ErrInvalidAccountWitness
			case "root_error":
				observedProof = &qualConsentEOAProofBoundary{Trie: r.proofTrie, boundary: func() (bool, error) { return false, nil }}
				r.proofTrie = observedProof
				calls := 0
				expected = ErrInvalidAccountWitness
				r.args.Marshaller = &qualConsentReadMarshal{originalMarshal, func(v interface{}, b []byte) error {
					if bytes.Equal(b, w.Header) {
						calls++
						if calls == 2 {
							return failure
						}
					}
					return originalMarshal.Unmarshal(v, b)
				}}
			case "recreate_error":
				r.proofTrie = &qualConsentProofTrie{Trie: r.proofTrie, boundary: func(tr common.Trie) (common.Trie, error) { return tr, failure }}
			case "get_error":
				r.proofTrie = &qualConsentProofTrie{Trie: r.proofTrie, boundary: func(tr common.Trie) (common.Trie, error) { return &qualConsentReadFailureTrie{tr, failure}, nil }}
			case "factory_error":
				r.accountFactory = &qualConsentProofFactory{AccountFactory: r.accountFactory, boundary: func(a vmcommon.AccountHandler) (vmcommon.AccountHandler, error) { return a, failure }}
			case "account_type":
				expected = ErrPrivilegedConsent
				saved, e := ctx.Accounts.GetExistingAccount(s.Address)
				require.NoError(t, e)
				r.accountFactory = &qualConsentProofFactory{AccountFactory: r.accountFactory, boundary: func(_ vmcommon.AccountHandler) (vmcommon.AccountHandler, error) {
					return &qualConsentVMOnly{saved.(vmcommon.UserAccountHandler)}, nil
				}}
				// A hostile dependency can report decode success for a nil target;
				// the account-shape gate must reject before that target is consumed.
				r.args.Marshaller = &qualConsentReadMarshal{originalMarshal, func(v interface{}, b []byte) error {
					if v == nil {
						return nil
					}
					return originalMarshal.Unmarshal(v, b)
				}}
			case "account_decode":
				expected = ErrPrivilegedConsent
				saved, e := ctx.Accounts.GetExistingAccount(s.Address)
				require.NoError(t, e)
				r.accountFactory = &qualConsentProofFactory{AccountFactory: r.accountFactory, boundary: func(_ vmcommon.AccountHandler) (vmcommon.AccountHandler, error) { return saved, nil }}
				calls := 0
				r.args.Marshaller = &qualConsentReadMarshal{originalMarshal, func(v interface{}, b []byte) error {
					if _, ok := v.(state.UserAccountHandler); ok {
						calls++
						if calls == 2 {
							return failure
						}
					}
					return originalMarshal.Unmarshal(v, b)
				}}
			case "header_decode":
				expected = ErrPrivilegedConsent
				calls := 0
				r.args.Marshaller = &qualConsentReadMarshal{originalMarshal, func(v interface{}, b []byte) error {
					if bytes.Equal(b, w.ExecutedHeader) {
						calls++
						if calls == 3 {
							return failure
						}
					}
					return originalMarshal.Unmarshal(v, b)
				}}
			}
			require.NotPanics(t, func() { err = c.ReadEvidence(r, h, 1, s, w, budget) })
			require.ErrorIs(t, err, expected)
			if observedProof != nil {
				require.Equal(t, 2, observedProof.calls, "a failed root selection must not proceed to EOA proof verification")
			}
		})
	}
}
