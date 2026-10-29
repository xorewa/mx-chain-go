package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

type sp1RootReadFault struct {
	state.AccountsAdapter
	at, calls int
	failure   error
}

func (s *sp1RootReadFault) RootHash() ([]byte, error) {
	s.calls++
	if s.calls == s.at {
		return nil, s.failure
	}
	return s.AccountsAdapter.RootHash()
}

type sp1ProofRecreateFault struct {
	common.Trie
	at, calls int
	failure   error
}

func (s *sp1ProofRecreateFault) Recreate(root common.RootHashHolder) (common.Trie, error) {
	s.calls++
	if s.calls == s.at {
		return nil, s.failure
	}
	return s.Trie.Recreate(root)
}

type sp1ProofAccountFactoryFault struct {
	state.AccountFactory
	failure error
}

func (s *sp1ProofAccountFactoryFault) CreateAccount([]byte) (vmcommon.AccountHandler, error) {
	return nil, s.failure
}

func TestSP1CoverageProjectionLeaseLoss(t *testing.T) {
	p := qualHeaderTimeOwner(t)
	calls := 0
	sentinel := errors.New("native lease lost before expiry derivation")
	context, err := p.BeginBound(&block.MetaBlockV3{Epoch: 10, TimestampMs: 105}, func() (func(), error) {
		calls++
		if calls == 2 {
			return nil, sentinel
		}
		return func() {}, nil
	}, func() error { return nil })
	require.NoError(t, err)
	expiry, err := (&governedActionWindow{100, 105, 120}).projectionExpiry(context, 7)
	require.ErrorIs(t, err, sentinel)
	require.Zero(t, expiry)
	require.Equal(t, 2, calls)
}
func TestSP1CoverageRegistrationRootReadFailures(t *testing.T) {
	for _, at := range []int{1, 2} {
		t.Run(fmt.Sprint(at), func(t *testing.T) {
			sentinel := errors.New("native root unavailable")
			s := &sp1RootReadFault{AccountsAdapter: qualRegistrationStore(t, 0), at: at, failure: sentinel}
			calls := 0
			err := verifyRegistrationState([]state.AccountsAdapter{s}, func() error { calls++; return nil })
			require.ErrorIs(t, err, sentinel)
			require.Equal(t, at-1, calls)
		})
	}
}
func TestSP1CoverageProofReaderDependencies(t *testing.T) {
	for _, mode := range []string{"main recreate", "data recreate", "account factory"} {
		t.Run(mode, func(t *testing.T) {
			f := qualNativeReaderFixture(t, false, 1)
			reader, err := NewResultAccountReader(qualReaderArgs(false))
			require.NoError(t, err)
			sentinel := errors.New("native authenticated-item dependency unavailable")
			if mode == "account factory" {
				reader.accountFactory = &sp1ProofAccountFactoryFault{AccountFactory: reader.accountFactory, failure: sentinel}
			} else {
				at := 1
				if mode == "data recreate" {
					at = 2
				}
				reader.proofTrie = &sp1ProofRecreateFault{Trie: reader.proofTrie, at: at, failure: sentinel}
			}
			root, err := f.adb.RootHash()
			require.NoError(t, err)
			item, err := reader.Read(f.anchor, 1, f.address, f.key, f.w, f.budget)
			require.ErrorIs(t, err, sentinel)
			require.Nil(t, item)
			after, err := f.adb.RootHash()
			require.NoError(t, err)
			require.Equal(t, root, after)
		})
	}
	f := qualRegistryTransport(t, false, []byte{0, 0, 0, 0, 0, 0, 0, 2}, []byte{1})
	item, err := f.reader.readRegistryItem(f.anchor, []byte(registryCountKey), f.count, 0)
	require.Error(t, err)
	require.Nil(t, item)
}

func sp1AdmissionDependencyOperation(t *testing.T, ready bool) (*qualRegistrationAdmissionFixture, func() error, *int) {
	t.Helper()
	f := qualRegistrationAdmission(t, core.FungibleESDT)
	t.Cleanup(f.end)
	effects := new(int)
	if ready {
		require.NoError(t, f.register(t, qualRegistrationCreator(t, "TOKEN-abcdef")))
		acks, verifier := qualRegistrationAcks(t, f)
		return f, func() error {
			return f.admit.WithBootstrapReadiness([]byte("TOKEN-abcdef"), acks, verifier, func() (*vmcommon.VMOutput, error) {
				*effects++
				return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
			})
		}, effects
	}
	f.admit.verifier = &qualBootstrapVerifier{f.verify}
	qualRecordPut(t, f.store, append([]byte(registrationIntentPrefix), f.owner.id...), nil)
	key := []byte(scopedAdmissionPrefix + "budget")
	budget := make([]byte, 32)
	binary.BigEndian.PutUint64(budget, 1)
	binary.BigEndian.PutUint64(budget[8:], uint64(len(key)+32))
	binary.BigEndian.PutUint64(budget[16:], 10)
	qualRecordPut(t, f.store, key, budget)
	return f, func() error { return f.admit.RetainBootstrapIntent(f.verify.body, []byte("explicit-step1-mandate")) }, effects
}
func TestSP1CoverageBootstrapDependencyFailures(t *testing.T) {
	var absent *RegistrationAdmission
	require.Error(t, absent.RetainBootstrapIntent(nil, nil))
	for _, ready := range []bool{false, true} {
		t.Run(fmt.Sprintf("readiness=%t", ready), func(t *testing.T) {
			f, run, _ := sp1AdmissionDependencyOperation(t, ready)
			control := &sp1RecordFault{calls: make(map[string]int)}
			f.store.AccountsAdapter = &sp1RecordStore{AccountsAdapter: f.store.AccountsAdapter, fault: control}
			f.owner.records.marshaller = &sp1RecordMarshal{Marshalizer: f.owner.records.marshaller, fault: control}
			require.NoError(t, run())
			for _, kind := range []string{"account", "read", "write", "save-account", "marshal", "unmarshal"} {
				for at := 1; at <= control.calls[kind]; at++ {
					t.Run(fmt.Sprintf("%s/%d", kind, at), func(t *testing.T) {
						f, run, effects := sp1AdmissionDependencyOperation(t, ready)
						fault := &sp1RecordFault{kind: kind, at: at, calls: make(map[string]int)}
						f.store.AccountsAdapter = &sp1RecordStore{AccountsAdapter: f.store.AccountsAdapter, fault: fault}
						f.owner.records.marshaller = &sp1RecordMarshal{Marshalizer: f.owner.records.marshaller, fault: fault}
						root, err := f.store.RootHash()
						require.NoError(t, err)
						journal, outputs := f.store.JournalLen(), len(f.boundary.outputs)
						require.Error(t, run())
						require.True(t, fault.hit)
						require.Zero(t, *effects)
						after, err := f.store.RootHash()
						require.NoError(t, err)
						require.Equal(t, root, after)
						require.Equal(t, journal, f.store.JournalLen())
						require.Len(t, f.boundary.outputs, outputs)
						fault.kind = ""
						if !ready {
							require.Empty(t, qualRegistryValue(t, f.store, registrationIntentPrefix+string(f.owner.id)), "failed retention left a positive record")
						}
					})
				}
			}
			f, run, _ = sp1AdmissionDependencyOperation(t, ready)
			f.end()
			require.Error(t, run())
		})
	}
}
func TestSP1CoverageCandidateOwnerAliasDenied(t *testing.T) {
	old, _, _ := qualRegistrationCandidate(t, false, false)
	next := *old
	called := false
	require.Error(t, old.WithDRWAClassifierReplacement(&next, func() { called = true }))
	require.False(t, called)
}

// Keep the seed ownership check independent of any admission encoder.
func TestSP1CoverageBootstrapProofBudget(t *testing.T) {
	f, _, _ := sp1AdmissionDependencyOperation(t, true)
	acks, verifier := qualRegistrationAcks(t, f)
	before := bytes.Clone(acks[0].GlobalState)
	f.owner.records.maxBytes = 3
	err := f.admit.WithBootstrapReadiness([]byte("TOKEN-abcdef"), acks, verifier, func() (*vmcommon.VMOutput, error) { t.Fatal("impossible ACK budget executed"); return nil, nil })
	require.Error(t, err)
	require.Equal(t, before, acks[0].GlobalState)
}
