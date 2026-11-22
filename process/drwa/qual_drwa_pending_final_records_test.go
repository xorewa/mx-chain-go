package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common/holders"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Synthetic host ONLY: no certificate/CEB/lifecycle/funding/G3/native importer.
// Actual AccountsDB/trie/journal/save/commit/recreation and T04 execute below.
type qualPendingFinalHost struct {
	t                             *testing.T
	s                             *qualNativeStore
	expected                      []byte
	fault                         string
	hook                          func(string)
	initializations, observations int
}

func (h *qualPendingFinalHost) IsInterfaceNil() bool { return h == nil }
func (h *qualPendingFinalHost) check(stage string, c []byte) error {
	if h.hook != nil {
		h.hook(stage)
	}
	if h.fault == stage || !bytes.Equal(c, h.expected) {
		return errPendingFinal
	}
	return nil
}
func (h *qualPendingFinalHost) Admit(c []byte) error { return h.check("admit", c) }
func (h *qualPendingFinalHost) Initialize(c []byte) (*vmcommon.VMOutput, error) {
	h.initializations++
	// Synthetic first holder initialization, retained in the actual native trie.
	if len(qualRegistryValue(h.t, h.s, "fixture/T23/nonce")) == 0 {
		qualRecordPut(h.t, h.s, []byte("fixture/T23/nonce"), []byte{0})
	}
	if err := h.check("initialize", c); err != nil {
		return nil, err
	}
	if h.fault == "nil-initialize" {
		return nil, nil
	}
	code := vmcommon.Ok
	if h.fault == "deny-initialize" {
		code = vmcommon.UserError
	}
	return &vmcommon.VMOutput{ReturnCode: code, ReturnData: [][]byte{[]byte("pending-only")}}, nil
}
func (h *qualPendingFinalHost) Canonical(c, evidence []byte) error {
	if !bytes.Equal(evidence, []byte("synthetic/exact-S-result-root-H-M-B")) {
		return errPendingFinal
	}
	return h.check("canonical", c)
}
func (h *qualPendingFinalHost) Observe(c []byte) (*vmcommon.VMOutput, error) {
	h.observations++
	if err := h.check("observe", c); err != nil {
		return nil, err
	}
	if h.fault == "nil-observe" {
		return nil, nil
	}
	code := vmcommon.Ok
	if h.fault == "deny-observe" {
		code = vmcommon.UserError
	}
	return &vmcommon.VMOutput{ReturnCode: code, Logs: []*vmcommon.LogEntry{{Identifier: []byte("synthetic-final-observation")}}}, nil
}

type qualPendingFinalFixture struct {
	s                                              *qualNativeStore
	r                                              *pendingFinalRecords
	h                                              *qualPendingFinalHost
	o                                              *RollbackContainment
	c                                              pendingFinalCandidate
	encoded, digest, pendingKey, finalKey, itemKey []byte
}

func qualPendingFinalNew(t *testing.T) *qualPendingFinalFixture {
	t.Helper()
	f := &qualPendingFinalFixture{s: qualRegistrationStore(t, 0)}
	f.c = pendingFinalCandidate{key: []byte("ELIGIBILITY/TOKEN-abcdef/holder"), version: 0,
		body: []byte("synthetic/complete-holder-decision-body"), origin: []byte("synthetic/origin-execution-result-root-identity")}
	f.encoded = qualRecordFrame(f.c.key, []byte{0, 0, 0, 0, 0, 0, 0, 0}, nil, f.c.body, f.c.origin)
	f.digest = blake2b.NewBlake2b().Compute(string(f.encoded))
	f.pendingKey = append([]byte(pendingFinalPrefix+"pending@"), qualRecordFrame(f.c.key)...)
	f.finalKey = append([]byte(pendingFinalPrefix+"final@"), qualRecordFrame(f.c.key)...)
	f.itemKey = append([]byte(pendingFinalPrefix+"item@"), qualRecordFrame(f.c.origin, f.c.key)...)
	f.h = &qualPendingFinalHost{t: t, s: f.s, expected: f.encoded}
	f.reopen(t)
	return f
}
func (f *qualPendingFinalFixture) reopen(t *testing.T) {
	t.Helper()
	var err error
	f.o, err = NewRollbackContainment(f.s)
	require.NoError(t, err)
	f.r, err = newPendingFinalRecords(f.s, f.o, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096, f.h)
	require.NoError(t, err)
}
func (f *qualPendingFinalFixture) promote() error {
	return f.r.promote(f.c, []byte("synthetic/exact-S-result-root-H-M-B"))
}
func (f *qualPendingFinalFixture) staged(t *testing.T) {
	t.Helper()
	require.Equal(t, f.encoded, qualRegistryValue(t, f.s, string(f.pendingKey)))
	require.Equal(t, f.digest, qualRegistryValue(t, f.s, string(f.itemKey)))
	require.Empty(t, qualRegistryValue(t, f.s, string(f.finalKey)))
}

func TestQualDRWAPendingFinalHealthy(t *testing.T) {
	f := qualPendingFinalNew(t)
	require.NoError(t, f.r.stage(f.c))
	f.staged(t)
	final, hash, err := f.r.final(f.c.key)
	require.NoError(t, err)
	require.Empty(t, final)
	require.Empty(t, hash)
	n := f.s.JournalLen()
	require.NoError(t, f.r.stage(f.c))
	require.Equal(t, n, f.s.JournalLen())
	require.Equal(t, 1, f.h.initializations)
	require.NoError(t, f.promote())
	final, hash, err = f.r.final(f.c.key)
	require.NoError(t, err)
	require.Equal(t, f.encoded, final)
	require.Equal(t, f.digest, hash)
	require.Empty(t, qualRegistryValue(t, f.s, string(f.pendingKey)))
	require.Empty(t, qualRegistryValue(t, f.s, string(f.itemKey)))
	n = f.s.JournalLen()
	require.NoError(t, f.promote())
	require.NoError(t, f.r.stage(f.c))
	require.Equal(t, n, f.s.JournalLen())
	require.Equal(t, 1, f.h.observations)
	require.Equal(t, 1, f.h.initializations)
	final[0] ^= 1
	hash[0] ^= 1
	actual, actualHash, err := f.r.final(f.c.key)
	require.NoError(t, err)
	require.Equal(t, f.encoded, actual)
	require.Equal(t, f.digest, actualHash)
}

func TestQualDRWAPendingFinalCAS(t *testing.T) {
	for _, mode := range []string{"competing-body", "different-origin", "different-version", "wrong-predecessor", "missing-item", "wrong-item", "malformed-pending", "malformed-final", "other-key-final", "orphan-item"} {
		t.Run(mode, func(t *testing.T) {
			f := qualPendingFinalNew(t)
			if mode != "orphan-item" {
				require.NoError(t, f.r.stage(f.c))
			}
			switch mode {
			case "competing-body":
				f.c.body = []byte("other")
			case "different-origin":
				f.c.origin = []byte("other-origin")
			case "different-version":
				f.c.version = 2
			case "wrong-predecessor":
				f.c.predecessor = bytes.Repeat([]byte{9}, 32)
			case "missing-item":
				qualRecordPut(t, f.s, f.itemKey, nil)
			case "wrong-item", "orphan-item":
				qualRecordPut(t, f.s, f.itemKey, bytes.Repeat([]byte{9}, 32))
			case "malformed-pending":
				qualRecordPut(t, f.s, f.pendingKey, []byte{1})
			case "malformed-final":
				qualRecordPut(t, f.s, f.finalKey, []byte{1})
			case "other-key-final":
				qualRecordPut(t, f.s, f.finalKey, qualRecordFrame([]byte("other"), []byte{0, 0, 0, 0, 0, 0, 0, 1}, nil, f.c.body, f.c.origin))
			}
			f.h.expected = qualRecordFrame(f.c.key, binary.BigEndian.AppendUint64(nil, f.c.version), f.c.predecessor, f.c.body, f.c.origin)
			root, err := f.s.RootHash()
			require.NoError(t, err)
			require.Error(t, f.r.stage(f.c))
			require.Error(t, f.promote())
			after, err := f.s.RootHash()
			require.NoError(t, err)
			require.Equal(t, root, after)
		})
	}
}

func TestQualDRWAPendingFinalWriteRollback(t *testing.T) {
	for _, fault := range []string{"admit", "initialize", "nil-initialize", "deny-initialize", "save", "callback-pending", "callback-final"} {
		t.Run(fault, func(t *testing.T) {
			f := qualPendingFinalNew(t)
			root, err := f.s.RootHash()
			require.NoError(t, err)
			f.h.fault = fault
			if fault == "save" {
				f.h.hook = func(stage string) {
					if stage == "initialize" {
						f.s.saveErr = errors.New("post-save fault")
					}
				}
			}
			if fault == "callback-pending" || fault == "callback-final" {
				f.h.hook = func(stage string) {
					if stage == "initialize" {
						key := f.pendingKey
						if fault == "callback-final" {
							key = f.finalKey
						}
						qualRecordPut(t, f.s, key, f.encoded)
					}
				}
			}
			require.Error(t, f.r.stage(f.c))
			f.s.saveErr = nil
			after, err := f.s.RootHash()
			require.NoError(t, err)
			require.Equal(t, root, after)
			require.Empty(t, qualRegistryValue(t, f.s, "fixture/T23/nonce"))
			require.Empty(t, qualRegistryValue(t, f.s, string(f.pendingKey)))
			require.Empty(t, qualRegistryValue(t, f.s, string(f.itemKey)))
		})
	}
}

func TestQualDRWAPendingFinalPromotionRollback(t *testing.T) {
	for _, fault := range []string{"canonical", "observe", "nil-observe", "deny-observe", "save", "callback-pending", "callback-final", "missing-evidence", "forged-evidence"} {
		t.Run(fault, func(t *testing.T) {
			f := qualPendingFinalNew(t)
			require.NoError(t, f.r.stage(f.c))
			root, err := f.s.RootHash()
			require.NoError(t, err)
			f.h.fault = fault
			if fault == "save" {
				f.s.saveErr = errors.New("post-save fault")
			}
			if fault == "callback-pending" || fault == "callback-final" {
				f.h.hook = func(stage string) {
					if stage == "observe" {
						key := f.pendingKey
						if fault == "callback-final" {
							key = f.finalKey
						}
						qualRecordPut(t, f.s, key, []byte{1})
					}
				}
			}
			evidence := []byte("synthetic/exact-S-result-root-H-M-B")
			if fault == "missing-evidence" {
				evidence = nil
			}
			if fault == "forged-evidence" {
				evidence = []byte("API-success")
			}
			require.Error(t, f.r.promote(f.c, evidence))
			f.s.saveErr = nil
			after, err := f.s.RootHash()
			require.NoError(t, err)
			require.Equal(t, root, after)
			f.staged(t)
		})
	}
}

func TestQualDRWAPendingFinalRestartAndSuccessor(t *testing.T) {
	f := qualPendingFinalNew(t)
	require.NoError(t, f.r.stage(f.c))
	roots, _, err := f.o.Commit()
	require.NoError(t, err)
	require.NoError(t, f.s.RecreateTrie(holders.NewDefaultRootHashesHolder(roots[0])))
	f.reopen(t)
	f.staged(t)
	require.NoError(t, f.promote())
	roots, _, err = f.o.Commit()
	require.NoError(t, err)
	require.NoError(t, f.s.RecreateTrie(holders.NewDefaultRootHashesHolder(roots[0])))
	f.reopen(t)
	qualRecordPut(t, f.s, []byte("fixture/T23/nonce"), []byte{7})
	f.c.version = 1
	f.c.body = []byte("next-decision")
	f.c.origin = []byte("next-origin")
	f.c.predecessor = bytes.Clone(f.digest)
	f.encoded = qualRecordFrame(f.c.key, []byte{0, 0, 0, 0, 0, 0, 0, 1}, f.c.predecessor, f.c.body, f.c.origin)
	f.h.expected = f.encoded
	require.NoError(t, f.r.stage(f.c))
	require.Equal(t, []byte{7}, qualRegistryValue(t, f.s, "fixture/T23/nonce"))
	require.NoError(t, f.promote())
	final, _, err := f.r.final(f.c.key)
	require.NoError(t, err)
	require.Equal(t, f.encoded, final)
}

func TestQualDRWAPendingFinalBuffersAndBusy(t *testing.T) {
	f := qualPendingFinalNew(t)
	f.h.hook = func(stage string) {
		if stage == "admit" {
			f.c.key[0] ^= 1
			f.c.body[0] ^= 1
			f.c.origin[0] ^= 1
		}
	}
	require.NoError(t, f.r.stage(f.c))
	f.staged(t)
	f = qualPendingFinalNew(t)
	f.h.hook = func(stage string) {
		if stage == "initialize" {
			require.ErrorIs(t, f.r.stage(f.c), ErrExecutionBusy)
		}
	}
	require.NoError(t, f.r.stage(f.c))
	f.staged(t)
}

func TestQualDRWAPendingFinalConsumingBlockRollback(t *testing.T) {
	f := qualPendingFinalNew(t)
	require.NoError(t, f.r.stage(f.c))
	_, _, err := f.o.Commit()
	require.NoError(t, err)
	f.reopen(t)
	require.NoError(t, f.promote())
	require.NoError(t, f.o.Execute(func() (*vmcommon.VMOutput, error) {
		qualRecordPut(t, f.s, []byte("fixture/T23/dependent-effect"), []byte{1})
		return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
	}))
	// Actual T04 containment aborts the isolated consuming candidate, suppresses
	// all buffered outputs and restores the retained committed staged root.
	// This is not an installed native block-replacement/import adapter.
	f.s.revertErr = errors.New("synthetic rollback interruption")
	require.Error(t, f.o.Execute(func() (*vmcommon.VMOutput, error) {
		return nil, errors.New("synthetic candidate abort")
	}))
	_, outputs, err := f.o.Commit()
	require.Error(t, err)
	require.Empty(t, outputs)
	f.s.revertErr = nil
	require.NoError(t, f.o.Recover())
	require.Empty(t, f.o.outputs)
	require.True(t, f.o.closed)
	f.staged(t)
	require.Empty(t, qualRegistryValue(t, f.s, "fixture/T23/dependent-effect"))
}

func TestQualDRWAPendingFinalBounds(t *testing.T) {
	for _, mode := range []string{"empty-key", "empty-body", "empty-origin", "oversize-key", "oversize-body", "oversize-origin", "short-predecessor"} {
		t.Run(mode, func(t *testing.T) {
			f := qualPendingFinalNew(t)
			switch mode {
			case "empty-key":
				f.c.key = nil
			case "empty-body":
				f.c.body = nil
			case "empty-origin":
				f.c.origin = nil
			case "oversize-key":
				f.c.key = make([]byte, 4097)
			case "oversize-body":
				f.c.body = make([]byte, 4097)
			case "oversize-origin":
				f.c.origin = make([]byte, 4097)
			case "short-predecessor":
				f.c.predecessor = []byte{1}
			}
			require.Error(t, f.r.stage(f.c))
			require.Zero(t, f.h.initializations)
		})
	}
	f := qualPendingFinalNew(t)
	for _, mode := range []string{"host", "owner", "foreign-owner", "accounts", "marshaller", "hasher", "bound"} {
		t.Run(mode, func(t *testing.T) {
			o := f.o
			h := pendingFinalHost(f.h)
			a := f.s.AccountsAdapter
			m := &marshal.GogoProtoMarshalizer{}
			limit := 4096
			if mode == "host" {
				h = nil
			}
			if mode == "owner" {
				o = nil
			}
			if mode == "foreign-owner" {
				o = &RollbackContainment{}
			}
			if mode == "accounts" {
				a = nil
			}
			if mode == "bound" {
				limit = 0
			}
			if mode == "marshaller" {
				_, err := newPendingFinalRecords(f.s, o, nil, blake2b.NewBlake2b(), limit, h)
				require.Error(t, err)
				return
			}
			if mode == "hasher" {
				_, err := newPendingFinalRecords(f.s, o, m, nil, limit, h)
				require.Error(t, err)
				return
			}
			if mode != "accounts" {
				a = f.s
			}
			_, err := newPendingFinalRecords(a, o, m, blake2b.NewBlake2b(), limit, h)
			require.Error(t, err)
		})
	}
}
