package drwa

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Qualification only: real AccountsDB/journals, synthetic canonical owner,
// prerequisites and applied-result evidence. CANCELLED is explicitly installed
// as a synthetic input; no cancellation-decision/execution adapter exists here.
// These fixtures cannot establish legal cancellation, native route finality,
// actual multi-shard administration, gas pricing, crash/fsync or pruning safety.
type qualIdentityHost struct {
	*qualConvergenceHost
	vector                                                                         convergenceVector
	owner, prior, permission, created, parent, entitlement, fence, authority, meta []byte
}

func (h *qualIdentityHost) read(key []byte) []byte {
	return qualRegistryValue(h.t, h.store, string(key))
}

func (h *qualIdentityHost) VerifyTransition(binding []byte) error {
	if err := h.qualConvergenceHost.VerifyTransition(binding); err != nil {
		return err
	}
	if !bytes.Equal(h.read(h.owner), qualRecordFrame(binding, []byte(h.vector.OriginalOutcome))) ||
		!bytes.Equal(h.read(h.prior), convergenceHex(h.t, h.vector.Predecessor)) {
		return errConvergence
	}
	if h.vector.OriginalOutcome == "CANCELLED" && !bytes.Equal(h.read(h.fence), binding) {
		return errConvergence
	}
	return nil
}

func (h *qualIdentityHost) Admission(binding []byte, retained uint64) error {
	if err := h.qualConvergenceHost.Admission(binding, retained); err != nil {
		return err
	}
	// Positive fixture permission, not absence-as-free. A retained receipt
	// prevents reconstruction of a missing/pruned progress slot as a new phase.
	if !bytes.Equal(h.read(h.permission), binding) || len(h.read(h.created)) != 0 {
		return errConvergence
	}
	qualRecordPut(h.t, h.store, h.created, binding)
	return nil
}

func (h *qualIdentityHost) Complete(binding, commitment []byte) (*vmcommon.VMOutput, error) {
	h.completeCalls++
	if err := h.check("complete", binding); err != nil {
		return nil, err
	}
	needsMeta := h.vector.Phase == "DRWAQuiescenceAck" || h.vector.Phase == "ADMIN_QUIESCENCE_ACK" ||
		h.vector.OriginalOutcome == "CANCELLED" && h.vector.Phase == "CURRENT_ACK"
	if needsMeta && !bytes.Equal(h.read(h.meta), binding) {
		return nil, errConvergence
	}
	if h.vector.Phase == "continuation" {
		if !bytes.Equal(h.read(h.entitlement), qualRecordFrame(binding, []byte("LIVE"))) ||
			!bytes.Equal(h.read(h.authority), []byte("synthetic-current-Program-Administration")) {
			return nil, errConvergence
		}
		qualRecordPut(h.t, h.store, h.entitlement, qualRecordFrame(binding, []byte("CONSUMED")))
	}
	qualRecordPut(h.t, h.store, h.parent, qualRecordFrame(binding, commitment))
	if hook := h.hooks["after_parent"]; hook != nil {
		hook()
	}
	return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, Logs: []*vmcommon.LogEntry{{Identifier: []byte("synthetic-phase-effect")}}}, nil
}

func (h *qualIdentityHost) VerifyParent(binding, commitment []byte) error {
	h.parentCalls++
	if err := h.check("parent", binding); err != nil {
		return err
	}
	if !bytes.Equal(h.read(h.parent), qualRecordFrame(binding, commitment)) {
		return errConvergence
	}
	if h.vector.Phase == "continuation" && !bytes.Equal(h.read(h.entitlement), qualRecordFrame(binding, []byte("CONSUMED"))) {
		return errConvergence
	}
	return nil
}

type qualIdentityFixture struct {
	*qualConvergenceFixture
	identity *qualIdentityHost
	vector   convergenceVector
}

func qualIdentityNew(t *testing.T, v convergenceVector) *qualIdentityFixture {
	t.Helper()
	f := qualConvergenceNew(t, 3)
	f.tr = v.transition(t)
	f.binding = convergenceHex(t, v.Binding)
	f.key = append([]byte(convergencePrefix), convergenceHex(t, v.Identity)...)
	f.host.binding, f.host.key = f.binding, f.key
	f.host.acks = make(map[string]uint32)
	for i, ack := range v.Ack {
		f.host.acks[string(convergenceHex(t, ack))] = uint32(i)
	}
	h := &qualIdentityHost{qualConvergenceHost: f.host, vector: v}
	for name, target := range map[string]*[]byte{"owner": &h.owner, "prior": &h.prior, "permission": &h.permission,
		"created": &h.created, "parent": &h.parent, "fence": &h.fence, "authority": &h.authority, "meta": &h.meta} {
		*target = append([]byte("fixture/synthetic-identity/"+name+"/"), f.key...)
	}
	// Entitlement is original-owner scoped, never recreated for a successor.
	h.entitlement = append([]byte("fixture/synthetic-identity/entitlement/"), f.tr.action...)
	qualRecordPut(t, f.store, h.owner, qualRecordFrame(f.binding, []byte(v.OriginalOutcome)))
	qualRecordPut(t, f.store, h.prior, convergenceHex(t, v.Predecessor))
	for _, k := range [][]byte{h.permission, h.fence, h.meta} {
		qualRecordPut(t, f.store, k, f.binding)
	}
	qualRecordPut(t, f.store, h.entitlement, qualRecordFrame(f.binding, []byte("LIVE")))
	qualRecordPut(t, f.store, h.authority, []byte("synthetic-current-Program-Administration"))
	_, err := f.store.Commit()
	require.NoError(t, err)
	result := &qualIdentityFixture{qualConvergenceFixture: f, identity: h, vector: v}
	result.rebind(t, f.store)
	return result
}

func (f *qualIdentityFixture) rebind(t *testing.T, store state.AccountsAdapter) {
	t.Helper()
	f.reopen(t, store)
	f.records.host = f.identity
}

func (f *qualIdentityFixture) root(t *testing.T) []byte {
	t.Helper()
	root, err := f.store.RootHash()
	require.NoError(t, err)
	return bytes.Clone(root)
}

func (f *qualIdentityFixture) assertVector(t *testing.T, name string) {
	t.Helper()
	require.Equal(t, convergenceHex(t, f.vector.States[name].Value), qualRegistryValue(t, f.store, string(f.key)))
}

func (f *qualIdentityFixture) fill(t *testing.T) {
	t.Helper()
	for _, shard := range []uint32{2, 0, 1} {
		require.NoError(t, f.ack(shard))
	}
}

func TestQualConvergenceIdentityPhases(t *testing.T) {
	for _, v := range convergenceVectors(t) {
		t.Run(v.Family+"/"+v.Phase+" should bind exact progress and apply once", func(t *testing.T) {
			f := qualIdentityNew(t, v)
			f.create(t)
			f.assertVector(t, "initial")
			require.NoError(t, f.ack(0))
			f.assertVector(t, "one")
			pendingOutputs := len(f.owner.outputs)
			observedBinding, observed, observeErr := f.records.observe(f.tr)
			require.NoError(t, observeErr)
			require.Equal(t, f.binding, observedBinding)
			require.Equal(t, "PENDING", observed.status)
			require.Equal(t, []byte{1}, observed.bitmap)
			require.Equal(t, pendingOutputs, len(f.owner.outputs), "observation must not accumulate nil output slots")
			before := f.root(t)
			require.Error(t, f.records.complete(f.tr), "partial set cannot complete")
			require.Equal(t, before, f.root(t))
			require.NoError(t, f.ack(2))
			require.NoError(t, f.ack(1))
			f.assertVector(t, "full")
			require.NoError(t, f.records.complete(f.tr))
			f.assertVector(t, "terminal")
			before = f.root(t)
			for _, op := range []func() error{func() error { return f.records.create(f.tr) }, func() error { return f.ack(0) }, func() error { return f.records.complete(f.tr) }} {
				require.NoError(t, op())
				require.Equal(t, before, f.root(t))
			}
			require.Equal(t, 1, f.identity.completeCalls)
			pendingOutputs = len(f.owner.outputs)
			binding, progress, err := f.records.observe(f.tr)
			require.NoError(t, err)
			require.Equal(t, f.binding, binding)
			require.Equal(t, "COMPLETE", progress.status)
			require.Equal(t, []byte{7}, progress.bitmap)
			require.Equal(t, pendingOutputs, len(f.owner.outputs))
			binding[0] ^= 1
			progress.bitmap[0] = 0
			progress.acks[0][0] ^= 1
			progress.commitment[0] ^= 1
			require.Equal(t, before, f.root(t), "observation owns its returned buffers")
			_, outputs, err := f.owner.Commit()
			require.NoError(t, err)
			count := 0
			for _, output := range outputs {
				if output != nil {
					count++
				}
			}
			require.Equal(t, 1, count, "only one phase effect/observation is published")
		})
	}
}

func TestQualConvergenceIdentityCoordinateDenials(t *testing.T) {
	for _, v := range convergenceVectors(t) {
		for _, field := range []string{"family", "phase", "action", "digest", "subject", "version", "target", "dependencies", "set", "lineage", "predecessor", "producer", "result", "proof"} {
			t.Run(v.Family+"/"+v.Phase+"/"+field+" should deny without state changes", func(t *testing.T) {
				f := qualIdentityNew(t, v)
				f.create(t)
				require.NoError(t, f.ack(0))
				tr := v.transition(t)
				local, proof := bytes.Clone(f.local[1]), []byte("synthetic-S-R-H-M-B-proof")
				switch field {
				case "family":
					tr.context.family = []byte("another synthetic family")
				case "phase":
					tr.context.phase = []byte("another synthetic phase")
				case "action":
					tr.action[0] ^= 1
				case "digest":
					tr.digest[0] ^= 1
				case "subject":
					tr.token = []byte("OTHER-abcdef")
				case "version":
					tr.version++
				case "target":
					tr.target[0] ^= 1
				case "dependencies":
					tr.dependencies[0] ^= 1
				case "set":
					tr.shards = []uint32{0, 1}
					tr.requiredSet = f.records.codec.hasher.Compute(string(qualRecordFrame([]byte{0, 0, 0, 0}, []byte{0, 0, 0, 1})))
				case "lineage":
					tr.context.lineage[0] ^= 1
				case "predecessor":
					tr.context.predecessor[0] ^= 1
				case "producer":
					f.host.wrongProducer = true
				case "result":
					local[0] ^= 1
				case "proof":
					proof = []byte("discarded-or-provisional-result")
				}
				before := f.root(t)
				require.Error(t, f.records.acknowledge(tr, 1, local, proof))
				require.Equal(t, before, f.root(t))
				if field != "producer" && field != "result" && field != "proof" {
					require.Error(t, f.records.create(tr))
					require.Equal(t, before, f.root(t))
					require.Error(t, f.records.complete(tr))
					require.Equal(t, before, f.root(t))
					binding, progress, err := f.records.observe(tr)
					require.Error(t, err)
					require.Nil(t, binding)
					require.Nil(t, progress)
					require.Equal(t, before, f.root(t))
				}
			})
		}
	}
}

func TestQualConvergenceIdentityMissingEvidence(t *testing.T) {
	for _, v := range convergenceVectors(t) {
		for _, stage := range []string{"creation", "matching", "duplicate", "completion", "replay"} {
			for _, missing := range []string{"owner", "predecessor", "permission", "progress", "corrupt", "result", "ack"} {
				if missing == "permission" && stage != "creation" {
					continue // permission is a creation-only prerequisite
				}
				t.Run(v.Phase+"/"+v.OriginalOutcome+"/"+stage+"/"+missing+" should deny missing evidence", func(t *testing.T) {
					f := qualIdentityNew(t, v)
					if stage != "creation" {
						f.create(t)
					}
					if stage == "duplicate" {
						require.NoError(t, f.ack(0))
					}
					if stage == "completion" || stage == "replay" {
						f.fill(t)
					}
					if stage == "replay" {
						require.NoError(t, f.records.complete(f.tr))
					}
					switch missing {
					case "owner":
						qualRecordPut(t, f.store, f.identity.owner, nil)
					case "predecessor":
						qualRecordPut(t, f.store, f.identity.prior, nil)
					case "permission":
						qualRecordPut(t, f.store, f.identity.permission, nil)
					case "progress":
						if stage == "creation" {
							qualRecordPut(t, f.store, f.identity.permission, nil)
						} else {
							qualRecordPut(t, f.store, f.key, nil)
						}
					case "corrupt":
						qualRecordPut(t, f.store, f.key, []byte("unreadable"))
					case "result", "ack":
						if stage == "creation" || stage == "completion" || stage == "replay" {
							// A missing canonical owner phase/result receipt is not an authorization, even after all bits exist.
							f.host.faults["transition"] = errors.New("synthetic committed phase evidence unavailable")
						} else {
							f.host.faults["ack"] = errors.New("synthetic applied result or ACK unavailable")
						}
					}
					before := f.root(t)
					var err error
					switch stage {
					case "creation":
						err = f.records.create(f.tr)
					case "matching":
						err = f.ack(1)
					case "duplicate":
						err = f.ack(0)
					case "completion", "replay":
						err = f.records.complete(f.tr)
					}
					require.Error(t, err)
					require.Equal(t, before, f.root(t))
				})
			}
		}
	}
}

func TestQualConvergenceIdentityRetentionAndEntitlement(t *testing.T) {
	for _, v := range convergenceVectors(t) {
		t.Run(v.Family+"/"+v.Phase+" should retain non-reuse after progress loss", func(t *testing.T) {
			f := qualIdentityNew(t, v)
			f.create(t)
			f.fill(t)
			require.NoError(t, f.records.complete(f.tr))
			qualRecordPut(t, f.store, f.key, nil) // hostile loss/compaction, not a production compactor
			before := f.root(t)
			require.Error(t, f.records.create(f.tr))
			require.Equal(t, before, f.root(t))
			require.Error(t, f.ack(0))
			require.Equal(t, before, f.root(t))
			require.Error(t, f.records.complete(f.tr))
			require.Equal(t, before, f.root(t))
			_, _, err := f.records.observe(f.tr)
			require.Error(t, err)
			require.Equal(t, before, f.root(t))
		})
		if v.OriginalOutcome == "CANCELLED" {
			for _, missing := range []string{"fence", "authority", "entitlement", "source-outcome", "meta"} {
				if (missing == "authority" || missing == "entitlement") && v.Phase != "continuation" {
					continue
				}
				if missing == "meta" && v.Phase != "DRWAQuiescenceAck" && v.Phase != "CURRENT_ACK" {
					continue
				}
				t.Run(v.Phase+"/"+missing+" should deny cancelled-lineage substitution", func(t *testing.T) {
					f := qualIdentityNew(t, v)
					f.create(t)
					f.fill(t)
					switch missing {
					case "fence":
						qualRecordPut(t, f.store, f.identity.fence, nil)
					case "authority":
						qualRecordPut(t, f.store, f.identity.authority, []byte("synthetic-cancellation-operator-only"))
					case "entitlement":
						qualRecordPut(t, f.store, f.identity.entitlement, nil)
					case "source-outcome":
						qualRecordPut(t, f.store, f.identity.owner, qualRecordFrame(f.binding, []byte("EXECUTED")))
					case "meta":
						qualRecordPut(t, f.store, f.identity.meta, nil)
					}
					before := f.root(t)
					require.Error(t, f.records.complete(f.tr))
					require.Equal(t, before, f.root(t))
				})
			}
		}
	}
}

func TestQualConvergenceIdentityCallbackAndParentDenials(t *testing.T) {
	for _, v := range convergenceVectors(t) {
		for _, stage := range []string{"transition", "ack", "after_parent", "parent"} {
			t.Run(v.Phase+"/"+v.OriginalOutcome+"/"+stage+" should roll back callback mutation", func(t *testing.T) {
				f := qualIdentityNew(t, v)
				f.create(t)
				f.fill(t)
				f.host.hooks[stage] = func() { qualRecordPut(t, f.store, f.key, []byte("changed by verifier")) }
				before := f.root(t)
				var err error
				if stage == "ack" {
					err = f.ack(0)
				} else {
					err = f.records.complete(f.tr)
				}
				require.Error(t, err)
				require.Equal(t, before, f.root(t))
				require.Empty(t, f.identity.read(f.identity.parent))
			})
		}
	}
}

func TestQualConvergenceIdentityVerifierBaseline(t *testing.T) {
	for _, v := range convergenceVectors(t) {
		for _, stage := range []string{"transition", "ack", "observation", "parent"} {
			t.Run(v.Family+"/"+v.Phase+"/"+stage+" should reject valid-looking progress manufactured by a verifier", func(t *testing.T) {
				f := qualIdentityNew(t, v)
				f.create(t)
				if stage == "parent" {
					f.fill(t)
				}
				key, state := stage, "full"
				if stage == "observation" {
					key = "transition"
				}
				if stage == "parent" {
					state = "terminal"
				}
				f.host.hooks[key] = func() { qualRecordPut(t, f.store, f.key, convergenceHex(t, v.States[state].Value)) }
				before := f.root(t)
				var err error
				if stage == "observation" {
					_, _, err = f.records.observe(f.tr)
				} else if stage == "parent" {
					err = f.records.complete(f.tr)
				} else {
					err = f.ack(0)
				}
				require.Error(t, err)
				require.Equal(t, before, f.root(t))
			})
		}
	}
}

func TestQualConvergenceIdentityRestartAndReorg(t *testing.T) {
	for _, v := range convergenceVectors(t) {
		for boundary := 0; boundary <= 5; boundary++ {
			t.Run(fmt.Sprintf("%s/%s/boundary_%d should restore canonical prefix", v.Family, v.Phase, boundary), func(t *testing.T) {
				f := qualIdentityNew(t, v)
				before := f.root(t)
				ops := []func() error{func() error { return f.records.create(f.tr) }, func() error { return f.ack(0) }, func() error { return f.ack(1) }, func() error { return f.ack(2) }, func() error { return f.records.complete(f.tr) }}
				for i := 0; i < boundary; i++ {
					require.NoError(t, ops[i]())
				}
				roots, _, err := f.owner.Commit()
				require.NoError(t, err)
				require.NoError(t, f.store.RecreateTrie(holders.NewDefaultRootHashesHolder(roots[0])))
				f.rebind(t, f.store)
				for _, op := range ops {
					require.NoError(t, op())
				}
				f.assertVector(t, "terminal")
				// Reorg the entire dependent parent/progress/entitlement journal.
				require.NoError(t, f.store.RecreateTrie(holders.NewDefaultRootHashesHolder(before)))
				f.rebind(t, f.store)
				require.Error(t, f.ack(0), "discarded progress cannot exist on predecessor")
				require.Empty(t, f.identity.read(f.identity.parent))
				if v.Phase == "continuation" {
					require.Equal(t, qualRecordFrame(f.binding, []byte("LIVE")), f.identity.read(f.identity.entitlement))
				}
				for _, op := range ops {
					require.NoError(t, op())
				}
				f.assertVector(t, "terminal")
			})
		}
	}
}

func TestQualConvergenceIdentityConcurrentEntry(t *testing.T) {
	for _, v := range convergenceVectors(t) {
		t.Run(v.Family+"/"+v.Phase+" should refuse competing journal entry", func(t *testing.T) {
			f := qualIdentityNew(t, v)
			f.create(t)
			entered, release, result := make(chan struct{}), make(chan struct{}), make(chan error, 1)
			f.host.hooks["ack"] = func() { close(entered); <-release }
			go func() { result <- f.ack(0) }()
			<-entered
			err := f.records.complete(f.tr)
			_, _, observeErr := f.records.observe(f.tr)
			close(release)
			require.ErrorIs(t, err, ErrExecutionBusy)
			require.ErrorIs(t, observeErr, ErrExecutionBusy)
			require.NoError(t, <-result)
			f.assertVector(t, "one")
		})
	}
}

func TestQualConvergenceIdentityConcurrentContinuation(t *testing.T) {
	for _, v := range convergenceVectors(t) {
		if v.Phase != "continuation" {
			continue
		}
		t.Run(v.OriginalOutcome+" should consume the exact synthetic entitlement once", func(t *testing.T) {
			f := qualIdentityNew(t, v)
			f.create(t)
			f.fill(t)
			entered, release, result := make(chan struct{}), make(chan struct{}), make(chan error, 1)
			f.host.hooks["complete"] = func() { close(entered); <-release }
			go func() { result <- f.records.complete(f.tr) }()
			<-entered
			err := f.records.complete(f.tr)
			close(release)
			require.ErrorIs(t, err, ErrExecutionBusy)
			require.NoError(t, <-result)
			before := f.root(t)
			require.NoError(t, f.records.complete(f.tr))
			require.Equal(t, 1, f.identity.completeCalls)
			require.Equal(t, qualRecordFrame(f.binding, []byte("CONSUMED")), f.identity.read(f.identity.entitlement))
			require.Equal(t, before, f.root(t))
		})
	}
}

type qualIdentityReadStore struct {
	state.AccountsAdapter
	key   []byte
	fault error
}

type qualIdentityReadAccount struct {
	state.UserAccountHandler
	store *qualIdentityReadStore
}

func (s *qualIdentityReadStore) GetExistingAccount(address []byte) (vmcommon.AccountHandler, error) {
	a, err := s.AccountsAdapter.GetExistingAccount(address)
	if err != nil {
		return nil, err
	}
	return &qualIdentityReadAccount{UserAccountHandler: a.(state.UserAccountHandler), store: s}, nil
}

func (a *qualIdentityReadAccount) RetrieveValue(key []byte) ([]byte, uint32, error) {
	if bytes.Equal(key, a.store.key) && a.store.fault != nil {
		return nil, 0, a.store.fault
	}
	return a.UserAccountHandler.RetrieveValue(key)
}

func (s *qualIdentityReadStore) SaveAccount(account vmcommon.AccountHandler) error {
	if a, wrapped := account.(*qualIdentityReadAccount); wrapped {
		account = a.UserAccountHandler
	}
	return s.AccountsAdapter.SaveAccount(account)
}

func TestQualConvergenceIdentityReadErrorsAndObservations(t *testing.T) {
	for _, v := range convergenceVectors(t) {
		for _, stage := range []string{"creation", "matching", "duplicate", "completion", "replay"} {
			t.Run(v.Family+"/"+v.Phase+"/"+stage+" should deny native read error", func(t *testing.T) {
				f := qualIdentityNew(t, v)
				if stage != "creation" {
					f.create(t)
				}
				if stage == "duplicate" {
					require.NoError(t, f.ack(0))
				}
				if stage == "completion" || stage == "replay" {
					f.fill(t)
				}
				if stage == "replay" {
					require.NoError(t, f.records.complete(f.tr))
				}
				// Commit the intended prefix before replacing its read adapter.
				_, _, err := f.owner.Commit()
				require.NoError(t, err)
				reader := &qualIdentityReadStore{AccountsAdapter: f.store, key: f.key, fault: errors.New("native progress read failed")}
				f.rebind(t, reader)
				before := f.root(t)
				if stage == "creation" {
					err = f.records.create(f.tr)
				} else if stage == "completion" || stage == "replay" {
					err = f.records.complete(f.tr)
				} else {
					err = f.ack(0)
				}
				require.ErrorIs(t, err, reader.fault)
				binding, progress, err := f.records.observe(f.tr)
				require.ErrorIs(t, err, reader.fault)
				require.Nil(t, binding)
				require.Nil(t, progress)
				require.Equal(t, before, f.root(t))
			})
		}
		for _, missing := range []string{"progress", "parent", "owner"} {
			t.Run(v.Family+"/"+v.Phase+"/"+missing+" should expose no completed observation without evidence", func(t *testing.T) {
				f := qualIdentityNew(t, v)
				f.create(t)
				f.fill(t)
				require.NoError(t, f.records.complete(f.tr))
				key := f.key
				if missing == "parent" {
					key = f.identity.parent
				}
				if missing == "owner" {
					key = f.identity.owner
				}
				qualRecordPut(t, f.store, key, nil)
				before := f.root(t)
				binding, progress, err := f.records.observe(f.tr)
				require.Error(t, err)
				require.Nil(t, binding)
				require.Nil(t, progress)
				require.Equal(t, before, f.root(t))
			})
		}
	}
}

func TestQualConvergenceIdentityFamilyAndPhaseIsolation(t *testing.T) {
	for _, pair := range [][2]int{{5, 10}, {0, 5}} {
		t.Run(fmt.Sprint(pair)+" should isolate equal action and target across family or phase", func(t *testing.T) {
			vectors := convergenceVectors(t)
			a, b := qualIdentityNew(t, vectors[pair[0]]), qualIdentityNew(t, vectors[pair[1]])
			for _, key := range [][]byte{b.identity.owner, b.identity.prior, b.identity.permission, b.identity.fence, b.identity.meta} {
				qualRecordPut(t, a.store, key, b.identity.read(key))
			}
			_, err := a.store.Commit()
			require.NoError(t, err)
			a.rebind(t, a.store)
			b.store, b.identity.store, b.owner = a.store, a.store, a.owner
			shared := *a.records
			shared.host = b.identity
			b.records = &shared
			a.create(t)
			b.create(t)
			aBefore, bBefore := bytes.Clone(qualRegistryValue(t, a.store, string(a.key))), bytes.Clone(qualRegistryValue(t, a.store, string(b.key)))
			require.NoError(t, a.ack(0))
			require.Equal(t, bBefore, qualRegistryValue(t, a.store, string(b.key)))
			require.NotEqual(t, aBefore, qualRegistryValue(t, a.store, string(a.key)))
			aBefore = bytes.Clone(qualRegistryValue(t, a.store, string(a.key)))
			require.NoError(t, b.ack(1))
			require.Equal(t, aBefore, qualRegistryValue(t, a.store, string(a.key)))
			_, aObserved, err := a.records.observe(a.tr)
			require.NoError(t, err)
			_, bObserved, err := b.records.observe(b.tr)
			require.NoError(t, err)
			require.Equal(t, []byte{1}, aObserved.bitmap)
			require.Equal(t, []byte{2}, bObserved.bitmap)
		})
	}
}

func TestQualConvergenceIdentityDiskRestart(t *testing.T) {
	for _, v := range convergenceVectors(t) {
		t.Run(v.Family+"/"+v.Phase+" should persist exact context through fresh disk owner", func(t *testing.T) {
			f := qualIdentityNew(t, v)
			path := filepath.Join(t.TempDir(), "identity")
			store, closeDisk := qualConvergenceDiskOpen(t, path, false)
			protected, err := newProtectedState(store)
			require.NoError(t, err)
			require.NoError(t, protected.provisionGenesis())
			// Copy only explicit synthetic canonical fixture inputs, never live
			// progress produced by the implementation under test.
			for _, key := range [][]byte{f.identity.owner, f.identity.prior, f.identity.permission, f.identity.entitlement, f.identity.fence, f.identity.authority, f.identity.meta} {
				qualRecordPut(t, store, key, f.identity.read(key))
			}
			require.NoError(t, f.store.Close())
			_, err = store.Commit()
			require.NoError(t, err)
			f.freshDiskOwner(t, store)
			f.create(t)
			require.NoError(t, f.ack(0))
			roots, _, err := f.owner.Commit()
			require.NoError(t, err)
			closeDisk()
			store, closeDisk = qualConvergenceDiskOpen(t, path, false)
			require.NoError(t, store.RecreateTrie(holders.NewDefaultRootHashesHolder(roots[0])))
			f.freshDiskOwner(t, store)
			f.assertVector(t, "one")
			f.fill(t)
			require.NoError(t, f.records.complete(f.tr))
			roots, _, err = f.owner.Commit()
			require.NoError(t, err)
			closeDisk()
			store, closeDisk = qualConvergenceDiskOpen(t, path, false)
			require.NoError(t, store.RecreateTrie(holders.NewDefaultRootHashesHolder(roots[0])))
			f.freshDiskOwner(t, store)
			f.assertVector(t, "terminal")
			require.NoError(t, f.ack(0))
			require.NoError(t, f.records.complete(f.tr))
			require.Zero(t, store.JournalLen())
			require.Zero(t, f.identity.completeCalls)
			closeDisk()
		})
	}
}

func (f *qualIdentityFixture) freshDiskOwner(t *testing.T, store *qualNativeStore) {
	t.Helper()
	h := *f.identity
	h.qualConvergenceHost = &qualConvergenceHost{t: t, store: store, binding: bytes.Clone(f.binding), key: bytes.Clone(f.key),
		acks: make(map[string]uint32), faults: make(map[string]error), hooks: make(map[string]func())}
	for i, ack := range f.vector.Ack {
		h.acks[string(convergenceHex(t, ack))] = uint32(i)
	}
	f.identity, f.host, f.store = &h, h.qualConvergenceHost, store
	f.rebind(t, store)
}
