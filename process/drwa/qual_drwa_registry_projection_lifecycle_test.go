package drwa

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func qualRegistryCandidateCommitError(v *registryCandidate) error {
	_, _, err := v.commit()
	return err
}

func TestQualDRWARegistryProjectionOutputReceipt(t *testing.T) {
	for _, auto := range []bool{false, true} {
		for _, name := range []string{"success", "commit_failure", "abort"} {
			t.Run(fmt.Sprintf("auto_%t/%s", auto, name), func(t *testing.T) {
				c, db, adapter, f, tr := qualRegistryLifecycle(t, auto)
				v, err := c.prepareDelta(tr, &c.anchor, f.anchor, f.count, []registryMemberWitness{f.members[2]})
				require.NoError(t, err)
				a := &qualRegistryLifecycleFault{qualRegistryMaterializationFault: adapter}
				require.NoError(t, v.stage(a))
				output := &vmcommon.VMOutput{GasRemaining: 17, ReturnData: [][]byte{[]byte("contained DRWA result")}}
				require.NoError(t, v.material.owner.Execute(func() (*vmcommon.VMOutput, error) { return output, nil }))
				if name == "commit_failure" {
					a.commitError = errors.New("output receipt native commit failure")
				}
				if name == "abort" {
					require.NoError(t, v.abort())
				}
				roots, outputs, err := v.commit()
				if name != "success" {
					require.Error(t, err)
					require.Nil(t, roots)
					require.Nil(t, outputs)
					return
				}
				require.NoError(t, err)
				root, err := db.RootHash()
				require.NoError(t, err)
				require.Equal(t, [][]byte{root}, roots)
				// Native containment retains the nil import output as well as the
				// actual operation output. Forward that existing ownership contract.
				require.Len(t, outputs, 2)
				require.Nil(t, outputs[0])
				require.Same(t, output, outputs[1])
				require.Nil(t, v.material.owner.outputs)
				require.Len(t, c.members, 3)
				roots, outputs, err = v.commit()
				require.Error(t, err)
				require.Nil(t, roots)
				require.Nil(t, outputs)
			})
		}
	}
}

func qualRegistryLifecycle(t *testing.T, auto bool) (*committedRegistry, *state.AccountsDB, *qualRegistryMaterializationFault, *qualRegistryTransportFixture, *registryTransport) {
	t.Helper()
	m, view, db, adapter := qualRegistryMaterialization(t, auto)
	require.NoError(t, m.prepare(context.Background(), view))
	c, err := m.commitProjection()
	require.NoError(t, err)
	// These are real native account/data proofs and native header encodings,
	// not canonical inter-candidate ancestry/finality evidence. The production
	// owner's admitted continuation contract remains a separate AN-03 item.
	f := qualRegistryTransport(t, auto, []byte{0, 0, 0, 0, 0, 0, 0, 3}, []byte{1}, []byte("AAA-abcdef"), []byte("BBB-123456"), []byte("CCC-abcdef"))
	tr, err := newRegistryTransport(f.reader, 3, f.limit)
	require.NoError(t, err)
	return c, db, adapter, f, tr
}

// Real native commit/recreation happens first. Post-operation faults exercise
// the boundary where journal length or root equality cannot prove publication.
type qualRegistryLifecycleFault struct {
	*qualRegistryMaterializationFault
	commitError, recreateError error
}

func (a *qualRegistryLifecycleFault) Commit() ([]byte, error) {
	root, err := a.AccountsAdapter.Commit()
	if err != nil {
		return nil, err
	}
	return root, a.commitError
}

func (a *qualRegistryLifecycleFault) RecreateTrie(root common.RootHashHolder) error {
	if err := a.AccountsAdapter.RecreateTrie(root); err != nil {
		return err
	}
	return a.recreateError
}

func TestQualDRWARegistryProjectionLifecycle(t *testing.T) {
	for _, auto := range []bool{false, true} {
		for _, name := range []string{"no_delta", "active_stage", "superseded_stage", "aborted_retry", "wrong_candidate", "memory_only", "commit_failure", "recovery_failure", "malformed_count", "regression", "wrong_marker", "commit_unprepared", "initial_unprepared", "external_commit"} {
			t.Run(fmt.Sprintf("auto_%t/%s", auto, name), func(t *testing.T) {
				c, db, adapter, f, tr := qualRegistryLifecycle(t, auto)
				fault := errors.New("native lifecycle persistence failed")
				var members = []registryMemberWitness{f.members[2]}
				if name == "no_delta" || name == "active_stage" {
					f = qualRegistryTransport(t, auto, []byte{0, 0, 0, 0, 0, 0, 0, 2}, []byte{1})
					var e error
					tr, e = newRegistryTransport(f.reader, 3, f.limit)
					require.NoError(t, e)
					members = nil
				}
				if name == "malformed_count" || name == "regression" || name == "wrong_marker" {
					count, marker := []byte{0, 0, 0, 0, 0, 0, 0, 3}, []byte{1}
					if name == "malformed_count" {
						count = []byte{3}
					}
					if name == "regression" {
						count = []byte{0, 0, 0, 0, 0, 0, 0, 1}
						members = nil
					}
					if name == "wrong_marker" {
						marker = []byte{2}
					}
					f = qualRegistryTransport(t, auto, count, marker, []byte("AAA-abcdef"), []byte("BBB-123456"), []byte("CCC-abcdef"))
					var e error
					tr, e = newRegistryTransport(f.reader, 3, f.limit)
					require.NoError(t, e)
					if name != "regression" {
						members = []registryMemberWitness{f.members[2]}
					}
				}
				v, e := c.prepareDelta(tr, &c.anchor, f.anchor, f.count, members)
				if name == "malformed_count" || name == "regression" || name == "wrong_marker" {
					require.Error(t, e)
					require.Nil(t, v)
					return
				}
				require.NoError(t, e)
				if name == "commit_unprepared" {
					require.Error(t, qualRegistryCandidateCommitError(v))
					return
				}
				if name == "initial_unprepared" {
					m, e := newRegistryMaterialization(adapter, f.anchor)
					require.NoError(t, e)
					initial, e := m.commitProjection()
					require.Error(t, e)
					require.Nil(t, initial)
					return
				}
				var other *registryCandidate
				if name == "active_stage" || name == "superseded_stage" {
					other, e = c.prepareDelta(tr, &c.anchor, f.anchor, f.count, members)
					require.NoError(t, e)
				}
				root, e := db.RootHash()
				require.NoError(t, e)
				a := &qualRegistryLifecycleFault{qualRegistryMaterializationFault: adapter}
				require.NoError(t, v.stage(a))
				if name == "external_commit" {
					_, _, e = v.material.owner.Commit()
					require.NoError(t, e)
					_, e = v.classify(f.anchor.candidateHash, []byte("CCC-abcdef"))
					require.ErrorIs(t, e, ErrExecutionClosed)
					return
				}
				if name == "active_stage" {
					require.Error(t, other.stage(a))
					return
				}
				if name == "superseded_stage" {
					require.NoError(t, qualRegistryCandidateCommitError(v))
					require.Error(t, other.stage(a))
					return
				}
				if name == "aborted_retry" {
					require.NoError(t, v.abort())
					require.Error(t, v.stage(a))
					return
				}
				if name == "wrong_candidate" {
					wrong := bytes.Clone(f.anchor.candidateHash)
					wrong[0] ^= 1
					_, e = v.classify(wrong, []byte("CCC-abcdef"))
					require.Error(t, e)
					return
				}
				if name == "commit_failure" || name == "recovery_failure" {
					a.commitError = fault
					require.ErrorIs(t, qualRegistryCandidateCommitError(v), fault)
					require.Len(t, c.members, 2)
					require.Same(t, v, c.active)
					_, e = v.classify(f.anchor.candidateHash, []byte("CCC-abcdef"))
					require.ErrorIs(t, e, fault)
					if name == "recovery_failure" {
						a.recreateError = errors.New("native recovery failed after rebuild")
						require.ErrorIs(t, v.recover(), fault)
						require.Same(t, v, c.active)
						_, e = v.classify(f.anchor.candidateHash, []byte("CCC-abcdef"))
						require.ErrorIs(t, e, a.recreateError)
					}
					a.recreateError = nil
					require.NoError(t, v.recover())
					require.Nil(t, c.active)
					actual, e := db.RootHash()
					require.NoError(t, e)
					require.Equal(t, root, actual)
					return
				}
				if name == "memory_only" {
					adapter.readError = errors.New("no native account read during classification")
				}
				for _, id := range []string{"AAA-abcdef", "BBB-123456"} {
					present, e := v.classify(f.anchor.candidateHash, []byte(id))
					require.NoError(t, e)
					require.True(t, present)
				}
				present, e := v.classify(f.anchor.candidateHash, []byte("CCC-abcdef"))
				require.NoError(t, e)
				require.Equal(t, name != "no_delta", present)
				present, e = v.classify(f.anchor.candidateHash, []byte("DDD-abcdef"))
				require.NoError(t, e)
				require.False(t, present)
				if name == "no_delta" {
					require.Zero(t, db.JournalLen())
					actual, e := db.RootHash()
					require.NoError(t, e)
					require.Equal(t, root, actual)
				}
			})
		}
	}
}

func TestQualDRWARegistryProjectionInitialPublication(t *testing.T) {
	for _, name := range []string{"commit_failure", "closed"} {
		t.Run(name, func(t *testing.T) {
			m, view, db, adapter := qualRegistryMaterialization(t, false)
			a := &qualRegistryLifecycleFault{qualRegistryMaterializationFault: adapter}
			var e error
			m, e = newRegistryMaterialization(a, &view.anchor)
			require.NoError(t, e)
			before, e := db.RootHash()
			require.NoError(t, e)
			require.NoError(t, m.prepare(context.Background(), view))
			if name == "closed" {
				require.NoError(t, m.abort())
			} else {
				a.commitError = errors.New("initial projection native commit failed")
			}
			c, e := m.commitProjection()
			require.Error(t, e)
			require.Nil(t, c)
			if name == "commit_failure" {
				require.ErrorIs(t, e, a.commitError)
				_, e = m.classify(view.anchor.candidateHash, []byte("AAA-abcdef"))
				require.ErrorIs(t, e, a.commitError)
				actual, e := db.RootHash()
				require.NoError(t, e)
				require.NotEqual(t, before, actual)
				require.NoError(t, m.owner.Recover())
			}
			actual, e := db.RootHash()
			require.NoError(t, e)
			require.Equal(t, before, actual)
		})
	}
}

func TestQualDRWARegistryProjectionDelta(t *testing.T) {
	for _, auto := range []bool{false, true} {
		for _, name := range []string{"valid", "old_context", "nil_transport", "nil_before", "nil_after", "cap", "cap_before_proof", "old_over_cap", "old_over_cap_before_proof", "missing", "old_member", "duplicate", "invalid_id", "count_proof", "member_proof", "budget", "alias", "unprepared", "save", "rollback", "abort", "abort_failure", "commit", "operation_rollback", "nested", "concurrent", "active", "stale_handle"} {
			t.Run(fmt.Sprintf("auto_%t/%s", auto, name), func(t *testing.T) {
				c, db, adapter, f, tr := qualRegistryLifecycle(t, auto)
				before := copyRegistryAnchor(&c.anchor)
				var prior *metaRegistryAnchor = &before
				after := f.anchor
				members := []registryMemberWitness{f.members[2]}
				switch name {
				case "old_context":
					before.root[0] ^= 1
				case "nil_transport":
					tr = nil
				case "nil_before":
					prior = nil
				case "nil_after":
					after = nil
				case "cap":
					tr.maxEver = 2
				case "cap_before_proof":
					tr.maxEver = 2
					f.count.DataProof = nil
				case "old_over_cap":
					tr.maxEver = 1
				case "old_over_cap_before_proof":
					tr.maxEver = 1
					f.count.DataProof = nil
				case "missing":
					members = nil
				case "old_member":
					members = []registryMemberWitness{f.members[0]}
				case "duplicate":
					f = qualRegistryTransport(t, auto, []byte{0, 0, 0, 0, 0, 0, 0, 4}, []byte{1}, []byte("AAA-abcdef"), []byte("BBB-123456"), []byte("CCC-abcdef"), []byte("DDD-abcdef"))
					var err error
					tr, err = newRegistryTransport(f.reader, 4, f.limit)
					require.NoError(t, err)
					after = f.anchor
					members = []registryMemberWitness{f.members[2], f.members[2]}
				case "invalid_id":
					f = qualRegistryTransport(t, auto, []byte{0, 0, 0, 0, 0, 0, 0, 3}, []byte{1}, []byte("AAA-abcdef"), []byte("BBB-123456"), []byte("bad"))
					var e error
					tr, e = newRegistryTransport(f.reader, 3, f.limit)
					require.NoError(t, e)
					after = f.anchor
					members = []registryMemberWitness{f.members[2]}
				case "count_proof":
					f.count.DataProof[0][0] ^= 1
				case "member_proof":
					members[0].proof.DataProof[0][0] ^= 1
				case "budget":
					tr.proofByteLimit = 1
				}
				v, err := c.prepareDelta(tr, prior, after, f.count, members)
				denied := map[string]bool{"old_context": true, "nil_transport": true, "nil_before": true, "nil_after": true, "cap": true, "cap_before_proof": true, "old_over_cap": true, "old_over_cap_before_proof": true, "missing": true, "old_member": true, "duplicate": true, "invalid_id": true, "count_proof": true, "member_proof": true, "budget": true}
				if denied[name] {
					require.Error(t, err)
					if name == "cap_before_proof" || name == "old_over_cap_before_proof" {
						require.Same(t, errInvalidRegistryTransport, err)
					}
					require.Nil(t, v)
					require.Len(t, c.members, 2)
					require.Nil(t, c.active)
					return
				}
				require.NoError(t, err)
				candidate := bytes.Clone(after.candidateHash)
				if name == "unprepared" {
					_, err = v.classify(candidate, []byte("CCC-abcdef"))
					require.Error(t, err)
					return
				}
				if name == "alias" {
					after.candidateHash[0] ^= 1
					members[0].tokenID[0] ^= 1
				}
				root, err := db.RootHash()
				require.NoError(t, err)
				failure := errors.New("delta save failed")
				if name == "save" || name == "rollback" {
					adapter.saveAt = adapter.saves + 1
					adapter.saveError = failure
				}
				if name == "rollback" {
					adapter.rollbackError = errors.New("delta rollback failed")
				}
				err = v.stage(adapter)
				if name == "save" || name == "rollback" {
					require.ErrorIs(t, err, failure)
					require.False(t, v.ready)
					require.Len(t, c.members, 2)
					_, err = v.classify(candidate, []byte("CCC-abcdef"))
					require.Error(t, err)
					if name == "rollback" {
						require.Same(t, v, c.active)
						require.ErrorIs(t, qualRegistryCandidateCommitError(v), failure)
						_, e := v.classify(candidate, []byte("CCC-abcdef"))
						require.ErrorIs(t, e, failure)
						require.ErrorIs(t, e, adapter.rollbackError)
						_, e = v.material.commitProjection()
						require.ErrorIs(t, e, failure)
						require.ErrorIs(t, e, adapter.rollbackError)
						complete, e := tr.reconstruct(after, f.count, f.members)
						require.NoError(t, e)
						adapter.readError = errors.New("poisoned store must not be read")
						e = v.material.prepare(context.Background(), complete)
						require.ErrorIs(t, e, failure)
						require.ErrorIs(t, e, adapter.rollbackError)
						adapter.readError = nil
						adapter.saveError = nil
						adapter.rollbackError = nil
						require.NoError(t, v.recover())
						require.Nil(t, c.active)
					} else {
						require.Nil(t, c.active)
					}
					actual, err := db.RootHash()
					require.NoError(t, err)
					require.Equal(t, root, actual)
					return
				}
				require.NoError(t, err)
				if name == "active" {
					_, err = c.prepareDelta(tr, &c.anchor, f.anchor, f.count, members)
					require.Error(t, err)
					require.Error(t, v.stage(adapter))
				}
				if name == "nested" {
					require.NoError(t, v.material.owner.Execute(func() (*vmcommon.VMOutput, error) {
						present, e := v.classify(candidate, []byte("CCC-abcdef"))
						require.NoError(t, e)
						require.True(t, present)
						return nil, nil
					}))
				}
				if name == "operation_rollback" {
					require.ErrorIs(t, v.material.owner.Execute(func() (*vmcommon.VMOutput, error) {
						a, e := db.LoadAccount(bytes.Repeat([]byte{8}, 32))
						require.NoError(t, e)
						require.NoError(t, db.SaveAccount(a))
						return nil, failure
					}), failure)
				}
				if name == "concurrent" {
					var wg sync.WaitGroup
					for i := 0; i < 8; i++ {
						wg.Add(1)
						go func() {
							defer wg.Done()
							present, e := v.classify(candidate, []byte("CCC-abcdef"))
							require.NoError(t, e)
							require.True(t, present)
						}()
					}
					wg.Wait()
				}
				for _, id := range []string{"AAA-abcdef", "BBB-123456", "CCC-abcdef"} {
					present, e := v.classify(candidate, []byte(id))
					require.NoError(t, e)
					require.True(t, present)
				}
				present, e := v.classify(candidate, []byte("DDD-abcdef"))
				require.NoError(t, e)
				require.False(t, present)
				if name == "abort_failure" {
					adapter.rollbackError = failure
					require.ErrorIs(t, v.abort(), failure)
					require.ErrorIs(t, qualRegistryCandidateCommitError(v), failure)
					adapter.rollbackError = nil
					require.NoError(t, v.recover())
				}
				if name == "abort" {
					require.NoError(t, v.abort())
				}
				if name == "commit" || name == "stale_handle" {
					require.NoError(t, qualRegistryCandidateCommitError(v))
					require.Len(t, c.members, 3)
					require.True(t, sameRegistryAnchor(&c.anchor, &v.after))
					require.Error(t, qualRegistryCandidateCommitError(v))
				}
				if name == "abort" || name == "abort_failure" || name == "commit" || name == "stale_handle" {
					_, err = v.classify(candidate, []byte("CCC-abcdef"))
					require.Error(t, err)
				}
				if name == "abort" || name == "abort_failure" {
					require.Len(t, c.members, 2)
					require.True(t, sameRegistryAnchor(&c.anchor, &before))
					actual, err := db.RootHash()
					require.NoError(t, err)
					require.Equal(t, root, actual)
				}
				if name == "commit" {
					a, err := db.GetExistingAccount(core.SystemAccountAddress)
					require.NoError(t, err)
					value, _, err := a.(state.UserAccountHandler).RetrieveValue([]byte("ELRONDDRWA@membership@CCC-abcdef"))
					require.NoError(t, err)
					require.Equal(t, []byte{1}, value)
				}
			})
		}
	}
}
