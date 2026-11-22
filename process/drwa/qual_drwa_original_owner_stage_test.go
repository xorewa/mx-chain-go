package drwa

import (
	"bytes"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// This qualifies original-owner journal composition over real AccountsDB only.
// The existing storage-unit host is synthetic: it supplies no class, canonical,
// original-execution, historical-profile, funding or native-ingress authority.
func TestQualDRWAOriginalOwnerStage(t *testing.T) {
	for _, name := range []string{"commit", "frozen-inputs", "parent-refusal", "staging-write-failure"} {
		t.Run(name, func(t *testing.T) {
			f := newPendingFinalTestFixture(t, 0)
			c := pendingFinalCandidate{
				key: []byte("fixture/owned-record"), version: 7,
				body: []byte("synthetic owned record bytes"), origin: []byte("synthetic origin"),
			}
			original := pendingFinalCandidate{key: bytes.Clone(c.key), version: c.version,
				body: bytes.Clone(c.body), origin: bytes.Clone(c.origin)}
			encoded, err := f.r.encode(c)
			require.NoError(t, err)
			f.host.expected[string(encoded)] = true
			pk, err := f.r.key("pending", original.key)
			require.NoError(t, err)
			ik, err := f.r.key("item", original.origin, original.key)
			require.NoError(t, err)
			ok, err := f.r.key("origin", original.origin)
			require.NoError(t, err)
			priorKey := []byte("fixture/original-owner")
			f.keys = append(f.keys, priorKey, pk, ik, ok)
			before := f.snapshot(t)
			operation, err := originalOwnerStageOperation(f.r, c)
			require.NoError(t, err)
			require.NotNil(t, operation)
			require.Equal(t, before, f.snapshot(t), "preparation has no write")
			require.Empty(t, f.owner.outputs, "preparation publishes no output")
			if name == "frozen-inputs" {
				c.key[0], c.body[0], c.origin[0] = 'X', 'X', 'X'
			}
			if name == "staging-write-failure" {
				// The original owner's write is first; pending persistence is second.
				f.s.writeFault = 2
			}
			refusal := errors.New("original owner refused after staging")
			var stagedOutput *vmcommon.VMOutput
			err = f.owner.Execute(func() (*vmcommon.VMOutput, error) {
				account, e := f.s.GetExistingAccount(core.SystemAccountAddress)
				if e != nil {
					return nil, e
				}
				if e = account.(state.UserAccountHandler).SaveKeyValue(priorKey, original.body); e != nil {
					return nil, e
				}
				if e = f.s.SaveAccount(account); e != nil {
					return nil, e
				}
				stagedOutput, e = operation()
				if e != nil {
					return nil, e
				}
				if name == "parent-refusal" {
					return nil, refusal
				}
				return stagedOutput, nil
			})
			if name == "parent-refusal" || name == "staging-write-failure" {
				if name == "parent-refusal" {
					require.ErrorIs(t, err, refusal)
				} else {
					require.Error(t, err)
				}
				require.Equal(t, before, f.snapshot(t), "original write and all stage writes revert together")
				require.Empty(t, f.owner.outputs)
				roots, outputs, e := f.owner.Commit()
				require.NoError(t, e)
				require.Equal(t, before[0], roots[0])
				require.Empty(t, outputs)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, stagedOutput)
			require.NoError(t, f.r.check(original, encoded, false))
			require.Len(t, f.owner.outputs, 1, "one owner retains the operation output")
			roots, outputs, err := f.owner.Commit()
			require.NoError(t, err)
			require.Len(t, outputs, 1)
			require.Same(t, stagedOutput, outputs[0], "original owner releases the unchanged stage output")
			require.Equal(t, roots[0], f.snapshot(t)[0])
			value, err := f.r.read(priorKey)
			require.NoError(t, err)
			require.Equal(t, original.body, value)
			f.reopen(t)
			require.NoError(t, f.r.check(original, encoded, false))
		})
	}
	t.Run("invalid-preparation", func(t *testing.T) {
		f := newPendingFinalTestFixture(t, 0)
		before := f.snapshot(t)
		operation, err := originalOwnerStageOperation(f.r, pendingFinalCandidate{})
		require.Error(t, err)
		require.Nil(t, operation)
		require.Equal(t, before, f.snapshot(t))
		require.Empty(t, f.owner.outputs)
	})
}

// Use the existing stage entry on the historical baseline so this same
// regression compiles there and observes its nested-journal refusal. The
// proposed entry is selected only when present; neither branch supplies
// class authority or weakens the assertions above.
func originalOwnerStageOperation(r *pendingFinalRecords, c pendingFinalCandidate) (func() (*vmcommon.VMOutput, error), error) {
	if preparer, exists := interface{}(r).(interface {
		prepareStage(pendingFinalCandidate) (func() (*vmcommon.VMOutput, error), error)
	}); exists {
		return preparer.prepareStage(c)
	}
	return func() (*vmcommon.VMOutput, error) {
		return nil, r.stage(c)
	}, nil
}
