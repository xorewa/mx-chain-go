package drwa

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// L46 development only: native journals and rollback are real; authoritative
// GAS, ACK and parent/finality evidence remains the existing synthetic host.
func TestQualDRWAConvergenceCallbackProgress(t *testing.T) {
	for _, name := range []string{"admission_pending", "admission_complete", "duplicate_create", "duplicate_ack", "duplicate_complete"} {
		t.Run(name, func(t *testing.T) {
			f := qualConvergenceNew(t, 3)
			duplicate := name != "admission_pending" && name != "admission_complete"
			if duplicate {
				f.create(t)
				for _, shard := range f.tr.shards {
					require.NoError(t, f.ack(shard))
				}
				require.NoError(t, f.records.complete(f.tr))
			}
			before := qualRegistryValue(t, f.store, string(f.key))
			parent := qualRegistryValue(t, f.store, qualConvergenceParent)
			roots, _, err := f.owner.Commit()
			require.NoError(t, err)
			f.reopen(t, f.store)
			completions := f.host.completeCalls
			if duplicate {
				f.host.hooks["parent"] = func() {
					reset, _ := f.expected("PENDING")
					qualRecordPut(t, f.store, f.key, reset)
				}
			} else {
				f.host.hooks["admission"] = func() {
					value, _ := f.expected("PENDING", 0)
					if name == "admission_complete" {
						value, _ = f.expected("COMPLETE", 0, 1, 2)
					}
					qualRecordPut(t, f.store, f.key, value)
				}
			}
			switch name {
			case "duplicate_ack":
				err = f.ack(0)
			case "duplicate_complete":
				err = f.records.complete(f.tr)
			default:
				err = f.records.create(f.tr)
			}
			require.ErrorIs(t, err, errConvergence)
			require.Equal(t, before, qualRegistryValue(t, f.store, string(f.key)))
			require.Equal(t, parent, qualRegistryValue(t, f.store, qualConvergenceParent))
			require.Equal(t, completions, f.host.completeCalls)
			after, rootErr := f.store.RootHash()
			require.NoError(t, rootErr)
			require.Equal(t, roots[0], after)
			_, outputs, commitErr := f.owner.Commit()
			require.NoError(t, commitErr)
			require.Empty(t, outputs, "no output escapes a failed callback boundary")
		})
	}
}

func TestQualDRWAConvergenceCallbackOtherKey(t *testing.T) {
	for _, stage := range []string{"admission", "parent"} {
		t.Run(stage, func(t *testing.T) {
			f := qualConvergenceNew(t, 3)
			key := []byte("fixture/convergence-callback/" + stage)
			if stage == "parent" {
				f.create(t)
				for _, shard := range f.tr.shards {
					require.NoError(t, f.ack(shard))
				}
				require.NoError(t, f.records.complete(f.tr))
				_, _, err := f.owner.Commit()
				require.NoError(t, err)
				f.reopen(t, f.store)
			}
			f.host.hooks[stage] = func() { qualRecordPut(t, f.store, key, []byte("preserved")) }
			if stage == "admission" {
				f.create(t)
				f.assert(t, "PENDING")
			} else {
				require.NoError(t, f.records.complete(f.tr))
				f.assert(t, "COMPLETE", 0, 1, 2)
				require.Equal(t, 1, f.host.completeCalls)
			}
			require.Equal(t, []byte("preserved"), qualRegistryValue(t, f.store, string(key)))
		})
	}
}
