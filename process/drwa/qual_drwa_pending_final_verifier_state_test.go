package drwa

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Synthetic verifiers exercise actual native journals, not canonical permission.
func TestQualDRWAPendingFinalVerifierState(t *testing.T) {
	for _, mode := range []string{
		"admit-inject-pending", "admit-inject-final", "admit-delete-pending", "admit-revive-final",
		"canonical-publish-final", "canonical-revive-final",
	} {
		t.Run(mode, func(t *testing.T) {
			f := qualPendingFinalNew(t)
			if mode == "admit-delete-pending" || mode == "canonical-publish-final" ||
				mode == "admit-revive-final" || mode == "canonical-revive-final" {
				require.NoError(t, f.r.stage(f.c))
			}
			if mode == "admit-revive-final" || mode == "canonical-revive-final" {
				require.NoError(t, f.promote())
			}
			keys := [][]byte{f.finalKey, f.pendingKey, f.itemKey}
			before := make([][]byte, len(keys))
			for i, key := range keys {
				before[i] = qualRegistryValue(t, f.s, string(key))
			}
			root, err := f.s.RootHash()
			require.NoError(t, err)
			outputs, initializations, observations := len(f.o.outputs), f.h.initializations, f.h.observations
			f.h.hook = func(stage string) {
				if stage != "admit" && stage != "canonical" {
					return
				}
				switch mode {
				case "admit-inject-pending":
					qualRecordPut(t, f.s, f.pendingKey, f.encoded)
					qualRecordPut(t, f.s, f.itemKey, f.digest)
				case "admit-inject-final":
					qualRecordPut(t, f.s, f.finalKey, f.encoded)
				case "admit-delete-pending":
					qualRecordPut(t, f.s, f.pendingKey, nil)
					qualRecordPut(t, f.s, f.itemKey, nil)
				case "canonical-publish-final":
					qualRecordPut(t, f.s, f.finalKey, f.encoded)
					qualRecordPut(t, f.s, f.pendingKey, nil)
					qualRecordPut(t, f.s, f.itemKey, nil)
				case "admit-revive-final", "canonical-revive-final":
					qualRecordPut(t, f.s, f.finalKey, nil)
					qualRecordPut(t, f.s, f.pendingKey, f.encoded)
					qualRecordPut(t, f.s, f.itemKey, f.digest)
				}
			}
			if mode == "canonical-publish-final" || mode == "canonical-revive-final" {
				err = f.promote()
			} else {
				err = f.r.stage(f.c)
			}
			require.ErrorIs(t, err, errPendingFinal)
			after, err := f.s.RootHash()
			require.NoError(t, err)
			require.Equal(t, root, after)
			for i, key := range keys {
				require.Equal(t, before[i], qualRegistryValue(t, f.s, string(key)))
			}
			require.Len(t, f.o.outputs, outputs)
			require.Equal(t, initializations, f.h.initializations)
			require.Equal(t, observations, f.h.observations)
		})
	}
	for _, mode := range []string{"admit-other-key", "canonical-other-key", "canonical-duplicate-other-key"} {
		t.Run(mode, func(t *testing.T) {
			f := qualPendingFinalNew(t)
			if mode != "admit-other-key" {
				require.NoError(t, f.r.stage(f.c))
			}
			if mode == "canonical-duplicate-other-key" {
				require.NoError(t, f.promote())
			}
			observations := f.h.observations
			f.h.hook = func(stage string) {
				if stage == "admit" || stage == "canonical" {
					qualRecordPut(t, f.s, []byte("fixture/T23/other-verifier-state"), []byte{1})
				}
			}
			if mode == "admit-other-key" {
				require.NoError(t, f.r.stage(f.c))
				f.staged(t)
			} else {
				require.NoError(t, f.promote())
				final, _, err := f.r.final(f.c.key)
				require.NoError(t, err)
				require.Equal(t, f.encoded, final)
				if mode == "canonical-duplicate-other-key" {
					require.Equal(t, observations, f.h.observations)
				} else {
					require.Equal(t, observations+1, f.h.observations)
				}
			}
			require.Equal(t, []byte{1}, qualRegistryValue(t, f.s, "fixture/T23/other-verifier-state"))
		})
	}
}
