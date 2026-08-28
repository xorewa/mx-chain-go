package drwaqualification

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRecorderRequiresExclusiveCreationAndMonotonicLifecycle(t *testing.T) {
	root := t.TempDir()
	arm := validTestArm(root, VariantBarrier)
	arm.EvidencePath = filepath.Join(root, "events.jsonl")
	recorder, err := CreateRecorder(arm.EvidencePath, sha256.Sum256([]byte("arm")), &arm)
	require.NoError(t, err)
	defer recorder.Close()

	_, err = CreateRecorder(arm.EvidencePath, sha256.Sum256([]byte("arm")), &arm)
	require.Error(t, err)
	require.ErrorIs(t, recorder.Append(LifecycleReached, map[string]any{}), ErrInvalidLifecycle)
	require.NoError(t, recorder.Append(LifecycleLoaded, map[string]any{"loaded": true}))
	require.NoError(t, recorder.Append(LifecycleReached, map[string]any{"reached": true}))
	require.NoError(t, recorder.Append(LifecycleConsumed, map[string]any{"consumed": true}))
	require.NoError(t, recorder.Append(LifecycleReleased, map[string]any{"released": true}))

	info, err := os.Stat(arm.EvidencePath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	raw, err := os.ReadFile(arm.EvidencePath)
	require.NoError(t, err)
	require.Equal(t, 5, len(splitNonEmptyLines(raw)))
}

func splitNonEmptyLines(raw []byte) [][]byte {
	lines := make([][]byte, 0)
	start := 0
	for index, value := range raw {
		if value == '\n' {
			if index > start {
				lines = append(lines, raw[start:index])
			}
			start = index + 1
		}
	}
	return lines
}
