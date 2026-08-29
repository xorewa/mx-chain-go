package f1t

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestActiveLoadCellsProveContinuousProgress(t *testing.T) {
	config := LoadConfig{CPUWorkers: 1, SchedulerWorkers: 2, GCRingEntries: 4, GCEntryBytes: 16, FsyncBlocks: 2, FsyncBlockBytes: 4096}
	for _, cell := range []LoadCell{LoadBaseline, LoadCPU, LoadScheduler, LoadGC, LoadFsync, LoadCombined} {
		t.Run(string(cell), func(t *testing.T) {
			handle, err := StartLoad(context.Background(), cell, t.TempDir(), config)
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			require.NoError(t, handle.ProveLiveness(ctx))
			require.NoError(t, handle.Stop())
		})
	}
}

func TestPersistentLoadRetainsOneWorkerSetAcrossRoundRobinActivations(t *testing.T) {
	config := LoadConfig{CPUWorkers: 1, SchedulerWorkers: 2, GCRingEntries: 4, GCEntryBytes: 16, FsyncBlocks: 2, FsyncBlockBytes: 4096}
	handle, err := StartPersistentLoad(context.Background(), LoadCPU, t.TempDir(), config)
	require.NoError(t, err)
	require.Equal(t, handle.expected, handle.live.Load())
	require.False(t, handle.active)

	for range 2 {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		require.NoError(t, handle.Activate(ctx))
		cancel()
		require.NoError(t, handle.Deactivate())
		quiesced := handle.progress.Load()
		time.Sleep(10 * time.Millisecond)
		require.Equal(t, quiesced, handle.progress.Load())
		require.Equal(t, handle.expected, handle.live.Load())
	}
	require.NoError(t, handle.Stop())
}

func TestPersistentLoadRejectsMissingOriginalWorkerBeforeActivation(t *testing.T) {
	config := LoadConfig{CPUWorkers: 1, SchedulerWorkers: 2, GCRingEntries: 4, GCEntryBytes: 16, FsyncBlocks: 2, FsyncBlockBytes: 4096}
	handle, err := StartPersistentLoad(context.Background(), LoadCPU, t.TempDir(), config)
	require.NoError(t, err)
	handle.live.Add(-1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	require.ErrorContains(t, handle.Activate(ctx), "continuity")
	cancel()
	handle.live.Add(1)
	require.NoError(t, handle.Stop())
}

func TestPersistentCombinedSetupFailureWakesAlreadyStartedWorkers(t *testing.T) {
	config := LoadConfig{CPUWorkers: 1, SchedulerWorkers: 2, GCRingEntries: 4, GCEntryBytes: 16, FsyncBlocks: 2, FsyncBlockBytes: 4096}
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "f1t-fsync-ring.bin"), []byte("collision"), 0o600))
	result := make(chan error, 1)
	go func() {
		_, err := StartPersistentLoad(context.Background(), LoadCombined, root, config)
		result <- err
	}()
	select {
	case err := <-result:
		require.Error(t, err)
	case <-time.After(2 * time.Second):
		require.Fail(t, "persistent Combined setup failure did not wake inactive workers")
	}
}
