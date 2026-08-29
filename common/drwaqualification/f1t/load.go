package f1t

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

type LoadConfig struct {
	CPUWorkers       int
	SchedulerWorkers int
	GCRingEntries    int
	GCEntryBytes     int
	FsyncBlocks      int
	FsyncBlockBytes  int
}

func DefaultLoadConfig() LoadConfig {
	return LoadConfig{
		CPUWorkers: max(1, runtime.NumCPU()-1), SchedulerWorkers: 1024 * runtime.NumCPU(),
		GCRingEntries: 4096, GCEntryBytes: 64 * 1024, FsyncBlocks: 4096, FsyncBlockBytes: 4096,
	}
}

func (config LoadConfig) Validate() error {
	if config.CPUWorkers < 1 || config.SchedulerWorkers < 1 || config.GCRingEntries < 2 || config.GCRingEntries%2 != 0 ||
		config.GCEntryBytes < 1 || config.FsyncBlocks < 1 || config.FsyncBlockBytes != 4096 ||
		config.FsyncBlocks > math.MaxInt/config.FsyncBlockBytes {
		return errors.New("invalid F1-T load configuration")
	}
	return nil
}

type LoadHandle struct {
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	file          *os.File
	errMu         sync.Mutex
	err           error
	stop          sync.Once
	stopErr       error
	cell          LoadCell
	activeWorkers bool
	progress      atomic.Uint64
	context       context.Context
	gateMu        sync.Mutex
	gateCond      *sync.Cond
	active        bool
	inFlight      int
	expected      int64
	live          atomic.Int64
}

func StartLoad(parent context.Context, cell LoadCell, root string, config LoadConfig) (*LoadHandle, error) {
	return startLoad(parent, cell, root, config, true)
}

// StartPersistentLoad creates one load worker set for a complete
// measurement cell. Activate and Deactivate select the cell for each
// round-robin observation without replacing its workers between samples.
func StartPersistentLoad(
	parent context.Context,
	cell LoadCell,
	root string,
	config LoadConfig,
) (*LoadHandle, error) {
	return startLoad(parent, cell, root, config, false)
}

func startLoad(
	parent context.Context,
	cell LoadCell,
	root string,
	config LoadConfig,
	initiallyActive bool,
) (*LoadHandle, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if !knownLoad(cell) || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("invalid F1-T load cell or root")
	}
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	if err = unix.Close(rootFD); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	handle := &LoadHandle{cancel: cancel, cell: cell, context: ctx, active: initiallyActive}
	handle.gateCond = sync.NewCond(&handle.gateMu)
	if cell == LoadBaseline && initiallyActive {
		handle.progress.Store(1)
	}
	startCPU := cell == LoadCPU || cell == LoadCombined
	startScheduler := cell == LoadScheduler || cell == LoadCombined
	startGC := cell == LoadGC || cell == LoadCombined
	startFsync := cell == LoadFsync || cell == LoadCombined
	handle.activeWorkers = startCPU || startScheduler || startGC || startFsync
	if startCPU {
		handle.startCPU(config)
	}
	if startScheduler {
		handle.startScheduler(config)
	}
	if startGC {
		handle.startGC(config)
	}
	if startFsync {
		rootFD, err = unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			handle.cancelAndWait()
			return nil, err
		}
		fd, err := unix.Openat(rootFD, "f1t-fsync-ring.bin", unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		_ = unix.Close(rootFD)
		if err != nil {
			handle.cancelAndWait()
			return nil, err
		}
		file := os.NewFile(uintptr(fd), filepath.Join(root, "f1t-fsync-ring.bin"))
		if err = file.Truncate(int64(config.FsyncBlocks * config.FsyncBlockBytes)); err != nil {
			_ = file.Close()
			handle.cancelAndWait()
			return nil, err
		}
		handle.file = file
		handle.addWorker()
		go func() {
			defer handle.workerDone()
			block := make([]byte, config.FsyncBlockBytes)
			for index := 0; ; index = (index + 1) % config.FsyncBlocks {
				if !handle.beginIteration() {
					return
				}
				written, writeErr := file.WriteAt(block, int64(index*config.FsyncBlockBytes))
				if writeErr != nil || written != len(block) {
					handle.endIteration()
					handle.fail(fmt.Errorf("F1-T fsync load write: %w", errors.Join(writeErr, errorIfShort(written, len(block)))))
					return
				}
				if syncErr := unix.Fdatasync(int(file.Fd())); syncErr != nil {
					handle.endIteration()
					handle.fail(fmt.Errorf("F1-T fsync load sync: %w", syncErr))
					return
				}
				handle.progress.Add(1)
				handle.endIteration()
			}
		}()
	}
	return handle, nil
}

// Activate enables exactly this persistent cell and proves that its original
// worker set is still present and making progress.
func (handle *LoadHandle) Activate(ctx context.Context) error {
	if handle == nil || ctx == nil {
		return errors.New("invalid F1-T load activation request")
	}
	handle.gateMu.Lock()
	if handle.active || handle.context.Err() != nil || handle.live.Load() != handle.expected {
		handle.gateMu.Unlock()
		return errors.New("F1-T load worker continuity failure")
	}
	handle.gateMu.Unlock()

	handle.gateMu.Lock()
	if handle.context.Err() != nil || handle.live.Load() != handle.expected {
		handle.gateMu.Unlock()
		return errors.New("F1-T load worker continuity failure")
	}
	handle.active = true
	if !handle.activeWorkers {
		handle.progress.Add(1)
	}
	handle.gateCond.Broadcast()
	handle.gateMu.Unlock()

	if err := handle.ProveLiveness(ctx); err != nil {
		return fmt.Errorf("F1-T prove load liveness: %w", err)
	}

	return nil
}

// Deactivate quiesces the selected load before another round-robin cell is
// enabled while retaining the same worker goroutines for the next cycle.
func (handle *LoadHandle) Deactivate() error {
	if handle == nil {
		return errors.New("invalid F1-T load deactivation request")
	}
	handle.gateMu.Lock()
	if !handle.active {
		handle.gateMu.Unlock()
		return errors.New("F1-T load cell is not active")
	}
	handle.active = false
	for handle.inFlight != 0 && handle.context.Err() == nil {
		handle.gateCond.Wait()
	}
	continuous := handle.context.Err() == nil && handle.live.Load() == handle.expected
	handle.gateMu.Unlock()
	if !continuous {
		return errors.New("F1-T load worker continuity failure")
	}
	handle.errMu.Lock()
	workerErr := handle.err
	handle.errMu.Unlock()
	return workerErr
}

func (handle *LoadHandle) ProveLiveness(ctx context.Context) error {
	if handle == nil || ctx == nil {
		return errors.New("invalid F1-T load liveness request")
	}
	handle.errMu.Lock()
	workerErr := handle.err
	handle.errMu.Unlock()
	if workerErr != nil {
		return errors.Join(errors.New("F1-T load not ready"), workerErr)
	}
	handle.gateMu.Lock()
	active := handle.active
	handle.gateMu.Unlock()
	if !active || handle.live.Load() != handle.expected {
		return errors.New("F1-T load worker continuity failure")
	}
	if !handle.activeWorkers {
		if handle.progress.Load() == 0 {
			return errors.New("F1-T load not ready")
		}
		return nil
	}
	before := handle.progress.Load()
	for {
		if handle.progress.Load() > before {
			return nil
		}
		handle.errMu.Lock()
		workerErr = handle.err
		handle.errMu.Unlock()
		if workerErr != nil {
			return workerErr
		}
		select {
		case <-ctx.Done():
			return errors.Join(errors.New("F1-T load liveness timeout"), ctx.Err())
		default:
			runtime.Gosched()
		}
	}
}

func (handle *LoadHandle) Stop() error {
	if handle == nil {
		return nil
	}
	handle.stop.Do(func() {
		handle.cancel()
		handle.gateMu.Lock()
		handle.active = false
		handle.gateCond.Broadcast()
		handle.gateMu.Unlock()
		handle.wg.Wait()
		handle.errMu.Lock()
		workerErr := handle.err
		handle.errMu.Unlock()
		if handle.file != nil {
			handle.stopErr = errors.Join(workerErr, handle.file.Sync(), handle.file.Close())
			return
		}
		handle.stopErr = workerErr
	})
	return handle.stopErr
}

func (handle *LoadHandle) fail(err error) {
	handle.errMu.Lock()
	if handle.err == nil {
		handle.err = err
	}
	handle.errMu.Unlock()
	handle.cancel()
	handle.gateMu.Lock()
	handle.gateCond.Broadcast()
	handle.gateMu.Unlock()
}

func (handle *LoadHandle) cancelAndWait() {
	handle.cancel()
	handle.gateMu.Lock()
	handle.gateCond.Broadcast()
	handle.gateMu.Unlock()
	handle.wg.Wait()
}

func (handle *LoadHandle) addWorker() {
	handle.expected++
	handle.live.Add(1)
	handle.wg.Add(1)
}

func (handle *LoadHandle) workerDone() {
	handle.live.Add(-1)
	handle.wg.Done()
	handle.gateMu.Lock()
	handle.gateCond.Broadcast()
	handle.gateMu.Unlock()
}

func (handle *LoadHandle) beginIteration() bool {
	handle.gateMu.Lock()
	defer handle.gateMu.Unlock()
	for !handle.active && handle.context.Err() == nil {
		handle.gateCond.Wait()
	}
	if handle.context.Err() != nil {
		return false
	}
	handle.inFlight++
	return true
}

func (handle *LoadHandle) endIteration() {
	handle.gateMu.Lock()
	handle.inFlight--
	handle.gateCond.Broadcast()
	handle.gateMu.Unlock()
}

func errorIfShort(actual, expected int) error {
	if actual == expected {
		return nil
	}
	return fmt.Errorf("short write: %d of %d", actual, expected)
}

func (handle *LoadHandle) startCPU(config LoadConfig) {
	buffer := make([]byte, 64*1024)
	for range config.CPUWorkers {
		handle.addWorker()
		go func() {
			defer handle.workerDone()
			for {
				if !handle.beginIteration() {
					return
				}
				_ = sha256.Sum256(buffer)
				handle.progress.Add(1)
				handle.endIteration()
			}
		}()
	}
}

func (handle *LoadHandle) startScheduler(config LoadConfig) {
	for range config.SchedulerWorkers {
		handle.addWorker()
		go func() {
			defer handle.workerDone()
			for {
				if !handle.beginIteration() {
					return
				}
				runtime.Gosched()
				handle.progress.Add(1)
				handle.endIteration()
			}
		}()
	}
}

func (handle *LoadHandle) startGC(config LoadConfig) {
	handle.addWorker()
	go func() {
		defer handle.workerDone()
		ring := make([][]byte, config.GCRingEntries)
		for index := 0; index < len(ring); index += 2 {
			ring[index] = make([]byte, config.GCEntryBytes)
		}
		for index := 0; ; index = (index + 2) % len(ring) {
			if !handle.beginIteration() {
				runtime.KeepAlive(ring)
				return
			}
			entry := make([]byte, config.GCEntryBytes)
			entry[0] = byte(index)
			ring[index] = entry
			handle.progress.Add(1)
			handle.endIteration()
		}
	}()
}
