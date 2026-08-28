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
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	file    *os.File
	errMu   sync.Mutex
	err     error
	stop    sync.Once
	stopErr error
}

type ReconnectController interface {
	CloseConnections(context.Context) error
	Reconnect(context.Context) error
	ProveReadiness(context.Context) error
}

func StartLoad(parent context.Context, cell LoadCell, root string, config LoadConfig) (*LoadHandle, error) {
	return StartLoadWithReconnect(parent, cell, root, config, nil)
}

func StartLoadWithReconnect(parent context.Context, cell LoadCell, root string, config LoadConfig, reconnect ReconnectController) (*LoadHandle, error) {
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
	handle := &LoadHandle{cancel: cancel}
	if cell == LoadReconnect {
		if reconnect == nil {
			cancel()
			return nil, errors.New("recent-reconnect controller unavailable")
		}
		if err := reconnect.CloseConnections(ctx); err != nil {
			cancel()
			return nil, err
		}
		if err := reconnect.Reconnect(ctx); err != nil {
			cancel()
			return nil, err
		}
		if err := reconnect.ProveReadiness(ctx); err != nil {
			cancel()
			return nil, err
		}
	}
	startCPU := cell == LoadCPU || cell == LoadCombined
	startScheduler := cell == LoadScheduler || cell == LoadCombined
	startGC := cell == LoadGC || cell == LoadCombined
	startFsync := cell == LoadFsync || cell == LoadCombined
	if startCPU {
		handle.startCPU(ctx, config)
	}
	if startScheduler {
		handle.startScheduler(ctx, config)
	}
	if startGC {
		handle.startGC(ctx, config)
	}
	if startFsync {
		rootFD, err = unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			cancel()
			handle.wg.Wait()
			return nil, err
		}
		fd, err := unix.Openat(rootFD, "f1t-fsync-ring.bin", unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		_ = unix.Close(rootFD)
		if err != nil {
			cancel()
			handle.wg.Wait()
			return nil, err
		}
		file := os.NewFile(uintptr(fd), filepath.Join(root, "f1t-fsync-ring.bin"))
		if err = file.Truncate(int64(config.FsyncBlocks * config.FsyncBlockBytes)); err != nil {
			_ = file.Close()
			cancel()
			handle.wg.Wait()
			return nil, err
		}
		handle.file = file
		handle.wg.Add(1)
		go func() {
			defer handle.wg.Done()
			block := make([]byte, config.FsyncBlockBytes)
			for index := 0; ; index = (index + 1) % config.FsyncBlocks {
				select {
				case <-ctx.Done():
					return
				default:
				}
				written, writeErr := file.WriteAt(block, int64(index*config.FsyncBlockBytes))
				if writeErr != nil || written != len(block) {
					handle.fail(fmt.Errorf("F1-T fsync load write: %w", errors.Join(writeErr, errorIfShort(written, len(block)))))
					return
				}
				if syncErr := unix.Fdatasync(int(file.Fd())); syncErr != nil {
					handle.fail(fmt.Errorf("F1-T fsync load sync: %w", syncErr))
					return
				}
			}
		}()
	}
	return handle, nil
}

func (handle *LoadHandle) Stop() error {
	if handle == nil {
		return nil
	}
	handle.stop.Do(func() {
		handle.cancel()
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
}

func errorIfShort(actual, expected int) error {
	if actual == expected {
		return nil
	}
	return fmt.Errorf("short write: %d of %d", actual, expected)
}

func (handle *LoadHandle) startCPU(ctx context.Context, config LoadConfig) {
	buffer := make([]byte, 64*1024)
	for range config.CPUWorkers {
		handle.wg.Add(1)
		go func() {
			defer handle.wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					_ = sha256.Sum256(buffer)
				}
			}
		}()
	}
}

func (handle *LoadHandle) startScheduler(ctx context.Context, config LoadConfig) {
	for range config.SchedulerWorkers {
		handle.wg.Add(1)
		go func() {
			defer handle.wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					runtime.Gosched()
				}
			}
		}()
	}
}

func (handle *LoadHandle) startGC(ctx context.Context, config LoadConfig) {
	handle.wg.Add(1)
	go func() {
		defer handle.wg.Done()
		ring := make([][]byte, config.GCRingEntries)
		for index := 0; index < len(ring); index += 2 {
			ring[index] = make([]byte, config.GCEntryBytes)
		}
		for index := 0; ; index = (index + 2) % len(ring) {
			select {
			case <-ctx.Done():
				runtime.KeepAlive(ring)
				return
			default:
			}
			entry := make([]byte, config.GCEntryBytes)
			entry[0] = byte(index)
			ring[index] = entry
		}
	}()
}
