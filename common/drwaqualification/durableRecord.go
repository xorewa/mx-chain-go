package drwaqualification

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const RecordSchema = "DRWA_S1_QUALIFICATION_EVENT_V1"

var ErrInvalidLifecycle = errors.New("invalid DRWA S1 qualification lifecycle transition")

type Lifecycle string

const (
	LifecycleCreated  Lifecycle = "created"
	LifecycleLoaded   Lifecycle = "loaded"
	LifecycleReached  Lifecycle = "reached"
	LifecycleConsumed Lifecycle = "consumed"
	LifecycleReleased Lifecycle = "released"
)

var lifecycleOrder = map[Lifecycle]int{
	LifecycleCreated: 1, LifecycleLoaded: 2, LifecycleReached: 3,
	LifecycleConsumed: 4, LifecycleReleased: 5,
}

type Event struct {
	Schema        string         `json:"schema"`
	Sequence      uint64         `json:"sequence"`
	State         Lifecycle      `json:"state"`
	ArmSHA256     string         `json:"arm_sha256"`
	CaseID        string         `json:"case_id"`
	Variant       Variant        `json:"variant"`
	TimestampUnix int64          `json:"timestamp_unix"`
	Details       map[string]any `json:"details"`
}

type Recorder struct {
	mu       sync.Mutex
	file     *os.File
	writer   *bufio.Writer
	armHash  string
	caseID   string
	variant  Variant
	sequence uint64
	state    Lifecycle
}

// CreateRecorder exclusively creates a mode-0600 JSONL record and fsyncs its parent.
func CreateRecorder(path string, armHash [32]byte, arm *Arm) (*Recorder, error) {
	if arm == nil || !filepath.IsAbs(filepath.Clean(path)) || filepath.Clean(path) != path || path != arm.EvidencePath {
		return nil, fmt.Errorf("%w: evidence path", ErrInvalidArm)
	}
	parent := filepath.Dir(path)
	parentFD, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open evidence parent: %w", err)
	}
	defer unix.Close(parentFD)
	fd, err := unix.Openat(parentFD, filepath.Base(path), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, requiredMode)
	if err != nil {
		return nil, fmt.Errorf("create evidence: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if err = unix.Fsync(parentFD); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("fsync evidence parent: %w", err)
	}
	recorder := &Recorder{file: file, writer: bufio.NewWriter(file), armHash: hex.EncodeToString(armHash[:]), caseID: arm.CaseID, variant: arm.Variant}
	if err = recorder.Append(LifecycleCreated, map[string]any{"authoritative_runtime_credit": 0, "production_eligible": false}); err != nil {
		_ = file.Close()
		return nil, err
	}
	return recorder, nil
}

// Append records one strictly monotonic lifecycle transition and fsyncs it before returning.
func (recorder *Recorder) Append(state Lifecycle, details map[string]any) error {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.file == nil || lifecycleOrder[state] != lifecycleOrder[recorder.state]+1 {
		return fmt.Errorf("%w: %s after %s", ErrInvalidLifecycle, state, recorder.state)
	}
	recorder.sequence++
	event := Event{Schema: RecordSchema, Sequence: recorder.sequence, State: state,
		ArmSHA256: recorder.armHash, CaseID: recorder.caseID, Variant: recorder.variant,
		TimestampUnix: time.Now().Unix(), Details: details}
	line, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if _, err = recorder.writer.Write(append(line, '\n')); err != nil {
		return err
	}
	if err = recorder.writer.Flush(); err != nil {
		return err
	}
	if err = recorder.file.Sync(); err != nil {
		return err
	}
	recorder.state = state
	return nil
}

func (recorder *Recorder) Close() error {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.file == nil {
		return nil
	}
	err := recorder.file.Close()
	recorder.file = nil
	return err
}
