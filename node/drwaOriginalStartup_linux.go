package node

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/process/drwa"
	storageFactory "github.com/multiversx/mx-chain-go/storage/factory"
)

const originalReleaseDirectory = "/opt/original-generation-release"

// Canonical host-only handoff record, never a protocol or genesis encoding.
// The host publishes fields in this declared order with two-space indentation
// and a terminal LF. Equality to the re-encoding rejects duplicate/aliased keys.
type originalRoleGrant struct {
	BackingPath string              `json:"backing_path"`
	BackingMount uint64             `json:"backing_mount_id"`
	ChainID string                  `json:"chain_id"`
	DeploymentIdentity string       `json:"deployment_identity_sha256"`
	Device uint64                   `json:"device"`
	Inode uint64                    `json:"inode"`
	ReleaseMount uint64             `json:"release_mount_id"`
	Role string                     `json:"role"`
	Subject originalProcessIdentity `json:"subject"`
	StartupRecord string            `json:"startup_record_sha256"`
}

type originalProcessIdentity struct {
	GID int          `json:"gid"`
	MountNS string   `json:"mountns"`
	NetNS string     `json:"netns"`
	PID int          `json:"pid"`
	PIDNS string     `json:"pidns"`
	StartTicks uint64 `json:"start_ticks"`
	UID int          `json:"uid"`
	UserNS string    `json:"userns"`
}

func statOriginalMount(fd int, directory bool) (originalMount, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return originalMount{}, err
	}
	if directory && st.Mode&unix.S_IFMT != unix.S_IFDIR ||
		uint32(st.Uid) != uint32(os.Geteuid()) || uint32(st.Gid) != uint32(os.Getegid()) {
		return originalMount{}, drwa.ErrDeploymentIdentity
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return originalMount{}, err
	}
	var sx unix.Statx_t
	err := unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &sx)
	if err != nil || sx.Mask&unix.STATX_MNT_ID == 0 {
		return originalMount{}, drwa.ErrDeploymentIdentity
	}
	return originalMount{uint64(st.Dev), uint64(st.Ino), sx.Mnt_id, fs.Flags&unix.ST_RDONLY != 0}, nil
}

func readOriginalDirectory(path string) (originalMount, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return originalMount{}, err
	}
	defer unix.Close(fd)
	return statOriginalMount(fd, true)
}

func originalSubject() (originalProcessIdentity, error) {
	raw, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return originalProcessIdentity{}, err
	}
	end := bytes.LastIndexByte(raw, ')')
	if end < 0 {
		return originalProcessIdentity{}, drwa.ErrDeploymentIdentity
	}
	fields := bytes.Fields(raw[end+1:])
	if len(fields) <= 19 {
		return originalProcessIdentity{}, drwa.ErrDeploymentIdentity
	}
	ticks, err := strconv.ParseUint(string(fields[19]), 10, 64)
	if err != nil || ticks == 0 {
		return originalProcessIdentity{}, drwa.ErrDeploymentIdentity
	}
	out := originalProcessIdentity{PID: os.Getpid(), StartTicks: ticks, UID: os.Geteuid(), GID: os.Getegid()}
	for _, ns := range []struct{name string; dest *string}{
		{"pid", &out.PIDNS}, {"mnt", &out.MountNS}, {"user", &out.UserNS}, {"net", &out.NetNS},
	} {
		*ns.dest, err = os.Readlink("/proc/self/ns/" + ns.name)
		if err != nil {
			return originalProcessIdentity{}, err
		}
	}
	return out, nil
}

func readOriginalRoleGrant(releaseFD int, name string, expectedMount uint64, maxBytes int64) (originalRoleGrant, error) {
	fd, err := unix.Openat(releaseFD, name+".json", unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return originalRoleGrant{}, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var info unix.Stat_t
	if err = unix.Fstat(fd, &info); err != nil || info.Mode&unix.S_IFMT != unix.S_IFREG ||
		info.Nlink < 1 || info.Nlink > 2 || info.Size <= 0 || info.Size > maxBytes {
		return originalRoleGrant{}, drwa.ErrDeploymentIdentity
	}
	mount, err := statOriginalMount(fd, false)
	if err != nil || !mount.readonly || mount.mount != expectedMount {
		return originalRoleGrant{}, drwa.ErrDeploymentIdentity
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil || int64(len(raw)) != info.Size {
		return originalRoleGrant{}, drwa.ErrDeploymentIdentity
	}
	var grant originalRoleGrant
	if err = json.Unmarshal(raw, &grant); err != nil {
		return originalRoleGrant{}, drwa.ErrDeploymentIdentity
	}
	canonical, err := json.MarshalIndent(grant, "", "  ")
	if err != nil || !bytes.Equal(raw, append(canonical, '\n')) {
		return originalRoleGrant{}, drwa.ErrDeploymentIdentity
	}
	return grant, nil
}

// Decide from the completed read, so a matching grant cannot win at or
// after the deadline. Only a missing grant read before expiry can retry.
func originalGrantReadDecision(completedAt, deadline time.Time, matched bool, err error) (accept, retry bool) {
	if !completedAt.Before(deadline) {
		return false, false
	}
	if err == nil {
		return matched, false
	}
	return false, errors.Is(err, unix.ENOENT)
}

func acquireDRWAOriginal(cfgs *config.Configs) (*acquiredDRWAOriginal, error) {
	if cfgs.FlagsConfig == nil || cfgs.GeneralConfig == nil || cfgs.ImportDbConfig == nil ||
		cfgs.FlagsConfig.CleanupStorage || cfgs.FlagsConfig.ForceStartFromNetwork || cfgs.FlagsConfig.EnableGops ||
		cfgs.ImportDbConfig.IsImportDBMode || cfgs.GeneralConfig.Hardfork.AfterHardFork ||
		cfgs.GeneralConfig.HardforkRecoveryCheckpoint.Enabled {
		return nil, drwa.ErrDeploymentIdentity
	}
	startup := cfgs.DRWAInitialProgrammeStartup
	flags := cfgs.FlagsConfig
	identity := cfgs.GeneralConfig.GeneralSettings.DRWADeploymentIdentity
	if identity == nil || startup.RecordDigest == [32]byte{} || startup.ReleaseWait <= 0 ||
		startup.ReleaseMaxBytes <= 0 || startup.ReleaseMaxBytes == int64(^uint64(0)>>1) ||
		!filepath.IsAbs(flags.WorkingDir) || filepath.Clean(flags.WorkingDir) != flags.WorkingDir ||
		flags.DbDir != flags.WorkingDir {
		return nil, drwa.ErrDeploymentIdentity
	}
	chain := cfgs.GeneralConfig.GeneralSettings.ChainID
	role := filepath.Base(flags.WorkingDir)
	prefixOK := strings.HasPrefix(role, "validator") || strings.HasPrefix(role, "observer")
	if !prefixOK {
		return nil, drwa.ErrDeploymentIdentity
	}
	pathManager, err := storageFactory.CreatePathManager(storageFactory.ArgCreatePathManager{
		WorkingDir: flags.DbDir, ChainID: chain,
	})
	if err != nil {
		return nil, err
	}
	path := pathManager.DatabasePath()
	if path != startup.OriginalDatabasePath || filepath.Dir(filepath.Dir(path)) != flags.WorkingDir {
		return nil, drwa.ErrDeploymentIdentity
	}
	working, err := readOriginalDirectory(flags.WorkingDir)
	if err != nil || !working.readonly {
		return nil, drwa.ErrDeploymentIdentity
	}
	parent, err := readOriginalDirectory(filepath.Dir(path))
	if err != nil || !parent.readonly || parent.mount != working.mount {
		return nil, drwa.ErrDeploymentIdentity
	}
	store, err := readOriginalDirectory(path)
	if err != nil || store.readonly || store.mount == parent.mount {
		return nil, drwa.ErrDeploymentIdentity
	}
	if entries, err := os.ReadDir(path); err != nil || len(entries) != 0 {
		return nil, drwa.ErrDeploymentIdentity
	}
	releaseFD, err := unix.Open(originalReleaseDirectory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, drwa.ErrDeploymentIdentity
	}
	defer unix.Close(releaseFD)
	release, err := statOriginalMount(releaseFD, true)
	if err != nil || !release.readonly || release.mount == parent.mount {
		return nil, drwa.ErrDeploymentIdentity
	}
	subject, err := originalSubject()
	if err != nil {
		return nil, err
	}
	expected := originalRoleGrant{
		BackingPath: path, BackingMount: store.mount, ChainID: chain,
		DeploymentIdentity: identity.SHA256, Device: store.device, Inode: store.inode,
		ReleaseMount: release.mount, Role: role, Subject: subject,
		StartupRecord: hex.EncodeToString(startup.RecordDigest[:]),
	}
	deadline := time.Now().Add(startup.ReleaseWait)
	for {
		if !time.Now().Before(deadline) {
			return nil, drwa.ErrDeploymentIdentity
		}
		actual, err := readOriginalRoleGrant(releaseFD, role, release.mount, startup.ReleaseMaxBytes)
		accept, retry := originalGrantReadDecision(time.Now(), deadline, actual == expected, err)
		if accept {
			break
		}
		if !retry {
			return nil, drwa.ErrDeploymentIdentity
		}
		pause := min(time.Until(deadline), time.Millisecond*20)
		if pause <= 0 {
			return nil, drwa.ErrDeploymentIdentity
		}
		time.Sleep(pause)
	}
	if !drwaOriginalProcessAcquired.CompareAndSwap(false, true) {
		return nil, drwa.ErrDeploymentIdentity
	}
	return &acquiredDRWAOriginal{path: path, store: store}, nil
}

func recheckOriginalStore(acquired *acquiredDRWAOriginal) error {
	actual, err := readOriginalDirectory(acquired.path)
	if err != nil || actual != acquired.store {
		return drwa.ErrDeploymentIdentity
	}
	if entries, err := os.ReadDir(acquired.path); err != nil || len(entries) != 0 {
		return drwa.ErrDeploymentIdentity
	}
	return nil
}
