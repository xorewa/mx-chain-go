package f1t

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

var ErrPreflight = errors.New("F1-T preflight failed")

type BoundFile struct {
	Path   string
	SHA256 string
	Bytes  []byte
}

type CampaignPreflightInput struct {
	TrustedRoot            string
	CampaignIdentityPath   string
	CampaignIdentitySHA256 string
	ProfileCatalogPath     string
	FixtureCatalogPath     string
	OwnerAuthorizationPath string
	ExpectedSourceCommit   string
	CampaignExecution      bool
}

type CampaignPreflight struct {
	Identity          CampaignIdentity
	ContextSHA256     string
	Profiles          []VerifiedProfile
	Constructor       CanonicalSourceConstructor
	Authorization     OwnerAuthorization
	AuthorizationPath string
}

type AttemptClaim struct {
	Schema                string `json:"schema"`
	AttemptID             string `json:"campaign_attempt_id"`
	CampaignContextSHA256 string `json:"campaign_context_sha256"`
	ExecutableSHA256      string `json:"campaign_executable_sha256"`
	AuthorizationSHA256   string `json:"owner_authorization_sha256"`
	Status                string `json:"status"`
	OutputRoot            string `json:"output_root"`
}

const OwnerAuthorizationSchema = "DRWA_S1_F1T_PHASE_II_OWNER_AUTHORIZATION_V1"

type OwnerAuthorization struct {
	Schema                                       string `json:"schema"`
	AttemptID                                    string `json:"campaign_attempt_id"`
	AutomaticRetryAllowed                        bool   `json:"automatic_retry_allowed"`
	FailedOrInvalidAttemptsMustBePreserved       bool   `json:"failed_or_invalid_attempts_must_be_preserved"`
	NewAttemptRequiresNewAuthorizationAndContext bool   `json:"new_attempt_requires_new_owner_authorization_and_new_campaign_context"`
	PriorAttemptMayBeReplacedOrHidden            bool   `json:"prior_attempt_may_be_replaced_cherry_picked_or_hidden"`
	PoolingAcrossAttemptsAllowed                 bool   `json:"pooling_or_selecting_across_attempts_allowed"`
	CampaignExecutionAuthorized                  bool   `json:"campaign_execution_authorized"`
	RuntimeCredit                                int    `json:"authoritative_runtime_credit"`
}

func decodeOwnerAuthorization(raw []byte, campaignExecution bool) (OwnerAuthorization, error) {
	var authorization OwnerAuthorization
	if err := decodeExactPayload(raw, &authorization); err != nil || authorization.Schema != OwnerAuthorizationSchema ||
		authorization.AttemptID == "" || len(authorization.AttemptID) > 128 || strings.ContainsAny(authorization.AttemptID, "/\\\x00") ||
		authorization.AutomaticRetryAllowed || !authorization.FailedOrInvalidAttemptsMustBePreserved ||
		!authorization.NewAttemptRequiresNewAuthorizationAndContext || authorization.PriorAttemptMayBeReplacedOrHidden ||
		authorization.PoolingAcrossAttemptsAllowed || authorization.RuntimeCredit != 0 ||
		authorization.CampaignExecutionAuthorized != campaignExecution {
		return OwnerAuthorization{}, ErrPreflight
	}
	return authorization, nil
}

func DecodeRehearsalAuthorization(raw []byte) (OwnerAuthorization, error) {
	return decodeOwnerAuthorization(raw, false)
}

func DecodeCampaignAuthorization(raw []byte) (OwnerAuthorization, error) {
	return decodeOwnerAuthorization(raw, true)
}

func VerifyCampaignPreflight(input CampaignPreflightInput) (CampaignPreflight, error) {
	identityFile, err := ReadBoundRegularFile(input.TrustedRoot, input.CampaignIdentityPath, input.CampaignIdentitySHA256)
	if err != nil {
		return CampaignPreflight{}, err
	}
	identity, err := DecodeCampaignIdentity(identityFile.Bytes)
	if err != nil {
		return CampaignPreflight{}, err
	}
	profiles, err := LoadAndVerifyProfileCatalog(input.TrustedRoot, input.ProfileCatalogPath, identity.ProfileCatalogSHA256)
	if err != nil {
		return CampaignPreflight{}, err
	}
	constructor, err := LoadAndVerifyFixtureCatalog(input.TrustedRoot, input.FixtureCatalogPath, identity.FixtureCatalogSHA256, input.ExpectedSourceCommit)
	if err != nil {
		return CampaignPreflight{}, err
	}
	ordered := []string{profiles[0].ExternalDigest, profiles[0].SelectorDigest, profiles[1].ExternalDigest, profiles[1].SelectorDigest}
	if len(identity.OrderedProfileDigests) != len(ordered) {
		return CampaignPreflight{}, ErrPreflight
	}
	for index := range ordered {
		if identity.OrderedProfileDigests[index] != ordered[index] {
			return CampaignPreflight{}, ErrPreflight
		}
	}
	_, executableHash, err := ExecutableIdentity(os.Getpid())
	if err != nil || executableHash != identity.CampaignExecutableSHA256 {
		return CampaignPreflight{}, ErrPreflight
	}
	moduleGraph, err := ModuleGraphSHA256()
	if err != nil || moduleGraph != identity.ModuleGraphSHA256 {
		return CampaignPreflight{}, ErrPreflight
	}
	hostFacts, err := HostFactsSHA256(input.TrustedRoot)
	if err != nil || hostFacts != identity.HostKernelCPUStorageFactsSHA256 {
		return CampaignPreflight{}, ErrPreflight
	}
	if PopulationManifestSHA256() != identity.PopulationManifestSHA256 {
		return CampaignPreflight{}, ErrPreflight
	}
	authorizationFile, err := ReadBoundRegularFile(input.TrustedRoot, input.OwnerAuthorizationPath, identity.OwnerAuthorizationSHA256)
	if err != nil {
		return CampaignPreflight{}, err
	}
	authorization, err := decodeOwnerAuthorization(authorizationFile.Bytes, input.CampaignExecution)
	if err != nil {
		return CampaignPreflight{}, err
	}
	contextDigest, err := identity.Digest()
	if err != nil {
		return CampaignPreflight{}, err
	}
	return CampaignPreflight{Identity: identity, ContextSHA256: contextDigest, Profiles: profiles,
		Constructor: constructor, Authorization: authorization, AuthorizationPath: authorizationFile.Path}, nil
}

// ClaimCampaignAttempt consumes one authorization before any child process or
// transport is started. O_EXCL and directory fsync make a crash consume the
// attempt; a later run cannot reinterpret the same authorization as unused.
func ClaimCampaignAttempt(root string, preflight CampaignPreflight) (string, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || !preflight.Authorization.CampaignExecutionAuthorized ||
		preflight.Authorization.AttemptID == "" || !isHexDigest(preflight.ContextSHA256) ||
		!filepath.IsAbs(preflight.AuthorizationPath) || filepath.Clean(preflight.AuthorizationPath) != preflight.AuthorizationPath {
		return "", ErrPreflight
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", ErrPreflight
	}
	claim := AttemptClaim{Schema: "DRWA_S1_F1T_PHASE_II_ATTEMPT_CLAIM_V1", AttemptID: preflight.Authorization.AttemptID,
		CampaignContextSHA256: preflight.ContextSHA256, ExecutableSHA256: preflight.Identity.CampaignExecutableSHA256,
		AuthorizationSHA256: preflight.Identity.OwnerAuthorizationSHA256, Status: "CONSUMED_BEFORE_PROCESS_OR_TRANSPORT_START", OutputRoot: root}
	raw, err := json.Marshal(claim)
	if err != nil {
		return "", err
	}
	raw = append(raw, '\n')
	claimDirectory := filepath.Dir(preflight.AuthorizationPath)
	parentFD, err := unix.Open(claimDirectory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer unix.Close(parentFD)
	name := "." + filepath.Base(preflight.AuthorizationPath) + "." + preflight.Authorization.AttemptID + ".claimed"
	fd, err := unix.Openat(parentFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(fd), filepath.Join(claimDirectory, name))
	written, writeErr := file.Write(raw)
	if writeErr == nil && written != len(raw) {
		writeErr = io.ErrShortWrite
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	dirSyncErr := unix.Fsync(parentFD)
	if err = errors.Join(writeErr, syncErr, closeErr, dirSyncErr); err != nil {
		return "", err
	}
	return filepath.Join(claimDirectory, name), nil
}

func ModuleGraphSHA256() (string, error) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "", ErrPreflight
	}
	rows := make([]string, 0, len(info.Deps)+len(info.Settings)+1)
	rows = append(rows, "main="+info.Main.Path+"@"+info.Main.Version+"#"+info.Main.Sum)
	for _, dependency := range info.Deps {
		row := dependency.Path + "@" + dependency.Version + "#" + dependency.Sum
		if dependency.Replace != nil {
			row += "=>" + dependency.Replace.Path + "@" + dependency.Replace.Version + "#" + dependency.Replace.Sum
		}
		rows = append(rows, row)
	}
	for _, setting := range info.Settings {
		rows = append(rows, "setting="+setting.Key+"="+setting.Value)
	}
	sort.Strings(rows)
	return digestHex([]byte(strings.Join(rows, "\n"))), nil
}

func HostFactsSHA256(trustedRoot string) (string, error) {
	encoded, err := hostFactsCanonicalJSON(trustedRoot)
	if err != nil {
		return "", err
	}
	return digestHex(encoded), nil
}

func hostFactsCanonicalJSON(trustedRoot string) ([]byte, error) {
	var system unix.Utsname
	if err := unix.Uname(&system); err != nil {
		return nil, err
	}
	var storage unix.Statfs_t
	if err := unix.Statfs(trustedRoot, &storage); err != nil {
		return nil, err
	}
	rootInfo, err := os.Stat(trustedRoot)
	if err != nil {
		return nil, err
	}
	var rootStat unix.Stat_t
	if err = unix.Stat(trustedRoot, &rootStat); err != nil {
		return nil, err
	}
	cpuIdentity, err := filteredHostFile("/proc/cpuinfo", []string{"vendor_id", "cpu family", "model", "model name", "stepping", "microcode", "flags", "features"})
	if err != nil {
		return nil, err
	}
	memoryTotal, err := filteredHostFile("/proc/meminfo", []string{"MemTotal"})
	if err != nil {
		return nil, err
	}
	mountInfo, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	clockSource := optionalHostFact("/sys/devices/system/clocksource/clocksource0/current_clocksource")
	loopbackMTU := optionalHostFact("/sys/class/net/lo/mtu")
	loopbackFlags := optionalHostFact("/sys/class/net/lo/flags")
	governors := hostGovernors()
	facts := struct {
		GOOS            string `json:"goos"`
		GOARCH          string `json:"goarch"`
		CPUCount        int    `json:"cpu_count"`
		CPUIdentity     string `json:"cpu_identity_sha256"`
		MemoryTotal     string `json:"memory_total_sha256"`
		Kernel          string `json:"kernel_release"`
		Machine         string `json:"machine"`
		Filesystem      int64  `json:"filesystem_type"`
		FilesystemFlags int64  `json:"filesystem_flags"`
		BlockSize       int64  `json:"block_size"`
		RootMode        uint32 `json:"root_mode"`
		RootDevice      uint64 `json:"root_device"`
		RootInode       uint64 `json:"root_inode"`
		RootRealpath    string `json:"root_realpath"`
		MountInfo       string `json:"mount_info_sha256"`
		ClockSource     string `json:"clock_source"`
		CPUGovernors    string `json:"cpu_governors_sha256"`
		LoopbackMTU     string `json:"loopback_mtu"`
		LoopbackFlags   string `json:"loopback_flags"`
	}{
		GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, CPUCount: runtime.NumCPU(), CPUIdentity: cpuIdentity,
		MemoryTotal: memoryTotal, Kernel: utsnameString(system.Release[:]), Machine: utsnameString(system.Machine[:]),
		Filesystem: int64(storage.Type), FilesystemFlags: int64(storage.Flags), BlockSize: int64(storage.Bsize),
		RootMode: uint32(rootInfo.Mode().Perm()), RootDevice: uint64(rootStat.Dev), RootInode: rootStat.Ino,
		RootRealpath: trustedRoot, MountInfo: digestHex(mountInfo), ClockSource: clockSource, CPUGovernors: governors,
		LoopbackMTU: loopbackMTU, LoopbackFlags: loopbackFlags,
	}
	encoded, err := json.Marshal(facts)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

func filteredHostFile(path string, keys []string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	wanted := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		wanted[strings.ToLower(key)] = struct{}{}
	}
	rows := make([]string, 0)
	for _, line := range strings.Split(string(raw), "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		if _, exists := wanted[key]; exists {
			rows = append(rows, key+"="+strings.Join(strings.Fields(parts[1]), " "))
		}
	}
	if len(rows) == 0 {
		return "", ErrPreflight
	}
	sort.Strings(rows)
	return digestHex([]byte(strings.Join(rows, "\n"))), nil
}

func optionalHostFact(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "UNAVAILABLE"
	}
	return strings.TrimSpace(string(raw))
}

func hostGovernors() string {
	paths, _ := filepath.Glob("/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor")
	rows := make([]string, 0, len(paths))
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return "UNAVAILABLE"
		}
		rows = append(rows, filepath.Base(filepath.Dir(filepath.Dir(path)))+"="+strings.TrimSpace(string(raw)))
	}
	if len(rows) == 0 {
		return "UNAVAILABLE"
	}
	sort.Strings(rows)
	return digestHex([]byte(strings.Join(rows, "\n")))
}

func PopulationManifestSHA256() string {
	manifest := struct {
		Profiles         []Profile  `json:"profiles"`
		Paths            []Path     `json:"paths"`
		Loads            []LoadCell `json:"loads"`
		SamplesPerCell   int        `json:"samples_per_profile_path_load"`
		ActionCount      int        `json:"total_action_indices"`
		ObservationCount int        `json:"total_path_observations"`
		Order            string     `json:"order"`
	}{Profiles(), Paths(), LoadCells(), SamplesPerProfilePathLoad, TotalActionIndices, TotalPathObservations,
		"DETERMINISTIC_ROUND_ROBIN_INDEX_THEN_PROFILE_THEN_LOAD"}
	encoded, _ := json.Marshal(manifest)
	return digestHex(encoded)
}

func utsnameString(value []byte) string {
	result := make([]byte, 0, len(value))
	for _, character := range value {
		if character == 0 {
			break
		}
		result = append(result, character)
	}
	return string(result)
}

func ReadBoundRegularFile(trustedRoot, path, expectedSHA256 string) (BoundFile, error) {
	var result BoundFile
	err := withBoundRegularFile(trustedRoot, path, expectedSHA256, func(_ int, canonicalPath string, raw []byte, digest string) error {
		result = BoundFile{Path: canonicalPath, SHA256: digest, Bytes: append([]byte(nil), raw...)}
		return nil
	})
	return result, err
}

func withBoundRegularFile(
	trustedRoot, path, expectedSHA256 string,
	consume func(fd int, canonicalPath string, raw []byte, digest string) error,
) error {
	if consume == nil || !isHexDigest(expectedSHA256) {
		return ErrPreflight
	}
	root, err := filepath.Abs(trustedRoot)
	if err != nil || root != trustedRoot || filepath.Clean(root) != root {
		return ErrPreflight
	}
	candidate := path
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(root, candidate)
	}
	candidate = filepath.Clean(candidate)
	relative, err := filepath.Rel(root, candidate)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%w: path outside trusted root", ErrPreflight)
	}
	fd, err := openAnchoredRegularFile(root, relative)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), candidate)
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() {
		return fmt.Errorf("%w: non-regular", ErrPreflight)
	}
	raw, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("%w: read: %v", ErrPreflight, err)
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != int64(len(raw)) || after.Size() != int64(len(raw)) {
		return fmt.Errorf("%w: replaced or changed", ErrPreflight)
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	if digest != expectedSHA256 {
		return fmt.Errorf("%w: digest", ErrPreflight)
	}
	snapshotFD, err := sealedSnapshot(raw)
	if err != nil {
		return err
	}
	defer unix.Close(snapshotFD)
	return consume(snapshotFD, candidate, raw, digest)
}

func openAnchoredRegularFile(root, relative string) (int, error) {
	components := strings.Split(relative, string(filepath.Separator))
	if len(components) == 0 {
		return -1, ErrPreflight
	}
	for _, component := range components {
		if component == "" || component == "." || component == ".." {
			return -1, ErrPreflight
		}
	}
	var rootBefore unix.Stat_t
	if err := unix.Stat(root, &rootBefore); err != nil || rootBefore.Mode&unix.S_IFMT != unix.S_IFDIR {
		return -1, fmt.Errorf("%w: trusted root", ErrPreflight)
	}
	currentFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, fmt.Errorf("%w: trusted root open: %v", ErrPreflight, err)
	}
	var rootOpened unix.Stat_t
	var rootAfter unix.Stat_t
	statErr := unix.Fstat(currentFD, &rootOpened)
	pathStatErr := unix.Stat(root, &rootAfter)
	if statErr != nil || pathStatErr != nil || rootBefore.Dev != rootOpened.Dev || rootBefore.Ino != rootOpened.Ino ||
		rootOpened.Dev != rootAfter.Dev || rootOpened.Ino != rootAfter.Ino {
		_ = unix.Close(currentFD)
		return -1, fmt.Errorf("%w: trusted root replaced", ErrPreflight)
	}
	for index, component := range components {
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW
		if index < len(components)-1 {
			flags |= unix.O_DIRECTORY
		}
		nextFD, openErr := unix.Openat(currentFD, component, flags, 0)
		_ = unix.Close(currentFD)
		if openErr != nil {
			return -1, fmt.Errorf("%w: anchored open: %v", ErrPreflight, openErr)
		}
		currentFD = nextFD
	}
	return currentFD, nil
}

func sealedSnapshot(raw []byte) (int, error) {
	fd, err := unix.MemfdCreate("drwa-f1t-bound-input", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return -1, fmt.Errorf("%w: snapshot create: %v", ErrPreflight, err)
	}
	written := 0
	for written < len(raw) {
		count, writeErr := unix.Write(fd, raw[written:])
		if writeErr != nil || count <= 0 {
			_ = unix.Close(fd)
			return -1, fmt.Errorf("%w: snapshot write", ErrPreflight)
		}
		written += count
	}
	if _, err = unix.Seek(fd, 0, io.SeekStart); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("%w: snapshot seek: %v", ErrPreflight, err)
	}
	seals := unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE
	if _, err = unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, seals); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("%w: snapshot seal: %v", ErrPreflight, err)
	}
	return fd, nil
}
