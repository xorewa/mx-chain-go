package f1t

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestReadBoundRegularFileRejectsHashSymlinkAndTraversal(t *testing.T) {
	root := t.TempDir()
	raw := []byte("bound-preimage")
	path := filepath.Join(root, "input.json")
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	bound, err := ReadBoundRegularFile(root, path, digest)
	require.NoError(t, err)
	require.Equal(t, raw, bound.Bytes)

	_, err = ReadBoundRegularFile(root, path, strings.Repeat("00", 32))
	require.ErrorIs(t, err, ErrPreflight)

	link := filepath.Join(root, "link.json")
	require.NoError(t, os.Symlink(path, link))
	_, err = ReadBoundRegularFile(root, link, digest)
	require.ErrorIs(t, err, ErrPreflight)

	outside := filepath.Join(filepath.Dir(root), "outside.json")
	require.NoError(t, os.WriteFile(outside, raw, 0o600))
	_, err = ReadBoundRegularFile(root, outside, digest)
	require.ErrorIs(t, err, ErrPreflight)
}

func TestBoundFileHashAndParseUseTheSameOpenDescriptor(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "input.json")
	original := []byte(`{"generation":"original"}`)
	replacement := []byte(`{"generation":"replacement"}`)
	require.NoError(t, os.WriteFile(path, original, 0o600))
	err := withBoundRegularFile(root, path, digestHex(original), func(fd int, canonical string, raw []byte, digest string) error {
		require.Equal(t, original, raw)
		require.Equal(t, digestHex(original), digest)
		require.NoError(t, os.Rename(canonical, canonical+".old"))
		require.NoError(t, os.WriteFile(canonical, replacement, 0o600))
		fromDescriptor, readErr := os.ReadFile("/proc/self/fd/" + strconv.Itoa(fd))
		require.NoError(t, readErr)
		require.Equal(t, original, fromDescriptor)
		return nil
	})
	require.NoError(t, err)
	_, err = ReadBoundRegularFile(root, path, digestHex(original))
	require.ErrorIs(t, err, ErrPreflight)
}

func TestBoundFileRejectsIntermediateSymlinkAndConsumesImmutableSnapshot(t *testing.T) {
	root := t.TempDir()
	realDirectory := filepath.Join(root, "real")
	require.NoError(t, os.Mkdir(realDirectory, 0o700))
	original := []byte(`{"generation":"original"}`)
	path := filepath.Join(realDirectory, "input.json")
	require.NoError(t, os.WriteFile(path, original, 0o600))

	linkDirectory := filepath.Join(root, "linked")
	require.NoError(t, os.Symlink(realDirectory, linkDirectory))
	_, err := ReadBoundRegularFile(root, filepath.Join(linkDirectory, "input.json"), digestHex(original))
	require.ErrorIs(t, err, ErrPreflight)

	err = withBoundRegularFile(root, path, digestHex(original), func(fd int, _ string, raw []byte, _ string) error {
		require.Equal(t, original, raw)
		require.NoError(t, os.WriteFile(path, []byte(`{"generation":"mutated"}`), 0o600))
		fromSnapshot, readErr := os.ReadFile("/proc/self/fd/" + strconv.Itoa(fd))
		require.NoError(t, readErr)
		require.Equal(t, original, fromSnapshot)
		_, writeErr := unix.Pwrite(fd, []byte("x"), 0)
		require.Error(t, writeErr)
		return nil
	})
	require.NoError(t, err)
}

func TestOwnerAuthorizationIsStrictAndBindsNoRetryPolicy(t *testing.T) {
	authorization := OwnerAuthorization{Schema: OwnerAuthorizationSchema, AttemptID: "attempt-1",
		FailedOrInvalidAttemptsMustBePreserved: true, NewAttemptRequiresNewAuthorizationAndContext: true}
	raw, err := json.Marshal(authorization)
	require.NoError(t, err)
	decoded, err := DecodeRehearsalAuthorization(raw)
	require.NoError(t, err)
	require.Equal(t, authorization, decoded)
	_, err = DecodeCampaignAuthorization(raw)
	require.ErrorIs(t, err, ErrPreflight)
	authorization.CampaignExecutionAuthorized = true
	raw, err = json.Marshal(authorization)
	require.NoError(t, err)
	_, err = DecodeCampaignAuthorization(raw)
	require.NoError(t, err)
	_, err = DecodeRehearsalAuthorization(raw)
	require.ErrorIs(t, err, ErrPreflight)
	authorization.CampaignExecutionAuthorized = false

	mutations := []func(*OwnerAuthorization){
		func(value *OwnerAuthorization) { value.AutomaticRetryAllowed = true },
		func(value *OwnerAuthorization) { value.FailedOrInvalidAttemptsMustBePreserved = false },
		func(value *OwnerAuthorization) { value.NewAttemptRequiresNewAuthorizationAndContext = false },
		func(value *OwnerAuthorization) { value.PriorAttemptMayBeReplacedOrHidden = true },
		func(value *OwnerAuthorization) { value.PoolingAcrossAttemptsAllowed = true },
		func(value *OwnerAuthorization) { value.RuntimeCredit = 1 },
		func(value *OwnerAuthorization) { value.AttemptID = "../escape" },
	}
	for _, mutate := range mutations {
		candidate := authorization
		mutate(&candidate)
		encoded, marshalErr := json.Marshal(candidate)
		require.NoError(t, marshalErr)
		_, decodeErr := DecodeRehearsalAuthorization(encoded)
		require.ErrorIs(t, decodeErr, ErrPreflight)
	}
}

func TestCampaignAttemptClaimIsDurableSingleUseAndRootBound(t *testing.T) {
	root := t.TempDir()
	authorizationPath := filepath.Join(t.TempDir(), "authorization.json")
	require.NoError(t, os.WriteFile(authorizationPath, []byte("bound"), 0o600))
	preflight := CampaignPreflight{ContextSHA256: strings.Repeat("ab", 32),
		Identity:      CampaignIdentity{CampaignExecutableSHA256: strings.Repeat("cd", 32), OwnerAuthorizationSHA256: strings.Repeat("ef", 32)},
		Authorization: OwnerAuthorization{AttemptID: "attempt-1", CampaignExecutionAuthorized: true}, AuthorizationPath: authorizationPath}
	claimPath, err := ClaimCampaignAttempt(root, preflight)
	require.NoError(t, err)
	raw, err := os.ReadFile(claimPath)
	require.NoError(t, err)
	var claim AttemptClaim
	require.NoError(t, json.Unmarshal(raw, &claim))
	require.Equal(t, preflight.ContextSHA256, claim.CampaignContextSHA256)
	require.Equal(t, "CONSUMED_BEFORE_PROCESS_OR_TRANSPORT_START", claim.Status)

	_, err = ClaimCampaignAttempt(root, preflight)
	require.Error(t, err, "a crash or retry must not reuse the authorization")
	preflight.Authorization.AttemptID = "attempt-2"
	otherRoot := t.TempDir()
	_, err = ClaimCampaignAttempt(otherRoot, preflight)
	require.NoError(t, err, "a separately named attempt can be authorized explicitly")
	preflight.Authorization.AttemptID = "attempt-1"
	_, err = ClaimCampaignAttempt(otherRoot, preflight)
	require.Error(t, err, "one authorization attempt cannot be replayed from another output root")

	realRoot := t.TempDir()
	symlinkRoot := filepath.Join(t.TempDir(), "linked-root")
	require.NoError(t, os.Symlink(realRoot, symlinkRoot))
	preflight.Authorization.AttemptID = "attempt-3"
	_, err = ClaimCampaignAttempt(symlinkRoot, preflight)
	require.ErrorIs(t, err, ErrPreflight)
}

func TestHostFactsBindPerformanceEnvironmentAndTrustedRootIdentity(t *testing.T) {
	firstRoot := t.TempDir()
	raw, err := hostFactsCanonicalJSON(firstRoot)
	require.NoError(t, err)

	var facts map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &facts))
	require.ElementsMatch(t, []string{
		"goos", "goarch", "cpu_count", "cpu_identity_sha256", "memory_total_sha256",
		"kernel_release", "machine", "filesystem_type", "filesystem_flags", "block_size",
		"root_mode", "root_device", "root_inode", "root_realpath", "mount_info_sha256",
		"clock_source", "cpu_governors_sha256", "loopback_mtu", "loopback_flags",
	}, mapKeys(facts))
	require.Equal(t, firstRoot, facts["root_realpath"])
	for _, field := range []string{"cpu_identity_sha256", "memory_total_sha256", "mount_info_sha256", "cpu_governors_sha256"} {
		value, ok := facts[field].(string)
		require.True(t, ok, field)
		require.Len(t, value, sha256.Size*2, field)
		_, err = hex.DecodeString(value)
		require.NoError(t, err, field)
	}

	firstDigest, err := HostFactsSHA256(firstRoot)
	require.NoError(t, err)
	secondDigest, err := HostFactsSHA256(t.TempDir())
	require.NoError(t, err)
	require.NotEqual(t, firstDigest, secondDigest, "trusted-root identity must affect host-facts binding")
}

func mapKeys(values map[string]interface{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}
