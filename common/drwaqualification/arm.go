package drwaqualification

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	ArmSchema          = "DRWA_S1_QUALIFICATION_ARM_V1"
	ArmPathEnvironment = "DRWA_S1_QUAL_ARM_PATH"
	maxArmBytes        = 64 * 1024
	requiredMode       = 0o600
	hexHashLength      = 64
	maxValiditySeconds = 600
)

var (
	// ErrArmUnavailable denotes an intentionally disarmed tagged binary.
	ErrArmUnavailable = errors.New("DRWA S1 qualification arm unavailable")
	// ErrInvalidArm denotes a malformed, stale, mismatched, or unsafe arm.
	ErrInvalidArm = errors.New("invalid DRWA S1 qualification arm")
)

// Arm is an exact, one-mutation, non-production qualification authorization.
type Arm struct {
	Schema                     string           `json:"schema"`
	Variant                    Variant          `json:"variant"`
	GenerationBindingSHA256    string           `json:"generation_binding_sha256"`
	NetworkDomain              string           `json:"network_domain"`
	CaseID                     string           `json:"case_id"`
	OriginalTransactionHash    string           `json:"original_transaction_hash"`
	EffectID                   string           `json:"effect_id"`
	ContextHash                string           `json:"context_hash"`
	ProtocolMessageKind        uint32           `json:"protocol_message_kind"`
	CarrierHash                string           `json:"carrier_hash"`
	MiniblockHash              string           `json:"miniblock_hash"`
	VariantBinarySHA256        string           `json:"variant_binary_sha256"`
	EvidencePath               string           `json:"evidence_path"`
	CreatedUnix                int64            `json:"created_unix"`
	ExpiresUnix                int64            `json:"expires_unix"`
	DeclaredMutation           DeclaredMutation `json:"declared_mutation"`
	Transport                  *TransportArm    `json:"transport,omitempty"`
	Barrier                    *BarrierArm      `json:"barrier,omitempty"`
	Replacement                *ReplacementArm  `json:"replacement,omitempty"`
	PostAuth                   *PostAuthArm     `json:"post_auth,omitempty"`
	AuthoritativeRuntimeCredit int              `json:"authoritative_runtime_credit"`
	ProductionEligible         bool             `json:"production_eligible"`
}

type DeclaredMutation struct {
	Kind        string `json:"kind"`
	ValueHex    string `json:"value_hex"`
	ValueSHA256 string `json:"value_sha256"`
}

type TransportArm struct {
	BaseTopic                      string `json:"base_topic"`
	SourceShard                    uint32 `json:"source_shard"`
	ReceivingShard                 uint32 `json:"receiving_shard"`
	CanonicalMembershipProofSHA256 string `json:"canonical_membership_proof_sha256"`
	DeclaredDeliveryAction         string `json:"declared_delivery_action"`
	RawDeliverySHA256              string `json:"raw_delivery_sha256"`
	MaxMatchedDeliveries           uint32 `json:"max_matched_deliveries"`
	ReleasePath                    string `json:"release_path"`
	ReleaseRecordSHA256            string `json:"release_record_sha256"`
}

type BarrierArm struct {
	DestinationExecutionIdentity  string `json:"destination_execution_identity"`
	DestinationValidatorSetSHA256 string `json:"destination_validator_set_sha256"`
	HoldGeneration                uint32 `json:"hold_generation"`
	ReleaseRecordSHA256           string `json:"release_record_sha256"`
	ReleasePath                   string `json:"release_path"`
}

type ReplacementArm struct {
	RetainedHeaderHash            string `json:"retained_header_hash"`
	RetainedHeaderMarshaledSHA256 string `json:"retained_header_marshaled_sha256"`
	RetainedBodyMarshaledSHA256   string `json:"retained_body_marshaled_sha256"`
	TriggerHeaderHash             string `json:"trigger_header_hash"`
	TriggerHeaderMarshaledSHA256  string `json:"trigger_header_marshaled_sha256"`
	TriggerBodyMarshaledSHA256    string `json:"trigger_body_marshaled_sha256"`
}

type PostAuthArm struct {
	CompletionFunction                string `json:"completion_function"`
	CanonicalPayloadSHA256            string `json:"canonical_payload_sha256"`
	DeclaredMutationKind              string `json:"declared_mutation_kind"`
	DeclaredMutationValueSHA256       string `json:"declared_mutation_value_sha256"`
	OriginalCarrierPreservationSHA256 string `json:"original_carrier_preservation_sha256"`
}

// LoadArm reads and validates a synchronously available exact arm. An empty path means disarmed.
func LoadArm(path string, expected Variant, now time.Time) (*Arm, [32]byte, error) {
	if path == "" {
		return nil, [32]byte{}, ErrArmUnavailable
	}
	if runtime.GOOS != "linux" {
		return nil, [32]byte{}, fmt.Errorf("%w: O_NOFOLLOW contract requires linux", ErrInvalidArm)
	}
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || clean != path {
		return nil, [32]byte{}, fmt.Errorf("%w: arm path must be canonical absolute", ErrInvalidArm)
	}
	fd, err := unix.Open(clean, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("%w: open: %v", ErrInvalidArm, err)
	}
	file := os.NewFile(uintptr(fd), clean)
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != requiredMode {
		return nil, [32]byte{}, fmt.Errorf("%w: regular mode-0600 file required", ErrInvalidArm)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return nil, [32]byte{}, fmt.Errorf("%w: arm owner differs from process euid", ErrInvalidArm)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxArmBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxArmBytes {
		return nil, [32]byte{}, fmt.Errorf("%w: unreadable or oversized", ErrInvalidArm)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var arm Arm
	if err = decoder.Decode(&arm); err != nil {
		return nil, [32]byte{}, fmt.Errorf("%w: decode: %v", ErrInvalidArm, err)
	}
	if err = ensureJSONEOF(decoder); err != nil {
		return nil, [32]byte{}, err
	}
	if err = arm.Validate(expected, now); err != nil {
		return nil, [32]byte{}, err
	}
	return &arm, sha256.Sum256(raw), nil
}

// LoadArmFromEnvironment uses the environment only to locate the durable arm. The environment
// is never itself authorization: all authority and selectors are validated from the arm bytes.
func LoadArmFromEnvironment(expected Variant, now time.Time) (*Arm, [32]byte, error) {
	return LoadArm(os.Getenv(ArmPathEnvironment), expected, now)
}

// VerifyRunningBinary binds a tagged process to the exact binary named by its arm.
func VerifyRunningBinary(arm *Arm) error {
	if arm == nil {
		return fmt.Errorf("%w: nil arm", ErrInvalidArm)
	}
	raw, err := readRunningExecutable()
	if err != nil {
		return fmt.Errorf("%w: running binary: %v", ErrInvalidArm, err)
	}
	observed := sha256.Sum256(raw)
	if hex.EncodeToString(observed[:]) != arm.VariantBinarySHA256 {
		return fmt.Errorf("%w: running binary identity mismatch", ErrInvalidArm)
	}
	return nil
}

// /proc/self/exe is a kernel magic link to the already executing inode. O_NOFOLLOW would reject
// that kernel interface itself, so this one read intentionally follows only this fixed procfs path.
func readRunningExecutable() ([]byte, error) {
	fd, err := unix.Open("/proc/self/exe", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "/proc/self/exe")
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("running executable is not regular")
	}
	return io.ReadAll(file)
}

// VerifyExactFile verifies a regular, non-symlink file against an arm-bound SHA-256.
func VerifyExactFile(path, expectedSHA256 string) error {
	if !isHexHash(expectedSHA256) {
		return fmt.Errorf("%w: expected file identity", ErrInvalidArm)
	}
	raw, err := readExactRegular(path, true)
	if err != nil {
		return fmt.Errorf("%w: exact file: %v", ErrInvalidArm, err)
	}
	observed := sha256.Sum256(raw)
	if hex.EncodeToString(observed[:]) != expectedSHA256 {
		return fmt.Errorf("%w: exact file identity mismatch", ErrInvalidArm)
	}
	return nil
}

func readExactRegular(path string, enforceOwnerMode bool) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if enforceOwnerMode {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm() != requiredMode {
			return nil, errors.New("owner or mode mismatch")
		}
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxArmBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > maxArmBytes {
		return nil, errors.New("empty or oversized file")
	}
	return raw, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing JSON", ErrInvalidArm)
	}
	return nil
}

// Validate enforces exact identity, expiry, variant, and one-mutation semantics.
func (arm *Arm) Validate(expected Variant, now time.Time) error {
	if arm == nil || arm.Schema != ArmSchema || arm.Variant != expected || !validVariant(expected) ||
		arm.AuthoritativeRuntimeCredit != 0 || arm.ProductionEligible || arm.ProtocolMessageKind == 0 {
		return fmt.Errorf("%w: schema, variant, credit, eligibility, or kind", ErrInvalidArm)
	}
	if arm.CreatedUnix <= 0 || arm.ExpiresUnix <= arm.CreatedUnix || arm.ExpiresUnix-arm.CreatedUnix > maxValiditySeconds ||
		now.Unix() < arm.CreatedUnix || now.Unix() >= arm.ExpiresUnix {
		return fmt.Errorf("%w: arm not in validity window", ErrInvalidArm)
	}
	if strings.TrimSpace(arm.CaseID) == "" || !filepath.IsAbs(filepath.Clean(arm.EvidencePath)) || filepath.Clean(arm.EvidencePath) != arm.EvidencePath {
		return fmt.Errorf("%w: case or evidence path", ErrInvalidArm)
	}
	for label, value := range map[string]string{
		"generation": arm.GenerationBindingSHA256, "domain": arm.NetworkDomain,
		"original": arm.OriginalTransactionHash, "effect": arm.EffectID,
		"context": arm.ContextHash, "carrier": arm.CarrierHash,
		"miniblock": arm.MiniblockHash, "binary": arm.VariantBinarySHA256,
		"mutation": arm.DeclaredMutation.ValueSHA256,
	} {
		if !isHexHash(value) {
			return fmt.Errorf("%w: %s identity", ErrInvalidArm, label)
		}
	}
	if strings.TrimSpace(arm.DeclaredMutation.Kind) == "" {
		return fmt.Errorf("%w: one declared mutation required", ErrInvalidArm)
	}
	mutationValue, err := hex.DecodeString(arm.DeclaredMutation.ValueHex)
	if err != nil || len(mutationValue) == 0 || len(mutationValue) > maxArmBytes {
		return fmt.Errorf("%w: declared mutation value", ErrInvalidArm)
	}
	mutationHash := sha256.Sum256(mutationValue)
	if hex.EncodeToString(mutationHash[:]) != arm.DeclaredMutation.ValueSHA256 {
		return fmt.Errorf("%w: declared mutation value hash", ErrInvalidArm)
	}
	if err := arm.validateVariantFields(); err != nil {
		return err
	}
	return nil
}

func (arm *Arm) validateVariantFields() error {
	present := 0
	if arm.Transport != nil {
		present++
	}
	if arm.Barrier != nil {
		present++
	}
	if arm.Replacement != nil {
		present++
	}
	if arm.PostAuth != nil {
		present++
	}
	if present != 1 {
		return fmt.Errorf("%w: exactly one variant payload required", ErrInvalidArm)
	}
	switch arm.Variant {
	case VariantTransport:
		value := arm.Transport
		if value == nil || value.BaseTopic == "" || value.SourceShard == value.ReceivingShard ||
			!isHexHash(value.CanonicalMembershipProofSHA256) || !isHexHash(value.RawDeliverySHA256) ||
			!isHexHash(value.ReleaseRecordSHA256) || value.MaxMatchedDeliveries != 1 ||
			!validTransportAction(value.DeclaredDeliveryAction) || value.DeclaredDeliveryAction != arm.DeclaredMutation.Kind ||
			!filepath.IsAbs(filepath.Clean(value.ReleasePath)) ||
			filepath.Clean(value.ReleasePath) != value.ReleasePath ||
			!DeclaredActionTagMatches(arm, value.DeclaredDeliveryAction) {
			return fmt.Errorf("%w: transport payload", ErrInvalidArm)
		}
	case VariantBarrier:
		value := arm.Barrier
		if value == nil || !isHexHash(value.DestinationExecutionIdentity) ||
			value.DestinationExecutionIdentity != arm.CarrierHash ||
			!isHexHash(value.DestinationValidatorSetSHA256) || value.HoldGeneration == 0 ||
			!isHexHash(value.ReleaseRecordSHA256) || !filepath.IsAbs(filepath.Clean(value.ReleasePath)) ||
			filepath.Clean(value.ReleasePath) != value.ReleasePath ||
			!DeclaredActionTagMatches(arm, "HOLD_POST_DELEGATE_PRE_VMOUTPUT_RETURN_UNTIL_EXACT_RELEASE") {
			return fmt.Errorf("%w: barrier payload", ErrInvalidArm)
		}
	case VariantReplacement:
		value := arm.Replacement
		if value == nil || !allHexHashes(value.RetainedHeaderHash, value.RetainedHeaderMarshaledSHA256,
			value.RetainedBodyMarshaledSHA256, value.TriggerHeaderHash,
			value.TriggerHeaderMarshaledSHA256, value.TriggerBodyMarshaledSHA256) ||
			value.RetainedHeaderHash == value.TriggerHeaderHash ||
			!DeclaredActionTagMatches(arm, "REPLAY_RETAINED_PAIR_ON_TRIGGER_ONCE") {
			return fmt.Errorf("%w: replacement payload", ErrInvalidArm)
		}
	case VariantPostAuth:
		value := arm.PostAuth
		if value == nil || value.CompletionFunction == "" || value.DeclaredMutationKind == "" ||
			!allHexHashes(value.CanonicalPayloadSHA256, value.DeclaredMutationValueSHA256,
				value.OriginalCarrierPreservationSHA256) ||
			value.DeclaredMutationKind != arm.DeclaredMutation.Kind ||
			value.DeclaredMutationValueSHA256 != arm.DeclaredMutation.ValueSHA256 ||
			value.OriginalCarrierPreservationSHA256 != value.CanonicalPayloadSHA256 {
			return fmt.Errorf("%w: post-auth payload", ErrInvalidArm)
		}
	default:
		return fmt.Errorf("%w: unsupported variant", ErrInvalidArm)
	}
	return nil
}

// DeclaredActionTagMatches binds variants whose mutation value is an action
// tag to the exact UTF-8 bytes of the action. Post-authentication replacement
// variants deliberately use action-specific replacement bytes instead.
func DeclaredActionTagMatches(arm *Arm, expected string) bool {
	if arm == nil || arm.DeclaredMutation.Kind != expected {
		return false
	}
	decoded, err := hex.DecodeString(arm.DeclaredMutation.ValueHex)
	return err == nil && bytes.Equal(decoded, []byte(expected))
}

func validTransportAction(value string) bool {
	switch value {
	case "HOLD_RELEASE_FORWARD_ONCE", "RELEASE_AT_BOUNDARY_FORWARD_ONCE", "DUPLICATE_ONCE", "REDRIVE_ONCE":
		return true
	default:
		return false
	}
}

func isHexHash(value string) bool {
	if len(value) != hexHashLength || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func allHexHashes(values ...string) bool {
	for _, value := range values {
		if !isHexHash(value) {
			return false
		}
	}
	return true
}
