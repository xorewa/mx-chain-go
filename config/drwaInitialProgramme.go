package config

import (
	"bytes"
	"errors"
	"time"
)

// ErrDRWAInitialProgrammeLimits signals missing or invalid admitted bounds.
var ErrDRWAInitialProgrammeLimits = errors.New("DRWA initial programme limits unavailable or exceeded")

// DRWAInitialProgrammeLimits carries the existing bounded native decoder's
// inputs. It supplies neither defaults nor profile or appointment admission.
type DRWAInitialProgrammeLimits struct {
	Files, FileBytes, AggregateBytes           int
	RecordBytes, FieldBytes, RoleBytes, Members int
	Records, RetainedBytes, NewRecordsPerEpoch uint64
	AdmissionRole, IndependentRole             []byte
}

func (l *DRWAInitialProgrammeLimits) Clone() *DRWAInitialProgrammeLimits {
	if l == nil {
		return nil
	}
	x := *l
	x.AdmissionRole = bytes.Clone(l.AdmissionRole)
	x.IndependentRole = bytes.Clone(l.IndependentRole)
	return &x
}

func (l *DRWAInitialProgrammeLimits) Validate() error {
	if l == nil || l.Files <= 0 || l.FileBytes <= 0 || l.AggregateBytes < l.FileBytes ||
		l.FileBytes > l.RecordBytes || l.Records == 0 || l.RetainedBytes == 0 || l.NewRecordsPerEpoch == 0 ||
		l.FieldBytes <= 0 || l.RoleBytes <= 0 || l.Members < 5 ||
		len(l.AdmissionRole) == 0 || len(l.AdmissionRole) > l.RoleBytes ||
		len(l.IndependentRole) == 0 || len(l.IndependentRole) > l.RoleBytes || bytes.Equal(l.AdmissionRole, l.IndependentRole) {
		return ErrDRWAInitialProgrammeLimits
	}
	return nil
}

// DRWAMinimumGenesis is the existing experimental genesis layout's input.
// Its digests and bounds come from the qualified immutable interpretation.
type DRWAMinimumGenesis struct {
	ProfileDigest, ReleaseDigest      [32]byte
	MaxEverTokens, RegistryProofBytes uint64
}

// DRWAInitialProgrammeStartup carries the typed inputs of a separately
// admitted fresh-generation construction. The ordinary CLI/TOML paths do not
// populate it. This is not a wire format or a fresh-ownership proof.
type DRWAInitialProgrammeStartup struct {
	OverlaySHA256        [32]byte
	OverlayMaxBytes      int64
	Limits               DRWAInitialProgrammeLimits
	Minimum              DRWAMinimumGenesis
	OriginalDatabasePath string
	RecordDigest         [32]byte
	ReleaseWait          time.Duration
	ReleaseMaxBytes      int64
	Persisted             bool
}

func (p *DRWAInitialProgrammeStartup) Clone() *DRWAInitialProgrammeStartup {
	if p == nil {
		return nil
	}
	copy := *p
	copy.Limits = *p.Limits.Clone()
	return &copy
}
