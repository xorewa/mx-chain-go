package drwa

import (
	"bytes"

	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/config"
)

// ErrInitialProgrammeLimits identifies absent or insufficient admitted limits.
var ErrInitialProgrammeLimits = config.ErrDRWAInitialProgrammeLimits

// InitialProgrammeLimits is explicit construction DATA, not profile admission.
type InitialProgrammeLimits = config.DRWAInitialProgrammeLimits

// InitialProgrammeEvidence is immutable decoded DATA. Its technical source pin
// authenticates neither appointment nor creating-owner authority. In particular
// it implements no verifier and cannot open protected registration ingress.
type InitialProgrammeEvidence struct {
	raw, owner, programme []byte
	path, pin             string
}

func (e InitialProgrammeEvidence) Raw() []byte              { return bytes.Clone(e.raw) }
func (e InitialProgrammeEvidence) Owner() []byte            { return bytes.Clone(e.owner) }
func (e InitialProgrammeEvidence) Programme() []byte        { return bytes.Clone(e.programme) }
func (e InitialProgrammeEvidence) Source() (string, string) { return e.path, e.pin }

func CloneInitialProgrammeEvidence(input []InitialProgrammeEvidence) []InitialProgrammeEvidence {
	if input == nil {
		return nil
	}
	out := make([]InitialProgrammeEvidence, len(input))
	for i, e := range input {
		out[i] = InitialProgrammeEvidence{bytes.Clone(e.raw), bytes.Clone(e.owner), bytes.Clone(e.programme), e.path, e.pin}
	}
	return out
}

// DecodeInitialProgrammeEvidence reuses the selected bounded B9/G6 decoder and
// effective native primitives. No new parser, hash formula or authority API.
func DecodeInitialProgrammeEvidence(raw []byte, path, pin string, limits *InitialProgrammeLimits,
	marshaller marshal.Marshalizer, hasher hashing.Hasher) (InitialProgrammeEvidence, error) {
	if limits.Validate() != nil {
		return InitialProgrammeEvidence{}, ErrInitialProgrammeLimits
	}
	if check.IfNil(marshaller) || check.IfNil(hasher) {
		return InitialProgrammeEvidence{}, errInvalidRegistrationRecord
	}
	c, err := newAuthorityBodyCodec(&registrationRecords{marshaller: marshaller, hasher: hasher, maxBytes: limits.RecordBytes},
		authorityBodyBounds{limits.RecordBytes, limits.FieldBytes, limits.RoleBytes, limits.Members})
	if err != nil {
		return InitialProgrammeEvidence{}, err
	}
	if len(raw) > limits.FileBytes {
		return InitialProgrammeEvidence{}, ErrInitialProgrammeLimits
	}
	a, err := c.decodeInitial(raw, limits.AdmissionRole, limits.IndependentRole)
	if err != nil {
		return InitialProgrammeEvidence{}, err
	}
	return InitialProgrammeEvidence{bytes.Clone(raw), bytes.Clone(a.owner), bytes.Clone(a.programme), path, pin}, nil
}
