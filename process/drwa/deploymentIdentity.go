package drwa

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
)

// A72 experimental allocation only; not a production format/profile admission.
const DeploymentIdentityRecord = "DRWA_NETWORK_IDENTITY_V1"
const deploymentIdentityTag = "DRWA/DEPLOYMENT-IDENTITY/v1"

var ErrDeploymentIdentity = errors.New("DRWA deployment identity unavailable or conflicting")

// DeploymentIdentityBounds are admitted construction inputs, never defaults.
// The deployment owner must admit actual resource ceilings before first use.
type DeploymentIdentityBounds struct{ Bytes, ChainIDBytes, HeaderBytes int }

// DeploymentIdentity is a read-only validated binding, not appointment, native
// transaction provenance, canonical state/history or a startup permission.
// The independent expected digest must come from the admitted trust channel;
// accepting a digest computed from the same untrusted file proves nothing.
type DeploymentIdentity struct {
	raw, chainID, header, genesisHash, domain []byte
	epoch                                     uint32
}

func (i *DeploymentIdentity) Raw() []byte {
	if i == nil {
		return nil
	}
	return bytes.Clone(i.raw)
}
func (i *DeploymentIdentity) Domain() []byte {
	if i == nil {
		return nil
	}
	return bytes.Clone(i.domain)
}
func (i *DeploymentIdentity) GenesisHash() []byte {
	if i == nil {
		return nil
	}
	return bytes.Clone(i.genesisHash)
}
func (i *DeploymentIdentity) Header() []byte {
	if i == nil {
		return nil
	}
	return bytes.Clone(i.header)
}
func (i *DeploymentIdentity) GenesisEpoch() uint32 {
	if i == nil {
		return 0
	}
	return i.epoch
}

// DecodeDeploymentIdentity reuses the existing bounded native Batch contract
// and canonical native metachain header. No extra generation/epoch/Mref/X or
// caller-selected hash algorithm, profile meaning or decoder is introduced.
func DecodeDeploymentIdentity(raw []byte, expectedSHA256 []byte, chainID []byte, genesisEpoch uint32,
	bounds DeploymentIdentityBounds, marshaller marshal.Marshalizer, hasher hashing.Hasher) (*DeploymentIdentity, error) {
	if check.IfNil(marshaller) || check.IfNil(hasher) || hasher.Size() <= 0 || bounds.Bytes <= 0 || bounds.ChainIDBytes <= 0 || bounds.HeaderBytes <= 0 || bounds.ChainIDBytes > bounds.Bytes || bounds.HeaderBytes > bounds.Bytes || len(raw) == 0 || len(raw) > bounds.Bytes || len(expectedSHA256) != sha256.Size || len(chainID) == 0 || len(chainID) > bounds.ChainIDBytes {
		return nil, ErrDeploymentIdentity
	}
	digest := sha256.Sum256(raw)
	if !bytes.Equal(digest[:], expectedSHA256) {
		return nil, ErrDeploymentIdentity
	}
	codec := &registrationRecords{marshaller: marshaller, hasher: hasher, maxBytes: bounds.Bytes}
	f, err := registrationBoundedFields(codec, raw, 6, 6, bounds.Bytes)
	if err != nil || !bytes.Equal(f[0], []byte(deploymentIdentityTag)) || !bytes.Equal(f[1], chainID) || len(f[1]) > bounds.ChainIDBytes || len(f[2]) != 4 || binary.BigEndian.Uint32(f[2]) != genesisEpoch || len(f[3]) == 0 || len(f[3]) > bounds.HeaderBytes || len(f[4]) != hasher.Size() || len(f[5]) != hasher.Size() {
		return nil, ErrDeploymentIdentity
	}
	header := &block.MetaBlock{}
	if err = marshaller.Unmarshal(header, f[3]); err != nil || header.GetEpoch() != genesisEpoch {
		return nil, ErrDeploymentIdentity
	}
	canonical, err := marshaller.Marshal(header)
	if err != nil || !bytes.Equal(canonical, f[3]) {
		return nil, ErrDeploymentIdentity
	}
	actualHash := hasher.Compute(string(f[3]))
	if !bytes.Equal(actualHash, f[4]) {
		return nil, ErrDeploymentIdentity
	}
	domain, err := common.ComputeDRWANetworkDomain(chainID, actualHash, hasher)
	if err != nil || !bytes.Equal(domain, f[5]) {
		return nil, ErrDeploymentIdentity
	}
	return &DeploymentIdentity{raw: bytes.Clone(raw), chainID: bytes.Clone(chainID), epoch: genesisEpoch, header: bytes.Clone(f[3]), genesisHash: bytes.Clone(actualHash), domain: bytes.Clone(domain)}, nil
}
