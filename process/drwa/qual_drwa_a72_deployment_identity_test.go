package drwa

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/stretchr/testify/require"
)

// Synthetic deployment only. Native header framing/hash are admitted inputs;
// independent literal Batch framing and domain concatenation never use the
// identity decoder as an encoder/oracle. Pin-from-fixture is integrity testing,
// NOT an authenticated deployment/digest delivery channel or original-G6 proof.
func qualA72IdentityInput(t *testing.T) ([][]byte, DeploymentIdentityBounds) {
	t.Helper()
	m := &marshal.GogoProtoMarshalizer{}
	h := blake2b.NewBlake2b()
	header, err := m.Marshal(&block.MetaBlock{Epoch: 17, RootHash: []byte("synthetic genesis root")})
	require.NoError(t, err)
	chain := []byte("synthetic-chain")
	hash := h.Compute(string(header))
	preimage := append(append([]byte("DRWA/NETWORK/v1"), chain...), hash...)
	epoch := make([]byte, 4)
	binary.BigEndian.PutUint32(epoch, 17)
	return [][]byte{[]byte("DRWA/DEPLOYMENT-IDENTITY/v1"), chain, epoch, header, hash, h.Compute(string(preimage))}, DeploymentIdentityBounds{Bytes: 4096, ChainIDBytes: 64, HeaderBytes: 2048}
}
func qualA72DecodeIdentity(raw []byte, pin []byte, chain []byte, epoch uint32, bounds DeploymentIdentityBounds) (*DeploymentIdentity, error) {
	return DecodeDeploymentIdentity(raw, pin, chain, epoch, bounds, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b())
}
func TestQualA72DeploymentIdentityBinding(t *testing.T) {
	fields, bounds := qualA72IdentityInput(t)
	raw := qualRecordFrame(fields...)
	pin := sha256.Sum256(raw)
	identity, err := qualA72DecodeIdentity(raw, pin[:], fields[1], 17, bounds)
	require.NoError(t, err)
	require.Equal(t, raw, identity.Raw())
	require.Equal(t, fields[3], identity.Header())
	require.Equal(t, fields[4], identity.GenesisHash())
	require.Equal(t, fields[5], identity.Domain())
	require.Equal(t, uint32(17), identity.GenesisEpoch())
	// The returned view owns all bytes, including across caller-buffer mutation.
	before := identity.Raw()
	raw[0] ^= 1
	fields[1][0] ^= 1
	for _, value := range [][]byte{identity.Raw(), identity.Header(), identity.GenesisHash(), identity.Domain()} {
		value[0] ^= 1
	}
	require.Equal(t, before, identity.Raw())
	for _, fault := range []string{"tag", "chain", "epoch_width", "epoch", "header", "hash", "domain", "extra_field", "missing_field", "reordered", "wrong_pin", "zero_bounds", "header_bound", "whole_bound", "noncanonical_length"} {
		t.Run(fault, func(t *testing.T) {
			f, b := qualA72IdentityInput(t)
			expectedChain := bytes.Clone(f[1])
			expectedEpoch := uint32(17)
			switch fault {
			case "tag":
				f[0] = []byte("DRWA/DEPLOYMENT-IDENTITY/v2")
			case "chain":
				f[1] = []byte("wrong-chain")
			case "epoch_width":
				f[2] = append(f[2], 0)
			case "epoch":
				expectedEpoch = 18
			case "header":
				f[3] = append(f[3], 0)
			case "hash":
				f[4][0] ^= 1
			case "domain":
				f[5][0] ^= 1
			case "extra_field":
				f = append(f, []byte("unselected generation"))
			case "missing_field":
				f = f[:5]
			case "reordered":
				f[0], f[1] = f[1], f[0]
			case "zero_bounds":
				b = DeploymentIdentityBounds{}
			case "header_bound":
				b.HeaderBytes = len(f[3]) - 1
			case "whole_bound":
				b.Bytes = 1
			}
			encoded := qualRecordFrame(f...)
			if fault == "noncanonical_length" {
				encoded = append([]byte{0x0a, byte(len(f[0])) | 0x80, 0}, encoded[2:]...)
			}
			digest := sha256.Sum256(encoded)
			if fault == "wrong_pin" {
				digest[0] ^= 1
			}
			got, e := qualA72DecodeIdentity(encoded, digest[:], expectedChain, expectedEpoch, b)
			require.ErrorIs(t, e, ErrDeploymentIdentity)
			require.Nil(t, got)
		})
	}
}
