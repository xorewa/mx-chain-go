package drwa

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/multiversx/mx-chain-core-go/hashing/sha256"
	"github.com/stretchr/testify/require"
)

// UNREVIEWED unsigned qualification encoder. No native authentication, detached
// certificate, namespace/appointment validation, parser, state or replay effect.
// Exact W03_scope_payload_parameters_01.json and these bytes require review.
var w03ErrScopePayload = errors.New("invalid synthetic M47 enrollment payload")

type w03ScopePayload struct {
	domain, owner, constitution, evidence, replay [32]byte
	programme                                     string
	format                                        uint64
	sets                                          [][32]byte
}

func w03ScopePayloadMessage(c w03ScopePayload) ([]byte, error) {
	// Bound variable geometry before constructing the unsigned message. Fixed32
	// widths encode commitments only, never authenticity or native address validity.
	if len(c.programme) == 0 || len(c.programme) > 64 {
		return nil, w03ErrScopePayload
	}
	if c.format != 1 {
		return nil, w03ErrScopePayload
	}
	if len(c.sets) == 0 || len(c.sets) > 6 {
		return nil, w03ErrScopePayload
	}
	var message []byte
	field := func(value []byte) {
		message = binary.BigEndian.AppendUint64(message, uint64(len(value)))
		message = append(message, value...)
	}
	field(c.domain[:])
	field(c.owner[:])
	field([]byte(c.programme))
	field([]byte("DRWA/SCOPE/ENROLL/v1"))
	message = binary.BigEndian.AppendUint64(message, c.format)
	field(c.constitution[:])
	message = binary.BigEndian.AppendUint64(message, uint64(len(c.sets)))
	for _, set := range c.sets {
		field(set[:])
	}
	field(c.evidence[:])
	field(c.replay[:])
	return message, nil
}

func w03ScopePayloadDigest(c w03ScopePayload) ([]byte, error) {
	message, err := w03ScopePayloadMessage(c)
	if err != nil {
		return nil, err
	}
	return sha256.NewSha256().Compute(string(message)), nil
}

func w03ScopePayloadPublic(programme string, count int) w03ScopePayload {
	c := w03ScopePayload{programme: programme, format: 1}
	for _, row := range []struct {
		target *[32]byte
		start  int
	}{{&c.domain, 0}, {&c.owner, 32}, {&c.constitution, 64}, {&c.evidence, 128}, {&c.replay, 160}} {
		for i := range row.target {
			row.target[i] = byte(row.start + i)
		}
	}
	for index := 0; index < count; index++ {
		var set [32]byte
		for offset := range set {
			set[offset] = byte((96 + 32*index + offset) % 256)
		}
		c.sets = append(c.sets, set)
	}
	return c
}

func TestQualDRWAAuthorityScopePayloadBounds(t *testing.T) {
	for _, change := range []func(*w03ScopePayload){
		func(c *w03ScopePayload) { c.programme = "" },
		func(c *w03ScopePayload) { c.programme = strings.Repeat("x", 65) },
		func(c *w03ScopePayload) { c.format = 0 },
		func(c *w03ScopePayload) { c.format = 2 },
		func(c *w03ScopePayload) { c.format = math.MaxUint64 },
		func(c *w03ScopePayload) { c.sets = nil },
		func(c *w03ScopePayload) { c.sets = make([][32]byte, 0) },
		func(c *w03ScopePayload) { c.sets = make([][32]byte, 7) },
	} {
		c := w03ScopePayloadPublic("PROGRAM-A", 1)
		change(&c)
		message, err := w03ScopePayloadMessage(c)
		require.ErrorIs(t, err, w03ErrScopePayload)
		require.Nil(t, message)
		digest, err := w03ScopePayloadDigest(c)
		require.ErrorIs(t, err, w03ErrScopePayload)
		require.Nil(t, digest)
	}
	// Every admitted toy geometry, including both endpoints, is representable.
	for count := 1; count <= 6; count++ {
		for _, programme := range []string{"x", strings.Repeat("x", 64), "DRWA/SCOPE/ENROLL/v1\x00\xff"} {
			message, err := w03ScopePayloadMessage(w03ScopePayloadPublic(programme, count))
			require.NoError(t, err)
			// Independent sum:252 fixed bytes + programme bytes +40 per set.
			require.Len(t, message, 252+len(programme)+40*count)
		}
	}
}

func TestQualDRWAAuthorityScopePayloadCodec(t *testing.T) {
	// Literal unsigned bytes/digests from Python struct/hashlib, independent of
	// this encoder/native hash; these public patterns prove no native authority.
	for _, row := range []struct {
		name, programme string
		count, length   int
		message, digest string
	}{
		{"one", "50524f4752414d2d41", 1, 301, "0000000000000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0000000000000020202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f000000000000000950524f4752414d2d410000000000000014445257412f53434f50452f454e524f4c4c2f763100000000000000010000000000000020404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f00000000000000010000000000000020606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f0000000000000020808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f0000000000000020a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf", "abff5ceffe866042e919f82f80849da1a3283371c05647250bbf4bd889afa654"},
		{"opaque", "70002f40ff", 2, 337, "0000000000000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0000000000000020202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f000000000000000570002f40ff0000000000000014445257412f53434f50452f454e524f4c4c2f763100000000000000010000000000000020404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f00000000000000020000000000000020606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f0000000000000020808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f0000000000000020808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f0000000000000020a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf", "3ebb25e18253c454fd9667f7c58deb5b7120837897318ac0eef6cab201fcc7c0"},
		{"maximum", "78787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878", 6, 556, "0000000000000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0000000000000020202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f0000000000000040787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878780000000000000014445257412f53434f50452f454e524f4c4c2f763100000000000000010000000000000020404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f00000000000000060000000000000020606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f0000000000000020808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f0000000000000020a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf0000000000000020c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf0000000000000020e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff0000000000000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0000000000000020808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f0000000000000020a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf", "18257037cd0d9fb1209891fdae3c5de7098057131fba4f1c24d375776e26d8ef"},
	} {
		t.Run(row.name, func(t *testing.T) {
			programme, err := hex.DecodeString(row.programme)
			require.NoError(t, err)
			expected, err := hex.DecodeString(row.message)
			require.NoError(t, err)
			expectedDigest, err := hex.DecodeString(row.digest)
			require.NoError(t, err)
			c := w03ScopePayloadPublic(string(programme), row.count)
			message, err := w03ScopePayloadMessage(c)
			require.NoError(t, err)
			require.Len(t, message, row.length)
			require.Equal(t, expected, message)
			digest, err := w03ScopePayloadDigest(c)
			require.NoError(t, err)
			require.Equal(t, expectedDigest, digest)
		})
	}
}
