package drwa

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/multiversx/mx-chain-core-go/hashing/sha256"
	"github.com/stretchr/testify/require"
)

// UNREVIEWED qualification-only encoder, not an authority or admission verifier.
// W03_protected_admission_signing_parameters_01.json and exact test bytes require
// independent review before execution. Unsigned public patterns prove no claim,
// current authority, native transaction, funded recovery or successor possession.
var w03ErrD03Certificate = errors.New("invalid synthetic D03 certificate bytes")

type w03D03CertificateContext struct {
	domain, owner                         [32]byte
	programme, token, operation           string
	branch, targets, impact               byte
	nonce                                 uint64
	action, predecessor, claim, successor [32]byte
	notBefore, notAfter                   uint64
}
type w03D03CertificateAuthority struct {
	id, roster [32]byte
	version    uint64
	role       byte
}

// This encoder bounds ASCII fields only. Semantic role/class/time/claim checks
// belong to the separate construction; arbitrary bytes here confer no authority.
func w03D03CertificateMessage(c w03D03CertificateContext, a w03D03CertificateAuthority, purpose string) ([]byte, error) {
	message := []byte("W03/D03/FIXTURE/v1")
	field := func(value string, maximum int) error {
		if len(value) == 0 || len(value) > maximum {
			return w03ErrD03Certificate
		}
		for _, b := range []byte(value) {
			if b > 127 {
				return w03ErrD03Certificate
			}
		}
		message = binary.BigEndian.AppendUint32(message, uint32(len(value)))
		message = append(message, value...)
		return nil
	}
	if err := field(purpose, 32); err != nil {
		return nil, err
	}
	message = append(message, c.domain[:]...)
	message = append(message, c.owner[:]...)
	for _, row := range []struct {
		value   string
		maximum int
	}{
		{c.programme, 64}, {c.token, 64}, {c.operation, 64},
	} {
		if err := field(row.value, row.maximum); err != nil {
			return nil, err
		}
	}
	message = append(message, c.branch, c.targets, c.impact)
	message = binary.BigEndian.AppendUint64(message, c.nonce)
	message = append(message, c.action[:]...)
	message = append(message, c.predecessor[:]...)
	message = append(message, c.claim[:]...)
	message = append(message, c.successor[:]...)
	message = binary.BigEndian.AppendUint64(message, c.notBefore)
	message = binary.BigEndian.AppendUint64(message, c.notAfter)
	message = append(message, a.id[:]...)
	message = binary.BigEndian.AppendUint64(message, a.version)
	message = append(message, a.roster[:]...)
	message = append(message, a.role)
	return message, nil
}

func w03D03CertificateDigest(c w03D03CertificateContext, a w03D03CertificateAuthority, purpose string) ([]byte, error) {
	message, err := w03D03CertificateMessage(c, a, purpose)
	if err != nil {
		return nil, err
	}
	return sha256.NewSha256().Compute(string(message)), nil
}

func w03D03CertificatePublicContext() (w03D03CertificateContext, w03D03CertificateAuthority) {
	c := w03D03CertificateContext{programme: "W03-SYNTHETIC-A", token: "TOKEN-000001",
		operation: "RECOVER_SCOPED_ROLE", branch: 2, targets: 1, nonce: 1, notBefore: 100, notAfter: 200}
	a := w03D03CertificateAuthority{version: 1, role: 1}
	for _, row := range []struct {
		target *[32]byte
		value  byte
	}{
		{&c.domain, 0xd1}, {&c.owner, 0xa1}, {&c.action, 0xb1}, {&c.predecessor, 0xc1},
		{&c.claim, 0xe1}, {&c.successor, 0xf1}, {&a.id, 0x31}, {&a.roster, 0x32},
	} {
		for i := range row.target {
			row.target[i] = row.value
		}
	}
	return c, a
}

func TestQualDRWAAuthorityD03CertificateCodec(t *testing.T) {
	c, a := w03D03CertificatePublicContext()
	// Expected bytes come from independent Python struct/hashlib over the
	// declared public grammar, never from this Go encoder or native hash.
	for _, row := range []struct {
		purpose, encoded, digest string
		role                     byte
		length                   int
	}{
		{"W03_D03_PROPOSE", "5730332f4430332f464958545552452f76310000000f5730335f4430335f50524f504f5345d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a10000000f5730332d53594e5448455449432d410000000c544f4b454e2d303030303031000000135245434f5645525f53434f5045445f524f4c450201000000000000000001b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1000000000000006400000000000000c831313131313131313131313131313131313131313131313131313131313131310000000000000001323232323232323232323232323232323232323232323232323232323232323201", "919bb56f19e2b45f89a8047ed2bf1303c2fc260b2d34bd4ee6cfa1497580e3ec", 1, 387},
		{"W03_D03_ADMIT", "5730332f4430332f464958545552452f76310000000d5730335f4430335f41444d4954d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a10000000f5730332d53594e5448455449432d410000000c544f4b454e2d303030303031000000135245434f5645525f53434f5045445f524f4c450201000000000000000001b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1000000000000006400000000000000c831313131313131313131313131313131313131313131313131313131313131310000000000000001323232323232323232323232323232323232323232323232323232323232323202", "fb77801d911c5edce1c49157dd70c97d4f1876c42219d19a06a78b5313c7169d", 2, 385},
		{"W03_D03_EXECUTE", "5730332f4430332f464958545552452f76310000000f5730335f4430335f45584543555445d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a10000000f5730332d53594e5448455449432d410000000c544f4b454e2d303030303031000000135245434f5645525f53434f5045445f524f4c450201000000000000000001b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1000000000000006400000000000000c831313131313131313131313131313131313131313131313131313131313131310000000000000001323232323232323232323232323232323232323232323232323232323232323201", "dc101697b99d541c0aade5cbfb993791f649fc755c25d1470326fbf32c490a3a", 1, 387},
	} {
		t.Run(row.purpose, func(t *testing.T) {
			a.role = row.role
			expected, err := hex.DecodeString(row.encoded)
			require.NoError(t, err)
			expectedDigest, err := hex.DecodeString(row.digest)
			require.NoError(t, err)
			message, err := w03D03CertificateMessage(c, a, row.purpose)
			require.NoError(t, err)
			require.Len(t, message, row.length)
			require.Equal(t, expected, message)
			digest, err := w03D03CertificateDigest(c, a, row.purpose)
			require.NoError(t, err)
			require.Equal(t, expectedDigest, digest)
		})
	}
}

func TestQualDRWAAuthorityD03CertificateFormats(t *testing.T) {
	for _, name := range []string{"purpose", "programme", "token", "operation"} {
		for _, value := range []string{"", strings.Repeat("x", 65), "\u0080"} {
			t.Run(name+"/"+hex.EncodeToString([]byte(value)), func(t *testing.T) {
				c, a := w03D03CertificatePublicContext()
				purpose := "W03_D03_PROPOSE"
				switch name {
				case "purpose":
					purpose = value
				case "programme":
					c.programme = value
				case "token":
					c.token = value
				case "operation":
					c.operation = value
				}
				message, err := w03D03CertificateMessage(c, a, purpose)
				require.ErrorIs(t, err, w03ErrD03Certificate)
				require.Nil(t, message)
				digest, err := w03D03CertificateDigest(c, a, purpose)
				require.ErrorIs(t, err, w03ErrD03Certificate)
				require.Nil(t, digest)
			})
		}
	}
	// Exact upper bounds are encoder geometry, not production profile limits.
	c, a := w03D03CertificatePublicContext()
	c.programme, c.token, c.operation = strings.Repeat("x", 64), strings.Repeat("x", 64), strings.Repeat("x", 64)
	message, err := w03D03CertificateMessage(c, a, strings.Repeat("x", 32))
	require.NoError(t, err)
	require.Len(t, message, 550)
	// Purpose bound is32, so33 bytes must deny independently of the64-byte fields.
	_, err = w03D03CertificateMessage(c, a, strings.Repeat("x", 33))
	require.ErrorIs(t, err, w03ErrD03Certificate)
}
