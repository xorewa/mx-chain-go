package drwa

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

// Independently framed R2 literals. The retained disposition and owner 7A
// specify the fields and time predicates. Existing R3 keys are synthetic.
func TestQualDRWAM14AdmissionCarrier(t *testing.T) {
	f := qualScopedNew(t)
	_, ctx, keys := qualR3Fixture(t, 100)
	c, err := newRegistrationApprovalCodec(f.records.codec, registrationApprovalBounds{
		bytes: 4096, fieldBytes: 512, roleBytes: 64, familyBytes: 64, maxMembers: 5, maxValidity: 100,
	})
	require.NoError(t, err)
	bodies, err := newAuthorityBodyCodec(f.records.codec, authorityBodyBounds{4096, 512, 64, 5})
	require.NoError(t, err)
	b9, err := bodies.decode(ctx.admission.body)
	require.NoError(t, err)
	subject := m14AdmissionSubject{owner: f.d.owner, programme: f.d.program, issuer: f.d.issuer,
		currentReference: f.d.authority, current: b9, at: 100}
	id := qualA126Bytes(t, "e95690d6fab476def9437b61dab5bbdd9f9ab85952a3aef2b0c805f5711c52f2")
	d6 := f.body()
	issue, withdrawal := "PROGRAMME_ADMISSION_ISSUE", "PROGRAMME_ADMISSION_WITHDRAW"
	issueTag, withdrawalTag := "DRWA/PROGRAMME_ADMISSION_ISSUE/candidate1", "DRWA/PROGRAMME_ADMISSION_WITHDRAW/candidate1"
	current := keys["REGISTER_TOKEN_ADMISSION"]
	fields := func(tag, purpose string, body []byte, nb, na uint64) [][]byte {
		return [][]byte{[]byte(tag), []byte("fixture-domain"), []byte(purpose), bytes.Clone(f.scope),
			bytes.Clone(f.d.issuer), bytes.Clone(id), bytes.Clone(body), bytes.Clone(f.d.authority),
			bytes.Clone(ctx.admission.role), bytes.Clone(ctx.admission.setID), bytes.Clone(ctx.admission.version),
			bytes.Clone(ctx.admission.bodyHash), qualA38U64(nb), qualA38U64(na)}
	}
	carrier := func(body []byte, messageFields [][]byte) []byte {
		return qualRecordFrame(body, qualA38Envelope(qualRecordFrame(messageFields...), current, 0, 2, 4))
	}

	root, err := f.store.RootHash()
	require.NoError(t, err)
	journal := f.store.JournalLen()
	positive := carrier(d6, fields(issueTag, issue, d6, 100, 200))
	r, err := c.verifyM14AdmissionCarrier(f.records, issue, subject, positive)
	require.NoError(t, err)
	require.Equal(t, id, r.decisionID)
	require.Equal(t, d6, r.body)
	require.Equal(t, f.d, r.decision)
	require.Equal(t, []uint64{0, 2, 4}, r.signerIndices)
	require.Equal(t, qualRecordFrame(fields(issueTag, issue, d6, 100, 200)...), r.message)
	copy(positive, make([]byte, len(positive)))
	require.Equal(t, d6, r.body, "verified D6 owns its bytes")
	require.Equal(t, f.d, r.decision, "decoded version and opaque commitment own their bytes")

	t.Run("purpose-specific windows", func(t *testing.T) {
		for _, row := range []struct {
			name, tag, purpose string
			nb, na             uint64
			expiry             uint64
			at                 HeaderMilliseconds
			accept             bool
		}{
			{"issue upper endpoint", issueTag, issue, 100, 200, 200, 200, true},
			{"issue upper exceeds decision", issueTag, issue, 100, 200, 199, 100, false},
			{"withdraw expired target", withdrawalTag, withdrawal, 100, 200, 50, 100, true},
			{"withdraw too long", withdrawalTag, withdrawal, 90, 200, 50, 100, false},
			{"withdraw future", withdrawalTag, withdrawal, 101, 200, 50, 100, false},
			{"withdraw expired certificate", withdrawalTag, withdrawal, 10, 99, 50, 100, false},
			{"withdraw reversed", withdrawalTag, withdrawal, 100, 99, 50, 100, false},
		} {
			t.Run(row.name, func(t *testing.T) {
				df := qualA38Split(d6)
				df[5] = qualA38U64(row.expiry)
				body := qualRecordFrame(df...)
				s := subject
				s.at = row.at
				_, e := c.verifyM14AdmissionCarrier(f.records, row.purpose, s, carrier(body, fields(row.tag, row.purpose, body, row.nb, row.na)))
				if row.accept {
					require.NoError(t, e)
				} else {
					require.Error(t, e)
				}
			})
		}
	})

	t.Run("signed coordinates must match their source", func(t *testing.T) {
		for i := range 12 {
			m := fields(issueTag, issue, d6, 100, 200)
			m[i][0] ^= 1
			_, e := c.verifyM14AdmissionCarrier(f.records, issue, subject, carrier(d6, m))
			require.Error(t, e, "M field %d", i+1)
		}
	})
	t.Run("exact purpose and bounded envelope", func(t *testing.T) {
		m := qualRecordFrame(fields(issueTag, issue, d6, 100, 200)...)
		e := qualA38Envelope(m, current, 0, 2, 4)
		encoded := qualRecordFrame(d6, e)
		_, err := c.verifyM14AdmissionCarrier(f.records, withdrawal, subject, encoded)
		require.Error(t, err)
		for _, invalid := range [][]byte{
			qualRecordFrame(d6, e, []byte("extra")),
			qualRecordFrame(d6, qualA38Envelope(m, current, 0, 2)),
			qualRecordFrame(d6, qualA38Envelope(m, current, 0, 2, 2)),
			qualRecordFrame(d6, qualA38Envelope(m, keys["REGISTER_TOKEN"], 0, 2, 4)),
			qualRecordFrame(d6, e[:len(e)-1]),
		} {
			_, err = c.verifyM14AdmissionCarrier(f.records, issue, subject, invalid)
			require.Error(t, err)
		}
		bounded := *c
		local := *c.codec
		local.maxBytes = len(encoded) - 1
		bounded.codec = &local
		_, err = bounded.verifyM14AdmissionCarrier(f.records, issue, subject, encoded)
		require.Error(t, err)
	})
	t.Run("issue requires current outer VERSION", func(t *testing.T) {
		bodyFields := qualA38Split(d6)
		bodyFields[4] = bytes.Repeat([]byte{0x21}, len(f.d.authority))
		old := qualRecordFrame(bodyFields...)
		_, err := c.verifyM14AdmissionCarrier(f.records, issue, subject, carrier(old, fields(issueTag, issue, old, 100, 200)))
		require.Error(t, err)
	})
	after, err := f.store.RootHash()
	require.NoError(t, err)
	require.Equal(t, root, after)
	require.Equal(t, journal, f.store.JournalLen())
}
