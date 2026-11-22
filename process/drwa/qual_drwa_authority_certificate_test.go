package drwa

import (
	"bytes"
	stded "crypto/ed25519"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// R3 construction fixtures only. All three B9 bodies, ordered public rosters,
// appointment/currentness assumptions and profile limits are SYNTHETIC. This
// does not supply a lawful admission decision, native lineage, OPEN-state proof,
// original G6, operation lease, funding or production RegistrationVerifier.
func qualR3Fixture(t *testing.T, expiry uint64) (*registrationApprovalCodec, *registrationApprovalContext, map[string][]stded.PrivateKey) {
	t.Helper()
	c, ctx, _ := qualA38Fixture(t)
	ctx.scopeOwner = bytes.Repeat([]byte{1}, 32)
	ctx.programme = []byte("program")
	scope := qualRecordFrame(ctx.network, ctx.scopeOwner, ctx.programme)
	keys := make(map[string][]stded.PrivateKey)
	for index, row := range []struct {
		name, purpose string
		set           *registrationApprovalAuthority
	}{{"A", "REGISTER_TOKEN_ADMISSION", &ctx.admission}, {"C", "REGISTER_TOKEN", &ctx.independent}, {"PA", "PROGRAM_ADMINISTRATION", &ctx.pa}} {
		body := qualB9Bytes(t, row.name+"_body")
		fields := qualA38Split(body) // test-only field-1 framing, not the decoder
		members, private := qualA38Keys(byte(index))
		*row.set = registrationApprovalAuthority{role: qualA38Split(fields[6])[0], scope: bytes.Clone(scope), setID: fields[1], version: fields[2], body: body, bodyHash: qualB9Bytes(t, row.name+"_hash"), threshold: 3, members: members}
		keys[row.purpose] = private
		require.Equal(t, row.set.bodyHash, qualA38Hash(qualRecordFrame([]byte("DRWA/AUTHORITY_SET_VERSION_HASH/candidate1"), body)))
	}
	fields := qualA38Split(ctx.intentBody)
	fields[2] = bytes.Clone(ctx.programme)
	fields[11] = qualRecordFrame(ctx.admission.body, ctx.pa.body)
	fields[12] = qualRecordFrame(ctx.admission.bodyHash, ctx.pa.bodyHash)
	fields[15] = qualA38U64(expiry)
	ctx.intentBody = qualRecordFrame(fields...)
	ctx.intentHash = qualA38Hash(qualRecordFrame([]byte("DRWA/BOOTSTRAP_INTENT_PAYLOAD/v1"), ctx.intentBody))
	ctx.intentID = qualA38Hash(qualRecordFrame([]byte("DRWA/BOOTSTRAP_INTENT/v1"), ctx.network, ctx.issuer, ctx.programme, fields[3], ctx.intentHash))
	return c, ctx, keys
}

// These exact twelve fields and their digest are derived BEFORE implementing
// the consumer: manual field-1 framing, independent BLAKE2b and Go Ed25519.
// No consuming encoder, native decoder or production roleMap produces them.
func qualR3Message(ctx *registrationApprovalContext, purpose string, nb, na uint64) []byte {
	row := func(p string, a registrationApprovalAuthority) []byte {
		return qualRecordFrame([]byte(p), a.role, a.setID, a.version, a.bodyHash)
	}
	projection := qualRecordFrame([]byte("DRWA/REGISTER_TOKEN_ROLE_MAP/candidate1"), ctx.network, ctx.scopeOwner, ctx.programme,
		row("REGISTER_TOKEN_ADMISSION", ctx.admission), row("REGISTER_TOKEN", ctx.independent))
	authority, binding := ctx.admission, qualA38Hash(projection)
	if purpose == "PROGRAM_ADMINISTRATION" {
		authority, binding = ctx.pa, ctx.intentHash
	}
	dependency := qualRecordFrame(authority.role, qualRecordFrame(ctx.network, ctx.scopeOwner, ctx.programme), authority.setID, authority.version, authority.bodyHash, binding)
	return qualRecordFrame([]byte("DRWA/REGISTER_TOKEN_AUTHORITY_CERTIFICATE/candidate1"), ctx.network, []byte(purpose),
		ctx.scopeOwner, ctx.programme, ctx.issuer, ctx.intentID, ctx.intentHash, qualR3CreationHash(), dependency, qualA38U64(nb), qualA38U64(na))
}

func qualR3CreationHash() []byte {
	// Existing independently derived A38 creation-body digest, copied literally.
	return []byte{0x39, 0x0c, 0xed, 0x52, 0x04, 0x4b, 0x7f, 0x71, 0x8c, 0x0c, 0x93, 0x6d, 0xaf, 0x0e, 0xce, 0x54, 0x42, 0x54, 0xa9, 0x42, 0x40, 0xa0, 0xe4, 0xd6, 0xd1, 0x7b, 0xfe, 0x5e, 0xd9, 0xf5, 0xda, 0xe2}
}

// Compile-neutral, rejection-only bridge retains the behavioural reproducer
// from before the selected consumer existed. It supplies no accepting provider
// or production seam: absent support rejects this independently signed envelope.
func qualR3Verify(c *registrationApprovalCodec, raw, creation []byte, ctx *registrationApprovalContext, purpose string) error {
	v, exists := any(c).(interface {
		verifyAuthorityCertificate([]byte, []byte, *registrationApprovalContext, string) error
	})
	if !exists {
		return errInvalidRegistrationRecord
	}
	return v.verifyAuthorityCertificate(raw, creation, ctx, purpose)
}

func TestQualA11R3PurposeCertificates(t *testing.T) {
	for _, purpose := range []string{"REGISTER_TOKEN_ADMISSION", "PROGRAM_ADMINISTRATION"} {
		t.Run(purpose, func(t *testing.T) {
			c, ctx, keys := qualR3Fixture(t, 100)
			message := qualR3Message(ctx, purpose, 10, 90)
			fields := qualA38Split(message)
			require.Len(t, fields, 12)
			require.Equal(t, qualR3CreationHash(), qualA38Hash(qualA38Bytes(t, "creation")))
			require.Len(t, qualA38Split(fields[9]), 6)
			nativeBytes, err := c.codec.frame(fields...)
			require.NoError(t, err)
			require.Equal(t, message, nativeBytes)
			digest, err := c.hash(message)
			require.NoError(t, err)
			require.Equal(t, qualA38Hash(message), digest)
			for _, indices := range [][]uint64{{0, 2, 4}, {0, 1, 2, 3, 4}} {
				envelope := qualA38Envelope(message, keys[purpose], indices...)
				require.NoError(t, qualR3Verify(c, envelope, qualA38Bytes(t, "creation"), ctx, purpose), "selected twelve-field certificate must verify against its own B9 roster")
				require.Error(t, c.verifyIndependent(envelope, qualA38Bytes(t, "creation"), ctx), "M14 must not reinterpret this new envelope")
			}
			for other, private := range keys {
				if other != purpose {
					require.Error(t, qualR3Verify(c, qualA38Envelope(message, private, 0, 2, 4), qualA38Bytes(t, "creation"), ctx, purpose), "another roster cannot discharge this proof")
				}
			}
			independent := qualA38Envelope(qualA38Message(t, ctx, 10, 90), keys["REGISTER_TOKEN"], 0, 2, 4)
			require.NoError(t, c.verifyIndependent(independent, qualA38Bytes(t, "creation"), ctx))
			require.Error(t, qualR3Verify(c, independent, qualA38Bytes(t, "creation"), ctx, purpose))
		})
	}
}

func TestQualA11R3CertificateBindings(t *testing.T) {
	for _, purpose := range []string{"REGISTER_TOKEN_ADMISSION", "PROGRAM_ADMINISTRATION"} {
		for field := 0; field < 12; field++ {
			t.Run(fmt.Sprintf("%s/message_%d", purpose, field), func(t *testing.T) {
				c, ctx, keys := qualR3Fixture(t, 100)
				valid := qualA38Envelope(qualR3Message(ctx, purpose, 10, 90), keys[purpose], 0, 2, 4)
				require.NoError(t, qualR3Verify(c, valid, qualA38Bytes(t, "creation"), ctx, purpose))
				fields := qualA38Split(qualR3Message(ctx, purpose, 10, 90))
				if field >= 10 {
					fields[field] = fields[field][:7]
				} else {
					fields[field][0] ^= 1
				}
				require.Error(t, qualR3Verify(c, qualA38Envelope(qualRecordFrame(fields...), keys[purpose], 0, 2, 4), qualA38Bytes(t, "creation"), ctx, purpose))
				require.NoError(t, qualR3Verify(c, valid, qualA38Bytes(t, "creation"), ctx, purpose))
			})
		}
		for field := 0; field < 6; field++ {
			t.Run(fmt.Sprintf("%s/dependency_%d", purpose, field), func(t *testing.T) {
				c, ctx, keys := qualR3Fixture(t, 100)
				fields := qualA38Split(qualR3Message(ctx, purpose, 10, 90))
				dependency := qualA38Split(fields[9])
				dependency[field][0] ^= 1
				fields[9] = qualRecordFrame(dependency...)
				require.Error(t, qualR3Verify(c, qualA38Envelope(qualRecordFrame(fields...), keys[purpose], 0, 2, 4), qualA38Bytes(t, "creation"), ctx, purpose))
				require.NoError(t, qualR3Verify(c, qualA38Envelope(qualR3Message(ctx, purpose, 10, 90), keys[purpose], 0, 2, 4), qualA38Bytes(t, "creation"), ctx, purpose))
			})
		}
	}
}

func TestQualA11R3CertificateValidity(t *testing.T) {
	for _, purpose := range []string{"REGISTER_TOKEN_ADMISSION", "PROGRAM_ADMINISTRATION"} {
		for _, tc := range []struct {
			name               string
			nb, na, at, expiry uint64
			accept             bool
		}{
			{"inclusive_start", 10, 90, 10, 100, true}, {"inclusive_end", 10, 90, 90, 100, true},
			{"zero_span", 50, 50, 50, 100, true}, {"maximum_span", 0, 100, 50, 250, true},
			{"future", 51, 90, 50, 100, false}, {"expired", 10, 49, 50, 100, false},
			{"intent_expiry", 90, 101, 95, 100, false}, {"over_span", 0, 101, 50, 250, false},
			{"reversed", 90, 10, 50, 100, false}, {"reversed_overflow", ^uint64(0), 0, 50, 100, false},
		} {
			t.Run(purpose+"/"+tc.name, func(t *testing.T) {
				c, ctx, keys := qualR3Fixture(t, tc.expiry)
				ctx.at = HeaderMilliseconds(tc.at)
				err := qualR3Verify(c, qualA38Envelope(qualR3Message(ctx, purpose, tc.nb, tc.na), keys[purpose], 0, 2, 4), qualA38Bytes(t, "creation"), ctx, purpose)
				if tc.accept {
					require.NoError(t, err)
				} else {
					require.Error(t, err)
				}
			})
		}
	}
}

func TestQualA11R3CertificateMalformed(t *testing.T) {
	for _, purpose := range []string{"REGISTER_TOKEN_ADMISSION", "PROGRAM_ADMINISTRATION"} {
		for _, fault := range []string{"empty", "truncated", "extra_envelope", "missing_envelope", "extra_message", "missing_message", "unknown_tag", "nonshort", "dependency_count", "index_width", "duplicate", "unordered", "out_of_range", "threshold", "missing_signature", "extra_signature", "bad_extra_signature", "signature_width"} {
			t.Run(purpose+"/"+fault, func(t *testing.T) {
				c, ctx, keys := qualR3Fixture(t, 100)
				message := qualR3Message(ctx, purpose, 10, 90)
				valid := qualA38Envelope(message, keys[purpose], 0, 2, 4)
				require.NoError(t, qualR3Verify(c, valid, qualA38Bytes(t, "creation"), ctx, purpose))
				raw := bytes.Clone(valid)
				switch fault {
				case "empty":
					raw = nil
				case "truncated":
					raw = raw[:len(raw)-1]
				case "extra_envelope":
					raw = qualRecordFrame(append(qualA38Split(raw), nil)...)
				case "missing_envelope":
					raw = qualRecordFrame(qualA38Split(raw)[:2]...)
				case "unknown_tag":
					raw = append(raw, 0x18, 0)
				case "nonshort":
					raw = append([]byte{0x0a, raw[1] | 0x80, raw[2] | 0x80, 0}, raw[3:]...)
				case "extra_message", "missing_message", "dependency_count":
					m := qualA38Split(message)
					if fault == "extra_message" {
						m = append(m, nil)
					} else if fault == "missing_message" {
						m = m[:11]
					} else {
						m[9] = qualRecordFrame(qualA38Split(m[9])[:5]...)
					}
					raw = qualA38Envelope(qualRecordFrame(m...), keys[purpose], 0, 2, 4)
				case "duplicate":
					raw = qualA38Envelope(message, keys[purpose], 0, 0, 4)
				case "unordered":
					raw = qualA38Envelope(message, keys[purpose], 2, 0, 4)
				case "out_of_range":
					raw = qualA38Envelope(message, keys[purpose], 0, 2, 5)
				case "threshold":
					raw = qualA38Envelope(message, keys[purpose], 0, 2)
				case "bad_extra_signature":
					e := qualA38Split(qualA38Envelope(message, keys[purpose], 0, 1, 2, 3))
					sigs := qualA38Split(e[2])
					sigs[3][0] ^= 1
					e[2] = qualRecordFrame(sigs...)
					raw = qualRecordFrame(e...)
				default:
					e := qualA38Split(raw)
					if fault == "index_width" {
						indices := qualA38Split(e[1])
						indices[0] = indices[0][:7]
						e[1] = qualRecordFrame(indices...)
					} else {
						sigs := qualA38Split(e[2])
						if fault == "missing_signature" {
							sigs = sigs[:2]
						} else if fault == "extra_signature" {
							sigs = append(sigs, sigs[0])
						} else {
							sigs[0] = sigs[0][:63]
						}
						e[2] = qualRecordFrame(sigs...)
					}
					raw = qualRecordFrame(e...)
				}
				require.Error(t, qualR3Verify(c, raw, qualA38Bytes(t, "creation"), ctx, purpose))
				require.NoError(t, qualR3Verify(c, valid, qualA38Bytes(t, "creation"), ctx, purpose))
			})
		}
	}
}

// A changed C row is a supplied SYNTHETIC lawful-current fact solely for this
// cryptographic construction. An A-authority change is deliberately NOT given
// a fresh-admission positive: its embedded decision's currentness is unresolved.
func qualR3Rotate(set *registrationApprovalAuthority, kind byte) []stded.PrivateKey {
	oldVersion, oldHash := bytes.Clone(set.version), bytes.Clone(set.bodyHash)
	members, keys := qualA38Keys(kind)
	body := qualA38Split(set.body)
	body[2] = qualA38U64(binary.BigEndian.Uint64(oldVersion) + 1)
	body[5] = qualRecordFrame(members...)
	body[7], body[8] = oldVersion, oldHash
	set.body = qualRecordFrame(body...)
	set.bodyHash = qualA38Hash(qualRecordFrame([]byte("DRWA/AUTHORITY_SET_VERSION_HASH/candidate1"), set.body))
	set.version, set.members = body[2], members
	return keys
}

func TestQualA11R3RoleMapRotation(t *testing.T) {
	c, ctx, keys := qualR3Fixture(t, 100)
	creation := qualA38Bytes(t, "creation")
	original, originalHash := bytes.Clone(ctx.intentBody), bytes.Clone(ctx.intentHash)
	admission := qualA38Envelope(qualR3Message(ctx, "REGISTER_TOKEN_ADMISSION", 10, 90), keys["REGISTER_TOKEN_ADMISSION"], 0, 2, 4)
	pa := qualA38Envelope(qualR3Message(ctx, "PROGRAM_ADMINISTRATION", 10, 90), keys["PROGRAM_ADMINISTRATION"], 0, 2, 4)
	independent := qualA38Envelope(qualA38Message(t, ctx, 10, 90), keys["REGISTER_TOKEN"], 0, 2, 4)
	newC := qualR3Rotate(&ctx.independent, 3)
	require.Error(t, qualR3Verify(c, admission, creation, ctx, "REGISTER_TOKEN_ADMISSION"))
	require.Error(t, c.verifyIndependent(independent, creation, ctx))
	require.NoError(t, qualR3Verify(c, qualA38Envelope(qualR3Message(ctx, "REGISTER_TOKEN_ADMISSION", 10, 90), keys["REGISTER_TOKEN_ADMISSION"], 0, 2, 4), creation, ctx, "REGISTER_TOKEN_ADMISSION"))
	require.NoError(t, c.verifyIndependent(qualA38Envelope(qualA38Message(t, ctx, 10, 90), newC, 0, 2, 4), creation, ctx))
	require.NoError(t, qualR3Verify(c, pa, creation, ctx, "PROGRAM_ADMINISTRATION"))
	require.Equal(t, original, ctx.intentBody)
	require.Equal(t, originalHash, ctx.intentHash)

	// A-row change invalidates this map-bound certificate too. No assertion
	// allocates continued validity or succession of the embedded A decision.
	freshA := qualA38Envelope(qualR3Message(ctx, "REGISTER_TOKEN_ADMISSION", 10, 90), keys["REGISTER_TOKEN_ADMISSION"], 0, 2, 4)
	qualR3Rotate(&ctx.admission, 4)
	require.Error(t, qualR3Verify(c, freshA, creation, ctx, "REGISTER_TOKEN_ADMISSION"))
	require.Equal(t, original, ctx.intentBody)
}

func TestQualA11R3CertificateContextAndBody(t *testing.T) {
	for _, purpose := range []string{"REGISTER_TOKEN_ADMISSION", "PROGRAM_ADMINISTRATION"} {
		for _, target := range []string{"admission", "pa", "independent"} {
			for _, fault := range []string{"roster", "threshold", "version", "body_hash", "unsupported_body"} {
				t.Run(purpose+"/"+target+"/"+fault, func(t *testing.T) {
					c, ctx, keys := qualR3Fixture(t, 100)
					valid := qualA38Envelope(qualR3Message(ctx, purpose, 10, 90), keys[purpose], 0, 2, 4)
					require.NoError(t, qualR3Verify(c, valid, qualA38Bytes(t, "creation"), ctx, purpose))
					set := &ctx.admission
					selected := "REGISTER_TOKEN_ADMISSION"
					if target == "pa" {
						set, selected = &ctx.pa, "PROGRAM_ADMINISTRATION"
					} else if target == "independent" {
						set, selected = &ctx.independent, "REGISTER_TOKEN"
					}
					private := append([]stded.PrivateKey(nil), keys[purpose]...)
					indices := []uint64{0, 2, 4}
					switch fault {
					case "roster":
						members, other := qualA38Keys(6)
						set.members = append([][]byte(nil), set.members...)
						set.members[0] = members[0]
						if selected == purpose {
							private[0] = other[0]
						}
					case "threshold":
						set.threshold = 4
						indices = []uint64{0, 1, 2, 4}
					case "version":
						set.version = qualA38U64(binary.BigEndian.Uint64(set.version) + 1)
					case "body_hash":
						set.bodyHash = bytes.Repeat([]byte{0x77}, 32)
					case "unsupported_body":
						set.body = []byte("opaque body is not a supported B9 schema")
					}
					message := qualR3Message(ctx, purpose, 10, 90)
					envelope := qualA38Envelope(message, private, indices...)
					// Signatures themselves are independently valid under the supplied
					// roster; only the B9/body/original-intent relation is substituted.
					sigs := qualA38Split(qualA38Split(envelope)[2])
					for i, index := range indices {
						require.True(t, stded.Verify(private[index].Public().(stded.PublicKey), qualA38Hash(message), sigs[i]))
					}
					require.Error(t, qualR3Verify(c, envelope, qualA38Bytes(t, "creation"), ctx, purpose))
				})
			}
		}
		for _, fault := range []string{"unknown_purpose", "cross_purpose", "nil_context", "missing_span", "narrow_span", "current_pa_substitution"} {
			t.Run(purpose+"/"+fault, func(t *testing.T) {
				c, ctx, keys := qualR3Fixture(t, 100)
				message := qualR3Message(ctx, purpose, 10, 90)
				envelope := qualA38Envelope(message, keys[purpose], 0, 2, 4)
				require.NoError(t, qualR3Verify(c, envelope, qualA38Bytes(t, "creation"), ctx, purpose))
				expected := purpose
				switch fault {
				case "unknown_purpose":
					expected = "REGISTER_TOKEN"
				case "cross_purpose":
					expected = "PROGRAM_ADMINISTRATION"
					if purpose == expected {
						expected = "REGISTER_TOKEN_ADMISSION"
					}
				case "nil_context":
					ctx = nil
				case "missing_span":
					c.bounds.maxValidity = 0
				case "narrow_span":
					c.bounds.maxValidity = 10
				case "current_pa_substitution":
					qualR3Rotate(&ctx.pa, 7)
				}
				require.Error(t, qualR3Verify(c, envelope, qualA38Bytes(t, "creation"), ctx, expected))
			})
		}
	}
}

func TestQualA11R3CertificateHasNoAlternateValidityLimit(t *testing.T) {
	for _, purpose := range []string{"REGISTER_TOKEN_ADMISSION", "PROGRAM_ADMINISTRATION"} {
		c, ctx, keys := qualR3Fixture(t, 100)
		message := qualR3Message(ctx, purpose, 50, 50)
		envelope := qualA38Envelope(message, keys[purpose], 0, 2, 4)
		require.NoError(t, qualR3Verify(c, envelope, qualA38Bytes(t, "creation"), ctx, purpose))
		c.bounds.maxValidity = 0
		require.Error(t, qualR3Verify(c, envelope, qualA38Bytes(t, "creation"), ctx, purpose), "even zero span cannot supply a missing admitted limit")
		c.bounds.maxValidity = 100 // restore the same explicitly labelled fixture limit
		require.NoError(t, qualR3Verify(c, envelope, qualA38Bytes(t, "creation"), ctx, purpose))
	}
}

// This bridge keeps the missing-producer regression behavioral rather than a
// compile error. No fallback can construct or authenticate a message.
func qualR3Preimage(c *registrationApprovalCodec, creation []byte, ctx *registrationApprovalContext, purpose string, nb, na uint64) ([]byte, []byte, error) {
	producer, exists := any(c).(interface {
		authorityCertificatePreimage([]byte, *registrationApprovalContext, string, uint64, uint64) ([]byte, []byte, error)
	})
	if !exists {
		return nil, nil, errInvalidRegistrationRecord
	}
	return producer.authorityCertificatePreimage(creation, ctx, purpose, nb, na)
}

func TestQualA11R3IndependentSigningPreimage(t *testing.T) {
	for _, purpose := range []string{"REGISTER_TOKEN_ADMISSION", "PROGRAM_ADMINISTRATION"} {
		t.Run(purpose, func(t *testing.T) {
			c, ctx, keys := qualR3Fixture(t, 100)
			// Expected bytes/hash are the pre-existing independent manual framing and
			// BLAKE2b oracle, not output from the new producer or consuming encoder.
			expected := qualR3Message(ctx, purpose, 10, 90)
			wantDigest := qualA38Hash(expected)
			beforeIntent, beforeHash := bytes.Clone(ctx.intentBody), bytes.Clone(ctx.intentHash)
			message, digest, err := qualR3Preimage(c, qualA38Bytes(t, "creation"), ctx, purpose, 10, 90)
			require.NoError(t, err, "selected certificate signing preimage must be constructible")
			require.Equal(t, expected, message)
			require.Equal(t, wantDigest, digest)
			require.Equal(t, beforeIntent, ctx.intentBody)
			require.Equal(t, beforeHash, ctx.intentHash)
			signatures := qualA38Envelope(message, keys[purpose], 0, 2, 4)
			require.NoError(t, qualR3Verify(c, signatures, qualA38Bytes(t, "creation"), ctx, purpose))
		})
	}
}

func TestQualA11R3SigningPreimageRefusesIncompleteInputs(t *testing.T) {
	for _, purpose := range []string{"REGISTER_TOKEN_ADMISSION", "PROGRAM_ADMINISTRATION"} {
		for _, fault := range []string{"nil_codec", "nil_context", "missing_bound", "unknown_purpose", "future", "expired", "reversed", "overflow", "intent_expiry", "over_span", "creation", "intent", "pa_body", "admission_body", "independent_body", "profile", "network", "missing_original_pa"} {
			t.Run(purpose+"/"+fault, func(t *testing.T) {
				c, ctx, _ := qualR3Fixture(t, 100)
				creation := qualA38Bytes(t, "creation")
				nb, na := uint64(10), uint64(90)
				selected := purpose
				switch fault {
				case "nil_codec":
					c = nil
				case "nil_context":
					ctx = nil
				case "missing_bound":
					c.bounds.maxValidity = 0
				case "unknown_purpose":
					selected = "REGISTER_TOKEN"
				case "future":
					nb = 51
				case "expired":
					na = 49
				case "reversed":
					nb, na = 90, 10
				case "overflow":
					nb, na = ^uint64(0), 0
				case "intent_expiry":
					na = 101
				case "over_span":
					nb = 0
					c.bounds.maxValidity = 89
				case "creation":
					creation = creation[:len(creation)-1]
				case "intent":
					ctx.intentBody = ctx.intentBody[:len(ctx.intentBody)-1]
				case "pa_body":
					ctx.pa.body = bytes.Clone(ctx.admission.body)
				case "admission_body":
					ctx.admission.body = bytes.Clone(ctx.independent.body)
				case "independent_body":
					ctx.independent.body = bytes.Clone(ctx.admission.body)
				case "profile":
					ctx.profile = nil
				case "network":
					ctx.network = []byte("foreign")
				case "missing_original_pa":
					ctx.pa.bodyHash = nil
				}
				message, digest, err := qualR3Preimage(c, creation, ctx, selected, nb, na)
				require.Error(t, err)
				require.Nil(t, message)
				require.Nil(t, digest)
				// M14 preserves its existing trusted-context contract: A/C body
				// authentication belongs to their native producer, not this
				// signing-data codec. M12 additionally decodes B9 bodies.
				if fault != "unknown_purpose" && fault != "admission_body" && fault != "independent_body" {
					independent, hash, e := qualR3IndependentPreimage(c, creation, ctx, nb, na)
					require.Error(t, e)
					require.Nil(t, independent)
					require.Nil(t, hash)
				}
			})
		}
	}
}

func qualR3IndependentPreimage(c *registrationApprovalCodec, creation []byte, ctx *registrationApprovalContext, nb, na uint64) ([]byte, []byte, error) {
	producer, exists := any(c).(interface {
		independentApprovalPreimage([]byte, *registrationApprovalContext, uint64, uint64) ([]byte, []byte, error)
	})
	if !exists {
		return nil, nil, errInvalidRegistrationRecord
	}
	return producer.independentApprovalPreimage(creation, ctx, nb, na)
}

func TestQualA11R3IndependentApprovalSigningPreimage(t *testing.T) {
	c, ctx, keys := qualR3Fixture(t, 100)
	creation := qualA38Bytes(t, "creation")
	want := qualA38Message(t, ctx, 10, 90)
	message, digest, err := qualR3IndependentPreimage(c, creation, ctx, 10, 90)
	require.NoError(t, err, "the independent REGISTER_TOKEN approval needs its exact existing M14 preimage")
	require.Equal(t, want, message)
	require.Equal(t, qualA38Hash(want), digest)
	require.NoError(t, c.verifyIndependent(qualA38Envelope(message, keys["REGISTER_TOKEN"], 0, 2, 4), creation, ctx))
	// The two M12 purpose certificates cannot discharge independent approval.
	for _, purpose := range []string{"REGISTER_TOKEN_ADMISSION", "PROGRAM_ADMINISTRATION"} {
		other, otherHash, e := qualR3Preimage(c, creation, ctx, purpose, 10, 90)
		require.NoError(t, e)
		require.NotEqual(t, message, other)
		require.NotEqual(t, digest, otherHash)
		require.Error(t, c.verifyIndependent(qualA38Envelope(other, keys[purpose], 0, 2, 4), creation, ctx))
	}
}
