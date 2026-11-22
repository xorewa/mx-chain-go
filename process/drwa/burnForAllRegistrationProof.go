package drwa

import (
	"bytes"
	"encoding/binary"

	"github.com/multiversx/mx-chain-core-go/core"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// BurnForAllRegistrationWitness is untrusted proof/creation-tuple transport.
// E10 option b needs exact registration/profile/manager binding (Part A
// L2265-2266/L2355-2373, SHA d2f6ea1d4036c32e8778da53f135961de91cf0d8576c930fb0dd76651e1c7831).
// Reuses T19's ledger L41 canonical experimental records/profile only; it grants
// no ingress, current authority, production allocation or ACK capability.
type BurnForAllRegistrationWitness struct {
	Association, Intent, Activation AccountItemWitness
	Profile, Name, Ticker           []byte
	Decimals                        uint32
}

// Authenticate internally derived native system-account keys at the EXACT
// materialized meta root. No local marker or transport assertion supplies the
// association's issuer/programme/intent/profile/manager identity. No new codec,
// registry, profile, persistence or caller-selectable protected key is created.
func (b *BurnForAllAbsence) authenticateRegistration(tokenID []byte, w BurnForAllRegistrationWitness) (bootstrapIntentBody, error) {
	bad := func() (bootstrapIntentBody, error) { return bootstrapIntentBody{}, errInvalidRegistrationRecord }
	if !vmcommon.ValidateToken(tokenID) {
		return bad()
	}
	for _, x := range [][]byte{w.Profile, w.Name, w.Ticker} {
		if len(x) > b.records.maxBytes {
			return bad()
		}
	}
	remaining := b.transport.proofByteLimit
	read := func(key []byte, witness AccountItemWitness) ([]byte, error) {
		n, e := registryProofBytes(witness, remaining)
		if e != nil {
			return nil, e
		}
		value, e := b.transport.reader.readRegistryItem(&b.material.required, key, witness, remaining)
		if e != nil {
			return nil, e
		}
		remaining -= n
		return value, nil
	}
	encoded, err := read(append([]byte(registrationAssociationPrefix), tokenID...), w.Association)
	if err != nil {
		return bootstrapIntentBody{}, err
	}
	f, err := b.records.unframe(encoded, 5)
	if err != nil {
		return bootstrapIntentBody{}, err
	}
	if !bytes.Equal(f[0], tokenID) || len(f[1]) != b.records.hasher.Size() || len(f[4]) != len(core.SystemAccountAddress) {
		return bad()
	}
	body, err := b.records.decodeBody(f[3])
	if err != nil {
		return bootstrapIntentBody{}, err
	}
	_, digest, id, err := b.records.identity(body)
	if err != nil {
		return bootstrapIntentBody{}, err
	}
	if !bytes.Equal(id, f[1]) || !bytes.Equal(digest, f[2]) {
		return bad()
	}
	consumed, err := read(append([]byte(registrationIntentPrefix), id...), w.Intent)
	if err != nil {
		return bootstrapIntentBody{}, err
	}
	fields, err := b.records.unframe(consumed, 3)
	if err != nil {
		return bootstrapIntentBody{}, err
	}
	if !bytes.Equal(fields[0], f[3]) || !bytes.Equal(fields[1], []byte("CONSUMED")) || !bytes.Equal(fields[2], tokenID) {
		return bad()
	}
	activation, err := read(append([]byte(registrationActivationPrefix), tokenID...), w.Activation)
	if err != nil {
		return bootstrapIntentBody{}, err
	}
	want, err := b.records.frame(tokenID, id, []byte("BootstrapDeny"))
	if err != nil {
		return bootstrapIntentBody{}, err
	}
	if !bytes.Equal(want, activation) {
		return bad()
	}
	width := make([]byte, 4)
	binary.BigEndian.PutUint32(width, w.Decimals)
	preimage, err := b.records.frame([]byte("DRWA/TOKEN_CREATION_BODY/v1"), body.requestedTokenFamily, body.creationProfile, w.Name, w.Ticker, width)
	if err != nil {
		return bootstrapIntentBody{}, err
	}
	// Existing L41 validator checks full profile/network/manager/family/fixed
	// fields plus authenticated name/ticker/property commitments, not our claims.
	_, err = b.records.creationProperties(body, f[4], body.requestedTokenFamily, w.Profile, w.Name, w.Ticker, w.Decimals, b.records.hasher.Compute(string(preimage)))
	if err != nil {
		return bootstrapIntentBody{}, err
	}
	return body, nil
}
