package drwa

import (
	"bytes"
	"encoding/binary"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// RegisterTokenForCommittedCreation is DRWA-defined, unwired construction of
// Part A L2199-2204 using ledger L41's experimental format (proposal e30be12c).
// It compares the actual creation tuple with the retained intent INSIDE T04,
// before invoking the native creator. The callback receives only the minimal
// native property arguments derived from the validated L39 profile.
//
// bodyDigest is the exact type_specific_body_digest to which the eventual T14
// producer must authenticate fresh certificates. Supplying it is NOT authority:
// issuer authentication, lawful current admission/approvals, support/epoch/expiry,
// canonical finality, fee ownership and configuration admission remain due.
// Profile bytes/manager are supplied experimental inputs, not allocated values.
// No ordinary route imports this component. Buffers must be stable on entry;
// private copies bind subsequent execution. The callback must use this same
// tuple, must not publish outputs, and must not commit the native journal.
func (o *RegistrationIntentOwner) RegisterTokenForCommittedCreation(issuer, manager, family,
	profile, name, ticker []byte, decimals uint32, bodyDigest []byte,
	create func(state.AccountsAdapter, [][]byte) ([]byte, *vmcommon.VMOutput, error)) error {
	if o == nil || o.records == nil || create == nil {
		return errInvalidRegistrationRecord
	}
	// Refuse oversize arguments before copying, decoding or hashing. The caller
	// supplies the existing positive, qualified record bound; no new default.
	inputs := [][]byte{issuer, manager, family, profile, name, ticker, bodyDigest}
	for i, input := range inputs {
		if len(input) > o.records.maxBytes {
			return errInvalidRegistrationRecord
		}
		inputs[i] = bytes.Clone(input)
	}
	issuer, manager, family, profile, name, ticker, bodyDigest = inputs[0], inputs[1], inputs[2], inputs[3], inputs[4], inputs[5], inputs[6]
	return o.RegisterTokenForCreation(issuer, manager, family,
		func(accounts state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
			intent, err := o.records.intent(o.id)
			if err != nil {
				return nil, nil, err
			}
			properties, err := o.records.creationProperties(intent.body, manager, family, profile,
				name, ticker, decimals, bodyDigest)
			if err != nil {
				return nil, nil, err
			}
			return create(accounts, properties)
		})
}

// creationProperties reuses the bounded canonical native Batch decoder and
// configured native hasher. It introduces no storage, authority or serializer.
// Semantic properties commit the validated fixed fields plus native uint32
// NumDecimals, never aliases/order in an externally supplied property list.
func (s *registrationRecords) creationProperties(body bootstrapIntentBody, manager, family,
	profile, name, ticker []byte, decimals uint32, bodyDigest []byte) ([][]byte, error) {
	f, err := s.unframe(profile, 14)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(f[0], []byte("DRWA/CREATION_PROFILE/v2")) || !bytes.Equal(f[1], body.networkDomain) ||
		!bytes.Equal(f[2], manager) || !bytes.Equal(f[3], family) {
		return nil, errInvalidRegistrationRecord
	}
	transfer := byte(0)
	switch string(family) {
	case core.FungibleESDT:
	case core.NonFungibleESDTv2, core.SemiFungibleESDT, core.MetaESDT,
		core.DynamicNFTESDT, core.DynamicSFTESDT, core.DynamicMetaESDT:
		transfer = 1
	default:
		return nil, errInvalidRegistrationRecord
	}
	for i, field := range f[4:] {
		want := byte(0)
		if i == 1 {
			want = 1 // CanAddSpecialRoles
		}
		if i == 9 {
			want = transfer // CanTransferNFTCreateRole, L39
		}
		if len(field) != 1 || field[0] != want {
			return nil, errInvalidRegistrationRecord
		}
	}
	profileHash := s.hasher.Compute(string(profile))
	if !bytes.Equal(profileHash, body.creationProfile) {
		return nil, errInvalidRegistrationRecord
	}
	checkCommitment := func(domain string, expected []byte, fields ...[]byte) error {
		preimage, frameErr := s.frame(append([][]byte{[]byte(domain)}, fields...)...)
		if frameErr != nil {
			return frameErr
		}
		if !bytes.Equal(s.hasher.Compute(string(preimage)), expected) {
			return errInvalidRegistrationRecord
		}
		return nil
	}
	if err = checkCommitment("DRWA/CREATION_NAME/v1", body.nameCommitment, name); err != nil {
		return nil, err
	}
	if err = checkCommitment("DRWA/CREATION_TICKER/v1", body.tickerCommitment, ticker); err != nil {
		return nil, err
	}
	width := make([]byte, 4)
	binary.BigEndian.PutUint32(width, decimals)
	if err = checkCommitment("DRWA/CREATION_PROPERTIES/v1", body.propertyCommitment, profileHash, width); err != nil {
		return nil, err
	}
	if err = checkCommitment("DRWA/TOKEN_CREATION_BODY/v1", bodyDigest, family, profileHash, name, ticker, width); err != nil {
		return nil, err
	}
	// Native createNewToken starts all other selected fields false. Upgradable
	// starts true, CanAddSpecialRoles true (06c383cf esdt.go L695-708). Reuse
	// native wire names (L42 and upgradeProperties L800-846), not Go aliases.
	properties := [][]byte{[]byte("canUpgrade"), []byte("false"), []byte("canAddSpecialRoles"), []byte("true")}
	if transfer == 1 {
		properties = append(properties, []byte("canTransferNFTCreateRole"), []byte("true"))
	}
	return properties, nil
}
