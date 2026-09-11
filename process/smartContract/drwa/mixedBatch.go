package drwa

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// DO_NOT_EXPOSE_AS_PUBLIC_WIRE_FORMAT
// REPLACED_BY_PART_B
//
// This file defines the S1 shared semantic seam for a future S8 mixed batch. It binds the
// baseline parser's complete ordered leg vector and terminal outcome, but does not execute,
// settle or refund a batch.

const (
	drwaMixedBatchVersion = byte(1)
	drwaMixedBatchMaxLegs = 10_000

	drwaMixedBatchLegsDomain = "DRWA/PROTOTYPE/FULL_BATCH_LEGS/v1"
)

var (
	// ErrInvalidMixedBatch signals a malformed or incomplete S1 mixed-batch binding.
	ErrInvalidMixedBatch = errors.New("invalid non-normative DRWA prototype mixed batch")
	// ErrMultipleRegulatedTokenIdentifiers signals more than one regulated identifier in a batch.
	ErrMultipleRegulatedTokenIdentifiers = errors.New("non-normative DRWA prototype mixed batch has multiple regulated token identifiers")
	// ErrInvalidMixedBatchOutcome signals a terminal outcome not bound to the complete batch.
	ErrInvalidMixedBatchOutcome = errors.New("invalid non-normative DRWA prototype mixed-batch outcome")
)

// MixedBatchLegKind distinguishes an ESDT tuple from the explicitly typed native-EGLD leg.
type MixedBatchLegKind byte

const (
	// MixedBatchLegKindESDT identifies one normalized ESDT token/nonce/quantity tuple.
	MixedBatchLegKindESDT MixedBatchLegKind = 1
	// MixedBatchLegKindNativeEGLD identifies one normalized native-EGLD value leg.
	MixedBatchLegKindNativeEGLD MixedBatchLegKind = 2
)

// MixedBatchLeg is one normalized leg from the baseline parser's complete ordered vector.
// Regulated is classification context and is deliberately excluded from FullBatchLegsDigest;
// the regulated identifier and CEB epoch are committed by the enclosing DRWA context.
type MixedBatchLeg struct {
	Kind      MixedBatchLegKind
	TokenID   []byte
	Nonce     uint64
	Quantity  []byte
	Regulated bool
}

// MixedBatchBinding commits every ordinary, regulated and native-EGLD leg in source order.
type MixedBatchBinding struct {
	Legs                []MixedBatchLeg
	RegulatedTokenID    []byte
	FullBatchLegsDigest [drwaDigestLength]byte
}

// MixedBatchOutcomeKind identifies the only two terminal outcomes of one atomic batch.
type MixedBatchOutcomeKind byte

const (
	// MixedBatchOutcomeSettled means every leg completed as one batch.
	MixedBatchOutcomeSettled MixedBatchOutcomeKind = 1
	// MixedBatchOutcomeRefunded means the already-debited complete batch is returned once.
	MixedBatchOutcomeRefunded MixedBatchOutcomeKind = 2
)

// MixedBatchOutcomeIntent supplies the existing S1 effect identities for one terminal batch result.
type MixedBatchOutcomeIntent struct {
	Kind                         MixedBatchOutcomeKind
	EffectID                     [drwaDigestLength]byte
	ContextHash                  [drwaDigestLength]byte
	DestinationExecutionIdentity [drwaDigestLength]byte
	OriginalTransferPayload      []byte
	RefundTo                     [drwaAddressLength]byte
}

// MixedBatchTerminalOutcome binds one terminal result to the full ordered batch. A refund carries
// the original payload; a settled outcome does not. Exactly-once mutation remains owned by the S1
// OpenEffect lifecycle and is integrated with batch execution in S8.
type MixedBatchTerminalOutcome struct {
	Kind                         MixedBatchOutcomeKind
	EffectID                     [drwaDigestLength]byte
	ContextHash                  [drwaDigestLength]byte
	DestinationExecutionIdentity [drwaDigestLength]byte
	FullBatchLegsDigest          [drwaDigestLength]byte
	OriginalTransferPayload      []byte
	RefundTo                     [drwaAddressLength]byte
}

// BuildMixedBatchBinding validates and copies the complete classified leg vector, enforces the
// one-regulated-token-identifier rule and derives its canonical ordered digest.
func BuildMixedBatchBinding(legs []MixedBatchLeg) (*MixedBatchBinding, error) {
	if len(legs) == 0 || len(legs) > drwaMixedBatchMaxLegs {
		return nil, fmt.Errorf("%w: leg count", ErrInvalidMixedBatch)
	}

	clonedLegs := make([]MixedBatchLeg, len(legs))
	var regulatedTokenID []byte
	for index, leg := range legs {
		if err := validateMixedBatchLeg(leg); err != nil {
			return nil, fmt.Errorf("%w: leg %d: %v", ErrInvalidMixedBatch, index, err)
		}
		clonedLegs[index] = MixedBatchLeg{
			Kind:      leg.Kind,
			TokenID:   append([]byte(nil), leg.TokenID...),
			Nonce:     leg.Nonce,
			Quantity:  append([]byte(nil), leg.Quantity...),
			Regulated: leg.Regulated,
		}
		if !leg.Regulated {
			continue
		}
		if regulatedTokenID == nil {
			regulatedTokenID = append([]byte(nil), leg.TokenID...)
			continue
		}
		if !bytes.Equal(regulatedTokenID, leg.TokenID) {
			return nil, ErrMultipleRegulatedTokenIdentifiers
		}
	}
	if len(regulatedTokenID) == 0 {
		return nil, fmt.Errorf("%w: no regulated token", ErrInvalidMixedBatch)
	}
	for index, leg := range clonedLegs {
		if leg.Kind == MixedBatchLegKindESDT && bytes.Equal(leg.TokenID, regulatedTokenID) && !leg.Regulated {
			return nil, fmt.Errorf("%w: leg %d: inconsistent regulated-token classification", ErrInvalidMixedBatch, index)
		}
	}

	digest := digestMixedBatchLegs(clonedLegs)
	return &MixedBatchBinding{
		Legs:                clonedLegs,
		RegulatedTokenID:    regulatedTokenID,
		FullBatchLegsDigest: digest,
	}, nil
}

// ValidateMixedBatchBinding rejects a modified, reordered, truncated or reclassified binding.
func ValidateMixedBatchBinding(binding MixedBatchBinding) error {
	rebuilt, err := BuildMixedBatchBinding(binding.Legs)
	if err != nil {
		return err
	}
	if !bytes.Equal(rebuilt.RegulatedTokenID, binding.RegulatedTokenID) ||
		rebuilt.FullBatchLegsDigest != binding.FullBatchLegsDigest {
		return fmt.Errorf("%w: binding mismatch", ErrInvalidMixedBatch)
	}
	return nil
}

// BuildMixedBatchTerminalOutcome creates one settled or full-refund result bound to the complete
// parsed batch. It performs no state mutation or message emission.
func BuildMixedBatchTerminalOutcome(
	binding MixedBatchBinding,
	intent MixedBatchOutcomeIntent,
) (*MixedBatchTerminalOutcome, error) {
	if err := ValidateMixedBatchBinding(binding); err != nil {
		return nil, fmt.Errorf("%w: batch binding: %v", ErrInvalidMixedBatchOutcome, err)
	}
	outcome := &MixedBatchTerminalOutcome{
		Kind:                         intent.Kind,
		EffectID:                     intent.EffectID,
		ContextHash:                  intent.ContextHash,
		DestinationExecutionIdentity: intent.DestinationExecutionIdentity,
		FullBatchLegsDigest:          binding.FullBatchLegsDigest,
		OriginalTransferPayload:      append([]byte(nil), intent.OriginalTransferPayload...),
		RefundTo:                     intent.RefundTo,
	}
	if err := ValidateMixedBatchTerminalOutcome(binding, *outcome); err != nil {
		return nil, err
	}
	return outcome, nil
}

// ValidateMixedBatchTerminalOutcome proves that one terminal result identifies the exact complete
// batch. A caller validates the original payload through the shared baseline parser before
// supplying the corresponding binding.
func ValidateMixedBatchTerminalOutcome(
	binding MixedBatchBinding,
	outcome MixedBatchTerminalOutcome,
) error {
	if err := ValidateMixedBatchBinding(binding); err != nil {
		return fmt.Errorf("%w: batch binding: %v", ErrInvalidMixedBatchOutcome, err)
	}
	if isZeroDRWADigest(outcome.EffectID) ||
		isZeroDRWADigest(outcome.ContextHash) ||
		isZeroDRWADigest(outcome.DestinationExecutionIdentity) ||
		outcome.FullBatchLegsDigest != binding.FullBatchLegsDigest {
		return fmt.Errorf("%w: identity binding", ErrInvalidMixedBatchOutcome)
	}

	switch outcome.Kind {
	case MixedBatchOutcomeSettled:
		if len(outcome.OriginalTransferPayload) != 0 || outcome.RefundTo != ([drwaAddressLength]byte{}) {
			return fmt.Errorf("%w: settled payload", ErrInvalidMixedBatchOutcome)
		}
	case MixedBatchOutcomeRefunded:
		if len(outcome.OriginalTransferPayload) == 0 ||
			len(outcome.OriginalTransferPayload) > drwaPayloadLimit ||
			outcome.RefundTo == ([drwaAddressLength]byte{}) {
			return fmt.Errorf("%w: refund payload", ErrInvalidMixedBatchOutcome)
		}
	default:
		return fmt.Errorf("%w: outcome kind", ErrInvalidMixedBatchOutcome)
	}
	return nil
}

func validateMixedBatchLeg(leg MixedBatchLeg) error {
	if len(leg.Quantity) == 0 || len(leg.Quantity) > drwaQuantityLimit || leg.Quantity[0] == 0 {
		return errors.New("non-canonical quantity")
	}
	switch leg.Kind {
	case MixedBatchLegKindESDT:
		if !vmcommon.ValidateToken(leg.TokenID) || len(leg.TokenID) > drwaTokenIDLimit ||
			bytes.Equal(leg.TokenID, []byte(vmcommon.EGLDIdentifier)) {
			return errors.New("invalid ESDT token identifier")
		}
	case MixedBatchLegKindNativeEGLD:
		if len(leg.TokenID) != 0 || leg.Nonce != 0 || leg.Regulated {
			return errors.New("invalid native EGLD leg")
		}
	default:
		return errors.New("unknown leg kind")
	}
	return nil
}

func digestMixedBatchLegs(legs []MixedBatchLeg) [drwaDigestLength]byte {
	encoded := make([]byte, 0, len(drwaMixedBatchLegsDomain)+1+4+len(legs)*48)
	encoded = append(encoded, drwaMixedBatchLegsDomain...)
	encoded = append(encoded, drwaMixedBatchVersion)
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(legs)))
	for index, leg := range legs {
		encoded = binary.BigEndian.AppendUint32(encoded, uint32(index))
		encoded = append(encoded, byte(leg.Kind))
		encoded = appendUint16Bytes(encoded, leg.TokenID)
		encoded = binary.BigEndian.AppendUint64(encoded, leg.Nonce)
		encoded = appendUint16Bytes(encoded, leg.Quantity)
	}
	return sha256.Sum256(encoded)
}
