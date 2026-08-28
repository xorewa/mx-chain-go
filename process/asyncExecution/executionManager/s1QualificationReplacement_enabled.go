//go:build drwa_s1_qual_replacement

package executionManager

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-go/common/drwaqualification"
	"github.com/multiversx/mx-chain-go/process/asyncExecution/cache"
)

type s1QualificationReplacement struct {
	manager              *executionManager
	arm                  *drwaqualification.Arm
	recorder             *drwaqualification.Recorder
	retainedHash         []byte
	retainedHeaderBytes  []byte
	retainedBodyBytes    []byte
	headerType           reflect.Type
	bodyType             reflect.Type
	retainedHeaderDigest [32]byte
	retainedBodyDigest   [32]byte
	replayed             bool
}

func init() {
	drwaqualification.RegisterVariant(drwaqualification.VariantReplacement)
}

func newS1QualificationReplacement(manager *executionManager) (*s1QualificationReplacement, error) {
	arm, armHash, err := drwaqualification.LoadArmFromEnvironment(drwaqualification.VariantReplacement, time.Now())
	if errors.Is(err, drwaqualification.ErrArmUnavailable) {
		return &s1QualificationReplacement{manager: manager}, nil
	}
	if err != nil {
		return nil, err
	}
	if !drwaqualification.DeclaredActionTagMatches(arm, "REPLAY_RETAINED_PAIR_ON_TRIGGER_ONCE") {
		return nil, fmt.Errorf("%w: replacement declared action", drwaqualification.ErrInvalidArm)
	}
	if err = drwaqualification.VerifyRunningBinary(arm); err != nil {
		return nil, err
	}
	recorder, err := drwaqualification.CreateRecorder(arm.EvidencePath, armHash, arm)
	if err != nil {
		return nil, err
	}
	if err = recorder.Append(drwaqualification.LifecycleLoaded, map[string]any{
		"retained_header_hash": arm.Replacement.RetainedHeaderHash,
		"trigger_header_hash":  arm.Replacement.TriggerHeaderHash,
	}); err != nil {
		_ = recorder.Close()
		return nil, err
	}
	return &s1QualificationReplacement{manager: manager, arm: arm, recorder: recorder}, nil
}

func (replacement *s1QualificationReplacement) prepare(pair cache.HeaderBodyPair) ([]cache.HeaderBodyPair, bool, error) {
	if replacement == nil || replacement.arm == nil {
		return []cache.HeaderBodyPair{pair}, false, nil
	}
	if !drwaqualification.DeclaredActionTagMatches(replacement.arm, "REPLAY_RETAINED_PAIR_ON_TRIGGER_ONCE") {
		return nil, false, fmt.Errorf("%w: replacement declared action", drwaqualification.ErrInvalidArm)
	}
	if check.IfNil(pair.Header) || check.IfNil(pair.Body) || len(pair.HeaderHash) == 0 {
		return nil, false, fmt.Errorf("%w: nil replacement pair", drwaqualification.ErrInvalidArm)
	}
	headerBytes, bodyBytes, headerHash, bodyHash, err := replacement.hashPair(pair)
	if err != nil {
		return nil, false, err
	}
	pairHash := hex.EncodeToString(pair.HeaderHash)
	arm := replacement.arm.Replacement
	switch pairHash {
	case arm.RetainedHeaderHash:
		if replacement.retainedHeaderBytes != nil ||
			hex.EncodeToString(headerHash[:]) != arm.RetainedHeaderMarshaledSHA256 ||
			hex.EncodeToString(bodyHash[:]) != arm.RetainedBodyMarshaledSHA256 {
			return nil, false, fmt.Errorf("%w: retained pair identity or cardinality", drwaqualification.ErrInvalidArm)
		}
		if check.IfNil(pair.Header) || check.IfNil(pair.Body) || reflect.TypeOf(pair.Header).Kind() != reflect.Ptr || reflect.TypeOf(pair.Body).Kind() != reflect.Ptr {
			return nil, false, fmt.Errorf("%w: retained dynamic types", drwaqualification.ErrInvalidArm)
		}
		headerType, bodyType := reflect.TypeOf(pair.Header), reflect.TypeOf(pair.Body)
		if _, _, _, restoreErr := replacement.restorePair(headerBytes, bodyBytes, headerType, bodyType, pair.HeaderHash); restoreErr != nil {
			return nil, false, restoreErr
		}
		if err = replacement.recorder.Append(drwaqualification.LifecycleReached, map[string]any{
			"retained_header_marshaled_sha256": hex.EncodeToString(headerHash[:]),
			"retained_body_marshaled_sha256":   hex.EncodeToString(bodyHash[:]),
			"retained_header_bytes":            len(headerBytes),
			"retained_body_bytes":              len(bodyBytes),
		}); err != nil {
			return nil, false, err
		}
		replacement.retainedHash = cloneBytes(pair.HeaderHash)
		replacement.retainedHeaderBytes = cloneBytes(headerBytes)
		replacement.retainedBodyBytes = cloneBytes(bodyBytes)
		replacement.headerType = headerType
		replacement.bodyType = bodyType
		replacement.retainedHeaderDigest = headerHash
		replacement.retainedBodyDigest = bodyHash
		return []cache.HeaderBodyPair{pair}, false, nil
	case arm.TriggerHeaderHash:
		if replacement.retainedHeaderBytes == nil || replacement.replayed ||
			hex.EncodeToString(headerHash[:]) != arm.TriggerHeaderMarshaledSHA256 ||
			hex.EncodeToString(bodyHash[:]) != arm.TriggerBodyMarshaledSHA256 {
			return nil, false, fmt.Errorf("%w: trigger identity, ordering, or cardinality", drwaqualification.ErrInvalidArm)
		}
		retainedCopy, retainedHeaderHash, retainedBodyHash, restoreErr := replacement.restorePair(
			replacement.retainedHeaderBytes, replacement.retainedBodyBytes, replacement.headerType, replacement.bodyType, replacement.retainedHash,
		)
		if restoreErr != nil || retainedHeaderHash != replacement.retainedHeaderDigest || retainedBodyHash != replacement.retainedBodyDigest ||
			!bytes.Equal(retainedCopy.HeaderHash, mustDecodeHash(arm.RetainedHeaderHash)) {
			return nil, false, fmt.Errorf("%w: retained pair alias drift", drwaqualification.ErrInvalidArm)
		}
		replacement.replayed = true
		if err = replacement.recorder.Append(drwaqualification.LifecycleConsumed, map[string]any{
			"trigger_header_marshaled_sha256": hex.EncodeToString(headerHash[:]),
			"trigger_body_marshaled_sha256":   hex.EncodeToString(bodyHash[:]),
			"replay_count":                    1,
		}); err != nil {
			return nil, false, err
		}
		return []cache.HeaderBodyPair{retainedCopy, pair}, true, nil
	default:
		return []cache.HeaderBodyPair{pair}, false, nil
	}
}

func (replacement *s1QualificationReplacement) restorePair(
	headerBytes []byte,
	bodyBytes []byte,
	headerType reflect.Type,
	bodyType reflect.Type,
	headerHash []byte,
) (cache.HeaderBodyPair, [32]byte, [32]byte, error) {
	if headerType == nil || bodyType == nil || headerType.Kind() != reflect.Ptr || bodyType.Kind() != reflect.Ptr {
		return cache.HeaderBodyPair{}, [32]byte{}, [32]byte{}, fmt.Errorf("%w: retained type metadata", drwaqualification.ErrInvalidArm)
	}
	header, ok := reflect.New(headerType.Elem()).Interface().(data.HeaderHandler)
	if !ok {
		return cache.HeaderBodyPair{}, [32]byte{}, [32]byte{}, fmt.Errorf("%w: retained header type", drwaqualification.ErrInvalidArm)
	}
	body, ok := reflect.New(bodyType.Elem()).Interface().(data.BodyHandler)
	if !ok {
		return cache.HeaderBodyPair{}, [32]byte{}, [32]byte{}, fmt.Errorf("%w: retained body type", drwaqualification.ErrInvalidArm)
	}
	if err := replacement.manager.marshaller.Unmarshal(header, cloneBytes(headerBytes)); err != nil {
		return cache.HeaderBodyPair{}, [32]byte{}, [32]byte{}, fmt.Errorf("unmarshal retained header: %w", err)
	}
	if err := replacement.manager.marshaller.Unmarshal(body, cloneBytes(bodyBytes)); err != nil {
		return cache.HeaderBodyPair{}, [32]byte{}, [32]byte{}, fmt.Errorf("unmarshal retained body: %w", err)
	}
	pair := cache.HeaderBodyPair{HeaderHash: cloneBytes(headerHash), Header: header, Body: body}
	_, _, restoredHeaderDigest, restoredBodyDigest, err := replacement.hashPair(pair)
	return pair, restoredHeaderDigest, restoredBodyDigest, err
}

func cloneBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	cloned := make([]byte, len(value))
	copy(cloned, value)
	return cloned
}

func (replacement *s1QualificationReplacement) complete(replayErr error) error {
	if replacement == nil || replacement.arm == nil || !replacement.replayed {
		return replayErr
	}
	if replayErr != nil {
		return replayErr
	}
	if err := replacement.recorder.Append(drwaqualification.LifecycleReleased, map[string]any{
		"dismissal_observation": "EXTERNAL_DOWNSTREAM_OWNER",
	}); err != nil {
		return err
	}
	return replacement.recorder.Close()
}

func (replacement *s1QualificationReplacement) hashPair(pair cache.HeaderBodyPair) ([]byte, []byte, [32]byte, [32]byte, error) {
	headerBytes, err := replacement.manager.marshaller.Marshal(pair.Header)
	if err != nil {
		return nil, nil, [32]byte{}, [32]byte{}, fmt.Errorf("marshal replacement header: %w", err)
	}
	bodyBytes, err := replacement.manager.marshaller.Marshal(pair.Body)
	if err != nil {
		return nil, nil, [32]byte{}, [32]byte{}, fmt.Errorf("marshal replacement body: %w", err)
	}
	return headerBytes, bodyBytes, sha256.Sum256(headerBytes), sha256.Sum256(bodyBytes), nil
}

func mustDecodeHash(value string) []byte {
	decoded, _ := hex.DecodeString(value)
	return decoded
}
