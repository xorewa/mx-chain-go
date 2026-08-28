//go:build drwa_s1_qual_transport

package interceptorscontainer

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common/drwaqualification"
	"github.com/multiversx/mx-chain-go/p2p"
	"github.com/multiversx/mx-chain-go/process"
)

type s1TransportInterceptor struct {
	process.Interceptor
	topic      string
	arm        *drwaqualification.Arm
	recorder   *drwaqualification.Recorder
	mu         sync.Mutex
	matchCount uint32
}

func init() {
	drwaqualification.RegisterVariant(drwaqualification.VariantTransport)
}

func s1QualificationTransportSeam(topic string, interceptor process.Interceptor) (process.Interceptor, error) {
	arm, armHash, err := drwaqualification.LoadArmFromEnvironment(drwaqualification.VariantTransport, time.Now())
	if errors.Is(err, drwaqualification.ErrArmUnavailable) {
		return interceptor, nil
	}
	if err != nil {
		return nil, err
	}
	if !drwaqualification.DeclaredActionTagMatches(arm, arm.Transport.DeclaredDeliveryAction) {
		return nil, fmt.Errorf("%w: transport declared action", drwaqualification.ErrInvalidArm)
	}
	if topic != arm.Transport.BaseTopic {
		return interceptor, nil
	}
	if _, statErr := os.Lstat(arm.Transport.ReleasePath); statErr == nil {
		return nil, fmt.Errorf("%w: transport release pre-exists arm load", drwaqualification.ErrInvalidArm)
	} else if !os.IsNotExist(statErr) {
		return nil, fmt.Errorf("%w: transport release preflight: %v", drwaqualification.ErrInvalidArm, statErr)
	}
	if err = drwaqualification.VerifyRunningBinary(arm); err != nil {
		return nil, err
	}
	recorder, err := drwaqualification.CreateRecorder(arm.EvidencePath, armHash, arm)
	if err != nil {
		return nil, err
	}
	if err = recorder.Append(drwaqualification.LifecycleLoaded, map[string]any{
		"base_topic":      topic,
		"source_shard":    arm.Transport.SourceShard,
		"receiving_shard": arm.Transport.ReceivingShard,
	}); err != nil {
		_ = recorder.Close()
		return nil, err
	}
	return &s1TransportInterceptor{Interceptor: interceptor, topic: topic, arm: arm, recorder: recorder}, nil
}

func (decorator *s1TransportInterceptor) ProcessReceivedMessage(
	message p2p.MessageP2P,
	fromConnectedPeer core.PeerID,
	source p2p.MessageHandler,
) ([]byte, error) {
	if message == nil {
		return nil, fmt.Errorf("%w: nil selected-topic message", drwaqualification.ErrInvalidArm)
	}
	if !drwaqualification.DeclaredActionTagMatches(decorator.arm, decorator.arm.Transport.DeclaredDeliveryAction) {
		return nil, fmt.Errorf("%w: transport declared action", drwaqualification.ErrInvalidArm)
	}
	raw := append([]byte(nil), message.Data()...)
	rawHash := sha256.Sum256(raw)
	if hex.EncodeToString(rawHash[:]) != decorator.arm.Transport.RawDeliverySHA256 {
		return decorator.Interceptor.ProcessReceivedMessage(message, fromConnectedPeer, source)
	}

	decorator.mu.Lock()
	defer decorator.mu.Unlock()
	decorator.matchCount++
	if decorator.matchCount > decorator.arm.Transport.MaxMatchedDeliveries {
		return nil, fmt.Errorf("%w: selected delivery cardinality exceeded", drwaqualification.ErrInvalidArm)
	}
	if err := decorator.recorder.Append(drwaqualification.LifecycleReached, map[string]any{
		"raw_delivery_sha256":               decorator.arm.Transport.RawDeliverySHA256,
		"canonical_membership_proof_sha256": decorator.arm.Transport.CanonicalMembershipProofSHA256,
		"delivery_index":                    decorator.matchCount,
	}); err != nil {
		return nil, err
	}
	if err := decorator.waitForExactRelease(); err != nil {
		return nil, err
	}
	action := decorator.arm.Transport.DeclaredDeliveryAction
	if action != decorator.arm.DeclaredMutation.Kind {
		return nil, fmt.Errorf("%w: transport action differs from declared mutation", drwaqualification.ErrInvalidArm)
	}
	result, err := decorator.Interceptor.ProcessReceivedMessage(message, fromConnectedPeer, source)
	if err != nil {
		return result, err
	}
	forwardCount := 1
	if action == "DUPLICATE_ONCE" || action == "REDRIVE_ONCE" {
		result, err = decorator.Interceptor.ProcessReceivedMessage(message, fromConnectedPeer, source)
		forwardCount = 2
	} else if action != "HOLD_RELEASE_FORWARD_ONCE" && action != "RELEASE_AT_BOUNDARY_FORWARD_ONCE" {
		return nil, fmt.Errorf("%w: unsupported transport action %q", drwaqualification.ErrInvalidArm, action)
	}
	if err != nil {
		return result, err
	}
	if err = decorator.recorder.Append(drwaqualification.LifecycleConsumed, map[string]any{
		"declared_action": action,
		"forward_count":   forwardCount,
	}); err != nil {
		return nil, err
	}
	if err = decorator.recorder.Append(drwaqualification.LifecycleReleased, map[string]any{
		"release_record_sha256": decorator.arm.Transport.ReleaseRecordSHA256,
	}); err != nil {
		return nil, err
	}
	if err = decorator.recorder.Close(); err != nil {
		return nil, err
	}
	return result, nil
}

func (decorator *s1TransportInterceptor) waitForExactRelease() error {
	for {
		if time.Now().Unix() >= decorator.arm.ExpiresUnix {
			return fmt.Errorf("%w: transport arm expired before release", drwaqualification.ErrInvalidArm)
		}
		_, err := os.Lstat(decorator.arm.Transport.ReleasePath)
		if err == nil {
			return drwaqualification.VerifyExactFile(
				decorator.arm.Transport.ReleasePath,
				decorator.arm.Transport.ReleaseRecordSHA256,
			)
		}
		if !os.IsNotExist(err) {
			return fmt.Errorf("%w: release observation: %v", drwaqualification.ErrInvalidArm, err)
		}
		time.Sleep(25 * time.Millisecond)
	}
}
