package hooks

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/enablers"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/epochNotifier"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// NON-NORMATIVE T05 feasibility candidate, Part A L550-568/L4956.
// The expected header identity and enforcement predicate are FIXTURE-ASSUMED
// authentic operation-owner inputs. This does not implement a classifier,
// authenticate an operation owner, wire a factory or bind a DRWA consumer.
// The fixture initializes only the real native header lifecycle fields; it
// does not claim constructor/factory coverage. All code stays test-only.
// It compares a source-owned atomic binding with the stale cached-wrapper
// counterexample. Native CurrentTimeStampMs remains completely unchanged.
type qualBoundHeaderMilliseconds uint64

var errQualHeaderBinding = errors.New("non-normative evaluated header binding unavailable")

func qualReadBoundHeaderTime(bh *BlockChainHookImpl, expected []byte, enforced bool) (qualBoundHeaderMilliseconds, error) {
	if bh == nil || len(expected) == 0 || !enforced {
		return 0, errQualHeaderBinding
	}
	bh.mutCurrentHdr.RLock()
	defer bh.mutCurrentHdr.RUnlock()
	if check.IfNil(bh.currentHdr) || check.IfNil(bh.enableEpochsHandler) ||
		!bh.enableEpochsHandler.IsFlagEnabledInEpoch(common.SupernovaFlag, bh.currentHdr.GetEpoch()) {
		return 0, errQualHeaderBinding
	}
	actual, err := core.CalculateHash(&marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), bh.currentHdr)
	if err != nil {
		return 0, err
	}
	if !bytes.Equal(actual, expected) {
		return 0, errQualHeaderBinding
	}
	// Calling CurrentTimeStampMs while holding its RLock could deadlock behind
	// a queued writer (recursive RLock). Use its adopted native helper under
	// the single lock so header identity, activation and time stay coherent.
	_, ms, err := common.GetHeaderTimestamps(bh.currentHdr, bh.enableEpochsHandler)
	if err != nil {
		return 0, err
	}
	return qualBoundHeaderMilliseconds(ms), nil
}

func qualTimeBindingHook(t *testing.T, h data.HeaderHandler) *BlockChainHookImpl {
	t.Helper()
	flags, err := enablers.NewEnableEpochsHandler(config.EnableEpochs{SupernovaEnableEpoch: 10}, &epochNotifier.EpochNotifierStub{
		RegisterNotifyHandlerCalled: func(handler vmcommon.EpochSubscriberHandler) { handler.EpochConfirmed(0, 0) },
	})
	require.NoError(t, err)
	return &BlockChainHookImpl{currentHdr: h, epochStartHdr: h, enableEpochsHandler: flags}
}
func qualTimeHeaderHash(t *testing.T, h data.HeaderHandler) []byte {
	t.Helper()
	hash, err := core.CalculateHash(&marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), h)
	require.NoError(t, err)
	return hash
}

func TestQualDRWAAtomicHeaderTimeBinding(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header data.HeaderHandler
	}{
		{"shard", &block.HeaderV3{Epoch: 10, Round: 21, Nonce: 7, TimestampMs: 1234567}},
		{"meta", &block.MetaBlockV3{Epoch: 10, Round: 21, Nonce: 7, TimestampMs: 1234567}},
		{"proposed_meta", &block.MetaBlockV3{Epoch: 10, Round: 21, Nonce: 7, TimestampMs: 1234567, EpochChangeProposed: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bh := qualTimeBindingHook(t, tc.header)
			expected := qualTimeHeaderHash(t, tc.header)
			ms, err := qualReadBoundHeaderTime(bh, expected, true)
			require.NoError(t, err)
			require.Equal(t, qualBoundHeaderMilliseconds(1234567), ms)
			require.Equal(t, uint64(ms), bh.CurrentTimeStampMs())
			require.Equal(t, uint64(1234), bh.CurrentTimeStamp())
			require.ErrorIs(t, func() error { _, err := qualReadBoundHeaderTime(bh, expected, false); return err }(), errQualHeaderBinding)
			require.ErrorIs(t, func() error { _, err := qualReadBoundHeaderTime(bh, nil, true); return err }(), errQualHeaderBinding)
			for _, expiry := range []uint64{1234566, 1234567, 1234568} {
				require.Equal(t, expiry == 1234568, uint64(ms) < expiry)
			}
		})
	}
}

func TestQualDRWAAtomicHeaderTimeHostileContexts(t *testing.T) {
	first := &block.HeaderV3{Epoch: 10, Round: 21, Nonce: 7, TimestampMs: 1234567, RandSeed: []byte("first")}
	for _, name := range []string{"direct_installer", "equal_coordinates_different_header", "in_place_mutation", "nil_header", "nil_handler", "pre_supernova", "failed_installation"} {
		t.Run(name, func(t *testing.T) {
			header := *first
			header.RandSeed = bytes.Clone(first.RandSeed)
			bh := qualTimeBindingHook(t, &header)
			expected := qualTimeHeaderHash(t, &header)
			switch name {
			case "direct_installer":
				require.NoError(t, bh.SetCurrentHeader(&block.HeaderV3{Epoch: 10, Round: 22, Nonce: 8, TimestampMs: 7654321}))
			case "equal_coordinates_different_header":
				other := header
				other.RandSeed = []byte("other")
				require.NoError(t, bh.SetCurrentHeader(&other))
				require.Equal(t, uint64(1234567), bh.CurrentTimeStampMs())
			case "in_place_mutation":
				header.RandSeed = []byte("changed")
			case "nil_header":
				bh.currentHdr = nil
			case "nil_handler":
				bh.enableEpochsHandler = nil
			case "pre_supernova":
				legacy := &block.Header{Epoch: 9, TimeStamp: 1234}
				bh.currentHdr = legacy
				expected = qualTimeHeaderHash(t, legacy)
			case "failed_installation":
				failed := errors.New("fixture epoch-start failure")
				// Callback sweep: this path calls LastCommitedEpochStartHdr once;
				// GetEpochStartHdrFromStorage is bound as well, but must not be reached.
				bh.epochStartTrigger = &testscommon.EpochStartTriggerStub{
					LastCommitedEpochStartHdrCalled:   func() (data.HeaderHandler, error) { return nil, failed },
					GetEpochStartHdrFromStorageCalled: func(uint32) (data.HeaderHandler, error) { t.Fatal("lookup after trigger failure"); return nil, failed },
				}
				attempted := &block.HeaderV3{Epoch: 11, TimestampMs: 7654321}
				expected = qualTimeHeaderHash(t, attempted)
				require.ErrorIs(t, bh.SetCurrentHeader(attempted), failed)
				require.Equal(t, uint64(1234567), bh.CurrentTimeStampMs(), "upstream retains its earlier header")
			}
			_, err := qualReadBoundHeaderTime(bh, expected, true)
			require.ErrorIs(t, err, errQualHeaderBinding)
		})
	}
}

func TestQualDRWAAtomicHeaderTimeConcurrentInstallation(t *testing.T) {
	first := &block.HeaderV3{Epoch: 10, TimestampMs: 1234567}
	second := &block.HeaderV3{Epoch: 10, TimestampMs: 7654321}
	bh := qualTimeBindingHook(t, first)
	firstHash, secondHash := qualTimeHeaderHash(t, first), qualTimeHeaderHash(t, second)
	failures := make(chan error, 3)
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			if err := bh.SetCurrentHeader(first); err != nil {
				failures <- err
				return
			}
			if err := bh.SetCurrentHeader(second); err != nil {
				failures <- err
				return
			}
		}
	}()
	for _, tc := range []struct {
		hash []byte
		ms   qualBoundHeaderMilliseconds
	}{{firstHash, 1234567}, {secondHash, 7654321}} {
		go func(expected []byte, ms qualBoundHeaderMilliseconds) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				actual, err := qualReadBoundHeaderTime(bh, expected, true)
				if err != nil && !errors.Is(err, errQualHeaderBinding) {
					failures <- err
					return
				}
				if err == nil && actual != ms {
					failures <- errors.New("mixed header identity and milliseconds")
					return
				}
			}
		}(tc.hash, tc.ms)
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		require.NoError(t, err)
	}
}
