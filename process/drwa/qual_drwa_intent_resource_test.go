package drwa

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Independent field-1 protobuf seed, reusing the existing manual vector helper.
// No production registration encoder constructs the body/identity expectation.
func qualIntentResourceVector(i int, expiry uint64) (encoded, digest, id []byte) {
	nonce, expiryBytes := make([]byte, 8), make([]byte, 8)
	binary.BigEndian.PutUint64(nonce, uint64(i))
	binary.BigEndian.PutUint64(expiryBytes, expiry)
	issuer := bytes.Repeat([]byte{0x11}, 32)
	encoded = qualRecordFrame([]byte("n"), issuer, []byte("p"), nonce,
		[]byte("FungibleESDT"), []byte("profile"), []byte("name"), []byte("ticker"), []byte("props"),
		[]byte("schema"), []byte("admission"), qualRecordFrame([]byte("pa-body")),
		qualRecordFrame(bytes.Repeat([]byte{2}, 32)), []byte("burn-and-retire"), []byte("network-profile"), expiryBytes)
	hash := blake2b.NewBlake2b()
	digest = hash.Compute(string(qualRecordFrame([]byte("DRWA/BOOTSTRAP_INTENT_PAYLOAD/v1"), encoded)))
	id = hash.Compute(string(qualRecordFrame([]byte("DRWA/BOOTSTRAP_INTENT/v1"), []byte("n"), issuer, []byte("p"), nonce, digest)))
	return
}

// Exact native memory-backing key/value bytes, excluding Go heap/map overhead,
// disk format, pruning/snapshot serviceability and operational capacity promises.
func qualIntentBackingSize(s *qualNativeStore) (keys, size int) {
	s.backing.RangeKeys(func(key, value []byte) bool {
		keys++
		size += len(key) + len(value)
		return true
	})
	return
}

// T09-M26: retained-state measurement, not an OPEN/cancellation/expiry producer.
// CONSUMED uses the real co-journal owner but the existing explicit synthetic
// token creator. No actual ESDT creation, authority, rate or numeric cap is proved.
func TestQualDRWAIntentRetainedResourceSamples(t *testing.T) {
	for _, category := range []string{"OPEN", "CONSUMED", "CANCELLED", "expired_retained"} {
		for _, count := range []int{1, 64, 1024} {
			t.Run(fmt.Sprintf("%s/n_%d", category, count), func(t *testing.T) {
				s := qualRegistrationStore(t, 0)
				beforeKeys, beforeBytes := qualIntentBackingSize(s)
				expiry := uint64(1000000)
				status := category
				if category == "expired_retained" {
					status, expiry = "OPEN", 1 // explicit sample coordinate 2 > expiry; no clock supplied to reader
				}
				seedStatus := status
				if category == "CONSUMED" {
					seedStatus = "OPEN"
				}
				started := time.Now() // measurement only, never policy timing
				for i := 0; i < count; i++ {
					body, _, id := qualIntentResourceVector(i, expiry)
					key := append([]byte("ELRONDDRWA@registration@intent@"), id...)
					qualRecordPut(t, s, key, qualRecordFrame(body, []byte(seedStatus), nil))
				}
				seedJournal := s.JournalLen()
				require.Positive(t, seedJournal)
				_, err := s.Commit()
				require.NoError(t, err)
				records, err := newRegistrationRecords(s, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096)
				require.NoError(t, err)
				manager := bytes.Repeat([]byte{0x22}, 32)
				consumptionJournal := 0
				if category == "CONSUMED" {
					registration, boundary := qualRegistrationOwner(t, s, uint64(count))
					for i := 0; i < count; i++ {
						_, digest, id := qualIntentResourceVector(i, expiry)
						token := fmt.Sprintf("TOKEN-%06x", i)
						require.NoError(t, registration.registerTokenForIntent(records, id, digest, manager, qualRegistrationCreator(t, token)))
					}
					consumptionJournal = s.JournalLen()
					require.Positive(t, consumptionJournal)
					roots, outputs, err := boundary.Commit()
					require.NoError(t, err)
					require.Len(t, roots, 1)
					require.Len(t, outputs, count)
				}
				populateNs := time.Since(started).Nanoseconds()
				require.Zero(t, s.JournalLen())
				root, err := s.RootHash()
				require.NoError(t, err)
				keys, backingBytes := qualIntentBackingSize(s)
				require.Greater(t, keys, beforeKeys)
				require.Greater(t, backingBytes, beforeBytes)
				// Count only the explicitly owned experimental key/value payload.
				// Native trie serialization is independently measured above.
				payloadBytes := len("ELRONDDRWA@registry@count") + 8
				started = time.Now()
				for pass := 0; pass < 2; pass++ {
					for i := 0; i < count; i++ {
						body, digest, id := qualIntentResourceVector(i, expiry)
						got, err := records.intent(id)
						require.NoError(t, err)
						require.Equal(t, body, got.encoded)
						require.Equal(t, digest, got.digest)
						require.Equal(t, status, got.status)
						require.Equal(t, HeaderMilliseconds(expiry), got.body.expiry)
						token := []byte(nil)
						if category == "CONSUMED" {
							token = []byte(fmt.Sprintf("TOKEN-%06x", i))
							associated, actualManager, err := records.registeredToken(token)
							require.NoError(t, err)
							require.Equal(t, body, associated.encoded)
							require.Equal(t, manager, actualManager)
							if pass == 0 {
								payloadBytes += len("ELRONDDRWA@registration@token@") + len(token) + len(qualRecordFrame(token, id, digest, body, manager))
								payloadBytes += len("ELRONDDRWA@registration@activation@") + len(token) + len(qualRecordFrame(token, id, []byte("BootstrapDeny")))
								payloadBytes += len("ELRONDDRWA@registry@member@") + len(token) + 1
								payloadBytes += len(token) + len("native-token-record") // declared synthetic ESDT-account payload
							}
						}
						if category == "CONSUMED" {
							require.Equal(t, token, got.tokenID)
						} else {
							require.Empty(t, got.tokenID)
						}
						if pass == 0 {
							payloadBytes += len("ELRONDDRWA@registration@intent@") + len(id) + len(qualRecordFrame(body, []byte(status), token))
						}
					}
				}
				readNs := time.Since(started).Nanoseconds()
				firstBody, _, firstID := qualIntentResourceVector(0, expiry)
				valid := true
				readAllocs := testing.AllocsPerRun(10, func() {
					got, e := records.intent(firstID)
					valid = valid && e == nil && bytes.Equal(got.encoded, firstBody)
				})
				require.True(t, valid)
				wantCount := uint64(0)
				if category == "CONSUMED" {
					wantCount = uint64(count)
				}
				require.Equal(t, wantCount, binary.BigEndian.Uint64(qualRegistryValue(t, s, "ELRONDDRWA@registry@count")))
				_, _, absentID := qualIntentResourceVector(count, expiry)
				_, err = records.intent(absentID)
				require.Error(t, err)
				if category == "CONSUMED" {
					registration, _ := qualRegistrationOwner(t, s, uint64(count))
					called := false
					err = registration.RegisterToken(func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) { called = true; return nil, nil, nil })
					require.ErrorIs(t, err, ErrInvalidRegistryRegistration)
					require.False(t, called)
				}
				after, err := s.RootHash()
				require.NoError(t, err)
				require.Equal(t, root, after)
				require.Zero(t, s.JournalLen())
				afterKeys, afterBytes := qualIntentBackingSize(s)
				require.Equal(t, keys, afterKeys)
				require.Equal(t, backingBytes, afterBytes)
				measurement := map[string]interface{}{
					"category": category, "intents": count, "expiry": expiry,
					"seed_journal_entries": seedJournal, "consumption_journal_entries": consumptionJournal,
					"populate_ns": populateNs, "two_read_passes_ns": readNs,
					"first_intent_read_allocs":         readAllocs,
					"timing_scope":                     "includes fixture generation and assertions; observed durations are not isolated decoder latency or policy thresholds",
					"experimental_owned_payload_bytes": payloadBytes,
					"native_memory_backing_keys":       keys, "native_memory_backing_bytes": backingBytes,
					"native_memory_backing_added_keys": keys - beforeKeys, "native_memory_backing_added_bytes": backingBytes - beforeBytes,
				}
				raw, err := json.Marshal(measurement)
				require.NoError(t, err)
				t.Logf("T09_INTENT_RESOURCE_SAMPLE %s", raw)
			})
		}
	}
}
