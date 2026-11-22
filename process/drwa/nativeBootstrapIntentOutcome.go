package drwa

import (
	"bytes"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
)

// nativeBootstrapIntentObservation reports the existing stored intent lifecycle
// at one native canonical context. OPEN is retained intent registration, not
// token creation, activation, settlement, refund or source completion.
// The hashes identify the queried canonical state context; presence alone does
// not prove which transaction created it or finalize a particular submission.
// This private construction is neither an RPC representation nor a wire format.
type nativeBootstrapIntentObservation struct {
	intent                               *bootstrapIntentRecord
	sourceHash, resultHash, consumerHash []byte
	producer, consumer                   uint32
	consumerNonce, consumerRound         uint64
	consumerEpoch                        uint32
}

// readBootstrapIntent binds the existing experimental Step-1 class/key/codec to
// the native canonical byte reader (Part A 4.1, 6.1; Part B 12.3/AM-012). It adds no
// authority, proof format or status encoding. The caller still owns actual B
// admission, original-era codec/profile, native verifier/cache/history inputs
// and paid historical-service admission. No live ingress is installed here.
func (r *canonicalResultReader) readBootstrapIntent(records *registrationRecords, committedB []byte,
	consumer, producer uint32, origin, intentID []byte, w canonicalResultWitness, byteLimit int,
) (*nativeBootstrapIntentObservation, error) {
	if r == nil || r.accounts == nil || records == nil || records.maxBytes <= 0 || byteLimit <= 0 ||
		len(intentID) > byteLimit || len(origin) > byteLimit || len(committedB) > byteLimit {
		return nil, errInvalidRegistrationRecord
	}
	if _, err := canonicalWitnessRemaining(w, byteLimit); err != nil {
		return nil, err
	}
	// Own the bounded witness and identities before codec and proof callbacks.
	committedB, origin, intentID = bytes.Clone(committedB), bytes.Clone(origin), bytes.Clone(intentID)
	w = cloneCanonicalResultWitness(w)
	if check.IfNil(records.marshaller) || check.IfNil(records.hasher) {
		return nil, errInvalidRegistrationRecord
	}
	size := records.hasher.Size()
	if size <= 0 || len(intentID) != size {
		return nil, errInvalidRegistrationRecord
	}
	key := append([]byte(registrationIntentPrefix), intentID...)
	projection, err := r.readBoundedContext(committedB, consumer, producer, origin, w)
	if err != nil {
		return nil, err
	}
	value, err := r.accounts.Read(projection.carryingHash, producer, core.SystemAccountAddress, key, w.Account, byteLimit)
	if err != nil {
		return nil, err
	}
	intent, err := records.decodeIntentRecord(intentID, bytes.Clone(value))
	if err != nil {
		return nil, err
	}
	b := projection.consumerHeader
	return &nativeBootstrapIntentObservation{intent: intent,
		sourceHash: origin, resultHash: projection.carryingHash,
		consumerHash: committedB, producer: producer, consumer: consumer,
		consumerNonce: b.GetNonce(), consumerRound: b.GetRound(), consumerEpoch: b.GetEpoch()}, nil
}
