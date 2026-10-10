package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// EXPERIMENTAL representation of the existing token/source/action ATES identity,
// not a release key/codec allocation or an additional projection nonce.
const sourceGrantPrefix = core.ProtectedKeyPrefix + "DRWA@sourceGrant@"

var errSourceGrant = errors.New("invalid DRWA source grant construction")

type sourceGrantProjection struct {
	token, source, action, digest, body []byte
	expiry                              HeaderMilliseconds
}

// sourceGrantHost belongs exclusively to the actual source-holder native owner.
// There is NO default host or public admission bool. VerifyProjection must bind
// canonical local projection provenance, full immutable body, admitted schema,
// GAS IN_PROGRESS and every field, not just a supplied SCR hash or matching tuple.
// ValidateConsume additionally resolves all current CEB/restriction/lifecycle/
// funding/ATES predicates. VerifyUnused independently proves canonical EXACT
// grant non-consumption and, for STALE_BINDING, that reason's current predicate.
// None may derive non-consumption from a missing ATES or STARTED ACK.
//
// Apply includes every actual native debit/ATES/OpenEffect or atomic terminal
// effect in the same exclusive T04 stores. Ack does not directly terminalize
// metachain GAS. Actual T42/T43/T25 producers/adapters remain unwired gates.
type sourceGrantHost interface {
	VerifyProjection(projection, evidence []byte) error
	ValidateAdmission(projection []byte, retainedBytes uint64) error
	ValidateConsume(projection []byte) error
	VerifyUnused(projection []byte, reason string, evidence []byte) error
	Apply(projection []byte) ([]byte, *vmcommon.VMOutput, error)
	// Ack appends to the SAME full native output. It must preserve the effect's
	// gas, accounts/transfers, logs and return data, and use the admitted funding.
	Ack(projection []byte, status, reason string, effect []byte, output *vmcommon.VMOutput) error
	IsInterfaceNil() bool
}

// sourceGrantRecords retains OPEN/CONSUMED/CLOSED_UNUSED under one existing
// identity in native protected state. It owns no journal, commit, cache, timer,
// second nonce or deletion/reopening operation. Prefix/field order/status bytes
// are experimental; native header/finality/debit serviceability is not claimed.
type sourceGrantRecords struct {
	codec    *registrationRecords
	boundary *RollbackContainment
	host     sourceGrantHost
	shard    uint32
}

func newSourceGrantRecords(accounts state.AccountsAdapter, boundary *RollbackContainment,
	marshaller marshal.Marshalizer, hasher hashing.Hasher, maxBytes int,
	sourceShard uint32, host sourceGrantHost) (*sourceGrantRecords, error) {
	if boundary == nil || check.IfNil(host) || sourceShard == core.MetachainShardId {
		return nil, errSourceGrant
	}
	owned := false
	for _, store := range boundary.stores {
		if store == accounts {
			owned = true
		}
	}
	if !owned {
		return nil, errSourceGrant
	}
	codec, err := newRegistrationRecords(accounts, marshaller, hasher, maxBytes)
	if err != nil {
		return nil, err
	}
	return &sourceGrantRecords{codec: codec, boundary: boundary, host: host, shard: sourceShard}, nil
}

func (s *sourceGrantRecords) encode(p sourceGrantProjection) (key, projection []byte, err error) {
	if len(p.token) > s.codec.maxBytes || len(p.body) > s.codec.maxBytes ||
		!vmcommon.ValidateToken(p.token) || len(p.source) != len(core.SystemAccountAddress) ||
		len(p.action) != s.codec.hasher.Size() || len(p.digest) != s.codec.hasher.Size() || len(p.body) == 0 {
		return nil, nil, errSourceGrant
	}
	identity, err := s.codec.frame(p.token, p.source, p.action)
	if err != nil {
		return nil, nil, err
	}
	projection, err = s.codec.frame(p.token, p.source, p.action, p.digest,
		binary.BigEndian.AppendUint64(nil, uint64(p.expiry)), p.body)
	if err != nil {
		return nil, nil, err
	}
	// A projection must fit every later retained state, before verifier work or
	// new admission. Reuse its existing digest bytes to check effect-size overhead.
	if _, err = s.codec.frame(projection, []byte("CONSUMED"), nil, p.digest); err != nil {
		return nil, nil, err
	}
	if _, err = s.codec.frame(projection, []byte("CLOSED_UNUSED"), []byte("STALE_BINDING"), nil); err != nil {
		return nil, nil, err
	}
	return append([]byte(sourceGrantPrefix), identity...), projection, nil
}

func (s *sourceGrantRecords) load(key, projection []byte) (string, string, []byte, error) {
	account, err := s.codec.state.systemAccount()
	if err != nil {
		return "", "", nil, err
	}
	value, _, err := account.RetrieveValue(key)
	if err != nil {
		return "", "", nil, err
	}
	f, err := s.codec.unframe(value, 4)
	if err != nil || !bytes.Equal(f[0], projection) {
		return "", "", nil, errSourceGrant
	}
	status, reason := string(f[1]), string(f[2])
	valid := status == "OPEN" && reason == "" && len(f[3]) == 0 ||
		status == "CONSUMED" && reason == "" && len(f[3]) == s.codec.hasher.Size() ||
		status == "CLOSED_UNUSED" && (reason == "EXPIRED" || reason == "STALE_BINDING") && len(f[3]) == 0
	if !valid {
		return "", "", nil, errSourceGrant
	}
	return status, reason, bytes.Clone(f[3]), nil
}

// check reloads the exact grant after native host work. Reloading only the
// account at save cannot establish that this single-use fact stayed unchanged.
func (s *sourceGrantRecords) check(key, projection []byte, status, reason string, effect []byte) error {
	currentStatus, currentReason, currentEffect, err := s.load(key, projection)
	if err != nil {
		return err
	}
	if currentStatus != status || currentReason != reason || !bytes.Equal(currentEffect, effect) {
		return errSourceGrant
	}
	return nil
}

func (s *sourceGrantRecords) save(key, projection []byte, status, reason string, effect []byte) error {
	value, err := s.codec.frame(projection, []byte(status), []byte(reason), effect)
	if err != nil {
		return err
	}
	// Reload AFTER native effects/host work: never save an earlier account object
	// over the native handler's writes to this same protected system account.
	account, err := s.codec.state.systemAccount()
	if err != nil {
		return err
	}
	if err = account.SaveKeyValue(key, value); err != nil {
		return err
	}
	return s.codec.state.accounts.SaveAccount(account)
}

func (s *sourceGrantRecords) lease(context *HeaderTimeContext) (func(), error) {
	if _, err := governedTimeAt(context, s.shard); err != nil {
		return nil, err
	}
	context.owner.mut.RLock()
	if context.owner.current != context {
		context.owner.mut.RUnlock()
		return nil, ErrInactiveHeaderTime
	}
	return context.owner.mut.RUnlock, nil
}

func sourceGrantOutput(output *vmcommon.VMOutput, err error) (*vmcommon.VMOutput, error) {
	if err != nil {
		return nil, err
	}
	if output == nil || output.ReturnCode != vmcommon.Ok {
		return nil, errSourceGrant
	}
	return output, nil
}

func (s *sourceGrantRecords) ack(key, projection []byte, status, reason string, effect []byte,
	output *vmcommon.VMOutput) (*vmcommon.VMOutput, error) {
	if output == nil {
		output = &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}
	}
	err := s.host.Ack(bytes.Clone(projection), status, reason, bytes.Clone(effect), output)
	if _, err = sourceGrantOutput(output, err); err != nil {
		return nil, err
	}
	retainedStatus := "CONSUMED"
	if status == "UNUSED" {
		retainedStatus = "CLOSED_UNUSED"
	}
	if err = s.check(key, projection, retainedStatus, reason, effect); err != nil {
		return nil, err
	}
	return output, nil
}

func (s *sourceGrantRecords) install(context *HeaderTimeContext, p sourceGrantProjection, evidence []byte) error {
	key, projection, err := s.encode(p)
	if err != nil {
		return err
	}
	if len(evidence) > s.codec.maxBytes {
		return errSourceGrant
	}
	return s.boundary.Execute(func() (*vmcommon.VMOutput, error) {
		if e := s.host.VerifyProjection(bytes.Clone(projection), bytes.Clone(evidence)); e != nil {
			return nil, e
		}
		account, e := s.codec.state.systemAccount()
		if e != nil {
			return nil, e
		}
		old, _, e := account.RetrieveValue(key)
		if e != nil {
			return nil, e
		}
		if len(old) != 0 {
			_, _, _, e = s.load(key, projection)
			if e != nil {
				return nil, e
			}
			release, e := s.lease(context)
			if e != nil {
				return nil, e
			}
			release()
			return nil, nil // exact duplicate NEVER rewrites terminal/consumed state
		}
		value, e := s.codec.frame(projection, []byte("OPEN"), nil, nil)
		if e != nil {
			return nil, e
		}
		if e = s.host.ValidateAdmission(bytes.Clone(projection), uint64(len(key))+uint64(len(value))); e != nil {
			return nil, e
		}
		release, e := s.lease(context)
		if e != nil {
			return nil, e
		}
		defer release()
		// Admission can perform other native work; it cannot replace the exact
		// grant's absence with a consumed/closed fact that OPEN would overwrite.
		account, e = s.codec.state.systemAccount()
		if e != nil {
			return nil, e
		}
		old, _, e = account.RetrieveValue(key)
		if e != nil {
			return nil, e
		}
		if len(old) != 0 {
			return nil, errSourceGrant
		}
		return nil, s.save(key, projection, "OPEN", "", nil)
	})
}

func (s *sourceGrantRecords) consume(context *HeaderTimeContext, p sourceGrantProjection, evidence []byte) error {
	return s.transition(context, p, "", evidence)
}

func (s *sourceGrantRecords) closeUnused(context *HeaderTimeContext, p sourceGrantProjection, reason string, evidence []byte) error {
	if reason != "EXPIRED" && reason != "STALE_BINDING" {
		return errSourceGrant
	}
	return s.transition(context, p, reason, evidence)
}

func (s *sourceGrantRecords) transition(context *HeaderTimeContext, p sourceGrantProjection, reason string, evidence []byte) error {
	key, projection, err := s.encode(p)
	if err != nil {
		return err
	}
	if len(evidence) > s.codec.maxBytes {
		return errSourceGrant
	}
	return s.boundary.Execute(func() (*vmcommon.VMOutput, error) {
		if e := s.host.VerifyProjection(bytes.Clone(projection), bytes.Clone(evidence)); e != nil {
			return nil, e
		}
		status, retainedReason, effect, e := s.load(key, projection)
		if e != nil {
			return nil, e // absence is never an open/non-consumed grant
		}
		if status != "OPEN" {
			if reason == "" && status == "CONSUMED" || reason != "" && status == "CLOSED_UNUSED" && reason == retainedReason {
				release, errLease := s.lease(context)
				if errLease != nil {
					return nil, errLease
				}
				defer release()
				ack := "STARTED"
				if status == "CLOSED_UNUSED" {
					ack = "UNUSED"
				}
				return s.ack(key, projection, ack, retainedReason, effect, nil)
			}
			return nil, errSourceGrant
		}
		before, e := sourceProjectionBeforeExpiry(context, s.shard, p.expiry)
		if e != nil {
			return nil, e
		}
		if reason == "" {
			if !before {
				return nil, errSourceGrant
			}
			e = s.host.ValidateConsume(bytes.Clone(projection))
		} else {
			if reason == "EXPIRED" && before {
				return nil, errSourceGrant
			}
			e = s.host.VerifyUnused(bytes.Clone(projection), reason, bytes.Clone(evidence))
		}
		if e != nil {
			return nil, e
		}
		release, e := s.lease(context)
		if e != nil {
			return nil, e
		}
		defer release()
		if e = s.check(key, projection, "OPEN", "", nil); e != nil {
			return nil, e
		}
		if reason != "" {
			if e = s.save(key, projection, "CLOSED_UNUSED", reason, nil); e != nil {
				return nil, e
			}
			return s.ack(key, projection, "UNUSED", reason, nil, nil)
		}
		effect, output, e := s.host.Apply(bytes.Clone(projection))
		if _, e = sourceGrantOutput(output, e); e != nil {
			return nil, e
		}
		if len(effect) != s.codec.hasher.Size() {
			return nil, errSourceGrant
		}
		if e = s.check(key, projection, "OPEN", "", nil); e != nil {
			return nil, e
		}
		if e = s.save(key, projection, "CONSUMED", "", bytes.Clone(effect)); e != nil {
			return nil, e
		}
		return s.ack(key, projection, "STARTED", "", effect, output)
	})
}
