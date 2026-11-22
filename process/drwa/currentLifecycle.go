package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

var (
	errCurrentLifecycle = errors.New("invalid DRWA current lifecycle dependency")
	errLifecycleClosed  = errors.New("DRWA lifecycle does not admit a current positive operation")
)

// lifecycleCEBFields comes from the SAME admitted full CEB decoder used by
// currentLocalDependencies. It supplies no fresh authority or default policy.
type lifecycleCEBFields struct {
	closurePlan, supplyOrigin []byte
	supplyOriginShard         uint32
	tokenType                 uint32
}

type currentLifecycleHost interface {
	currentLocalHost
	LifecycleFields(body []byte) (lifecycleCEBFields, error)
	// VerifyLifecycle proves exact local canonical application of these
	// activation/LRC bytes in the owning native context, not DB presence. The
	// admitted replicated bundle preserves registration/intent lineage, native
	// type and immutable plan. Execution shards do not fetch the metachain intent.
	VerifyLifecycle(token []byte, epoch uint64, hash, activation, lifecycle []byte, context *HeaderTimeContext) error
}

// lifecycleReadView is detached metadata, NOT admission, a reusable capability
// or a public wire schema. In particular SETUP does not imply local readiness;
// the explicit SupplyState/PositionTrackingState contract remains separate.
type lifecycleReadView struct {
	token, cebHash, closurePlan, supplyOrigin []byte
	cebEpoch                                  uint64
	supplyOriginShard, tokenType              uint32
	activation, lifecycle                     string
}

type currentLifecycleReader struct {
	current     *currentLocalDependencies
	boundary    *RollbackContainment
	source      HeaderTimeSource
	coordinator vmcommon.Coordinator
	host        currentLifecycleHost
}

func newCurrentLifecycleReader(current *currentLocalDependencies, boundary *RollbackContainment,
	source HeaderTimeSource, coordinator vmcommon.Coordinator) (*currentLifecycleReader, error) {
	if current == nil || current.codec == nil || current.codec.state == nil || boundary == nil ||
		check.IfNil(source) || check.IfNil(coordinator) || coordinator.NumberOfShards() == 0 ||
		check.IfNil(current.codec.state.accounts) || check.IfNil(current.codec.hasher) || check.IfNil(current.codec.marshaller) ||
		source.GetAccountsAdapter() != current.codec.state.accounts {
		return nil, errCurrentLifecycle
	}
	owned := false
	for _, store := range boundary.stores {
		owned = owned || store == current.codec.state.accounts
	}
	host, found := current.host.(currentLifecycleHost)
	if !owned || !found || check.IfNil(host) {
		return nil, errCurrentLifecycle
	}
	return &currentLifecycleReader{current, boundary, source, coordinator, host}, nil
}

func validCurrentLifecyclePair(activation, lifecycle string) bool {
	switch activation {
	case "Active":
		return lifecycle == "SETUP" || lifecycle == "SETUP_SEALED" || lifecycle == "OPEN" || lifecycle == "REQUALIFYING"
	case "WindDownDeny":
		return lifecycle == "WIND_DOWN" || lifecycle == "WIND_DOWN_SEALED"
	default:
		return false
	}
}

// withCurrent runs INSIDE the configured original native boundary. The caller
// owns rollback, outputs and actual operation/factor admission. No nested owner,
// remote lookup, epoch cache or ordinary-token fallback is created here.
func (r *currentLifecycleReader) withCurrent(context *HeaderTimeContext, token []byte, epoch uint64, hash []byte,
	execute func(lifecycleReadView) (*vmcommon.VMOutput, error)) (*vmcommon.VMOutput, error) {
	return r.withCurrentAndApply(context, token, epoch, hash, execute, nil)
}

// withCurrentAndApply keeps an owning native writer's final write INSIDE the
// same header capability, after every current/lifecycle/decoder revalidation.
// apply is not authentication or a general exposed writer: its sole current
// caller is setupLifecycle's exact predecessor-checked LRC write. Other readers
// keep the nil tail and their existing immutable dependency contract.
func (r *currentLifecycleReader) withCurrentAndApply(context *HeaderTimeContext, token []byte, epoch uint64, hash []byte,
	execute func(lifecycleReadView) (*vmcommon.VMOutput, error), apply func() error) (*vmcommon.VMOutput, error) {
	if r == nil || execute == nil || epoch == 0 {
		return nil, errCurrentLifecycle
	}
	r.boundary.mut.Lock()
	active := r.boundary.running && !r.boundary.closed && r.boundary.failure == nil
	r.boundary.mut.Unlock()
	if !active || context == nil {
		return nil, errCurrentLifecycle
	}
	_, shard := context.HeaderIdentity()
	if shard != r.coordinator.SelfId() {
		return nil, errCurrentLifecycle
	}
	codec := r.current.codec
	if len(token) > codec.maxBytes || !vmcommon.ValidateToken(token) || len(hash) != codec.hasher.Size() {
		return nil, errCurrentLifecycle
	}
	token, hash = bytes.Clone(token), bytes.Clone(hash)
	return withHeaderTime(r.source, context, func() (*vmcommon.VMOutput, error) {
		var base *currentLocalView
		var intent *bootstrapIntentRecord
		var intentID, activation, lifecycle []byte
		var activationState string
		var keys, values [][]byte
		// Resolve authoritative registration BEFORE positive CEB lookup. Valid
		// closed members may lack a current CEB; that never means ordinary.
		err := verifyRegistrationState(r.boundary.stores, func() error {
			var e error
			tokenKey, e := codec.frame(token)
			if e != nil {
				return e
			}
			keys = [][]byte{
				append([]byte(registryMemberKeyPrefix), token...),
				append([]byte(registrationActivationPrefix), token...),
			}
			for _, key := range keys {
				value, e := r.current.read(key)
				if e != nil {
					return e
				}
				values = append(values, value)
			}
			if !bytes.Equal(values[0], []byte{1}) {
				return errCurrentLifecycle
			}
			activation = values[1]
			fields, e := codec.decodeActivationParent(activation, token)
			if e != nil {
				return errCurrentLifecycle
			}
			activationState = string(fields[2])
			if activationState == "BootstrapDeny" || activationState == "RetiredDeny" {
				return errLifecycleClosed
			}
			if r.coordinator.SelfId() == core.MetachainShardId {
				intent, _, e = codec.registeredToken(token)
				if e != nil {
					return e
				}
				_, _, intentID, e = codec.identity(intent.body)
				if e != nil {
					return e
				}
				if !bytes.Equal(fields[1], intentID) {
					return errCurrentLifecycle
				}
				for _, key := range [][]byte{append([]byte(registrationAssociationPrefix), token...), append([]byte(registrationIntentPrefix), intentID...)} {
					value, e := r.current.read(key)
					if e != nil {
						return e
					}
					keys, values = append(keys, key), append(values, value)
				}
			}
			keys = append(keys, append([]byte(lifecycleRecordPrefix), tokenKey...))
			lifecycle, e = r.current.read(keys[len(keys)-1])
			if e != nil {
				return e
			}
			values = append(values, lifecycle)
			base, e = r.current.resolve(token, epoch, hash)
			return e
		})
		if err != nil {
			return nil, err
		}
		unchanged := func() error {
			if e := r.current.unchanged(base); e != nil {
				return e
			}
			for i, key := range keys {
				now, e := r.current.read(key)
				if e != nil {
					return e
				}
				if !bytes.Equal(now, values[i]) {
					return errCurrentLifecycle
				}
			}
			return nil
		}
		if err = unchanged(); err != nil {
			return nil, err
		}
		phase, err := codec.unframe(lifecycle, 3)
		if err != nil || !bytes.Equal(phase[0], token) || len(phase[1]) != 8 ||
			binary.BigEndian.Uint64(phase[1]) != epoch || !validCurrentLifecyclePair(activationState, string(phase[2])) {
			return nil, errCurrentLifecycle
		}
		var fields lifecycleCEBFields
		err = verifyRegistrationState(r.boundary.stores, func() error {
			var e error
			fields, e = r.host.LifecycleFields(bytes.Clone(base.body))
			return e
		})
		if err != nil {
			return nil, err
		}
		if err = unchanged(); err != nil {
			return nil, err
		}
		if intent != nil {
			family, e := core.ConvertESDTTypeToUint32(string(intent.body.requestedTokenFamily))
			if e != nil || fields.tokenType != family || !bytes.Equal(fields.closurePlan, intent.body.closurePlan) {
				return nil, errCurrentLifecycle
			}
		}
		validFamily := false
		switch core.ESDTType(fields.tokenType) {
		case core.Fungible, core.NonFungibleV2, core.SemiFungible, core.MetaFungible, core.DynamicNFT, core.DynamicSFT, core.DynamicMeta:
			validFamily = true
		}
		if !validFamily || !bytes.Equal(fields.closurePlan, []byte("burn-and-retire")) && !bytes.Equal(fields.closurePlan, []byte("preserve-and-close")) ||
			len(fields.supplyOrigin) != len(core.SystemAccountAddress) || fields.supplyOriginShard >= r.coordinator.NumberOfShards() ||
			r.coordinator.ComputeId(fields.supplyOrigin) != fields.supplyOriginShard {
			return nil, errCurrentLifecycle
		}
		view := lifecycleReadView{token: bytes.Clone(token), cebHash: bytes.Clone(hash), cebEpoch: epoch,
			activation: activationState, lifecycle: string(phase[2]), closurePlan: bytes.Clone(fields.closurePlan),
			supplyOrigin: bytes.Clone(fields.supplyOrigin), supplyOriginShard: fields.supplyOriginShard, tokenType: fields.tokenType}
		err = verifyRegistrationState(r.boundary.stores, func() error {
			return r.host.VerifyLifecycle(bytes.Clone(token), epoch, bytes.Clone(hash), bytes.Clone(activation), bytes.Clone(lifecycle), context)
		})
		if err != nil {
			return nil, err
		}
		if err = unchanged(); err != nil {
			return nil, err
		}
		consumer := view
		consumer.token, consumer.cebHash = bytes.Clone(view.token), bytes.Clone(view.cebHash)
		consumer.closurePlan, consumer.supplyOrigin = bytes.Clone(view.closurePlan), bytes.Clone(view.supplyOrigin)
		output, err := execute(consumer)
		if err != nil {
			return nil, err
		}
		err = verifyRegistrationState(r.boundary.stores, func() error { return r.current.revalidate(base) })
		if err != nil {
			return nil, err
		}
		if err = unchanged(); err != nil {
			return nil, err
		}
		// Canonical lifecycle proof is a read dependency too, not a one-time
		// cached permit. Recheck after any dependent consumer mutation.
		err = verifyRegistrationState(r.boundary.stores, func() error {
			return r.host.VerifyLifecycle(bytes.Clone(token), epoch, bytes.Clone(hash), bytes.Clone(activation), bytes.Clone(lifecycle), context)
		})
		if err != nil {
			return nil, err
		}
		if err = unchanged(); err != nil {
			return nil, err
		}
		var afterFields lifecycleCEBFields
		err = verifyRegistrationState(r.boundary.stores, func() error {
			var e error
			afterFields, e = r.host.LifecycleFields(bytes.Clone(base.body))
			return e
		})
		if err != nil {
			return nil, err
		}
		if afterFields.tokenType != view.tokenType || afterFields.supplyOriginShard != view.supplyOriginShard ||
			!bytes.Equal(afterFields.closurePlan, view.closurePlan) || !bytes.Equal(afterFields.supplyOrigin, view.supplyOrigin) {
			return nil, errCurrentLifecycle
		}
		if err = unchanged(); err != nil {
			return nil, err
		}
		if apply != nil {
			if err = apply(); err != nil {
				return nil, err
			}
		}
		return output, nil
	})
}
