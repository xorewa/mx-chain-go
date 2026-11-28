package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// Candidate physical construction only, reusing the existing bounded native
// framing. Part B5.2/AR28 schema, independent vectors and production admission
// remain required. This is the existing LRC, not another lifecycle authority.
const lifecycleRecordPrefix = core.ProtectedKeyPrefix + "DRWA@lifecycle@"

var errActivationRecord = errors.New("invalid DRWA activation construction")

type activationActionClass struct{ subject, class []byte }

// activationGenesis is the complete class-init projection from the admitted
// genesis decoder, not a requester-selected subset or an authority certificate.
type activationGenesis struct {
	token, closurePlan []byte
	epoch              uint64
	classes            []activationActionClass
}

// activationHost belongs to native protected ingress. It must validate the
// COMPLETE canonical genesis body, resource/profile support, exact immutable
// consumed-intent and installed-set bindings, CURRENT unexpired/unwithdrawn
// admission, fresh ACTIVATE_PROGRAM_ADMISSION, PA and every independent scoped
// activation mandate. Classes enumerates ALL prescribed v1 action classes and
// their actual subject identities. No default implementation, roster, codec or
// authority mapping is supplied here. Synthetic hosts are not native admission.
type activationHost interface {
	VerifyActivation(domain, token, intentID, intentBody, genesis, certificates []byte,
		at HeaderMilliseconds, epoch uint32) (activationGenesis, error)
	IsInterfaceNil() bool
}

// activationRecords uses the existing registration, time, GAS and rollback
// owners. It neither commits nor publishes a reply. The actual native endpoint
// and source-bound canonical/authority providers remain integration gates.
type activationRecords struct {
	registration *RegistrationAdmission
	actions      *governedActionRecords
	host         activationHost
}

func newActivationRecords(registration *RegistrationAdmission, actions *governedActionRecords, host activationHost) (*activationRecords, error) {
	if registration == nil || registration.owner == nil || registration.owner.records == nil ||
		registration.owner.records.state == nil || registration.owner.boundary == nil || check.IfNil(registration.source) ||
		actions == nil || actions.codec == nil || actions.codec.state == nil || actions.boundary == nil ||
		check.IfNil(actions.host) || check.IfNil(actions.timeSource) || check.IfNil(host) || actions.boundary != registration.owner.boundary ||
		actions.codec.state.accounts != registration.owner.records.state.accounts ||
		!bytes.Equal(actions.domain, registration.domain) {
		return nil, errActivationRecord
	}
	return &activationRecords{registration: registration, actions: actions, host: host}, nil
}

// activateFromReadinessOwned is the T01 route. It uses the existing exact K
// and original operation, without the whole-set comparison guard. The native
// host still owns proof admission and the funded replication/output effects.
func (a *activationRecords) activateFromReadinessOwned(operation *rollbackOperation, context *HeaderTimeContext,
	readiness *convergenceRecords, transition convergenceTransition, genesis, certificates []byte) (*vmcommon.VMOutput, error) {
	if a == nil || a.registration == nil || a.registration.owner == nil || a.registration.owner.records == nil ||
		readiness == nil || readiness.codec == nil || readiness.codec.state == nil || check.IfNil(readiness.host) {
		return nil, errActivationRecord
	}
	owner := a.registration.owner
	r := owner.records
	if readiness.boundary != owner.boundary || readiness.codec.state.accounts != r.state.accounts {
		return nil, errInvalidMetaContext
	}
	var output *vmcommon.VMOutput
	err := operation.withWrite(owner.boundary, r.state.accounts, func() error {
		if !owner.matchesBootstrapReadiness(transition) || len(genesis) == 0 || len(certificates) == 0 {
			return errActivationRecord
		}
		if _, err := r.frame(transition.token, transition.action, genesis, certificates); err != nil {
			return err
		}
		_, binding, err := readiness.encode(transition)
		if err != nil {
			return err
		}
		bound := *readiness
		bound.host = &activationReadinessHost{
			convergenceHost: readiness.host, activation: a, context: context, binding: binding,
			token: bytes.Clone(transition.token), intentID: bytes.Clone(transition.action),
			genesis: bytes.Clone(genesis), certificates: bytes.Clone(certificates),
		}
		complete, err := bound.prepareComplete(transition)
		if err != nil {
			return err
		}
		output, err = withHeaderTime(a.registration.source, context, complete)
		return err
	})
	if err != nil {
		return nil, err
	}
	return output, nil
}

// For this one phase the adapter owns the Active, genesis and initial GAS
// records. The supplied native host's Complete owns the funded replication and
// output, and VerifyParent still authenticates the parent in its native locus.
type activationReadinessHost struct {
	convergenceHost
	activation                                      *activationRecords
	context                                         *HeaderTimeContext
	binding, token, intentID, genesis, certificates []byte
	written                                         []scopedAdmissionWrite
}

func (h *activationReadinessHost) Complete(binding, commitment []byte) (*vmcommon.VMOutput, error) {
	r := h.activation.registration.owner.records
	if !bytes.Equal(binding, h.binding) || len(commitment) != r.hasher.Size() {
		return nil, errActivationRecord
	}
	_, err := h.activation.writeActivationInHeader(h.context, h.token, h.intentID, h.genesis, h.certificates, commitment, &h.written)
	if err != nil {
		return nil, err
	}
	return h.convergenceHost.Complete(binding, commitment)
}

func (h *activationReadinessHost) VerifyParent(binding, commitment []byte) error {
	r := h.activation.registration.owner.records
	if !bytes.Equal(binding, h.binding) || len(commitment) != r.hasher.Size() {
		return errActivationRecord
	}
	account, err := r.state.systemAccount()
	if err != nil {
		return err
	}
	key := append([]byte(registrationActivationPrefix), h.token...)
	parent, _, err := account.RetrieveValue(key)
	if err != nil {
		return err
	}
	fields, err := r.decodeActivationParent(parent, h.token)
	if err != nil || len(fields) != 4 || !bytes.Equal(fields[1], h.intentID) || !bytes.Equal(fields[3], commitment) {
		return errActivationRecord
	}
	for _, w := range h.written {
		current, _, err := account.RetrieveValue(w.key)
		if err != nil {
			return err
		}
		if !bytes.Equal(current, w.value) {
			return errActivationRecord
		}
	}
	return h.convergenceHost.VerifyParent(binding, commitment)
}

// decodeActivationParent checks the retained state-specific shape. It does not
// authenticate canonical application or supply a readiness commitment.
func (r *registrationRecords) decodeActivationParent(raw, token []byte) ([][]byte, error) {
	fields, err := registrationBoundedFields(r, raw, 3, 7, r.maxBytes)
	if err != nil || !bytes.Equal(fields[0], token) || len(fields[1]) != r.hasher.Size() {
		return nil, errActivationRecord
	}
	switch string(fields[2]) {
	case "BootstrapDeny":
		if len(fields) == 3 {
			return fields, nil
		}
	case "RetiredDeny":
		if len(fields) == 7 {
			for _, proof := range fields[3:] {
				if len(proof) == 0 {
					return nil, errActivationRecord
				}
			}
			return fields, nil
		}
		fallthrough
	case "Active", "WindDownDeny":
		if len(fields) == 4 && len(fields[3]) == r.hasher.Size() {
			return fields, nil
		}
	}
	return nil, errActivationRecord
}

func (a *activationRecords) writeActivationInHeader(context *HeaderTimeContext, token, intentID, genesis, certificates,
	commitment []byte, written *[]scopedAdmissionWrite) (*vmcommon.VMOutput, error) {
	r := a.registration.owner.records
	at, epoch, err := scopedAdmissionTime(context)
	if err != nil {
		return nil, err
	}
	intent, manager, err := r.registeredToken(token)
	if err != nil {
		return nil, err
	}
	_, digest, id, err := r.identity(intent.body)
	if err != nil || epoch < a.registration.enableEpoch || at > intent.body.expiry || !bytes.Equal(id, intentID) ||
		!bytes.Equal(digest, a.registration.owner.digest) || !bytes.Equal(manager, a.registration.owner.manager) ||
		!bytes.Equal(intent.body.networkDomain, a.registration.domain) {
		return nil, errActivationRecord
	}
	// F04: the intent-bound admission must still be current, unexpired and
	// unwithdrawn at activation (Part A L2390-2395).
	if err = a.registration.coveredAdmission(context, intent.body); err != nil {
		return nil, err
	}
	var decoded activationGenesis
	err = verifyRegistrationState(a.registration.owner.boundary.stores, func() error {
		var verifyError error
		decoded, verifyError = a.host.VerifyActivation(bytes.Clone(a.registration.domain), bytes.Clone(token),
			bytes.Clone(intentID), bytes.Clone(intent.encoded), bytes.Clone(genesis), bytes.Clone(certificates), at, epoch)
		return verifyError
	})
	if err != nil {
		return nil, err
	}
	if decoded.epoch != 1 || !bytes.Equal(decoded.token, token) ||
		!bytes.Equal(decoded.closurePlan, intent.body.closurePlan) ||
		len(decoded.classes) == 0 || len(decoded.classes) > r.maxBytes/2 {
		return nil, errActivationRecord
	}
	// Validate complete provider output before retaining aliases or writing.
	remaining := r.maxBytes
	classes := make([]activationActionClass, len(decoded.classes))
	seen := make(map[string]struct{}, len(classes))
	for i, c := range decoded.classes {
		if len(c.subject) == 0 || len(c.class) == 0 || len(c.subject) > remaining {
			return nil, errActivationRecord
		}
		remaining -= len(c.subject)
		if len(c.class) > remaining {
			return nil, errActivationRecord
		}
		remaining -= len(c.class)
		identity, e := r.frame(a.actions.domain, c.subject, c.class)
		if e != nil {
			return nil, e
		}
		if _, duplicate := seen[string(identity)]; duplicate {
			return nil, errActivationRecord
		}
		seen[string(identity)] = struct{}{}
		classes[i] = activationActionClass{bytes.Clone(c.subject), bytes.Clone(c.class)}
	}
	epochBytes := binary.BigEndian.AppendUint64(nil, 1)
	tokenKey, err := r.frame(token)
	if err != nil {
		return nil, err
	}
	bodyIdentity, err := r.frame(token, epochBytes)
	if err != nil {
		return nil, err
	}
	bodyKey := append([]byte(currentLocalBodyPrefix), bodyIdentity...)
	pointerKey := append([]byte(currentLocalPointerPrefix), tokenKey...)
	lifecycleKey := append([]byte(lifecycleRecordPrefix), tokenKey...)
	activeKey, err := a.actions.key("active", a.actions.domain, token)
	if err != nil {
		return nil, err
	}
	account, err := r.state.systemAccount()
	if err != nil {
		return nil, err
	}
	for _, key := range [][]byte{bodyKey, pointerKey, lifecycleKey, activeKey} {
		value, _, e := account.RetrieveValue(key)
		if e != nil {
			return nil, e
		}
		if len(value) != 0 {
			return nil, errActivationRecord
		}
	}
	pointer, err := r.frame(epochBytes, r.hasher.Compute(string(genesis)))
	if err != nil {
		return nil, err
	}
	lifecycle, err := r.frame(token, epochBytes, []byte("SETUP"))
	if err != nil {
		return nil, err
	}
	bootstrap, err := r.frame(token, intentID, []byte("BootstrapDeny"))
	if err != nil {
		return nil, err
	}
	activationKey := append([]byte(registrationActivationPrefix), token...)
	checkBootstrap := func() error {
		old, _, e := account.RetrieveValue(activationKey)
		if e != nil {
			return e
		}
		if !bytes.Equal(old, bootstrap) {
			return errActivationRecord
		}
		return nil
	}
	baseWrites := []scopedAdmissionWrite{{bodyKey, genesis}, {pointerKey, pointer}, {lifecycleKey, lifecycle}}
	if written != nil {
		if len(commitment) != r.hasher.Size() {
			return nil, errActivationRecord
		}
		if err = checkBootstrap(); err != nil {
			return nil, err
		}
		memberKey := append([]byte(registryMemberKeyPrefix), token...)
		member, _, e := account.RetrieveValue(memberKey)
		if e != nil {
			return nil, e
		}
		if !bytes.Equal(member, []byte{1}) {
			return nil, errActivationRecord
		}
		activation, e := r.frameBatch(true, token, intentID, []byte("Active"), commitment)
		if e != nil {
			return nil, e
		}
		baseWrites = append(baseWrites, scopedAdmissionWrite{activationKey, activation})
		if e = a.registration.resourceBudget(r).retainRecords(account, epoch, true, baseWrites...); e != nil {
			return nil, e
		}
		association, e := r.frame(token, intentID, digest, intent.encoded, manager)
		if e != nil {
			return nil, e
		}
		consumed, e := r.frame(intent.encoded, []byte("CONSUMED"), token)
		if e != nil {
			return nil, e
		}
		*written = append(baseWrites,
			scopedAdmissionWrite{memberKey, []byte{1}},
			scopedAdmissionWrite{append([]byte(registrationAssociationPrefix), token...), association},
			scopedAdmissionWrite{append([]byte(registrationIntentPrefix), intentID...), consumed})
	} else {
		activation, e := r.frame(token, intentID, []byte("Active"))
		if e != nil || len(activation) > len(bootstrap) {
			return nil, errActivationRecord
		}
		if e = a.registration.resourceBudget(r).retain(account, epoch, baseWrites...); e != nil {
			return nil, e
		}
		// Preserve the original comparison path's already charged slot.
		account, e = r.state.systemAccount()
		if e != nil {
			return nil, e
		}
		if e = checkBootstrap(); e != nil {
			return nil, e
		}
		if e = account.SaveKeyValue(activationKey, activation); e != nil {
			return nil, e
		}
		if e = r.state.accounts.SaveAccount(account); e != nil {
			return nil, e
		}
	}
	for _, c := range classes {
		if err = a.actions.initializeInOperation(context, c.subject, c.class, token); err != nil {
			return nil, err
		}
		key, e := a.actions.key("nonce", a.actions.domain, c.subject, c.class)
		if e != nil {
			return nil, e
		}
		counter, e := a.actions.read(key)
		if e != nil {
			return nil, e
		}
		// Activation cannot reset a live action class in order to manufacture
		// its prescribed initial zero state. The actual class/subject registry
		// must select the correct replay domain before admitting this owner.
		if len(counter) != 8 || binary.BigEndian.Uint64(counter) != 0 {
			return nil, errActivationRecord
		}
		if written != nil {
			*written = append(*written, scopedAdmissionWrite{key, bytes.Clone(counter)})
		}
	}
	if written != nil {
		aggregate, e := a.actions.aggregate(nil)
		if e != nil {
			return nil, e
		}
		*written = append(*written, scopedAdmissionWrite{activeKey, aggregate})
		return nil, nil // the native phase host owns the pending output
	}
	return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
}
