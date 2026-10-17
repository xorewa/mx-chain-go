package drwa

import (
	"bytes"

	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// RegistrationVerifier is the mandatory trusted ingress adapter for Part A
// L2199-2209/L2220-2234. Its DRWA-defined purpose discriminators below are
// construction inputs, not allocated certificate/wire enums. It must verify
// native issuer origin, canonical OPEN intent, CURRENT lawful scoped admission,
// fresh admission and intent-bound PA and independent REGISTER_TOKEN proofs,
// actual family/profile support and aggregate resource admission respectively.
// All checks bind this exact immutable body, creation digest and native time.
// It must be read-only and cannot commit/publish or replace the native owner.
//
// There is no default implementation. In particular, a requester-supplied
// boolean, address, roster or digest is never this adapter. D01 appointments,
// canonical import/finality and real route admission remain prerequisites;
// synthetic qualification adapters are not those protocol facts.
type RegistrationVerifier interface {
	VerifyRegistration(purpose string, intentID, intentHash, intentBody, creationDigest, proof []byte,
		at HeaderMilliseconds, epoch uint32) error
	IsInterfaceNil() bool
}

// RegistrationProofs transports untrusted evidence; no field is an authority.
type RegistrationProofs struct {
	CanonicalIntent, Issuer, CurrentAdmission, Admission, ProgramAdministration, Independent, Support, Resources []byte
}

func (p RegistrationProofs) values() [][]byte {
	return [][]byte{p.CanonicalIntent, p.Issuer, p.CurrentAdmission, p.Admission,
		p.ProgramAdministration, p.Independent, p.Support, p.Resources}
}

// RegistrationAdmission couples the existing T19 creator contract to the
// Part A L2199-2218 first-effect checks. It adds no journal or public bypass.
// The native registration endpoint supplies this owner, never transaction data.
type RegistrationAdmission struct {
	owner       *RegistrationIntentOwner
	source      HeaderTimeSource
	domain      []byte
	enableEpoch uint32
	verifier    RegistrationVerifier
	proofs      [][]byte
	limits      RegistrationResourceLimits
}

// RegistrationResourceLimits binds the existing GLOBAL scoped/intent budget,
// not a per-programme reservation. All retained states consume it permanently.
// Values come from the actual configured profile; R7 experiments select them
// explicitly. Permanent registry count/marker growth has T19's separate maxEver
// bound. Provision/reconcile this existing budget before admitting the owner.
type RegistrationResourceLimits struct {
	Records, RetainedBytes, NewRecordsPerEpoch uint64
}

// WithRegistrationAdmission binds one actual native time/account owner. Domain,
// epoch, verifier and manager are trusted configured inputs, without defaults.
// Experimental selections need R7; competent admission is still separate.
func (o *RegistrationIntentOwner) WithRegistrationAdmission(source HeaderTimeSource, domain []byte,
	enableEpoch uint32, limits RegistrationResourceLimits, verifier RegistrationVerifier, proofs RegistrationProofs) (*RegistrationAdmission, error) {
	if o == nil || o.records == nil || o.boundary == nil || o.guard != nil || check.IfNil(o.registration) ||
		check.IfNil(source) || source.GetAccountsAdapter() != o.records.state.accounts || check.IfNil(verifier) ||
		len(domain) == 0 || len(domain) > o.records.maxBytes || limits.Records == 0 || limits.RetainedBytes == 0 || limits.NewRecordsPerEpoch == 0 {
		return nil, errInvalidRegistrationRecord
	}
	remaining := o.records.maxBytes
	owned := make([][]byte, 0, 8)
	for _, proof := range proofs.values() {
		if len(proof) == 0 || len(proof) > remaining {
			return nil, errInvalidRegistrationRecord
		}
		remaining -= len(proof)
		owned = append(owned, bytes.Clone(proof))
	}
	return &RegistrationAdmission{owner: o, source: source, domain: bytes.Clone(domain),
		enableEpoch: enableEpoch, limits: limits, verifier: verifier, proofs: owned}, nil
}

func (a *RegistrationAdmission) IsInterfaceNil() bool { return a == nil }

// RegisterTokenForAuthenticatedCreation is the native endpoint's distinct
// structural contract: a bare T19 identity owner cannot satisfy it. Bind the
// actual endpoint arguments, not a caller-asserted body digest.
func (a *RegistrationAdmission) RegisterTokenForAuthenticatedCreation(intentID, creationBody,
	issuer, manager, family, profile, name, ticker []byte, decimals uint32,
	create func(state.AccountsAdapter, []byte, []byte, []byte, []byte, []byte, uint32, [][]byte) ([]byte, *vmcommon.VMOutput, error)) error {
	if a == nil || a.owner == nil || !bytes.Equal(intentID, a.owner.id) || len(creationBody) == 0 ||
		len(creationBody) > a.owner.records.maxBytes {
		return errInvalidRegistrationRecord
	}
	digest := a.owner.records.hasher.Compute(string(creationBody))
	return a.RegisterTokenForCommittedCreation(issuer, manager, family, profile, name, ticker, decimals, digest, create)
}

// RegisterTokenForCommittedCreation preserves the native structural creator
// contract. All checks and the COMPLETE creation/consumption/count operation
// share T04 and T42's lease, including the final post-write invalidation check.
func (a *RegistrationAdmission) RegisterTokenForCommittedCreation(issuer, manager, family,
	profile, name, ticker []byte, decimals uint32, bodyDigest []byte,
	create func(state.AccountsAdapter, []byte, []byte, []byte, []byte, []byte, uint32, [][]byte) ([]byte, *vmcommon.VMOutput, error)) error {
	if a == nil || a.owner == nil || a.owner.records == nil || len(bodyDigest) != a.owner.records.hasher.Size() {
		return errInvalidRegistrationRecord
	}
	digest := bytes.Clone(bodyDigest)
	bound := *a.owner
	// A private per-invocation codec binds resource growth to this exact native
	// epoch/operation; other handles retain their original lower-level contract.
	codec := *bound.records
	bound.records = &codec
	bound.guard = func(stores []state.AccountsAdapter, execute func() (*vmcommon.VMOutput, error)) (*vmcommon.VMOutput, error) {
		context, err := a.source.EvaluatedHeaderTimeContext()
		if err != nil {
			return nil, err
		}
		return withHeaderTime(a.source, context, func() (*vmcommon.VMOutput, error) {
			at, epoch, err := scopedAdmissionTime(context)
			if err != nil {
				return nil, err
			}
			intent, err := bound.records.intent(bound.id)
			if err != nil {
				return nil, err
			}
			if epoch < a.enableEpoch || intent.status != "OPEN" || at > intent.body.expiry ||
				!bytes.Equal(intent.digest, bound.digest) || !bytes.Equal(intent.body.networkDomain, a.domain) {
				return nil, errInvalidRegistrationRecord
			}
			purposes := []string{"CANONICAL_OPEN_INTENT", "ISSUER_TRANSACTION", "CURRENT_ADMISSION",
				"REGISTER_TOKEN_ADMISSION", "PROGRAM_ADMINISTRATION", "REGISTER_TOKEN", "CURRENT_SUPPORT", "RESOURCE_ADMISSION"}
			for i, purpose := range purposes {
				if err = verifyRegistrationState(stores, func() error {
					return a.verifier.VerifyRegistration(purpose, bytes.Clone(bound.id), bytes.Clone(bound.digest),
						bytes.Clone(intent.encoded), bytes.Clone(digest), bytes.Clone(a.proofs[i]), at, epoch)
				}); err != nil {
					return nil, err
				}
			}
			budget := a.resourceBudget(&codec)
			codec.retain = func(account state.UserAccountHandler, writes ...scopedAdmissionWrite) error {
				return budget.retainRecords(account, epoch, true, writes...)
			}
			return execute()
		})
	}
	return bound.RegisterTokenForCommittedCreation(issuer, manager, family, profile, name, ticker, decimals, digest, create)
}

func (a *RegistrationAdmission) resourceBudget(codec *registrationRecords) *scopedAdmissionRecords {
	return &scopedAdmissionRecords{codec: codec, limits: scopedAdmissionLimits{recordBytes: codec.maxBytes,
		records: a.limits.Records, retainedBytes: a.limits.RetainedBytes, newRecordsPerEpoch: a.limits.NewRecordsPerEpoch}}
}

// RetainBootstrapIntent is the D07 retained-creation boundary for the trusted
// bootstrap producer, before a new OPEN record exists. BOOTSTRAP_INTENT must
// authenticate the separate Step-1 issuer/current admission/proposed-set mandates
// (Part A L2133-2177); it is not a canonical-final registration certificate.
// The same native global budget used by scoped admission counts every retained
// intent, regardless of later expiry/cancellation/consumption. No eviction,
// per-platform reservation, new deposit, reset, or slot reuse is introduced.
func (a *RegistrationAdmission) RetainBootstrapIntent(encoded, proof []byte) error {
	if a == nil || a.owner == nil || a.owner.records == nil || a.owner.boundary == nil || len(encoded) == 0 || len(proof) == 0 || len(encoded) > a.owner.records.maxBytes || len(proof) > a.owner.records.maxBytes {
		return errInvalidRegistrationRecord
	}
	encoded, proof = bytes.Clone(encoded), bytes.Clone(proof)
	return a.owner.boundary.Execute(func() (*vmcommon.VMOutput, error) {
		context, err := a.source.EvaluatedHeaderTimeContext()
		if err != nil {
			return nil, err
		}
		return withHeaderTime(a.source, context, func() (*vmcommon.VMOutput, error) {
			at, epoch, err := scopedAdmissionTime(context)
			if err != nil {
				return nil, err
			}
			records := a.owner.records
			body, err := records.decodeBody(encoded)
			if err != nil {
				return nil, err
			}
			_, digest, id, err := records.identity(body)
			if err != nil || !bytes.Equal(id, a.owner.id) || !bytes.Equal(digest, a.owner.digest) ||
				!bytes.Equal(body.networkDomain, a.domain) || at > body.expiry {
				return nil, errInvalidRegistrationRecord
			}
			if err = verifyRegistrationState(a.owner.boundary.stores, func() error {
				return a.verifier.VerifyRegistration("BOOTSTRAP_INTENT", bytes.Clone(id), bytes.Clone(digest), bytes.Clone(encoded), nil, bytes.Clone(proof), at, epoch)
			}); err != nil {
				return nil, err
			}
			account, err := records.state.systemAccount()
			if err != nil {
				return nil, err
			}
			key := append([]byte(registrationIntentPrefix), id...)
			old, _, err := account.RetrieveValue(key)
			if err != nil {
				return nil, err
			}
			if len(old) != 0 {
				return nil, errInvalidRegistrationRecord
			}
			value, err := records.frame(encoded, []byte("OPEN"), nil)
			if err != nil {
				return nil, err
			}
			return nil, a.resourceBudget(records).retain(account, epoch, scopedAdmissionWrite{key, value})
		})
	})
}

// Authentication callbacks cannot mutate ANY participating native store, even
// through a retained alias. Native roots plus journal positions cover the full
// owned state, including a same-value save/ABA journal entry. On rejection T04
// restores every store; rollback failure retains the existing poison latch.
func verifyRegistrationState(stores []state.AccountsAdapter, verify func() error) error {
	roots, journals := make([][]byte, len(stores)), make([]int, len(stores))
	for i, store := range stores {
		root, err := store.RootHash()
		if err != nil {
			return err
		}
		roots[i], journals[i] = bytes.Clone(root), store.JournalLen()
	}
	if err := verify(); err != nil {
		return err
	}
	for i, store := range stores {
		root, err := store.RootHash()
		if err != nil {
			return err
		}
		if store.JournalLen() != journals[i] || !bytes.Equal(root, roots[i]) {
			return errInvalidRegistrationRecord
		}
	}
	return nil
}
