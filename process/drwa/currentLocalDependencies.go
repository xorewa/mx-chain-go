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

// EXPERIMENTAL physical representations of the existing current CEB, immutable
// CEB and dependency identities. No release allocation or new state writer.
const currentLocalPointerPrefix = core.ProtectedKeyPrefix + "DRWA@currentCEB@"
const currentLocalBodyPrefix = core.ProtectedKeyPrefix + "DRWA@CEB@"
const currentLocalDependencyPrefix = core.ProtectedKeyPrefix + "DRWA@dependency@"

var errCurrentLocalDependency = errors.New("invalid DRWA current local dependency")

type currentLocalReference struct {
	kind, id, version, hash []byte
}

// currentLocalHost MUST belong to the actual native import/writer owner. There
// is no default. Dependencies validates the complete CEB's admitted versioned
// interpretation and enumerates ALL required authorities, schemas, gas/profile/
// parser and token-admin material. A caller-selected subset is not acceptable.
// VerifyCurrent/VerifyDependency prove actual canonical local application under
// the qualified route predicate, not AccountsDB presence, Commit or a boolean.
// Actual canonicality/CEB decoder/native installation remain first-consumer gates.
type currentLocalHost interface {
	VerifyCurrent(token, pointer, body []byte) error
	Dependencies(body []byte) ([]currentLocalReference, error)
	VerifyDependency(reference currentLocalReference, material []byte) error
	IsInterfaceNil() bool
}

// currentLocalDependencies is a private bounded native reader. It owns no
// cache, journal, allocation, mutation, all-shard barrier or positive capability.
// Its caller must use the same exclusive native owner for resolution,
// revalidation and dependent writes. Read/re-read detects changed bytes, not
// aliases or a globally atomic snapshot. T23 supplies the remaining route,
// lifecycle, current purpose, account/control, version/CAS and promotion checks.
type currentLocalDependencies struct {
	codec         *registrationRecords
	host          currentLocalHost
	maxReferences int
}

type currentLocalView struct {
	owner                      *currentLocalDependencies
	token, hash, pointer, body []byte
	epoch                      uint64
	keys, materials            [][]byte
}

func newCurrentLocalDependencies(accounts state.AccountsAdapter, marshaller marshal.Marshalizer,
	hasher hashing.Hasher, maxBytes, maxReferences int, host currentLocalHost) (*currentLocalDependencies, error) {
	if check.IfNil(host) || maxReferences <= 0 || maxReferences > maxBytes/2 {
		return nil, errCurrentLocalDependency
	}
	codec, err := newRegistrationRecords(accounts, marshaller, hasher, maxBytes)
	if err != nil {
		return nil, err
	}
	return &currentLocalDependencies{codec: codec, host: host, maxReferences: maxReferences}, nil
}

func (r *currentLocalDependencies) read(key []byte) ([]byte, error) {
	account, err := r.codec.state.systemAccount()
	if err != nil {
		return nil, err
	}
	value, _, err := account.RetrieveValue(bytes.Clone(key))
	if err != nil {
		return nil, err
	}
	if len(value) == 0 || len(value) > r.codec.maxBytes {
		return nil, errCurrentLocalDependency
	}
	return bytes.Clone(value), nil
}

func cloneCurrentLocalReference(ref currentLocalReference) currentLocalReference {
	return currentLocalReference{bytes.Clone(ref.kind), bytes.Clone(ref.id), bytes.Clone(ref.version), bytes.Clone(ref.hash)}
}

func (r *currentLocalDependencies) referenceKey(ref currentLocalReference) ([]byte, error) {
	if len(ref.kind) == 0 || len(ref.id) == 0 || len(ref.version) == 0 || len(ref.hash) != r.codec.hasher.Size() {
		return nil, errCurrentLocalDependency
	}
	identity, err := r.codec.frame(ref.kind, ref.id, ref.version)
	if err != nil {
		return nil, err
	}
	return append([]byte(currentLocalDependencyPrefix), identity...), nil
}

func (r *currentLocalDependencies) resolve(token []byte, epoch uint64, hash []byte) (*currentLocalView, error) {
	if len(token) > r.codec.maxBytes || !vmcommon.ValidateToken(token) || len(hash) != r.codec.hasher.Size() {
		return nil, errCurrentLocalDependency
	}
	// Retain expected identity before invoking an external native owner/decoder.
	token, hash = bytes.Clone(token), bytes.Clone(hash)
	tokenKey, err := r.codec.frame(token)
	if err != nil {
		return nil, err
	}
	pointerKey := append([]byte(currentLocalPointerPrefix), tokenKey...)
	pointer, err := r.read(pointerKey)
	if err != nil {
		return nil, err
	}
	f, err := r.codec.unframe(pointer, 2)
	if err != nil {
		return nil, err
	}
	if len(f[0]) != 8 || binary.BigEndian.Uint64(f[0]) != epoch || !bytes.Equal(f[1], hash) {
		return nil, errCurrentLocalDependency
	}
	identity, err := r.codec.frame(token, f[0])
	if err != nil {
		return nil, err
	}
	bodyKey := append([]byte(currentLocalBodyPrefix), identity...)
	body, err := r.read(bodyKey)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(r.codec.hasher.Compute(string(body)), hash) {
		return nil, errCurrentLocalDependency
	}
	if err = r.host.VerifyCurrent(bytes.Clone(token), bytes.Clone(pointer), bytes.Clone(body)); err != nil {
		return nil, err
	}
	refs, err := r.host.Dependencies(bytes.Clone(body))
	if err != nil {
		return nil, err
	}
	if len(refs) == 0 || len(refs) > r.maxReferences {
		return nil, errCurrentLocalDependency
	}
	ownedRefs := make([]currentLocalReference, len(refs))
	for i, ref := range refs {
		// Validate bounded native framing/hash width BEFORE copying decoder
		// buffers. Count bounds alone cannot bound an oversized nested field.
		if _, err = r.referenceKey(ref); err != nil {
			return nil, err
		}
		ownedRefs[i] = cloneCurrentLocalReference(ref)
	}
	view := &currentLocalView{owner: r, token: token, hash: hash, pointer: pointer, body: body, epoch: epoch,
		keys: [][]byte{pointerKey, bodyKey}, materials: [][]byte{pointer, body}}
	seen := make(map[string]struct{}, len(refs))
	for _, candidate := range ownedRefs {
		ref := cloneCurrentLocalReference(candidate)
		key, e := r.referenceKey(ref)
		if e != nil {
			return nil, e
		}
		if _, duplicate := seen[string(key)]; duplicate {
			return nil, errCurrentLocalDependency
		}
		seen[string(key)] = struct{}{}
		material, e := r.read(key)
		if e != nil {
			return nil, e
		}
		if !bytes.Equal(r.codec.hasher.Compute(string(material)), ref.hash) {
			return nil, errCurrentLocalDependency
		}
		if e = r.host.VerifyDependency(cloneCurrentLocalReference(ref), bytes.Clone(material)); e != nil {
			return nil, e
		}
		view.keys = append(view.keys, key)
		view.materials = append(view.materials, material)
	}
	// Native reads may observe candidate-state changes from earlier owner work.
	// No stale account object or mutable verifier buffer may supply this result.
	for i, key := range view.keys {
		value, e := r.read(key)
		if e != nil {
			return nil, e
		}
		if !bytes.Equal(value, view.materials[i]) {
			return nil, errCurrentLocalDependency
		}
	}
	return view, nil
}

// revalidate repeats canonical/interpretation/material resolution. A snapshot
// is never an authorization token or permission to skip the owning writer.
func (r *currentLocalDependencies) revalidate(prior *currentLocalView) error {
	if prior == nil || prior.owner != r {
		return errCurrentLocalDependency
	}
	current, err := r.resolve(prior.token, prior.epoch, prior.hash)
	if err != nil {
		return err
	}
	if len(current.keys) != len(prior.keys) {
		return errCurrentLocalDependency
	}
	for i, key := range current.keys {
		if !bytes.Equal(key, prior.keys[i]) || !bytes.Equal(current.materials[i], prior.materials[i]) {
			return errCurrentLocalDependency
		}
	}
	return nil
}
