package drwa

import (
	"bytes"
	"errors"
	"sync"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	nodeErrors "github.com/multiversx/mx-chain-go/errors"
)

// HeaderMilliseconds is the DRWA-defined typed evaluated-header coordinate
// (Part A L550-568). It introduces no clock or encoding.
type HeaderMilliseconds uint64

var (
	ErrInactiveHeaderTime    = errors.New("DRWA evaluated-header context is inactive")
	ErrUnavailableHeaderTime = errors.New("DRWA evaluated-header milliseconds are unavailable")
)

// EvaluatedHeaderTime owns the lifecycle of unwired DRWA time contexts. Begin
// accepts an already selected and successfully installed evaluated header, never
// a notification epoch or committed tip. The eventual T42 producer must prove
// that selection/installation, native hook alias ownership and execution mode.
// This component does not install a hook, authenticate canonicality or bind a
// policy consumer. No ordinary producer or consumer imports it.
type EvaluatedHeaderTime struct {
	mut        sync.RWMutex
	flags      common.EnableEpochsHandler
	marshaller marshal.Marshalizer
	hasher     hashing.Hasher
	current    *HeaderTimeContext
}

// HeaderTimeContext is an operation-owned capability, not a reusable cached
// timestamp. Its header identity and coordinate are captured from the same
// producer-owned native header. That producer must not mutate it during Begin.
// No mutable header or native installer alias is exposed by this component.
type HeaderTimeContext struct {
	owner      *EvaluatedHeaderTime
	headerHash []byte
	epoch      uint32
	shard      uint32
	timestamp  uint64
}

func NewEvaluatedHeaderTime(flags common.EnableEpochsHandler, marshaller marshal.Marshalizer, hasher hashing.Hasher) (*EvaluatedHeaderTime, error) {
	if check.IfNil(flags) {
		return nil, nodeErrors.ErrNilEnableEpochsHandler
	}
	if check.IfNil(marshaller) {
		return nil, nodeErrors.ErrNilMarshalizer
	}
	if check.IfNil(hasher) {
		return nil, nodeErrors.ErrNilHasher
	}
	return &EvaluatedHeaderTime{flags: flags, marshaller: marshaller, hasher: hasher}, nil
}

// Begin invalidates the previous operation BEFORE validation, including failed
// attempts or repeated A -> B -> A header identities. No integer generation or
// protocol field is allocated. Missing context is an error; valid zero is valid.
func (p *EvaluatedHeaderTime) Begin(header data.HeaderHandler) (*HeaderTimeContext, error) {
	p.mut.Lock()
	defer p.mut.Unlock()
	p.current = nil
	if check.IfNil(header) {
		return nil, common.ErrNilHeaderHandler
	}
	if !header.IsHeaderV3() || !p.flags.IsFlagEnabledInEpoch(common.SupernovaFlag, header.GetEpoch()) {
		return nil, ErrUnavailableHeaderTime
	}
	identity, err := core.CalculateHash(p.marshaller, p.hasher, header)
	if err != nil {
		return nil, err
	}
	_, milliseconds, err := common.GetHeaderTimestamps(header, p.flags)
	if err != nil {
		return nil, err
	}
	context := &HeaderTimeContext{owner: p, headerHash: bytes.Clone(identity), epoch: header.GetEpoch(), shard: header.GetShardID(), timestamp: milliseconds}
	p.current = context
	return context, nil
}

// End cannot end a newer operation when an old capability is supplied.
func (p *EvaluatedHeaderTime) End(context *HeaderTimeContext) {
	p.mut.Lock()
	defer p.mut.Unlock()
	if context != nil && p.current == context {
		p.current = nil
	}
}

// Reset invalidates contexts on owning-mode handoff, failed native installation
// or recovery. T42 must call it before any actual attempted native installation,
// including one that fails while leaving the old native header installed.
func (p *EvaluatedHeaderTime) Reset() {
	p.mut.Lock()
	defer p.mut.Unlock()
	p.current = nil
}

func (c *HeaderTimeContext) Milliseconds() (HeaderMilliseconds, error) {
	if c == nil || c.owner == nil {
		return 0, ErrInactiveHeaderTime
	}
	p := c.owner
	p.mut.RLock()
	defer p.mut.RUnlock()
	if p.current != c {
		return 0, ErrInactiveHeaderTime
	}
	if !p.flags.IsFlagEnabledInEpoch(common.SupernovaFlag, c.epoch) {
		return 0, ErrUnavailableHeaderTime
	}
	// Adopt the native helper, retaining its error instead of authorizing zero.
	_, milliseconds, err := common.PrepareTimestampBasedOnHeaderData(c.timestamp, c.epoch, p.flags)
	if err != nil {
		return 0, err
	}
	return HeaderMilliseconds(milliseconds), nil
}

// HeaderIdentity returns defensive copies of native identity plus owning locus,
// for the future producer/adapter binding. It grants no canonicality by itself.
func (c *HeaderTimeContext) HeaderIdentity() ([]byte, uint32) {
	if c == nil {
		return nil, 0
	}
	return bytes.Clone(c.headerHash), c.shard
}
