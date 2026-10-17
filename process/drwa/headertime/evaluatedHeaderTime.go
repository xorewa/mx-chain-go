package headertime

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
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// HeaderMilliseconds is the DRWA-defined typed evaluated-header coordinate
// (Part A L550-568). It introduces no clock or encoding.
type HeaderMilliseconds uint64

var (
	ErrInactiveHeaderTime    = errors.New("DRWA evaluated-header context is inactive")
	ErrUnavailableHeaderTime = errors.New("DRWA evaluated-header milliseconds are unavailable")
)

// HeaderTimeSource is the read-only typed view supplied by the native evaluated
// header owner. A consumer binds one source at construction, not per request.
// It adds no method to the upstream vm-common interfaces.
type HeaderTimeSource interface {
	EvaluatedHeaderTimeContext() (*HeaderTimeContext, error)
	IsInterfaceNil() bool
}

// EvaluatedHeaderTime owns operation contexts. The native hook uses BeginBound
// after successful installation and supplies its exclusive lease/identity
// checks. Begin alone is the unbound primitive; it is not native installation
// or canonicality evidence and cannot impersonate another consumer's source.
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
	acquire    func() (func(), error)
	validate   func() error
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
	return p.begin(header, nil, nil)
}

// BeginBound attaches the native owner's lease and validation to this operation.
// The owner keeps its installer and clock private; consumers receive only the
// context. The callbacks are native constructor dependencies, never wire input.
func (p *EvaluatedHeaderTime) BeginBound(header data.HeaderHandler,
	acquire func() (func(), error), validate func() error) (*HeaderTimeContext, error) {
	if acquire == nil || validate == nil {
		p.Reset()
		return nil, ErrInactiveHeaderTime
	}
	return p.begin(header, acquire, validate)
}

func (p *EvaluatedHeaderTime) begin(header data.HeaderHandler,
	acquire func() (func(), error), validate func() error) (*HeaderTimeContext, error) {
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
	context := &HeaderTimeContext{owner: p, headerHash: bytes.Clone(identity), epoch: header.GetEpoch(),
		shard: header.GetShardID(), timestamp: milliseconds, acquire: acquire, validate: validate}
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

// Lease holds the same immutable operation coordinate across a native effect.
// It exposes no setter, header alias, clock owner or host-provided timestamp.
func (c *HeaderTimeContext) Lease() (HeaderMilliseconds, uint32, func(), error) {
	if c == nil || c.owner == nil {
		return 0, 0, nil, ErrInactiveHeaderTime
	}
	releaseNative := func() {}
	if c.acquire != nil {
		var err error
		releaseNative, err = c.acquire()
		if err != nil {
			return 0, 0, nil, err
		}
	}
	p := c.owner
	p.mut.RLock()
	release := func() { p.mut.RUnlock(); releaseNative() }
	if p.current != c {
		release()
		return 0, 0, nil, ErrInactiveHeaderTime
	}
	if c.validate != nil {
		if err := c.validate(); err != nil {
			release()
			return 0, 0, nil, err
		}
	}
	if !p.flags.IsFlagEnabledInEpoch(common.SupernovaFlag, c.epoch) {
		release()
		return 0, 0, nil, ErrUnavailableHeaderTime
	}
	_, milliseconds, err := common.PrepareTimestampBasedOnHeaderData(c.timestamp, c.epoch, p.flags)
	if err != nil {
		release()
		return 0, 0, nil, err
	}
	return HeaderMilliseconds(milliseconds), c.epoch, release, nil
}

func (c *HeaderTimeContext) Milliseconds() (HeaderMilliseconds, error) {
	time, _, release, err := c.Lease()
	if err != nil {
		return 0, err
	}
	defer release()
	return time, nil
}

// HeaderIdentity returns defensive copies of native identity plus owning locus,
// for the producer/adapter binding. It grants no canonicality by itself.
func (c *HeaderTimeContext) HeaderIdentity() ([]byte, uint32) {
	if c == nil {
		return nil, 0
	}
	return bytes.Clone(c.headerHash), c.shard
}

func (p *EvaluatedHeaderTime) EvaluatedHeaderTimeContext() (*HeaderTimeContext, error) {
	if p == nil {
		return nil, ErrInactiveHeaderTime
	}
	p.mut.RLock()
	defer p.mut.RUnlock()
	if p.current == nil {
		return nil, ErrInactiveHeaderTime
	}
	return p.current, nil
}

func (p *EvaluatedHeaderTime) IsInterfaceNil() bool { return p == nil }

// WithHeaderTime runs inside the caller's existing T04 rollback boundary.
// Native installation is leased across callbacks and writes. An attempted
// reentrant installation invalidates the context; the final check therefore
// turns an otherwise successful callback into rollback, never a committed debit.
func WithHeaderTime(source HeaderTimeSource, context *HeaderTimeContext,
	execute func() (*vmcommon.VMOutput, error)) (*vmcommon.VMOutput, error) {
	if check.IfNil(source) || context == nil {
		return nil, ErrInactiveHeaderTime
	}
	current, err := source.EvaluatedHeaderTimeContext()
	if err != nil {
		return nil, err
	}
	if current != context {
		return nil, ErrInactiveHeaderTime
	}
	if context.acquire != nil {
		release, err := context.acquire()
		if err != nil {
			return nil, err
		}
		defer release()
	}
	output, err := execute()
	if err != nil {
		return output, err
	}
	if _, err = context.Milliseconds(); err != nil {
		return nil, err
	}
	return output, nil
}
