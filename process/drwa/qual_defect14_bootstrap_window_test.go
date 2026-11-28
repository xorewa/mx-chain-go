package drwa

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// DEFECTS item 14: on every path of the bootstrap proof the validity window
// is the one in the signed bytes (Part A L1234-1237, AR-05 L1692). The header
// time of these fixtures is 50, the intent expires at 100 and the longest
// allowed validity is 100.

type qualDefect14Case struct {
	signed  [2]uint64 // not-before, not-after in the signed message
	binding [2]uint64 // what the caller's binding states; zero is absent
	admit   bool
}

func qualDefect14Cases() map[string]qualDefect14Case {
	return map[string]qualDefect14Case{
		// The signed window against header time 50, binding absent.
		"ends one before":    {[2]uint64{10, 49}, [2]uint64{}, false},
		"ends at the time":   {[2]uint64{10, 50}, [2]uint64{}, true},
		"ends one after":     {[2]uint64{10, 51}, [2]uint64{}, true},
		"starts one before":  {[2]uint64{49, 90}, [2]uint64{}, true},
		"starts at the time": {[2]uint64{50, 90}, [2]uint64{}, true},
		"starts one after":   {[2]uint64{51, 90}, [2]uint64{}, false},
		"one instant":        {[2]uint64{50, 50}, [2]uint64{}, true},
		"reversed":           {[2]uint64{60, 40}, [2]uint64{}, false},
		"after the intent":   {[2]uint64{10, 101}, [2]uint64{}, false},
		// The caller's binding against the signed window.
		"binding equal":                          {[2]uint64{10, 90}, [2]uint64{10, 90}, true},
		"binding wider, signed window expired":   {[2]uint64{10, 40}, [2]uint64{10, 90}, false},
		"binding wider, signed window not begun": {[2]uint64{60, 90}, [2]uint64{10, 90}, false},
		"binding wider, signed window current":   {[2]uint64{20, 80}, [2]uint64{10, 90}, false},
		"binding narrower":                       {[2]uint64{10, 90}, [2]uint64{20, 80}, false},
		"binding states only the end":            {[2]uint64{10, 90}, [2]uint64{0, 90}, false},
		"binding states only the start":          {[2]uint64{10, 90}, [2]uint64{10, 0}, false},
	}
}

func TestQualDefect14GenericPathTakesTheWindowFromTheSignedBytes(t *testing.T) {
	for name, tc := range qualDefect14Cases() {
		t.Run(name, func(t *testing.T) {
			c, boundary, source, context, provider, b, _, _ := qualBootstrapMechanicsFixture(t)
			_, _, keys := qualR3Fixture(t, 100)
			fields := qualA38Split(b.message)
			fields[11], fields[12] = qualA38U64(tc.signed[0]), qualA38U64(tc.signed[1])
			b.message = qualRecordFrame(fields...)
			b.notBefore, b.notAfter = tc.binding[0], tc.binding[1]
			// The provider is told the signed window, never the caller's.
			provider.expected.message = bytes.Clone(b.message)
			provider.expected.notBefore, provider.expected.notAfter = tc.signed[0], tc.signed[1]
			raw := qualA38Envelope(b.message, keys["REGISTER_TOKEN_ADMISSION"], 0, 2, 4)
			if !tc.admit {
				qualBootstrapMechanicsDenial(t, c, boundary, source, context, provider, b, raw)
				require.Zero(t, provider.calls, "refused before the provider is asked")
				return
			}
			require.NoError(t, boundary.executeOwned(func(op *rollbackOperation) ([]*vmcommon.VMOutput, error) {
				return nil, qualVerifyBootstrapMechanics(c, op, boundary, source, context, provider, b, raw)
			}))
			require.Equal(t, 1, provider.calls)
		})
	}
	// A signed message that carries no window in its last two fields.
	for name, edit := range map[string]func(fields [][]byte) [][]byte{
		"last field is not eight bytes":        func(f [][]byte) [][]byte { f[12] = []byte{90}; return f },
		"last field is nine bytes":             func(f [][]byte) [][]byte { f[12] = append(qualA38U64(90), 0); return f },
		"second last field is nine bytes":      func(f [][]byte) [][]byte { f[11] = append(qualA38U64(10), 0); return f },
		"second last field is not eight bytes": func(f [][]byte) [][]byte { f[11] = []byte("ten"); return f },
		"window fields removed":                func(f [][]byte) [][]byte { return f[:11] },
		"one field only":                       func(f [][]byte) [][]byte { return f[:1] },
	} {
		t.Run(name, func(t *testing.T) {
			c, boundary, source, context, provider, b, _, _ := qualBootstrapMechanicsFixture(t)
			_, _, keys := qualR3Fixture(t, 100)
			b.message = qualRecordFrame(edit(qualA38Split(b.message))...)
			provider.expected.message = bytes.Clone(b.message)
			raw := qualA38Envelope(b.message, keys["REGISTER_TOKEN_ADMISSION"], 0, 2, 4)
			qualBootstrapMechanicsDenial(t, c, boundary, source, context, provider, b, raw)
			b.notBefore, b.notAfter = 0, 0
			qualBootstrapMechanicsDenial(t, c, boundary, source, context, provider, b, raw)
			require.Zero(t, provider.calls)
		})
	}
}

// The A126 path already read the window from the signed message; the same
// table holds, and what the caller's binding states about a window is ignored.
func TestQualDefect14A126PathTakesTheWindowFromTheSignedBytes(t *testing.T) {
	for name, tc := range qualDefect14Cases() {
		t.Run(name, func(t *testing.T) {
			c, owner, source, context, p, b, _, _ := qualBootstrapMechanicsFixture(t)
			_, ctx, keys := qualR3Fixture(t, 100)
			m := qualA126Message(t, ctx, tc.signed[0], tc.signed[1])
			b.purpose, b.intent = []byte("BOOTSTRAP_INTENT"), ctx.intentBody
			b.role, b.authority, b.message = ctx.independent.role, ctx.independent.body, nil
			b.notBefore, b.notAfter = 0, 0
			p.id, p.digest = ctx.intentID, ctx.intentHash
			p.expected = b
			p.expected.message = bytes.Clone(m)
			p.expected.notBefore, p.expected.notAfter = tc.signed[0], tc.signed[1]
			p.expected.signerIndices = []uint64{0, 2, 4}
			b.notBefore, b.notAfter = tc.binding[0], tc.binding[1]
			raw := qualA38Envelope(m, keys["REGISTER_TOKEN"], 0, 2, 4)
			err := owner.executeOwned(func(op *rollbackOperation) ([]*vmcommon.VMOutput, error) {
				return nil, qualA126Verify(c, op, owner, source, context, p, b, raw)
			})
			// On this path only the signed window decides.
			signedValid := tc.signed[0] <= 50 && 50 <= tc.signed[1] && tc.signed[1] <= 100
			if signedValid {
				require.NoError(t, err)
				require.Equal(t, 1, p.calls)
				return
			}
			require.Error(t, err)
			require.Zero(t, p.calls)
		})
	}
}

// Restart: a new hook and codec over the reopened store decide the same.
func TestQualDefect14SameDecisionsAfterRestart(t *testing.T) {
	for name, tc := range map[string]qualDefect14Case{
		"signed window current, binding absent": {[2]uint64{10, 90}, [2]uint64{}, true},
		"signed window expired, binding wider":  {[2]uint64{10, 40}, [2]uint64{10, 90}, false},
		"signed window expired, binding absent": {[2]uint64{10, 49}, [2]uint64{}, false},
	} {
		t.Run(name, func(t *testing.T) {
			c, _, _, _, provider, b, _, end := qualBootstrapMechanicsFixture(t)
			_, _, keys := qualR3Fixture(t, 100)
			fields := qualA38Split(b.message)
			fields[11], fields[12] = qualA38U64(tc.signed[0]), qualA38U64(tc.signed[1])
			b.message = qualRecordFrame(fields...)
			b.notBefore, b.notAfter = tc.binding[0], tc.binding[1]
			provider.expected.message = bytes.Clone(b.message)
			provider.expected.notBefore, provider.expected.notAfter = tc.signed[0], tc.signed[1]
			raw := qualA38Envelope(b.message, keys["REGISTER_TOKEN_ADMISSION"], 0, 2, 4)
			end()
			reopened := qualSP224Reopen(t, c.source.state.accounts.(*qualNativeStore))
			records, err := newRegistrationRecords(reopened, c.source.marshaller, c.source.hasher, c.source.maxBytes)
			require.NoError(t, err)
			codec, err := newRegistrationApprovalCodec(records, c.bounds)
			require.NoError(t, err)
			boundary, err := NewRollbackContainment(reopened)
			require.NoError(t, err)
			hook, _ := qualT42Hook(t, reopened, core.MetachainShardId, true)
			context, endAgain := qualT42Install(t, hook, core.MetachainShardId, 50)
			defer endAgain()
			err = boundary.executeOwned(func(op *rollbackOperation) ([]*vmcommon.VMOutput, error) {
				return nil, qualVerifyBootstrapMechanics(codec, op, boundary, hook, context, provider, b, raw)
			})
			require.Equal(t, tc.admit, err == nil, fmt.Sprint(err))
		})
	}
}

// A caller binding whose intent or authority body cannot be decoded is
// refused on both paths before any window or signature is looked at.
func TestQualDefect14UndecodableBindingIsRefused(t *testing.T) {
	for name, edit := range map[string]func(b *bootstrapProofBinding){
		"intent is not an intent body":       func(b *bootstrapProofBinding) { b.intent = []byte("not an intent body") },
		"authority is not an authority body": func(b *bootstrapProofBinding) { b.authority = []byte("not an authority body") },
	} {
		t.Run(name, func(t *testing.T) {
			c, boundary, source, context, provider, b, raw, _ := qualBootstrapMechanicsFixture(t)
			edit(&b)
			qualBootstrapMechanicsDenial(t, c, boundary, source, context, provider, b, raw)
			require.Zero(t, provider.calls)
		})
	}
}
