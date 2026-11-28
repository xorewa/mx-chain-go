package processing

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"

	drwaTime "github.com/multiversx/mx-chain-go/process/drwa/headertime"
)

// Owner decision SP2-24 D-1 (b), 28 November 2026: a header whose time field
// is zero gives no typed coordinate. These tests show the refusal stays a DRWA
// time error: the header is installed, the ordinary accessors answer, and
// ordinary calls give the same output, error and committed state as with the
// plain setter and as on a node without DRWA.

type qualSP224Digest struct{ lines []string }

func (d *qualSP224Digest) add(t *testing.T, label string, output *vmcommon.VMOutput, err error) {
	t.Helper()
	encoded, marshalErr := json.Marshal(output)
	require.NoError(t, marshalErr)
	d.lines = append(d.lines, fmt.Sprintf("%s|%s|%v", label, encoded, err))
}

func (d *qualSP224Digest) sum() string {
	sort.Strings(d.lines)
	hash := sha256.New()
	for _, line := range d.lines {
		_, _ = hash.Write([]byte(line + "\n"))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// qualSP224ZeroShard runs every ordinary shard route under a header with time
// zero on three nodes and returns the digest of the DRWA deployment whose
// header the block processor's installer installed.
func qualSP224ZeroShard(t *testing.T, route string, check func(t *testing.T, context *drwaTime.HeaderTimeContext, err error)) string {
	t.Helper()
	resolved := func() *qualSP225RegistrySource {
		return &qualSP225RegistrySource{regulated: map[string]bool{qualSP225Regulated: true}}
	}
	timed, plain, native := qualSP224ShardNode(t, true, resolved()), qualSP224ShardNode(t, true, resolved()), qualSP224ShardNode(t, false, nil)
	header := func() data.HeaderHandler { return qualSP224Header(0, 12, 440, 0) }
	context, _, err := qualSP224Evaluate(t, timed.hook, header())
	check(t, context, err)
	for _, other := range []*qualSP225Shard{plain, native} {
		require.NoError(t, other.hook.SetEpochStartHeader(header()))
		require.NoError(t, other.hook.SetCurrentHeader(header()))
	}
	for _, node := range []*qualSP225Shard{timed, plain, native} {
		require.Equal(t, uint64(0), node.hook.CurrentTimeStampMs())
		require.Equal(t, uint64(440), node.hook.CurrentRound())
		require.Equal(t, uint32(12), node.hook.CurrentEpoch())
	}
	digest := &qualSP224Digest{}
	for _, token := range []string{qualSP225Ordinary, "UNKNOWN-abcdef"} {
		expected, nativeErr := native.hook.ProcessBuiltInFunction(native.routes(token)[route])
		for name, node := range map[string]*qualSP225Shard{"installer": timed, "plain setter": plain} {
			actual, actualErr := node.hook.ProcessBuiltInFunction(node.routes(token)[route])
			require.Equal(t, nativeErr, actualErr, "%s %s", name, token)
			require.Equal(t, expected, actual, "%s %s", name, token)
			if node == timed {
				digest.add(t, route+"/"+token, actual, actualErr)
			}
		}
	}
	nativeRoot, err := native.store.Commit()
	require.NoError(t, err)
	for _, node := range []*qualSP225Shard{timed, plain} {
		root, commitErr := node.store.Commit()
		require.NoError(t, commitErr)
		require.Equal(t, nativeRoot, root)
	}
	if route == "transfer" || route == "multi_transfer" {
		require.EqualValues(t, 90, timed.balance(t, timed.sender, qualSP225Ordinary), "the ordinary effect really happened")
		require.EqualValues(t, 10, timed.balance(t, timed.another, qualSP225Ordinary))
	}
	digest.lines = append(digest.lines, "root|"+hex.EncodeToString(nativeRoot))
	return digest.sum()
}

func qualSP224ZeroMeta(t *testing.T, check func(t *testing.T, context *drwaTime.HeaderTimeContext, err error)) (string, int) {
	t.Helper()
	timed := qualSP224MetaNode(t, true, qualSP225GenesisStore(t, qualSP225Regulated))
	plain := qualSP224MetaNode(t, true, qualSP225GenesisStore(t, qualSP225Regulated))
	native := qualSP224MetaNode(t, false, qualSP225GenesisStore(t, qualSP225Regulated))
	header := func() data.HeaderHandler { return qualSP224Header(core.MetachainShardId, 12, 440, 0) }
	context, _, err := qualSP224Evaluate(t, timed.hook, header())
	check(t, context, err)
	for _, other := range []*qualSP225Node{plain, native} {
		require.NoError(t, other.hook.SetEpochStartHeader(header()))
		require.NoError(t, other.hook.SetCurrentHeader(header()))
	}
	for _, node := range []*qualSP225Node{timed, plain, native} {
		require.Equal(t, uint64(0), node.hook.CurrentTimeStampMs())
		require.Equal(t, uint64(440), node.hook.CurrentRound())
	}
	require.NoError(t, timed.owner.BeginExecution())
	require.NoError(t, plain.owner.BeginExecution())

	digest, calls := &qualSP224Digest{}, 0
	run := func(label string, input func() *vmcommon.ContractCallInput) *vmcommon.VMOutput {
		t.Helper()
		calls++
		expected, nativeErr := native.system.RunSmartContractCall(input())
		for name, node := range map[string]*qualSP225Node{"installer": timed, "plain setter": plain} {
			actual, actualErr := node.system.RunSmartContractCall(input())
			require.Equal(t, nativeErr, actualErr, name)
			require.Equal(t, expected, actual, name)
			if node == timed {
				digest.add(t, fmt.Sprintf("%02d/%s", calls, label), actual, actualErr)
			}
		}
		return expected
	}
	issued := run("issue", func() *vmcommon.ContractCallInput {
		input := qualSP225ESDTCall("issue", []byte("OrdinaryToken"), []byte("ORDINARY"), big.NewInt(1000).Bytes(), []byte{2},
			[]byte("canPause"), []byte("true"), []byte("canFreeze"), []byte("true"), []byte("canWipe"), []byte("true"), []byte("canChangeOwner"), []byte("true"))
		input.CallValue = big.NewInt(1000)
		return input
	})
	require.Equal(t, vmcommon.Ok, issued.ReturnCode, issued.ReturnMessage)
	for _, function := range qualSP225PublicMutations {
		run(function, func() *vmcommon.ContractCallInput { return qualSP225PublicCall(function, qualSP225Ordinary) })
	}
	run("getTokenProperties", func() *vmcommon.ContractCallInput {
		return qualSP225ESDTCall("getTokenProperties", []byte(qualSP225Ordinary))
	})
	run("unknownEndpoint", func() *vmcommon.ContractCallInput {
		return qualSP225ESDTCall("unknownEndpoint", []byte(qualSP225Ordinary))
	})
	require.Equal(t, len(qualSP225PublicMutations)+3, calls)
	nativeRoot, err := native.user.Commit()
	require.NoError(t, err)
	for _, node := range []*qualSP225Node{timed, plain} {
		root, commitErr := node.user.Commit()
		require.NoError(t, commitErr)
		require.Equal(t, nativeRoot, root, "identical ordinary state delta")
	}
	digest.lines = append(digest.lines, "root|"+hex.EncodeToString(nativeRoot))
	return digest.sum(), calls
}

func TestQualSP224HeaderTimeZeroGivesNoContextAndLeavesOrdinaryCallsUnchanged(t *testing.T) {
	refused := func(t *testing.T, context *drwaTime.HeaderTimeContext, err error) {
		t.Helper()
		require.ErrorIs(t, err, drwaTime.ErrUnavailableHeaderTime)
		require.Nil(t, context)
	}
	for route := range (&qualSP225Shard{}).routes(qualSP225Ordinary) {
		t.Run("shard/"+route, func(t *testing.T) { qualSP224ZeroShard(t, route, refused) })
	}
	t.Run("meta", func(t *testing.T) {
		_, calls := qualSP224ZeroMeta(t, refused)
		require.Equal(t, 26, calls)
	})
}

// The digests printed here do not depend on whether the typed view accepts a
// zero time. The row's notes record them from the commit before the change and
// from this one: equal lines mean equal ordinary result, gas, logs and state.
func TestQualSP224OrdinaryDigestAtHeaderTimeZero(t *testing.T) {
	either := func(*testing.T, *drwaTime.HeaderTimeContext, error) {}
	routes := make([]string, 0)
	for route := range (&qualSP225Shard{}).routes(qualSP225Ordinary) {
		routes = append(routes, route)
	}
	sort.Strings(routes)
	for _, route := range routes {
		fmt.Printf("SP224_ZERO_TIME_DIGEST shard/%s %s\n", route, qualSP224ZeroShard(t, route, either))
	}
	digest, _ := qualSP224ZeroMeta(t, either)
	fmt.Printf("SP224_ZERO_TIME_DIGEST meta %s\n", digest)
}
