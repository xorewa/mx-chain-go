package drwa

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/stretchr/testify/require"
)

// Independent Python field1/BLAKE2b-256 calculation, prepared before Go runs.
// Public synthetic bytes only; no authority, canonicality, normative codec,
// signer compatibility, time installer, funding or whole T39 qualification.
// Constants make the test self-contained in a clean repository export.
const qualScopedKATScope = "0a0e666978747572652d646f6d61696e0a2001010101010101010101010101010101010101010101010101010101010101010a80017070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070"
const qualScopedKATVersion = "0ab5010a0e666978747572652d646f6d61696e0a2001010101010101010101010101010101010101010101010101010101010101010a800170707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070700a000a1d7075626c69632073796e74686574696320636f6e737469747574696f6e"
const qualScopedKATPointer = "0ab5010a0e666978747572652d646f6d61696e0a2001010101010101010101010101010101010101010101010101010101010101010a800170707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070700a2012c3b7cca715343b2f7c77648286ad8fdbe099b42859f284c2bb8fbea850554d"
const qualScopedKATDecision = "0ab5010a0e666978747572652d646f6d61696e0a2001010101010101010101010101010101010101010101010101010101010101010a800170707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070700a2002020202020202020202020202020202020202020202020202020202020202020a0a6465636973696f6e2d310a1a7075626c69632065766964656e636520636f6d6d69746d656e740a2012c3b7cca715343b2f7c77648286ad8fdbe099b42859f284c2bb8fbea850554d0a080102030405060708"
const qualScopedKATVersionDigest = "12c3b7cca715343b2f7c77648286ad8fdbe099b42859f284c2bb8fbea850554d"
const qualScopedKATScopeDigest = "4dbe7a3c71cf63d20b7015de476659c9419857a8d3b9798c3a319d8167fd5725"
const qualScopedKATDecisionDigest = "645511c7f8834a9debf085c8602557a7eb37d2e04ab655d591013f38bc42d996"
const qualScopedKATAdmissionDigest = "f9012a3036138cb7bed38f06f54991be76db28769723809a58e3b69849777e0d"
const qualScopedKATWithdrawDigest = "812445b040ffa9ca2afa8c7d7ff1780053f86a669f5a963757c7add07d58967b"
const qualScopedKATCurrentKey = "454c524f4e44445257414073636f70656441646d697373696f6e4063757272656e74404dbe7a3c71cf63d20b7015de476659c9419857a8d3b9798c3a319d8167fd5725"
const qualScopedKATVersionKey = "454c524f4e44445257414073636f70656441646d697373696f6e4076657273696f6e4012c3b7cca715343b2f7c77648286ad8fdbe099b42859f284c2bb8fbea850554d"
const qualScopedKATDecisionKey = "454c524f4e44445257414073636f70656441646d697373696f6e406465636973696f6e40645511c7f8834a9debf085c8602557a7eb37d2e04ab655d591013f38bc42d996"
const qualScopedKATWithdrawnKey = "454c524f4e44445257414073636f70656441646d697373696f6e4077697468647261776e40645511c7f8834a9debf085c8602557a7eb37d2e04ab655d591013f38bc42d996"

func qualScopedKATBytes(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	require.NoError(t, err)
	return decoded
}

func TestQualDRWAScopedRecordIndependentKAT(t *testing.T) {
	decode := func(value string) []byte { return qualScopedKATBytes(t, value) }
	scope, version, pointer, decision := decode(qualScopedKATScope), decode(qualScopedKATVersion), decode(qualScopedKATPointer), decode(qualScopedKATDecision)
	authority := decode(qualScopedKATVersionDigest)
	f := qualScopedNew(t)
	f.d.program = bytes.Repeat([]byte("p"), 128)
	f.d.commitment = []byte("public evidence commitment")
	f.d.authority = authority
	f.d.validUntil = HeaderMilliseconds(0x0102030405060708)
	constitution := []byte("public synthetic constitution")
	t.Run("scope", func(t *testing.T) {
		actual, err := f.records.scope(f.d.owner, f.d.program)
		require.NoError(t, err)
		require.Equal(t, scope, actual)
	})
	t.Run("version", func(t *testing.T) {
		actual, err := f.records.codec.frame(scope, nil, constitution)
		require.NoError(t, err)
		require.Equal(t, version, actual)
		fields, err := f.records.codec.unframe(version, 3)
		require.NoError(t, err)
		require.Equal(t, [][]byte{scope, {}, constitution}, fields)
	})
	t.Run("pointer", func(t *testing.T) {
		actual, err := f.records.codec.frame(scope, authority)
		require.NoError(t, err)
		require.Equal(t, pointer, actual)
	})
	t.Run("decision", func(t *testing.T) {
		actualScope, actual, err := f.records.decisionBody(f.d)
		require.NoError(t, err)
		require.Equal(t, scope, actualScope)
		require.Equal(t, decision, actual)
	})
	for _, tc := range []struct {
		kind, golden string
		fields       [][]byte
	}{
		{"VERSION", qualScopedKATVersionDigest, [][]byte{scope, {}, constitution}},
		{"SCOPE", qualScopedKATScopeDigest, [][]byte{scope}},
		{"DECISION", qualScopedKATDecisionDigest, [][]byte{scope, f.d.issuer, f.d.version}},
		{"ADMISSION", qualScopedKATAdmissionDigest, [][]byte{decision}},
		{"WITHDRAW", qualScopedKATWithdrawDigest, [][]byte{scope, decode(qualScopedKATDecisionDigest), decision, authority}},
	} {
		t.Run(tc.kind+"-digest", func(t *testing.T) {
			actual, err := f.records.digest(tc.kind, tc.fields...)
			require.NoError(t, err)
			require.Equal(t, decode(tc.golden), actual)
		})
	}
	for _, tc := range []struct{ kind, digest, golden string }{
		{"current", qualScopedKATScopeDigest, qualScopedKATCurrentKey},
		{"version", qualScopedKATVersionDigest, qualScopedKATVersionKey},
		{"decision", qualScopedKATDecisionDigest, qualScopedKATDecisionKey},
		{"withdrawn", qualScopedKATDecisionDigest, qualScopedKATWithdrawnKey},
	} {
		t.Run(tc.kind+"-key", func(t *testing.T) {
			require.Equal(t, decode(tc.golden), f.records.key(tc.kind, decode(tc.digest)))
		})
	}
	put := func(key string, value []byte) { qualRecordPut(t, f.store, decode(key), bytes.Clone(value)) }
	put(qualScopedKATCurrentKey, pointer)
	put(qualScopedKATVersionKey, version)
	put(qualScopedKATDecisionKey, decision)
	account, err := f.store.GetExistingAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	t.Run("native-current-and-withdrawal-reader", func(t *testing.T) {
		actual, err := f.records.current(account.(state.UserAccountHandler), scope)
		require.NoError(t, err)
		require.Equal(t, authority, actual)
		require.NoError(t, f.records.checkDecision(f.context, f.d))
		put(qualScopedKATWithdrawnKey, decision)
		require.ErrorIs(t, f.records.checkDecision(f.context, f.d), errScopedAdmission)
	})
	for _, tc := range []struct {
		name  string
		key   string
		value []byte
	}{
		{"changed-version-body", qualScopedKATVersionKey, qualRecordFrame(scope, nil, []byte("changed constitution"))},
		{"omitted-empty-predecessor", qualScopedKATVersionKey, qualRecordFrame(scope, constitution)},
		{"unknown-version-field", qualScopedKATVersionKey, append(bytes.Clone(version), 0x28, 0)},
		{"unknown-pointer-field", qualScopedKATCurrentKey, append(bytes.Clone(pointer), 0x28, 0)},
		{"swapped-pointer-order", qualScopedKATCurrentKey, qualRecordFrame(authority, scope)},
		//181 is encoded b5 01; b5 81 00 is its forbidden overlong alternative.
		{"overlong-pointer-length", qualScopedKATCurrentKey, append([]byte{0x0a, 0xb5, 0x81, 0}, pointer[3:]...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			put(qualScopedKATCurrentKey, pointer)
			put(qualScopedKATVersionKey, version)
			currentAccount, err := f.store.GetExistingAccount(core.SystemAccountAddress)
			require.NoError(t, err)
			_, err = f.records.current(currentAccount.(state.UserAccountHandler), scope)
			require.NoError(t, err, "exact control before corrupt record")
			put(tc.key, tc.value)
			currentAccount, err = f.store.GetExistingAccount(core.SystemAccountAddress)
			require.NoError(t, err)
			_, err = f.records.current(currentAccount.(state.UserAccountHandler), scope)
			require.Error(t, err)
		})
	}
	t.Run("different-domain", func(t *testing.T) {
		put(qualScopedKATCurrentKey, pointer)
		put(qualScopedKATVersionKey, version)
		f.records.domain = []byte("different-domain")
		changedScope, err := f.records.scope(f.d.owner, f.d.program)
		require.NoError(t, err)
		require.NotEqual(t, scope, changedScope)
		actual, err := f.records.digest("VERSION", scope, nil, constitution)
		require.NoError(t, err)
		require.NotEqual(t, authority, actual)
		currentAccount, err := f.store.GetExistingAccount(core.SystemAccountAddress)
		require.NoError(t, err)
		_, err = f.records.current(currentAccount.(state.UserAccountHandler), changedScope)
		require.Error(t, err, "other domain cannot retrieve this original pointer")
	})
}
