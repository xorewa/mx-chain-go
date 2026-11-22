package drwa

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-go/state"
	"github.com/stretchr/testify/require"
)

// A72 synthetic mutation inputs, not appointment/creating-owner authentication.
// The reserved key is independently literal; no production key builder sets it.
type qualA72ImmutableAccount struct {
	state.UserAccountHandler
	reads, writes int
}

func (a *qualA72ImmutableAccount) RetrieveValue(key []byte) ([]byte, uint32, error) {
	a.reads++
	return a.UserAccountHandler.RetrieveValue(key)
}
func (a *qualA72ImmutableAccount) SaveKeyValue(key, value []byte) error {
	a.writes++
	return a.UserAccountHandler.SaveKeyValue(key, value)
}

func TestQualA72ImmutableInitialWriteClass(t *testing.T) {
	for _, growth := range []bool{false, true} {
		for _, suffix := range []string{"", "identity"} {
			for _, value := range [][]byte{nil, {}, []byte("same-size"), []byte("longer replacement")} {
				for _, late := range []bool{false, true} {
					t.Run(fmt.Sprintf("growth_%t/suffix_%q/value_%x/late_%t", growth, suffix, value, late), func(t *testing.T) {
						f := qualScopedNew(t)
						account, err := f.records.codec.state.systemAccount()
						require.NoError(t, err)
						spy := &qualA72ImmutableAccount{UserAccountHandler: account}
						key := []byte("ELRONDDRWA@scopedAdmission@initial@" + suffix)
						writes := []scopedAdmissionWrite{{key, bytes.Clone(value)}}
						if late {
							writes = append([]scopedAdmissionWrite{{[]byte("synthetic ordinary key"), []byte("synthetic value")}}, writes...)
						}
						root, err := f.store.RootHash()
						require.NoError(t, err)
						require.ErrorIs(t, f.records.retainRecords(spy, 10, growth, writes...), errScopedAdmission)
						require.Zero(t, spy.reads, "reserved class must be rejected structurally before budget read")
						require.Zero(t, spy.writes, "not even the earlier batch entry may be staged")
						after, err := f.store.RootHash()
						require.NoError(t, err)
						require.Equal(t, root, after)
					})
				}
			}
		}
	}
}

// Real native-account controls isolate the mutation from the supplementary
// callback spy's non-native dynamic type. Ordinary positive must save normally.
func TestQualA72ImmutableNativeInitialPreserved(t *testing.T) {
	t.Run("ordinary_positive", func(t *testing.T) {
		f := qualScopedNew(t)
		a, err := f.records.codec.state.systemAccount()
		require.NoError(t, err)
		key, value := []byte("synthetic ordinary key"), []byte("synthetic ordinary value")
		require.NoError(t, f.records.retainRecords(a, 10, false, scopedAdmissionWrite{key, value}))
		a, err = f.records.codec.state.systemAccount()
		require.NoError(t, err)
		got, _, err := a.RetrieveValue(key)
		require.NoError(t, err)
		require.Equal(t, value, got)
	})
	for _, value := range [][]byte{nil, []byte("swap"), []byte("longer replacement")} {
		for _, late := range []bool{false, true} {
			for _, growth := range []bool{false, true} {
				t.Run(fmt.Sprintf("value_%x/late_%t/growth_%t", value, late, growth), func(t *testing.T) {
					f := qualScopedNew(t)
					key := []byte("ELRONDDRWA@scopedAdmission@initial@synthetic identity")
					qualRecordPut(t, f.store, key, []byte("seed"))
					_, err := f.store.Commit()
					require.NoError(t, err)
					a, err := f.records.codec.state.systemAccount()
					require.NoError(t, err)
					budgetKey := []byte("ELRONDDRWA@scopedAdmission@budget")
					before, _, err := a.RetrieveValue(budgetKey)
					require.NoError(t, err)
					before = bytes.Clone(before)
					writes := []scopedAdmissionWrite{{key, bytes.Clone(value)}}
					ordinary := []byte("synthetic earlier batch key")
					if late {
						writes = append([]scopedAdmissionWrite{{ordinary, []byte("must not publish")}}, writes...)
					}
					refusal := f.records.retainRecords(a, 10, growth, writes...)
					// Check actual retained bytes BEFORE classifying the error. A downstream
					// budget/serializer failure cannot masquerade as reserved-key refusal.
					a, err = f.records.codec.state.systemAccount()
					require.NoError(t, err)
					got, _, err := a.RetrieveValue(key)
					require.NoError(t, err)
					require.Equal(t, []byte("seed"), got, "original key changed")
					budget, _, err := a.RetrieveValue(budgetKey)
					require.NoError(t, err)
					require.Equal(t, before, budget)
					first, _, err := a.RetrieveValue(ordinary)
					require.NoError(t, err)
					require.Empty(t, first)
					require.ErrorIs(t, refusal, errScopedAdmission)
				})
			}
		}
	}
}
