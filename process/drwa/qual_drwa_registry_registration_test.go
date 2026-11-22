package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
	"math"
	"testing"
)

func qualRegistrationStore(t *testing.T, count uint64) *qualNativeStore {
	t.Helper()
	s := qualContainmentStore(t)
	a, err := s.LoadAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	encoded := make([]byte, 8)
	binary.BigEndian.PutUint64(encoded, count)
	require.NoError(t, a.(state.UserAccountHandler).SaveKeyValue([]byte(registryCountKey), encoded))
	require.NoError(t, s.SaveAccount(a))
	_, err = s.Commit()
	require.NoError(t, err)
	return s
}
func qualRegistrationOwner(t *testing.T, s *qualNativeStore, bound uint64) (*RegistryRegistration, *RollbackContainment) {
	t.Helper()
	r, c, err := NewRegistryRegistration(s, &testscommon.ShardsCoordinatorMock{SelfIDCalled: func() uint32 { return core.MetachainShardId }}, bound)
	require.NoError(t, err)
	return r, c
}
func qualRegistryValue(t *testing.T, s *qualNativeStore, key string) []byte {
	t.Helper()
	a, err := s.GetExistingAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	v, _, err := a.(state.UserAccountHandler).RetrieveValue([]byte(key))
	require.NoError(t, err)
	return v
}
func qualRegistrationCreator(t *testing.T, id string) func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
	return func(accounts state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
		a, err := accounts.LoadAccount(core.ESDTSCAddress)
		if err != nil {
			return nil, nil, err
		}
		err = a.(state.UserAccountHandler).SaveKeyValue([]byte(id), []byte("native-token-record"))
		if err != nil {
			return nil, nil, err
		}
		err = accounts.SaveAccount(a)
		return []byte(id), &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, ReturnData: [][]byte{[]byte(id)}}, err
	}
}
func TestQualDRWARegistryRegistrationAtomic(t *testing.T) {
	s := qualRegistrationStore(t, 0)
	r, c := qualRegistrationOwner(t, s, 2)
	require.NoError(t, r.RegisterToken(qualRegistrationCreator(t, "TOKEN-abcdef")))
	require.Equal(t, uint64(1), binary.BigEndian.Uint64(qualRegistryValue(t, s, registryCountKey)))
	require.Equal(t, []byte{1}, qualRegistryValue(t, s, registryMemberKeyPrefix+"TOKEN-abcdef"))
	require.NoError(t, r.RegisterToken(qualRegistrationCreator(t, "TOKEN-abcdee")))
	called := false
	require.ErrorIs(t, r.RegisterToken(func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) { called = true; return nil, nil, nil }), ErrInvalidRegistryRegistration)
	require.False(t, called)
	roots, outputs, err := c.Commit()
	require.NoError(t, err)
	require.Len(t, roots, 1)
	require.Len(t, outputs, 2)
	require.Equal(t, []byte("TOKEN-abcdef"), outputs[0].ReturnData[0])
	require.Error(t, r.RegisterToken(qualRegistrationCreator(t, "TOKEN-abcddd")))
}
func TestQualDRWARegistryRegistrationRollback(t *testing.T) {
	for _, fault := range []string{"creator", "invalid-id", "nil-output", "failed-output", "duplicate", "count-tamper", "save", "failed-rollback"} {
		t.Run(fault, func(t *testing.T) {
			s := qualRegistrationStore(t, 0)
			if fault == "duplicate" {
				a, err := s.GetExistingAccount(core.SystemAccountAddress)
				require.NoError(t, err)
				require.NoError(t, a.(state.UserAccountHandler).SaveKeyValue([]byte(registryMemberKeyPrefix+"TOKEN-abcdef"), []byte{1}))
				require.NoError(t, s.SaveAccount(a))
				_, err = s.Commit()
				require.NoError(t, err)
			}
			root, err := s.RootHash()
			require.NoError(t, err)
			r, c := qualRegistrationOwner(t, s, 2)
			original := errors.New("creator fault")
			rollback := errors.New("rollback fault")
			creator := qualRegistrationCreator(t, "TOKEN-abcdef")
			err = r.RegisterToken(func(accounts state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
				id, out, e := creator(accounts)
				if e != nil {
					return nil, nil, e
				}
				switch fault {
				case "creator":
					return nil, nil, original
				case "invalid-id":
					id = []byte("invalid")
				case "nil-output":
					out = nil
				case "failed-output":
					out.ReturnCode = vmcommon.UserError
				case "count-tamper":
					a, e := accounts.GetExistingAccount(core.SystemAccountAddress)
					require.NoError(t, e)
					v := make([]byte, 8)
					binary.BigEndian.PutUint64(v, 1)
					require.NoError(t, a.(state.UserAccountHandler).SaveKeyValue([]byte(registryCountKey), v))
					require.NoError(t, accounts.SaveAccount(a))
				case "save":
					s.saveErr = original
				case "failed-rollback":
					s.revertErr = rollback
					return nil, nil, original
				}
				return id, out, nil
			})
			require.Error(t, err)
			if fault == "failed-rollback" {
				require.ErrorIs(t, err, original)
				require.ErrorIs(t, err, rollback)
				_, out, err := c.Commit()
				require.Error(t, err)
				require.Empty(t, out)
				require.Error(t, r.RegisterToken(creator))
				return
			}
			after, e := s.RootHash()
			require.NoError(t, e)
			require.Equal(t, root, after)
			require.Zero(t, s.JournalLen())
			require.Equal(t, uint64(0), binary.BigEndian.Uint64(qualRegistryValue(t, s, registryCountKey)))
		})
	}
}
func TestQualDRWARegistryRegistrationGuards(t *testing.T) {
	s := qualRegistrationStore(t, math.MaxUint64)
	r, _ := qualRegistrationOwner(t, s, math.MaxUint64)
	called := false
	require.ErrorIs(t, r.RegisterToken(func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) { called = true; return nil, nil, nil }), ErrInvalidRegistryRegistration)
	require.False(t, called)
	require.ErrorIs(t, r.RegisterToken(nil), ErrInvalidOperation)
	_, _, err := NewRegistryRegistration(s, nil, 1)
	require.Error(t, err)
	_, _, err = NewRegistryRegistration(s, &testscommon.ShardsCoordinatorMock{SelfIDCalled: func() uint32 { return 0 }}, 1)
	require.Error(t, err)
	_, _, err = NewRegistryRegistration(nil, &testscommon.ShardsCoordinatorMock{SelfIDCalled: func() uint32 { return core.MetachainShardId }}, 1)
	require.Error(t, err)
	for _, value := range [][]byte{nil, {1}, bytes.Repeat([]byte{1}, 9)} {
		s := qualRegistrationStore(t, 0)
		a, e := s.GetExistingAccount(core.SystemAccountAddress)
		require.NoError(t, e)
		require.NoError(t, a.(state.UserAccountHandler).SaveKeyValue([]byte(registryCountKey), value))
		require.NoError(t, s.SaveAccount(a))
		_, e = s.Commit()
		require.NoError(t, e)
		r, _ := qualRegistrationOwner(t, s, 2)
		require.Error(t, r.RegisterToken(qualRegistrationCreator(t, "TOKEN-abcdef")))
	}
}
func TestQualDRWARegistryRegistrationReloadAndBusy(t *testing.T) {
	s := qualRegistrationStore(t, 0)
	r, c := qualRegistrationOwner(t, s, 2)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- r.RegisterToken(func(accounts state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
			close(entered)
			<-release
			a, e := accounts.GetExistingAccount(core.SystemAccountAddress)
			if e != nil {
				return nil, nil, e
			}
			e = a.(state.UserAccountHandler).SaveKeyValue([]byte("fixture/associated"), []byte{7})
			if e != nil {
				return nil, nil, e
			}
			if e = accounts.SaveAccount(a); e != nil {
				return nil, nil, e
			}
			return qualRegistrationCreator(t, "TOKEN-abcdef")(accounts)
		})
	}()
	<-entered
	require.ErrorIs(t, r.RegisterToken(qualRegistrationCreator(t, "TOKEN-abcdee")), ErrExecutionBusy)
	close(release)
	require.NoError(t, <-done)
	require.Equal(t, []byte{7}, qualRegistryValue(t, s, "fixture/associated"))
	_, _, err := c.Commit()
	require.NoError(t, err)
}
