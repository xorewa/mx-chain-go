package systemSmartContracts

import (
	"bytes"
	"errors"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

type endpointOwner struct {
	called   bool
	id, body []byte
}

func (o *endpointOwner) IsInterfaceNil() bool { return o == nil }

func (o *endpointOwner) RegisterTokenForAuthenticatedCreation(id, body, issuer, manager, family, profile, name, ticker []byte, decimals uint32,
	create func(state.AccountsAdapter, []byte, []byte, []byte, []byte, []byte, uint32, [][]byte) ([]byte, *vmcommon.VMOutput, error)) error {
	o.called = true
	o.id = bytes.Clone(id)
	o.body = bytes.Clone(body)
	_, _, err := create(nil, issuer, manager, family, name, ticker, decimals, nil)
	return err
}

func TestDRWAEndpointCreation_RegisterTokenForCommittedCreation(t *testing.T) {
	_, ctx, _, _, _, _ := qualNativeRegistration(t)
	owner := &endpointOwner{}
	endpoint := &drwaEndpointCreation{owner: owner, context: ctx, id: []byte("intent"), body: []byte("immutable-body"), value: big.NewInt(17)}
	sentinel := errors.New("native creator denied")
	err := endpoint.RegisterTokenForCommittedCreation(nil, nil, nil, nil, nil, nil, 0, nil,
		func(state.AccountsAdapter, []byte, []byte, []byte, []byte, []byte, uint32, [][]byte) ([]byte, *vmcommon.VMOutput, error) {
			return nil, nil, sentinel
		})
	require.ErrorIs(t, err, sentinel)
	require.True(t, owner.called)
	require.Equal(t, endpoint.id, owner.id)
	require.Equal(t, endpoint.body, owner.body)
	require.Empty(t, ctx.outputAccounts)
	require.Empty(t, ctx.output)
	require.Empty(t, ctx.storageUpdate)
}
