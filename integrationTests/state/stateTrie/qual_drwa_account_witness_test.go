package stateTrie

import (
	"bytes"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/integrationTests"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/state/factory"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/testscommon/storageManager"
	"github.com/multiversx/mx-chain-go/trie"
	"github.com/stretchr/testify/require"
)

// NON-NORMATIVE Part A 6.1 AR-01 item -> authenticated result-root construction.
// Extends the synthetic item-trie experiment to real native AccountsDB bytes:
// committed main root -> account at the required address -> its data root -> key.
// The selected result root and expected address/key are TRUSTED INPUTS here.
// H/S/M/B finality, production address/key allocation, transport and gas remain
// separate prerequisites. This fixture uses the upstream integration helper's
// SHA-256/marshaller and legacy (AutoBalanceDataTriesFlag disabled) configuration;
// it is not a selected production cryptographic or activation configuration.
// No remote response's separate Value or data-root field is accepted as evidence.
func qualReadAccountWitness(t *testing.T, root, address, key []byte, accountNodes, dataNodes [][]byte, limit int) ([]byte, error) {
	t.Helper()
	deny := errors.New("qualification account witness rejected")
	if len(root) == 0 || len(address) == 0 || len(key) == 0 || len(accountNodes) == 0 || len(dataNodes) == 0 {
		return nil, deny
	}
	used := 0
	for _, nodes := range [][][]byte{accountNodes, dataNodes} {
		for _, node := range nodes {
			if len(node) == 0 || used > limit || len(node) > limit-used {
				return nil, deny
			}
			used += len(node)
		}
	}
	// A fresh witness-only database prevents the verifier from silently filling
	// an omitted proof node from the producer's complete local account state.
	recreate := func(selectedRoot []byte, nodes [][]byte) (common.Trie, error) {
		db := testscommon.NewMemDbMock()
		for _, node := range nodes {
			if err := db.Put(integrationTests.TestHasher.Compute(string(node)), bytes.Clone(node)); err != nil {
				return nil, err
			}
		}
		tr, err := trie.NewTrie(&storageManager.StorageManagerStub{
			GetCalled: db.Get, GetFromCurrentEpochCalled: db.Get, PutCalled: db.Put,
		}, integrationTests.TestMarshalizer, integrationTests.TestHasher, &enableEpochsHandlerMock.EnableEpochsHandlerStub{}, 5)
		if err != nil {
			return nil, err
		}
		return tr.Recreate(holders.NewDefaultRootHashesHolder(selectedRoot))
	}
	main, err := recreate(root, accountNodes)
	if err != nil {
		return nil, err
	}
	accountBytes, _, err := main.Get(address)
	if err != nil || len(accountBytes) == 0 {
		return nil, deny
	}
	creator, err := factory.NewAccountCreator(factory.ArgsAccountCreator{
		Hasher: integrationTests.TestHasher, Marshaller: integrationTests.TestMarshalizer,
		EnableEpochsHandler:    &enableEpochsHandlerMock.EnableEpochsHandlerStub{},
		StateAccessesCollector: &stateMock.StateAccessesCollectorStub{},
	})
	if err != nil {
		return nil, err
	}
	account, err := creator.CreateAccount(address)
	if err != nil {
		return nil, err
	}
	if err = integrationTests.TestMarshalizer.Unmarshal(account, accountBytes); err != nil {
		return nil, err
	}
	user := account.(state.UserAccountHandler)
	if !bytes.Equal(user.AddressBytes(), address) || len(user.GetRootHash()) == 0 {
		return nil, deny
	}
	data, err := recreate(user.GetRootHash(), dataNodes)
	if err != nil {
		return nil, err
	}
	user.SetDataTrie(data)
	value, _, err := user.RetrieveValue(key)
	if err != nil || len(value) == 0 {
		return nil, deny
	}
	return bytes.Clone(value), nil
}

func TestQualDRWAAccountWitness(t *testing.T) {
	adb := createAccountsDBTestSetup()
	t.Cleanup(func() { require.NoError(t, adb.Close()) })
	address, otherAddress := bytes.Repeat([]byte{41}, 32), bytes.Repeat([]byte{42}, 32)
	key := qualProtectedFixtureKey([]byte("item"), []byte("action-A"))
	expected := []byte("literal predecessor-A;target-B;dependency-C")
	for i, addr := range [][]byte{address, otherAddress} {
		acc, err := adb.LoadAccount(addr)
		require.NoError(t, err)
		value := expected
		if i == 1 {
			value = []byte("different owner's item")
		}
		require.NoError(t, acc.(state.UserAccountHandler).SaveKeyValue(key, value))
		require.NoError(t, acc.(state.UserAccountHandler).SaveKeyValue([]byte("unrelated"), []byte("ordinary")))
		require.NoError(t, adb.SaveAccount(acc))
	}
	root, err := adb.Commit()
	require.NoError(t, err)
	main, err := adb.GetTrie(root)
	require.NoError(t, err)
	accountProof, _, err := main.GetProof(address)
	require.NoError(t, err)
	otherProof, _, err := main.GetProof(otherAddress)
	require.NoError(t, err)
	getDataProof := func(addr []byte) [][]byte {
		acc, getErr := adb.GetExistingAccount(addr)
		require.NoError(t, getErr)
		data, trieErr := adb.GetTrie(acc.(state.UserAccountHandler).GetRootHash())
		require.NoError(t, trieErr)
		proof, _, proofErr := data.GetProof(key)
		require.NoError(t, proofErr)
		return proof
	}
	dataProof, otherDataProof := getDataProof(address), getDataProof(otherAddress)
	limit := 0
	for _, nodes := range [][][]byte{accountProof, dataProof} {
		for _, node := range nodes {
			limit += len(node)
		}
	}
	clone := func(proof [][]byte) [][]byte {
		out := make([][]byte, len(proof))
		for i := range proof {
			out[i] = bytes.Clone(proof[i])
		}
		return out
	}
	for _, name := range []string{"valid", "wrong_result_root", "wrong_address", "other_account_witness", "other_data_witness", "wrong_key", "missing_account_node", "missing_data_node", "corrupt_account_node", "corrupt_data_node", "aggregate_byte_limit", "reordered_node_set"} {
		t.Run(name, func(t *testing.T) {
			r, a, k := bytes.Clone(root), bytes.Clone(address), bytes.Clone(key)
			ap, dp, budget := clone(accountProof), clone(dataProof), limit
			switch name {
			case "wrong_result_root":
				r[0] ^= 1
			case "wrong_address":
				a = otherAddress
			case "other_account_witness":
				ap = clone(otherProof)
				budget = limit * 2 // challenge account binding, not proof length
			case "other_data_witness":
				dp = clone(otherDataProof)
				budget = limit * 2 // do not let the size guard mask root binding
			case "wrong_key":
				k = []byte("nonexistent")
			case "missing_account_node":
				ap = ap[:len(ap)-1]
			case "missing_data_node":
				dp = dp[:len(dp)-1]
			case "corrupt_account_node":
				ap[len(ap)-1][0] ^= 1
			case "corrupt_data_node":
				dp[len(dp)-1][0] ^= 1
			case "aggregate_byte_limit":
				budget--
			case "reordered_node_set":
				// This adapter consumes a bounded node set, not the ordered
				// native proof API sequence tested in the block-package case.
				require.Greater(t, len(ap), 1)
				require.Greater(t, len(dp), 1)
				ap[0], ap[len(ap)-1] = ap[len(ap)-1], ap[0]
				dp[0], dp[len(dp)-1] = dp[len(dp)-1], dp[0]
			}
			value, readErr := qualReadAccountWitness(t, r, a, k, ap, dp, budget)
			if name == "valid" || name == "reordered_node_set" {
				require.NoError(t, readErr)
				require.Equal(t, expected, value)
			} else {
				require.Error(t, readErr)
				require.Empty(t, value)
			}
		})
	}
}
