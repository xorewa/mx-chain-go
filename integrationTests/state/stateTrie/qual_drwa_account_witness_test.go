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
// SHA-256/marshaller. The caller supplies the trusted activation handler, never
// the witness producer. Both legacy and auto-balanced reads are exercised below;
// these fixtures do not select a production cryptographic or activation profile.
// No remote response's separate Value or data-root field is accepted as evidence.
func qualReadAccountWitness(t *testing.T, root, address, key []byte, accountNodes, dataNodes [][]byte, limit int, enableEpochs common.EnableEpochsHandler) ([]byte, error) {
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
		}, integrationTests.TestMarshalizer, integrationTests.TestHasher, enableEpochs, 5)
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
		EnableEpochsHandler:    enableEpochs,
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
			value, readErr := qualReadAccountWitness(t, r, a, k, ap, dp, budget, &enableEpochsHandlerMock.EnableEpochsHandlerStub{})
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

func TestQualDRWAAccountWitnessAddressBinding(t *testing.T) {
	adb := createAccountsDBTestSetup()
	t.Cleanup(func() { require.NoError(t, adb.Close()) })
	address, otherAddress := bytes.Repeat([]byte{41}, 32), bytes.Repeat([]byte{42}, 32)
	key, expected := []byte("item"), []byte("other account's authenticated item")
	acc, err := adb.LoadAccount(otherAddress)
	require.NoError(t, err)
	require.NoError(t, acc.(state.UserAccountHandler).SaveKeyValue(key, expected))
	require.NoError(t, adb.SaveAccount(acc))
	root, err := adb.Commit()
	require.NoError(t, err)
	main, err := adb.GetTrie(root)
	require.NoError(t, err)
	accountBytes, _, err := main.Get(otherAddress)
	require.NoError(t, err)
	data, err := adb.GetTrie(acc.(state.UserAccountHandler).GetRootHash())
	require.NoError(t, err)
	dp, _, err := data.GetProof(key)
	require.NoError(t, err)

	// Deliberately malformed main-trie fixture: authenticated bytes at the
	// requested key decode as a DIFFERENT account. Not an AccountsDB write or
	// a claim that honest account saves can create this state. Shared main-trie
	// key space must not turn membership alone into account identity.
	require.NoError(t, main.Update(address, accountBytes))
	root, err = main.RootHash()
	require.NoError(t, err)
	ap, gotAccountBytes, err := main.GetProof(address)
	require.NoError(t, err)
	require.Equal(t, accountBytes, gotAccountBytes, "lookup succeeds before the identity check")
	flags := &enableEpochsHandlerMock.EnableEpochsHandlerStub{}
	budget := 0
	for _, nodes := range [][][]byte{ap, dp} {
		for _, node := range nodes {
			budget += len(node)
		}
	}
	value, err := qualReadAccountWitness(t, root, address, key, ap, dp, budget, flags)
	require.Error(t, err, "authenticated bytes for another address must not become this account")
	require.Empty(t, value)
}

func TestQualDRWAAccountWitnessAutoBalance(t *testing.T) {
	// Reuse native account creation, SaveKeyValue, AccountsDB journals/commit,
	// versioned trie storage, and RetrieveValue's hashed-first lookup. No local
	// substitute for the native migration or value decoder is introduced.
	for _, layout := range []string{"legacy_fallback", "hashed_only", "migrated", "hashed_precedence"} {
		t.Run(layout, func(t *testing.T) {
			adb := createAccountsDBTestSetup()
			t.Cleanup(func() { require.NoError(t, adb.Close()) })
			flags := enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
			creator, err := factory.NewAccountCreator(factory.ArgsAccountCreator{
				Hasher: integrationTests.TestHasher, Marshaller: integrationTests.TestMarshalizer,
				EnableEpochsHandler: flags, StateAccessesCollector: &stateMock.StateAccessesCollectorStub{},
			})
			require.NoError(t, err)
			address := bytes.Repeat([]byte{41}, 32)
			acc, err := creator.CreateAccount(address)
			require.NoError(t, err)
			user := acc.(state.UserAccountHandler)
			key := qualProtectedFixtureKey([]byte("item"), []byte("action-A"))
			hashedKey := integrationTests.TestHasher.Compute(string(key))
			expected := []byte("literal predecessor-A;target-B;dependency-C")
			// Native trie nibbles run in reverse byte order (node.go). This
			// neighbour shares the hashed path but is absent at hashedKey.
			// Its non-membership node is not in the raw-key membership proof.
			neighbour := bytes.Clone(hashedKey)
			neighbour[0] ^= 1
			require.NoError(t, user.SaveKeyValue(neighbour, []byte("unrelated legacy value")))
			if layout == "legacy_fallback" || layout == "migrated" {
				require.NoError(t, user.SaveKeyValue(key, expected))
			}
			require.NoError(t, adb.SaveAccount(acc))
			_, err = adb.Commit()
			require.NoError(t, err)
			flags.AddActiveFlags(common.AutoBalanceDataTriesFlag)
			if layout != "legacy_fallback" {
				require.NoError(t, user.SaveKeyValue(key, expected))
				require.NoError(t, adb.SaveAccount(acc))
			}
			if layout == "hashed_precedence" {
				// Adversarial mixed layout: a stale raw value cannot override
				// a present hashed value. Normal migration deletes the raw key.
				flags.RemoveActiveFlags(common.AutoBalanceDataTriesFlag)
				require.NoError(t, user.SaveKeyValue(key, []byte("stale raw value")))
				require.NoError(t, adb.SaveAccount(acc))
				flags.AddActiveFlags(common.AutoBalanceDataTriesFlag)
			}
			root, err := adb.Commit()
			require.NoError(t, err)
			main, err := adb.GetTrie(root)
			require.NoError(t, err)
			ap, _, err := main.GetProof(address)
			require.NoError(t, err)
			data, err := adb.GetTrie(user.GetRootHash())
			require.NoError(t, err)
			hashedValue, _, err := data.Get(hashedKey)
			require.NoError(t, err)
			rawValue, _, err := data.Get(key)
			require.NoError(t, err)
			if layout == "legacy_fallback" {
				require.Empty(t, hashedValue)
				require.NotEmpty(t, rawValue)
			} else {
				require.NotEmpty(t, hashedValue)
				if layout == "hashed_precedence" {
					require.NotEmpty(t, rawValue)
				} else {
					require.Empty(t, rawValue, "hashed-only and native migration leave no raw value")
				}
			}
			// Full SMALL fixture node set, not a proposed production proof
			// size or transport. It includes nodes proving hashed-key absence
			// before fallback; GetProof alone supplies membership only.
			dp, remaining, err := data.GetSerializedNodes(user.GetRootHash(), 1<<20)
			require.NoError(t, err)
			require.Positive(t, remaining)
			budget := 0
			for _, nodes := range [][][]byte{ap, dp} {
				for _, node := range nodes {
					budget += len(node)
				}
			}
			t.Run("valid", func(t *testing.T) {
				value, readErr := qualReadAccountWitness(t, root, address, key, ap, dp, budget, flags)
				require.NoError(t, readErr)
				require.Equal(t, expected, value)
			})
			t.Run("absent_item", func(t *testing.T) {
				value, readErr := qualReadAccountWitness(t, root, address, []byte("absent-item"), ap, dp, budget, flags)
				require.Error(t, readErr)
				require.Empty(t, value)
			})
			t.Run("incomplete_nodes", func(t *testing.T) {
				require.Greater(t, len(dp), 1)
				value, readErr := qualReadAccountWitness(t, root, address, key, ap, dp[1:], budget, flags)
				require.Error(t, readErr)
				require.Empty(t, value)
			})
			if layout == "legacy_fallback" {
				t.Run("raw_membership_cannot_replace_hashed_absence", func(t *testing.T) {
					rawProof, _, proofErr := data.GetProof(key)
					require.NoError(t, proofErr)
					// Same root/raw proof succeeds with legacy semantics.
					value, readErr := qualReadAccountWitness(t, root, address, key, ap, rawProof, budget, &enableEpochsHandlerMock.EnableEpochsHandlerStub{})
					require.NoError(t, readErr)
					require.Equal(t, expected, value)
					// Under active semantics missing nodes are UNKNOWN, not
					// authenticated absence permitting the raw-key fallback.
					value, readErr = qualReadAccountWitness(t, root, address, key, ap, rawProof, budget, flags)
					require.Error(t, readErr)
					require.Empty(t, value)
				})
			}
		})
	}
}
