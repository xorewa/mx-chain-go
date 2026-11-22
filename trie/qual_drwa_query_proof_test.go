package trie

import (
	"bytes"
	"errors"
	"reflect"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
)

type qualQueryProofGetter interface {
	GetProofForQuery([]byte) ([][]byte, []byte, error)
}

type qualQueryStore struct {
	common.StorageManager
	blocked             []byte
	readKeys, readNodes [][]byte
	puts                int
}

func (s *qualQueryStore) Get(key []byte) ([]byte, error) {
	if len(s.blocked) > 0 && bytes.Equal(key, s.blocked) {
		return nil, errors.New("qualification unavailable native node")
	}
	value, err := s.StorageManager.Get(key)
	if err == nil {
		s.readKeys = append(s.readKeys, bytes.Clone(key))
		s.readNodes = append(s.readNodes, bytes.Clone(value))
	}
	return value, err
}
func (s *qualQueryStore) GetFromCurrentEpoch(key []byte) ([]byte, error) { return s.Get(key) }
func (s *qualQueryStore) Put(key, value []byte) error {
	s.puts++
	return s.StorageManager.Put(key, value)
}

type qualQueryFaultNode struct {
	node
	hashErr, encodingErr error
}

func (n *qualQueryFaultNode) setRootHash() error {
	if n.hashErr != nil {
		return n.hashErr
	}
	return n.node.setRootHash()
}
func (n *qualQueryFaultNode) getEncodedNode() ([]byte, error) {
	if n.encodingErr != nil {
		return nil, n.encodingErr
	}
	return n.node.getEncodedNode()
}

// The dataset is independent of proof production and is not a source-era profile.
var qualQueryDataset = []struct{ key, value string }{{"doe", "reindeer"}, {"dog", "puppy"}, {"ddog", "cat"}, {"z", "tail"}}

func qualQueryFixture(t *testing.T) *patriciaMerkleTrie {
	t.Helper()
	tr, store := newEmptyTrie()
	if tr == nil || store == nil {
		t.Fatal("native fixture construction")
	}
	t.Cleanup(func() {
		if err := tr.Close(); err != nil {
			t.Error(err)
		}
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	for _, item := range qualQueryDataset {
		if err := tr.Update([]byte(item.key), []byte(item.value)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tr.Commit(); err != nil {
		t.Fatal(err)
	}
	return tr
}
func qualQueryFresh(t *testing.T, seed *patriciaMerkleTrie, store common.StorageManager) *patriciaMerkleTrie {
	t.Helper()
	root, err := seed.RootHash()
	if err != nil {
		t.Fatal(err)
	}
	base, err := NewTrie(store, seed.marshalizer, seed.hasher, seed.enableEpochsHandler, seed.maxTrieLevelInMemory)
	if err != nil {
		t.Fatal(err)
	}
	recreated, err := base.Recreate(holders.NewDefaultRootHashesHolder(root))
	if err != nil {
		t.Fatal(err)
	}
	tr, ok := recreated.(*patriciaMerkleTrie)
	if !ok {
		t.Fatal("native recreated trie type")
	}
	t.Cleanup(func() {
		if err := tr.Close(); err != nil {
			t.Error(err)
		}
	})
	return tr
}
func qualQueryGetter(t *testing.T, tr *patriciaMerkleTrie) qualQueryProofGetter {
	t.Helper()
	query, ok := any(tr).(qualQueryProofGetter)
	if !ok {
		t.Fatal("native query primitive absent")
	}
	return query
}
func qualQuerySameError(a, b error) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return reflect.TypeOf(a) == reflect.TypeOf(b) && a.Error() == b.Error()
}
func qualQuerySameTuple(t *testing.T, ap [][]byte, av []byte, ae error, bp [][]byte, bv []byte, be error) {
	t.Helper()
	if !reflect.DeepEqual(ap, bp) || !reflect.DeepEqual(av, bv) || !qualQuerySameError(ae, be) {
		t.Fatalf("ordinary proof tuple differs: proof %v/%v value %x/%x errors %v/%v", ap, bp, av, bv, ae, be)
	}
}
func qualQueryStateUnchanged(t *testing.T, seed *patriciaMerkleTrie, before []byte) {
	t.Helper()
	after, err := seed.RootHash()
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("native root changed: %x/%x %v", before, after, err)
	}
	for _, item := range qualQueryDataset {
		value, _, err := seed.Get([]byte(item.key))
		if err != nil || !bytes.Equal(value, []byte(item.value)) {
			t.Fatalf("literal state changed: %s %x %v", item.key, value, err)
		}
	}
}

// BASELINE_BODY: replaced only at authoring with the byte-identical pinned body.
func qualUntouchedGetProof(tr *patriciaMerkleTrie, key []byte) ([][]byte, []byte, error) {
	tr.mutOperation.Lock()
	defer tr.mutOperation.Unlock()

	if tr.root == nil {
		return nil, nil, ErrNilNode
	}

	var proof [][]byte
	hexKey := keyBytesToHex(key)
	currentNode := tr.root

	err := currentNode.setRootHash()
	if err != nil {
		return nil, nil, err
	}

	for {
		encodedNode, errGet := currentNode.getEncodedNode()
		if errGet != nil {
			return nil, nil, errGet
		}
		proof = append(proof, encodedNode)
		value := currentNode.getValue()

		currentNode, hexKey, errGet = currentNode.getNext(hexKey, tr.trieStorage)
		if errGet != nil {
			return nil, nil, errGet
		}

		if currentNode == nil {
			return proof, value, nil
		}
	}
}

func TestQualDRWAQueryProof(t *testing.T) {
	t.Run("baseline", func(t *testing.T) {
		seed := qualQueryFixture(t)
		before, err := seed.RootHash()
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"doe", "dog", "ddog", "z", "dogx"} {
			t.Run(key, func(t *testing.T) {
				a := qualQueryFresh(t, seed, seed.trieStorage)
				b := qualQueryFresh(t, seed, seed.trieStorage)
				ap, av, ae := qualUntouchedGetProof(a, []byte(key))
				bp, bv, be := b.GetProof([]byte(key))
				qualQuerySameTuple(t, ap, av, ae, bp, bv, be)
				if key == "dogx" {
					if ae == nil || ap != nil || av != nil {
						t.Fatal("legacy missing-query tuple")
					}
				} else {
					value, _, getErr := a.Get([]byte(key))
					if getErr != nil || !bytes.Equal(av, value) || ae != nil {
						t.Fatal("literal/native lookup comparison")
					}
				}
			})
		}
		for _, kind := range []string{"nil_root", "root_hash_error", "encoding_error"} {
			t.Run(kind, func(t *testing.T) {
				a := qualQueryFresh(t, seed, seed.trieStorage)
				b := qualQueryFresh(t, seed, seed.trieStorage)
				sentinel := errors.New("qualification " + kind)
				if kind == "nil_root" {
					a.root = nil
					b.root = nil
				} else {
					af, bf := &qualQueryFaultNode{node: a.root}, &qualQueryFaultNode{node: b.root}
					if kind == "root_hash_error" {
						af.hashErr = sentinel
						bf.hashErr = sentinel
					} else {
						af.encodingErr = sentinel
						bf.encodingErr = sentinel
					}
					a.root = af
					b.root = bf
				}
				ap, av, ae := qualUntouchedGetProof(a, []byte("dog"))
				bp, bv, be := b.GetProof([]byte("dog"))
				qualQuerySameTuple(t, ap, av, ae, bp, bv, be)
				if be == nil || bp != nil || bv != nil {
					t.Fatal("legacy error publication")
				}
			})
		}
		qualQueryStateUnchanged(t, seed, before)
	})
	t.Run("query_path_from_independent_native_lookup", func(t *testing.T) {
		seed := qualQueryFixture(t)
		before, _ := seed.RootHash()
		for _, key := range []string{"dog", "dogx"} {
			t.Run(key, func(t *testing.T) {
				oracleStore := &qualQueryStore{StorageManager: seed.trieStorage}
				oracle := qualQueryFresh(t, seed, oracleStore)
				value, _, lookupErr := oracle.Get([]byte(key))
				if lookupErr != nil {
					t.Fatal(lookupErr)
				}
				if key == "dog" && !bytes.Equal(value, []byte("puppy")) {
					t.Fatal("literal membership")
				}
				if key == "dogx" && value != nil {
					t.Fatal("literal absence")
				}
				store := &qualQueryStore{StorageManager: seed.trieStorage}
				tr := qualQueryFresh(t, seed, store)
				for i := 0; i < 3; i++ {
					proof, got, queryErr := qualQueryGetter(t, tr).GetProofForQuery([]byte(key))
					if !reflect.DeepEqual(proof, oracleStore.readNodes) {
						t.Fatal("query path differs from cold native lookup")
					}
					if key == "dog" {
						if queryErr != nil || !bytes.Equal(got, []byte("puppy")) {
							t.Fatal("positive query result")
						}
						op, ov, oe := qualUntouchedGetProof(qualQueryFresh(t, seed, seed.trieStorage), []byte(key))
						qualQuerySameTuple(t, op, ov, oe, proof, got, queryErr)
					} else if queryErr == nil || got != nil {
						t.Fatal("missing query must retain original error and nil value")
					}
				}
				if store.puts != 0 || oracleStore.puts != 0 {
					t.Fatal("query published storage output")
				}
			})
		}
		qualQueryStateUnchanged(t, seed, before)
	})
	t.Run("unavailable_then_restored", func(t *testing.T) {
		seed := qualQueryFixture(t)
		before, _ := seed.RootHash()
		// Native keyBytesToHex begins with the last byte. This absent key shares
		// the stored dog suffix and exercises a later unavailable node.
		key := []byte("xdog")
		complete := &qualQueryStore{StorageManager: seed.trieStorage}
		oracle := qualQueryFresh(t, seed, complete)
		value, _, err := oracle.Get(key)
		if err != nil || value != nil || len(complete.readKeys) < 2 {
			t.Fatal("independent missing-key path")
		}
		blocked := bytes.Clone(complete.readKeys[1])
		oldStore := &qualQueryStore{StorageManager: seed.trieStorage, blocked: blocked}
		old := qualQueryFresh(t, seed, oldStore)
		op, ov, oe := qualUntouchedGetProof(old, key)
		if oe == nil || op != nil || ov != nil {
			t.Fatal("legacy unavailable tuple")
		}
		store := &qualQueryStore{StorageManager: seed.trieStorage, blocked: blocked}
		tr := qualQueryFresh(t, seed, store)
		proof, got, queryErr := qualQueryGetter(t, tr).GetProofForQuery(key)
		if queryErr == nil || got != nil || len(proof) == 0 || !qualQuerySameError(oe, queryErr) {
			t.Fatal("partial path/error contract")
		}
		unavailable := &qualQueryStore{StorageManager: seed.trieStorage, blocked: blocked}
		lookup := qualQueryFresh(t, seed, unavailable)
		if _, _, lookupErr := lookup.Get(key); lookupErr == nil {
			t.Fatal("missing storage became no-work")
		}
		if !reflect.DeepEqual(proof, unavailable.readNodes) {
			t.Fatal("partial path differs from completed native reads")
		}
		cp, cv, ce := qualQueryFresh(t, seed, &qualQueryStore{StorageManager: seed.trieStorage, blocked: blocked}).GetProof(key)
		qualQuerySameTuple(t, op, ov, oe, cp, cv, ce)
		store.blocked = nil
		restored, got, restoredErr := qualQueryGetter(t, tr).GetProofForQuery(key)
		if restoredErr == nil || got != nil || !reflect.DeepEqual(restored, complete.readNodes) {
			t.Fatal("exact restoration did not restore terminal path")
		}
		if _, _, getErr := tr.Get(key); getErr != nil {
			t.Fatal("restored lookup unavailable")
		}
		if store.puts != 0 {
			t.Fatal("query published storage output")
		}
		qualQueryStateUnchanged(t, seed, before)
	})
	t.Run("query_errors_keep_nil_value", func(t *testing.T) {
		seed := qualQueryFixture(t)
		for _, kind := range []string{"nil_root", "root_hash_error", "encoding_error"} {
			t.Run(kind, func(t *testing.T) {
				tr := qualQueryFresh(t, seed, seed.trieStorage)
				original := tr.root
				if kind == "nil_root" {
					tr.root = nil
				} else {
					fault := &qualQueryFaultNode{node: tr.root}
					if kind == "root_hash_error" {
						fault.hashErr = errors.New("qualification root hash")
					} else {
						fault.encodingErr = errors.New("qualification encoding")
					}
					tr.root = fault
				}
				proof, value, err := qualQueryGetter(t, tr).GetProofForQuery([]byte("dog"))
				if err == nil || value != nil || proof != nil {
					t.Fatal("root/encoding failure changed into evidence")
				}
				tr.root = original
				if _, _, err = tr.GetProof([]byte("dog")); err != nil {
					t.Fatal("error left native mutex/ordinary query unusable")
				}
			})
		}
	})
	t.Run("concurrent_ordinary_and_opt_in", func(t *testing.T) {
		seed := qualQueryFixture(t)
		before, _ := seed.RootHash()
		tr := qualQueryFresh(t, seed, seed.trieStorage)
		op, ov, oe := qualUntouchedGetProof(qualQueryFresh(t, seed, seed.trieStorage), []byte("dog"))
		if oe != nil {
			t.Fatal(oe)
		}
		query := qualQueryGetter(t, tr)
		results := make(chan bool, 8)
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				same := true
				for j := 0; j < 8; j++ {
					var p [][]byte
					var v []byte
					var e error
					if i%2 == 0 {
						p, v, e = tr.GetProof([]byte("dog"))
					} else {
						p, v, e = query.GetProofForQuery([]byte("dog"))
					}
					same = same && reflect.DeepEqual(op, p) && reflect.DeepEqual(ov, v) && qualQuerySameError(oe, e)
				}
				results <- same
			}(i)
		}
		wg.Wait()
		close(results)
		for same := range results {
			if !same {
				t.Fatal("concurrent proof tuple differs")
			}
		}
		qualQueryStateUnchanged(t, seed, before)
	})
}
