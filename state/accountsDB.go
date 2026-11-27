//go:generate protoc -I=. -I=$GOPATH/src -I=$GOPATH/src/github.com/multiversx/protobuf/protobuf  --gogoslick_out=. codeEntry.proto
package state

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/data/stateChange"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/marshal"
	logger "github.com/multiversx/mx-chain-logger-go"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/errChan"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state/parsers"
	"github.com/multiversx/mx-chain-go/trie/keyBuilder"
	"github.com/multiversx/mx-chain-go/trie/statistics"
)

const (
	leavesChannelSize       = 100
	missingNodesChannelSize = 100
)

type loadingMeasurements struct {
	sync.Mutex
	numCalls   uint64
	size       uint64
	duration   time.Duration
	identifier string
}

func (lm *loadingMeasurements) addMeasurement(size int, duration time.Duration) {
	lm.Lock()
	lm.numCalls++
	lm.size += uint64(size)
	lm.duration += duration
	lm.Unlock()
}

func (lm *loadingMeasurements) resetAndPrint() {
	lm.Lock()
	numCalls := lm.numCalls
	lm.numCalls = 0

	size := lm.size
	lm.size = 0

	duration := lm.duration
	lm.duration = 0
	lm.Unlock()

	log.Debug(lm.identifier+" time measurements",
		"num calls", numCalls,
		"total size in bytes", size,
		"total cumulated duration", duration,
	)
}

type snapshotInfo struct {
	rootHash []byte
	epoch    uint32
}

// AccountsDB is the struct used for accessing accounts. This struct is concurrent safe.
type AccountsDB struct {
	mainTrie               common.Trie
	hasher                 hashing.Hasher
	marshaller             marshal.Marshalizer
	accountFactory         AccountFactory
	storagePruningManager  StoragePruningManager
	obsoleteDataTrieHashes map[string][][]byte
	snapshotsManger        SnapshotsManager

	lastRootHash           []byte
	dataTries              common.TriesHolder
	entries                []JournalEntry
	stateAccessesCollector StateAccessesCollector
	mutOp                  sync.RWMutex
	loadCodeMeasurements   *loadingMeasurements
	addressConverter       core.PubkeyConverter
	pruningEnabled         bool

	protectedChildRoot     ProtectedChildRoot
	protectedCheckpoints   *ProtectedChildCheckpoints
	protectedChildren      map[protectedChildKey]*stagedProtectedChild
	protectedCommitFailure error
	rollbackFailure        error

	stackDebug []byte
}

var log = logger.GetOrCreate("state")

var errProtectedChild = errors.New("invalid protected child trie")

// ProtectedChildRoot is supplied by the native owner for its admitted protected
// record format. It must reject unowned locators and missing/uninitialized
// records. The root it returns belongs to the same native storage and profile.
type ProtectedChildRoot func(address, key, record []byte) ([]byte, error)

// ProtectedChildLocator carries the record bytes authenticated by the native
// owner for this exact account-state checkpoint. No new encoding is persisted.
type ProtectedChildLocator struct {
	Address, Key, Record []byte
}

// ProtectedChildCheckpoints is supplied by the native canonical/retention
// owner. An epoch or a current root alone cannot supply these locators or the
// last-use checkpoint set. The limits are explicit owner inputs.
type ProtectedChildCheckpoints struct {
	Locate   func(common.RootHashHolder) ([]ProtectedChildLocator, error)
	Retained func() ([]common.RootHashHolder, error)
	// ReadNode is the configured native trie decoder using the supplied
	// authenticated reader. Factory assembly binds the existing native decoder.
	ReadNode       func([]byte, common.TrieStorageInteractor) ([]common.TrieNodeData, error)
	MaxLocators    int
	MaxCheckpoints int
	MaxBytes       uint64
}

// ProtectedChildResolver resolves protected children from the supplied native
// checkpoint. A nil resolver is the unconfigured ordinary path.
type ProtectedChildResolver func(common.RootHashHolder) ([]ProtectedChildReference, error)

// ProtectedChildReference retains the native store view of a checked locator.
// Resolution authenticates the record location; Verify checks the node bytes.
type ProtectedChildReference struct {
	root     []byte
	view     common.Trie
	readNode func([]byte, common.TrieStorageInteractor) ([]common.TrieNodeData, error)
	hasher   hashing.Hasher
	maxBytes uint64
}

// RootHash returns the exact child root without exposing the resolver's bytes.
func (ref ProtectedChildReference) RootHash() []byte {
	return bytes.Clone(ref.root)
}

// IsForStorage binds a reference to the native store a consumer will use.
func (ref ProtectedChildReference) IsForStorage(store common.StorageManager) bool {
	if check.IfNil(ref.view) || check.IfNil(store) {
		return false
	}
	referenceStore := ref.view.GetStorageManager().GetBaseTrieStorageManager()
	return !check.IfNil(referenceStore) && referenceStore == store.GetBaseTrieStorageManager()
}

// Verify checks availability and the content hash of every native child node.
func (ref ProtectedChildReference) Verify() error {
	budget := ref.maxBytes
	return ref.collectNodes(make(common.ModifiedHashes), &budget)
}

func (ref ProtectedChildReference) collectNodes(seen common.ModifiedHashes, budget *uint64) error {
	if check.IfNil(ref.view) || check.IfNil(ref.hasher) || ref.readNode == nil || len(ref.root) != ref.hasher.Size() {
		return errProtectedChild
	}
	if common.IsEmptyTrie(ref.root) {
		return nil
	}
	reader := &verifiedProtectedTrieStorage{TrieStorageInteractor: ref.view.GetStorageManager(), hasher: ref.hasher, budget: budget}
	stack := [][]byte{ref.root}
	for len(stack) != 0 {
		last := len(stack) - 1
		hash := stack[last]
		stack = stack[:last]
		if _, exists := seen[string(hash)]; exists {
			continue
		}
		nodes, err := ref.readNode(hash, reader)
		if err != nil {
			return err
		}
		seen[string(hash)] = struct{}{}
		for _, node := range nodes {
			if !node.IsLeaf() {
				stack = append(stack, node.GetData())
			}
		}
	}
	return nil
}

type verifiedProtectedTrieStorage struct {
	common.TrieStorageInteractor
	hasher hashing.Hasher
	budget *uint64
}

// Get authenticates the exact buffer passed to the existing native node decoder.
func (reader *verifiedProtectedTrieStorage) Get(hash []byte) ([]byte, error) {
	if len(hash) != reader.hasher.Size() || *reader.budget == 0 {
		return nil, errProtectedChild
	}
	raw, err := reader.TrieStorageInteractor.Get(hash)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || uint64(len(raw)) > *reader.budget || !bytes.Equal(reader.hasher.Compute(string(raw)), hash) {
		return nil, errProtectedChild
	}
	*reader.budget -= uint64(len(raw))
	return raw, nil
}

type protectedChildKey struct {
	address, record string
}

type stagedProtectedChild struct {
	trie   DataTrie
	root   []byte
	record []byte
}

// ArgsAccountsDB is the arguments DTO for the AccountsDB instance
type ArgsAccountsDB struct {
	Trie                      common.Trie
	Hasher                    hashing.Hasher
	Marshaller                marshal.Marshalizer
	AccountFactory            AccountFactory
	StoragePruningManager     StoragePruningManager
	AddressConverter          core.PubkeyConverter
	SnapshotsManager          SnapshotsManager
	StateAccessesCollector    StateAccessesCollector
	PruningEnabled            bool
	ProtectedChildRoot        ProtectedChildRoot
	ProtectedChildCheckpoints *ProtectedChildCheckpoints
}

// NewAccountsDB creates a new account manager
func NewAccountsDB(args ArgsAccountsDB) (*AccountsDB, error) {
	err := checkArgsAccountsDB(args)
	if err != nil {
		return nil, err
	}

	db := createAccountsDb(args)
	if supplied := args.ProtectedChildCheckpoints; supplied != nil {
		if args.ProtectedChildRoot == nil || supplied.Locate == nil || supplied.Retained == nil || supplied.ReadNode == nil ||
			supplied.MaxLocators <= 0 || supplied.MaxCheckpoints <= 0 || supplied.MaxBytes == 0 {
			return nil, errProtectedChild
		}
		checkpoints := *supplied
		db.protectedCheckpoints = &checkpoints
		if manager, ok := args.SnapshotsManager.(*snapshotsManager); ok {
			manager.mutex.Lock()
			defer manager.mutex.Unlock()
			if manager.protectedChildren != nil {
				return nil, errProtectedChild
			}
			manager.protectedChildren = db.ProtectedChildResolver()
		}
	}
	return db, nil
}

func createAccountsDb(args ArgsAccountsDB) *AccountsDB {
	return &AccountsDB{
		mainTrie:               args.Trie,
		hasher:                 args.Hasher,
		marshaller:             args.Marshaller,
		accountFactory:         args.AccountFactory,
		storagePruningManager:  args.StoragePruningManager,
		entries:                make([]JournalEntry, 0),
		mutOp:                  sync.RWMutex{},
		dataTries:              NewDataTriesHolder(),
		obsoleteDataTrieHashes: make(map[string][][]byte),
		loadCodeMeasurements: &loadingMeasurements{
			identifier: "load code",
		},
		addressConverter:       args.AddressConverter,
		snapshotsManger:        args.SnapshotsManager,
		stateAccessesCollector: args.StateAccessesCollector,
		pruningEnabled:         args.PruningEnabled,
		protectedChildRoot:     args.ProtectedChildRoot,
	}
}

func checkArgsAccountsDB(args ArgsAccountsDB) error {
	if check.IfNil(args.Trie) {
		return ErrNilTrie
	}
	if check.IfNil(args.Hasher) {
		return ErrNilHasher
	}
	if check.IfNil(args.Marshaller) {
		return ErrNilMarshalizer
	}
	if check.IfNil(args.AccountFactory) {
		return ErrNilAccountFactory
	}
	if check.IfNil(args.StoragePruningManager) {
		return ErrNilStoragePruningManager
	}
	if check.IfNil(args.AddressConverter) {
		return ErrNilAddressConverter
	}
	if check.IfNil(args.SnapshotsManager) {
		return ErrNilSnapshotsManager
	}
	if check.IfNil(args.StateAccessesCollector) {
		return ErrNilStateAccessesCollector
	}

	return nil
}

func handleLoggingWhenError(message string, err error, extraArguments ...interface{}) {
	if err == nil {
		return
	}
	if core.IsClosingError(err) {
		args := []interface{}{"reason", err}
		log.Debug(message, append(args, extraArguments...)...)
		return
	}

	args := []interface{}{"error", err}
	log.Warn(message, append(args, extraArguments...)...)
}

// SetSyncer sets the given syncer as the syncer for the underlying trie
func (adb *AccountsDB) SetSyncer(syncer AccountsDBSyncer) error {
	return adb.snapshotsManger.SetSyncer(syncer)
}

// StartSnapshotIfNeeded starts the snapshot if the previous snapshot process was not fully completed
func (adb *AccountsDB) StartSnapshotIfNeeded() error {
	return adb.snapshotsManger.StartSnapshotAfterRestartIfNeeded(adb.getMainTrie().GetStorageManager())
}

// GetCode returns the code for the given account
func (adb *AccountsDB) GetCode(codeHash []byte) []byte {
	if len(codeHash) == 0 {
		return nil
	}

	var codeEntry CodeEntry

	startTime := time.Now()
	defer func() {
		duration := time.Since(startTime)
		adb.loadCodeMeasurements.addMeasurement(len(codeEntry.Code), duration)
	}()

	val, _, err := adb.getMainTrie().Get(codeHash)
	if err != nil {
		return nil
	}

	sc := &stateChange.StateAccess{
		Type:            stateChange.Read,
		MainTrieKey:     codeHash,
		MainTrieVal:     val,
		Operation:       stateChange.GetCode,
		DataTrieChanges: nil,
	}
	adb.stateAccessesCollector.AddStateAccess(sc)

	err = adb.marshaller.Unmarshal(&codeEntry, val)
	if err != nil {
		return nil
	}

	return codeEntry.Code
}

// ImportAccount saves the account in the trie. It does not modify
func (adb *AccountsDB) ImportAccount(account vmcommon.AccountHandler) error {
	if check.IfNil(account) {
		return fmt.Errorf("%w in accountsDB ImportAccount", ErrNilAccountHandler)
	}

	mainTrie := adb.getMainTrie()
	_, err := adb.saveAccountToTrie(account, mainTrie)
	return err
}

func (adb *AccountsDB) getMainTrie() common.Trie {
	adb.mutOp.RLock()
	defer adb.mutOp.RUnlock()

	return adb.mainTrie
}

// SaveAccount saves in the trie all changes made to the account.
func (adb *AccountsDB) SaveAccount(account vmcommon.AccountHandler) error {
	if check.IfNil(account) {
		return fmt.Errorf("%w in accountsDB SaveAccount", ErrNilAccountHandler)
	}

	// this is a critical section, do not remove the mutex
	adb.mutOp.Lock()
	defer adb.mutOp.Unlock()

	return adb.saveAccount(account)
}

func (adb *AccountsDB) saveAccount(account vmcommon.AccountHandler) error {
	if adb.protectedCommitFailure != nil {
		return adb.protectedCommitFailure
	}
	oldAccount, err := adb.getAccount(account.AddressBytes(), adb.mainTrie)
	if err != nil {
		return err
	}

	var entry JournalEntry
	if check.IfNil(oldAccount) {
		entry, err = NewJournalEntryAccountCreation(account.AddressBytes(), adb.mainTrie)
		if err != nil {
			return err
		}
		adb.journalize(entry)
	} else {
		entry, err = NewJournalEntryAccount(oldAccount)
		if err != nil {
			return err
		}
		adb.journalize(entry)
	}

	newDataTrieValues, err := adb.saveCodeAndDataTrie(oldAccount, account)
	if err != nil {
		return err
	}

	marshalledAccount, err := adb.saveAccountToTrie(account, adb.mainTrie)
	if err != nil {
		return err
	}

	sc := &stateChange.StateAccess{
		Type:            stateChange.Write,
		MainTrieKey:     account.AddressBytes(),
		MainTrieVal:     marshalledAccount,
		DataTrieChanges: newDataTrieValues,
		Operation:       stateChange.SaveAccount,
		Index:           int32(len(adb.entries)),
		AccountChanges:  adb.stateAccessesCollector.GetAccountChanges(oldAccount, account),
	}

	adb.stateAccessesCollector.AddStateAccess(sc)

	return nil
}

func (adb *AccountsDB) saveCodeAndDataTrie(oldAcc, newAcc vmcommon.AccountHandler) ([]*stateChange.DataTrieChange, error) {
	baseNewAcc, newAccOk := newAcc.(baseAccountHandler)
	baseOldAccount, _ := oldAcc.(baseAccountHandler)

	if !newAccOk {
		return nil, nil
	}

	newValues, err := adb.saveDataTrie(baseNewAcc)
	if err != nil {
		return nil, err
	}

	err = adb.saveCode(baseNewAcc, baseOldAccount)
	if err != nil {
		return nil, err
	}

	return newValues, nil
}

func (adb *AccountsDB) saveCode(newAcc, oldAcc baseAccountHandler) error {
	// TODO when state splitting is implemented, check how the code should be copied in different shards

	if !newAcc.HasNewCode() {
		return nil
	}

	var oldCodeHash []byte
	if !check.IfNil(oldAcc) {
		oldCodeHash = oldAcc.GetCodeHash()
	}

	newCode := newAcc.GetCode()
	var newCodeHash []byte
	if len(newCode) != 0 {
		newCodeHash = adb.hasher.Compute(string(newCode))
	}

	if bytes.Equal(oldCodeHash, newCodeHash) {
		newAcc.SetCodeHash(newCodeHash)
		return nil
	}

	oldCodeEntry, err := adb.getCodeEntry(oldCodeHash)
	if err != nil {
		return err
	}

	newCodeEntry, err := adb.getCodeEntry(newCodeHash)
	if err != nil {
		return err
	}

	entry, err := NewJournalEntryCode(oldCodeEntry, oldCodeHash, newCodeEntry, newCodeHash, adb.mainTrie, adb.marshaller)
	if err != nil {
		return err
	}
	adb.journalize(entry)

	err = adb.updateOldCodeEntry(oldCodeHash, oldCodeEntry)
	if err != nil {
		return err
	}

	err = adb.updateNewCodeEntry(newCodeHash, newCodeEntry, newCode)
	if err != nil {
		return err
	}

	newAcc.SetCodeHash(newCodeHash)
	return nil
}

func (adb *AccountsDB) getCodeEntry(hash []byte) (*CodeEntry, error) {
	codeEntry, err := getCodeEntry(hash, adb.mainTrie, adb.marshaller)
	if err != nil {
		return nil, err
	}

	sc := &stateChange.StateAccess{
		Type:            stateChange.Read,
		MainTrieKey:     hash,
		MainTrieVal:     nil,
		Operation:       stateChange.GetCode,
		DataTrieChanges: nil,
	}
	adb.stateAccessesCollector.AddStateAccess(sc)

	return codeEntry, nil
}

func (adb *AccountsDB) updateOldCodeEntry(oldCodeHash []byte, oldCodeEntry *CodeEntry) error {
	if oldCodeEntry == nil {
		return nil
	}

	codeEntryClone := &CodeEntry{
		Code:          oldCodeEntry.Code,
		NumReferences: oldCodeEntry.NumReferences,
	}

	if codeEntryClone.NumReferences <= 1 {
		err := adb.mainTrie.Delete(oldCodeHash)
		if err != nil {
			return err
		}

		sc1 := &stateChange.StateAccess{
			Type:            stateChange.Write,
			MainTrieKey:     oldCodeHash,
			MainTrieVal:     nil,
			Operation:       stateChange.WriteCode,
			DataTrieChanges: nil,
		}
		adb.stateAccessesCollector.AddStateAccess(sc1)

		return nil
	}

	codeEntryClone.NumReferences--
	codeEntryBytes, err := saveCodeEntry(oldCodeHash, codeEntryClone, adb.mainTrie, adb.marshaller)
	if err != nil {
		return err
	}

	sc := &stateChange.StateAccess{
		Type:            stateChange.Write,
		MainTrieKey:     oldCodeHash,
		MainTrieVal:     codeEntryBytes,
		Operation:       stateChange.WriteCode,
		DataTrieChanges: nil,
	}
	adb.stateAccessesCollector.AddStateAccess(sc)

	return nil
}

func (adb *AccountsDB) updateNewCodeEntry(newCodeHash []byte, newCodeEntry *CodeEntry, newCode []byte) error {
	if len(newCode) == 0 {
		return nil
	}

	codeEntry := &CodeEntry{}
	codeEntry.Code = newCode
	if newCodeEntry != nil {
		codeEntry.NumReferences = newCodeEntry.NumReferences
	}
	codeEntry.NumReferences++

	codeEntryBytes, err := saveCodeEntry(newCodeHash, codeEntry, adb.mainTrie, adb.marshaller)
	if err != nil {
		return err
	}

	sc := &stateChange.StateAccess{
		Type:            stateChange.Write,
		MainTrieKey:     newCodeHash,
		MainTrieVal:     codeEntryBytes,
		Operation:       stateChange.WriteCode,
		DataTrieChanges: nil,
	}
	adb.stateAccessesCollector.AddStateAccess(sc)

	return nil
}

func getCodeEntry(codeHash []byte, trie Updater, marshalizer marshal.Marshalizer) (*CodeEntry, error) {
	val, _, err := trie.Get(codeHash)
	if err != nil {
		return nil, err
	}

	if len(val) == 0 {
		return nil, nil
	}

	var codeEntry CodeEntry
	err = marshalizer.Unmarshal(&codeEntry, val)
	if err != nil {
		return nil, err
	}

	return &codeEntry, nil
}

func saveCodeEntry(codeHash []byte, entry *CodeEntry, trie Updater, marshalizer marshal.Marshalizer) ([]byte, error) {
	codeEntry, err := marshalizer.Marshal(entry)
	if err != nil {
		return nil, err
	}

	err = trie.Update(codeHash, codeEntry)
	if err != nil {
		return nil, err
	}

	return codeEntry, nil
}

// loadDataTrieConcurrentSafe retrieves and saves the SC data inside accountHandler object.
// Errors if something went wrong
func (adb *AccountsDB) loadDataTrieConcurrentSafe(accountHandler baseAccountHandler, mainTrie common.Trie) error {
	adb.mutOp.Lock()
	defer adb.mutOp.Unlock()

	return adb.loadDataTrie(accountHandler, mainTrie)
}

func (adb *AccountsDB) loadDataTrie(accountHandler baseAccountHandler, mainTrie common.Trie) error {
	dataTrie := adb.dataTries.Get(accountHandler.AddressBytes())
	if dataTrie != nil {
		accountHandler.SetDataTrie(dataTrie)
		return nil
	}

	if len(accountHandler.GetRootHash()) == 0 {
		return nil
	}

	rootHashHolder := holders.NewDefaultRootHashesHolder(accountHandler.GetRootHash())
	dataTrie, err := mainTrie.Recreate(rootHashHolder)
	if err != nil {
		return fmt.Errorf("trie was not found for hash, rootHash = %s, err = %w", hex.EncodeToString(accountHandler.GetRootHash()), err)
	}

	accountHandler.SetDataTrie(dataTrie)
	adb.dataTries.Put(accountHandler.AddressBytes(), dataTrie)
	return nil
}

// StageProtectedChildTrie saves the next protected record and enlists its child
// in this AccountsDB's journal. The original operation owner supplies the exact
// predecessor and the already validated, bounded raw leaf updates. Any error
// requires that owner to undo its operation before continuing.
func (adb *AccountsDB) StageProtectedChildTrie(address, key, predecessor, successor []byte, updates []core.TrieData) error {
	adb.mutOp.Lock()
	defer adb.mutOp.Unlock()

	if adb.protectedCommitFailure != nil {
		return adb.protectedCommitFailure
	}
	if len(successor) == 0 || len(updates) == 0 {
		return errProtectedChild
	}
	previousRoot, err := adb.protectedPredecessorRoot(address, key, predecessor)
	if err != nil {
		return err
	}
	nextRoot, err := adb.decodeProtectedChildRoot(address, key, successor)
	if err != nil {
		return err
	}
	_, err = adb.stageProtectedChildTrie(address, key, predecessor, previousRoot,
		func(DataTrie) ([]core.TrieData, error) { return updates, nil },
		func(actualRoot []byte) ([]byte, error) {
			if !bytes.Equal(actualRoot, nextRoot) {
				return nil, errProtectedChild
			}
			return successor, nil
		})
	return err
}

// StageDerivedProtectedChildTrie reads and updates one initialized protected
// child, including the original owner's uncommitted state. The owning operation
// supplies its admitted, bounded touched keys and pure derivation and record
// encoding functions. They receive detached bytes, never a store or trie.
// Any error requires the original operation to undo its effects.
func (adb *AccountsDB) StageDerivedProtectedChildTrie(address, key, predecessor []byte, keys [][]byte,
	derive func([]core.TrieData) ([]core.TrieData, error), encode func([]byte) ([]byte, error)) ([]byte, error) {
	adb.mutOp.Lock()
	defer adb.mutOp.Unlock()

	previousRoot, err := adb.protectedPredecessorRoot(address, key, predecessor)
	if err != nil {
		return nil, err
	}
	if derive == nil || encode == nil {
		return nil, errProtectedChild
	}
	owned, err := protectedChildKeys(keys)
	if err != nil {
		return nil, err
	}
	return adb.stageProtectedChildTrie(address, key, predecessor, previousRoot,
		func(child DataTrie) ([]core.TrieData, error) {
			current, err := readProtectedChildLeaves(child, owned)
			if err != nil {
				return nil, err
			}
			updates, err := derive(current)
			if err != nil {
				return nil, err
			}
			if len(updates) != len(owned) {
				return nil, errProtectedChild
			}
			for i, update := range updates {
				if !bytes.Equal(update.Key, owned[i]) {
					return nil, errProtectedChild
				}
			}
			return updates, nil
		},
		func(actualRoot []byte) ([]byte, error) {
			successor, err := encode(bytes.Clone(actualRoot))
			if err != nil {
				return nil, err
			}
			if len(successor) == 0 {
				return nil, errProtectedChild
			}
			nextRoot, err := adb.decodeProtectedChildRoot(address, key, successor)
			if err != nil {
				return nil, err
			}
			if !bytes.Equal(actualRoot, nextRoot) {
				return nil, errProtectedChild
			}
			return successor, nil
		})
}

// ReadProtectedChildLeaves reads the original owner's admitted, bounded keys
// against the exact current outer record, including earlier uncommitted stages.
// It returns detached values and native leaf versions in input order. A missing
// leaf has an empty value, while an unavailable child returns an error.
func (adb *AccountsDB) ReadProtectedChildLeaves(address, key, predecessor []byte, keys [][]byte) ([]core.TrieData, error) {
	adb.mutOp.Lock()
	defer adb.mutOp.Unlock()

	root, err := adb.protectedPredecessorRoot(address, key, predecessor)
	if err != nil {
		return nil, err
	}
	owned, err := protectedChildKeys(keys)
	if err != nil {
		return nil, err
	}
	if _, err = adb.protectedChildPredecessorAccount(address, key, predecessor); err != nil {
		return nil, err
	}
	staged := adb.protectedChildren[protectedChildKey{string(address), string(key)}]
	if staged == nil && !common.IsEmptyTrie(root) {
		// Native Recreate attaches the requested hash to the decoded node.
		// Check the stored node bytes before relying on that hash.
		raw, readErr := adb.mainTrie.GetSerializedNode(root)
		if readErr != nil {
			return nil, readErr
		}
		if !bytes.Equal(adb.hasher.Compute(string(raw)), root) {
			return nil, errProtectedChild
		}
	}
	child, err := adb.protectedChildForUpdate(staged, root, predecessor)
	if err != nil {
		return nil, err
	}
	return readProtectedChildLeaves(child, owned)
}

func protectedChildKeys(keys [][]byte) ([][]byte, error) {
	if len(keys) == 0 {
		return nil, errProtectedChild
	}
	owned := make([][]byte, len(keys))
	seen := make(map[string]struct{}, len(keys))
	for i, key := range keys {
		if _, exists := seen[string(key)]; exists || len(key) == 0 {
			return nil, errProtectedChild
		}
		seen[string(key)] = struct{}{}
		owned[i] = bytes.Clone(key)
	}
	return owned, nil
}

func readProtectedChildLeaves(child DataTrie, keys [][]byte) ([]core.TrieData, error) {
	current := make([]core.TrieData, len(keys))
	for i, key := range keys {
		value, _, version, err := child.GetWithVersion(key)
		if err != nil {
			return nil, err
		}
		current[i] = core.TrieData{Key: bytes.Clone(key), Value: bytes.Clone(value), Version: core.TrieNodeVersion(version)}
	}
	return current, nil
}

func (adb *AccountsDB) protectedPredecessorRoot(address, key, predecessor []byte) ([]byte, error) {
	if adb.protectedCommitFailure != nil {
		return nil, adb.protectedCommitFailure
	}
	if adb.protectedChildRoot == nil || len(address) == 0 || !bytes.HasPrefix(key, []byte(core.ProtectedKeyPrefix)) || len(predecessor) == 0 {
		return nil, errProtectedChild
	}
	return adb.decodeProtectedChildRoot(address, key, predecessor)
}

// stageProtectedChildTrie runs with mutOp held and uses the account journal
// shared by both protected children and the debit/credit that owns them.
func (adb *AccountsDB) stageProtectedChildTrie(address, key, predecessor, previousRoot []byte,
	prepare func(DataTrie) ([]core.TrieData, error), encode func([]byte) ([]byte, error)) ([]byte, error) {
	account, err := adb.protectedChildPredecessorAccount(address, key, predecessor)
	if err != nil {
		return nil, err
	}
	locator := protectedChildKey{string(address), string(key)}
	previous := adb.protectedChildren[locator]
	child, err := adb.protectedChildForUpdate(previous, previousRoot, predecessor)
	if err != nil {
		return nil, err
	}
	updates, err := prepare(child)
	if err != nil {
		return nil, err
	}
	entry := &journalEntryProtectedChild{owner: adb, key: locator, previous: previous, child: child, root: previousRoot}
	adb.journalize(entry)
	for _, update := range updates {
		value, _, version, readErr := child.GetWithVersion(update.Key)
		if readErr != nil {
			return nil, readErr
		}
		entry.undo = append(entry.undo, core.TrieData{
			Key: bytes.Clone(update.Key), Value: bytes.Clone(value), Version: core.TrieNodeVersion(version),
		})
		if err = child.UpdateWithVersion(bytes.Clone(update.Key), bytes.Clone(update.Value), update.Version); err != nil {
			return nil, err
		}
	}
	actualRoot, err := child.RootHash()
	if err != nil {
		return nil, err
	}
	successor, err := encode(actualRoot)
	if err != nil {
		return nil, err
	}
	if adb.protectedChildren == nil {
		adb.protectedChildren = make(map[protectedChildKey]*stagedProtectedChild)
	}
	adb.protectedChildren[locator] = &stagedProtectedChild{trie: child, root: bytes.Clone(actualRoot), record: bytes.Clone(successor)}
	if err = account.SaveKeyValue(bytes.Clone(key), bytes.Clone(successor)); err != nil {
		return nil, err
	}
	if err = adb.saveAccount(account); err != nil {
		return nil, err
	}
	return bytes.Clone(successor), nil
}

func (adb *AccountsDB) decodeProtectedChildRoot(address, key, value []byte) ([]byte, error) {
	root, err := adb.protectedChildRoot(bytes.Clone(address), bytes.Clone(key), bytes.Clone(value))
	if err != nil {
		return nil, err
	}
	if len(root) != adb.hasher.Size() {
		return nil, errProtectedChild
	}
	return bytes.Clone(root), nil
}

func (adb *AccountsDB) protectedChildAccount(address []byte) (UserAccountHandler, error) {
	account, err := adb.getAccount(address, adb.mainTrie)
	if err != nil {
		return nil, err
	}
	user, ok := account.(UserAccountHandler)
	if !ok || check.IfNil(user) {
		return nil, errProtectedChild
	}
	base, ok := account.(baseAccountHandler)
	if !ok || check.IfNil(base) {
		return nil, errProtectedChild
	}
	if err = adb.loadDataTrie(base, adb.mainTrie); err != nil {
		return nil, err
	}
	return user, nil
}

func (adb *AccountsDB) protectedChildPredecessorAccount(address, key, predecessor []byte) (UserAccountHandler, error) {
	account, err := adb.protectedChildAccount(address)
	if err != nil {
		return nil, err
	}
	stored, _, err := account.RetrieveValue(key)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(stored, predecessor) {
		return nil, errProtectedChild
	}
	return account, nil
}

func (adb *AccountsDB) protectedChildForUpdate(previous *stagedProtectedChild, root, record []byte) (DataTrie, error) {
	if previous != nil {
		if !bytes.Equal(previous.root, root) || !bytes.Equal(previous.record, record) {
			return nil, errProtectedChild
		}
		actual, err := previous.trie.RootHash()
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(actual, root) {
			return nil, errProtectedChild
		}
		return previous.trie, nil
	}
	tr, err := adb.mainTrie.Recreate(holders.NewDefaultRootHashesHolder(root))
	if err != nil {
		return nil, err
	}
	child, ok := tr.(DataTrie)
	if !ok || check.IfNil(child) {
		return nil, errProtectedChild
	}
	return child, nil
}

// saveDataTrie is used to save the data trie (not committing it) and to recompute the new Root value
// If data is not dirtied, method will not create its JournalEntries to keep track of data modification
func (adb *AccountsDB) saveDataTrie(accountHandler baseAccountHandler) ([]*stateChange.DataTrieChange, error) {
	newValues, oldValues, err := accountHandler.SaveDirtyData(adb.mainTrie)
	if err != nil {
		return nil, err
	}
	if len(oldValues) == 0 {
		return nil, nil
	}

	entry, err := NewJournalEntryDataTrieUpdates(oldValues, accountHandler)
	if err != nil {
		return nil, err
	}
	adb.journalize(entry)

	rootHash, err := accountHandler.DataTrie().RootHash()
	if err != nil {
		return nil, err
	}
	accountHandler.SetRootHash(rootHash)
	log.Trace("saveDataTrie: rootHash changed", "address", accountHandler.AddressBytes(), "rootHash", rootHash)

	if check.IfNil(adb.dataTries.Get(accountHandler.AddressBytes())) {
		trie, ok := accountHandler.DataTrie().(common.Trie)
		if !ok {
			log.Warn("wrong type conversion", "trie type", fmt.Sprintf("%T", accountHandler.DataTrie()))
			return nil, nil
		}

		adb.dataTries.Put(accountHandler.AddressBytes(), trie)
	}

	return newValues, nil
}

func (adb *AccountsDB) saveAccountToTrie(accountHandler vmcommon.AccountHandler, mainTrie common.Trie) ([]byte, error) {
	log.Trace("accountsDB.saveAccountToTrie", "address", accountHandler.AddressBytes())

	// pass the reference to marshaller, otherwise it will fail marshalling balance
	buff, err := adb.marshaller.Marshal(accountHandler)
	if err != nil {
		return nil, err
	}

	err = mainTrie.Update(accountHandler.AddressBytes(), buff)
	if err != nil {
		return nil, err
	}

	return buff, nil
}

// RemoveAccount removes the account data from underlying trie.
// It basically calls Update with empty slice
func (adb *AccountsDB) RemoveAccount(address []byte) error {
	if len(address) == 0 {
		return fmt.Errorf("%w in RemoveAccount", ErrNilAddress)
	}

	// this is a critical section, do not remove the mutex
	adb.mutOp.Lock()
	defer adb.mutOp.Unlock()

	acnt, err := adb.getAccount(address, adb.mainTrie)
	if err != nil {
		return err
	}
	if check.IfNil(acnt) {
		return fmt.Errorf("%w in RemoveAccount for address %s", ErrAccNotFound, address)
	}

	entry, err := NewJournalEntryAccount(acnt)
	if err != nil {
		return err
	}
	adb.journalize(entry)

	err = adb.removeCodeAndDataTrie(acnt)
	if err != nil {
		return err
	}

	log.Trace("accountsDB.RemoveAccount",
		"address", hex.EncodeToString(address),
	)

	return adb.mainTrie.Delete(address)
}

func (adb *AccountsDB) removeCodeAndDataTrie(acnt vmcommon.AccountHandler) error {
	baseAcc, ok := acnt.(baseAccountHandler)
	if !ok {
		return nil
	}

	err := adb.removeCode(baseAcc)
	if err != nil {
		return err
	}

	err = adb.removeDataTrie(baseAcc)
	if err != nil {
		return err
	}

	return nil
}

func (adb *AccountsDB) removeDataTrie(baseAcc baseAccountHandler) error {
	rootHash := baseAcc.GetRootHash()
	if len(rootHash) == 0 {
		return nil
	}

	rootHashHolder := holders.NewDefaultRootHashesHolder(rootHash)
	dataTrie, err := adb.mainTrie.Recreate(rootHashHolder)
	if err != nil {
		return err
	}

	hashes, err := dataTrie.GetAllHashes()
	if err != nil {
		return err
	}

	adb.obsoleteDataTrieHashes[string(rootHash)] = hashes

	sc := &stateChange.StateAccess{
		Type:            stateChange.Write,
		MainTrieKey:     baseAcc.AddressBytes(),
		Operation:       stateChange.RemoveDataTrie,
		DataTrieChanges: nil,
	}
	adb.stateAccessesCollector.AddStateAccess(sc)
	entry, err := NewJournalEntryDataTrieRemove(rootHash, adb.obsoleteDataTrieHashes)
	if err != nil {
		return err
	}
	adb.journalize(entry)

	return nil
}

func (adb *AccountsDB) removeCode(baseAcc baseAccountHandler) error {
	oldCodeHash := baseAcc.GetCodeHash()

	oldCodeEntry, err := adb.getCodeEntry(oldCodeHash)
	if err != nil {
		return err
	}

	entry, err := NewJournalEntryCode(oldCodeEntry, oldCodeHash, nil, nil, adb.mainTrie, adb.marshaller)
	if err != nil {
		return err
	}
	adb.journalize(entry)

	return adb.updateOldCodeEntry(oldCodeHash, oldCodeEntry)
}

// LoadAccount fetches the account based on the address. Creates an empty account if the account is missing.
func (adb *AccountsDB) LoadAccount(address []byte) (vmcommon.AccountHandler, error) {
	if len(address) == 0 {
		return nil, fmt.Errorf("%w in LoadAccount", ErrNilAddress)
	}

	log.Trace("accountsDB.LoadAccount", "address", address)

	mainTrie := adb.getMainTrie()
	acnt, err := adb.getAccount(address, mainTrie)
	if err != nil {
		return nil, err
	}
	if check.IfNil(acnt) {
		return adb.accountFactory.CreateAccount(address)
	}

	baseAcc, ok := acnt.(baseAccountHandler)
	if ok {
		err = adb.loadDataTrieConcurrentSafe(baseAcc, mainTrie)
		if err != nil {
			return nil, err
		}
	}

	return acnt, nil
}

func (adb *AccountsDB) getAccount(address []byte, mainTrie common.Trie) (vmcommon.AccountHandler, error) {
	val, _, err := mainTrie.Get(address)
	if err != nil {
		return nil, err
	}
	if val == nil {
		return nil, nil
	}

	sc := &stateChange.StateAccess{
		Type:            stateChange.Read,
		MainTrieKey:     address,
		MainTrieVal:     val,
		Operation:       stateChange.GetAccount,
		DataTrieChanges: nil,
	}
	adb.stateAccessesCollector.AddStateAccess(sc)

	acnt, err := adb.accountFactory.CreateAccount(address)
	if err != nil {
		return nil, err
	}

	err = adb.marshaller.Unmarshal(acnt, val)
	if err != nil {
		if adb.isReservedAccountAddress(address, val) {
			return nil, ErrAccountAddressIsReserved
		}

		return nil, err
	}

	return acnt, nil
}

func (adb *AccountsDB) isReservedAccountAddress(address []byte, value []byte) bool {
	var codeEntry CodeEntry
	err := adb.marshaller.Unmarshal(&codeEntry, value)
	if err != nil || len(codeEntry.Code) == 0 {
		return false
	}

	computedHash := adb.hasher.Compute(string(codeEntry.Code))
	return bytes.Equal(computedHash, address)
}

// GetExistingAccount returns an existing account if exists or nil if missing
func (adb *AccountsDB) GetExistingAccount(address []byte) (vmcommon.AccountHandler, error) {
	if len(address) == 0 {
		return nil, fmt.Errorf("%w in GetExistingAccount", ErrNilAddress)
	}

	log.Trace("accountsDB.GetExistingAccount", "address", address)

	mainTrie := adb.getMainTrie()
	acnt, err := adb.getAccount(address, mainTrie)
	if err != nil {
		return nil, err
	}
	if check.IfNil(acnt) {
		return nil, ErrAccNotFound
	}

	baseAcc, ok := acnt.(baseAccountHandler)
	if ok {
		err = adb.loadDataTrieConcurrentSafe(baseAcc, mainTrie)
		if err != nil {
			return nil, err
		}
	}

	return acnt, nil
}

// GetAccountFromBytes returns an account from the given bytes
func (adb *AccountsDB) GetAccountFromBytes(address []byte, accountBytes []byte) (vmcommon.AccountHandler, error) {
	if len(address) == 0 {
		return nil, fmt.Errorf("%w in GetAccountFromBytes", ErrNilAddress)
	}

	acnt, err := adb.accountFactory.CreateAccount(address)
	if err != nil {
		return nil, err
	}

	err = adb.marshaller.Unmarshal(acnt, accountBytes)
	if err != nil {
		return nil, err
	}

	baseAcc, ok := acnt.(baseAccountHandler)
	if !ok {
		return acnt, nil
	}

	err = adb.loadDataTrieConcurrentSafe(baseAcc, adb.getMainTrie())
	if err != nil {
		return nil, err
	}

	return acnt, nil
}

// loadCode retrieves and saves the SC code inside AccountState object. Errors if something went wrong
func (adb *AccountsDB) loadCode(accountHandler baseAccountHandler) error {
	if len(accountHandler.GetCodeHash()) == 0 {
		return nil
	}

	val, _, err := adb.mainTrie.Get(accountHandler.GetCodeHash())
	if err != nil {
		return err
	}

	var codeEntry CodeEntry
	err = adb.marshaller.Unmarshal(&codeEntry, val)
	if err != nil {
		return err
	}

	accountHandler.SetCode(codeEntry.Code)
	return nil
}

// RevertToSnapshot apply Revert method over accounts object and removes entries from the list
// Calling with 0 will revert everything. If the snapshot value is out of bounds, an err will be returned
func (adb *AccountsDB) RevertToSnapshot(snapshot int) (result error) {
	log.Trace("accountsDB.RevertToSnapshot started",
		"snapshot", snapshot,
	)

	adb.mutOp.Lock()

	defer func() {
		adb.retainRollbackFailure(result)
		log.Trace("accountsDB.RevertToSnapshot ended")
		adb.mutOp.Unlock()
	}()

	if adb.protectedCommitFailure != nil {
		return adb.protectedCommitFailure
	}
	if snapshot > len(adb.entries) || snapshot < 0 {
		return ErrSnapshotValueOutOfBounds
	}

	if snapshot == 0 {
		log.Trace("revert snapshot to adb.lastRootHash", "hash", adb.lastRootHash)
		return adb.recreateTrie(holders.NewDefaultRootHashesHolder(adb.lastRootHash))
	}

	for i := len(adb.entries) - 1; i >= snapshot; i-- {
		account, err := adb.entries[i].Revert()
		if err != nil {
			adb.entries = adb.entries[:i+1]
			return err
		}

		if !check.IfNil(account) {
			_, err = adb.saveAccountToTrie(account, adb.mainTrie)
			if err != nil {
				adb.entries = adb.entries[:i+1]
				return err
			}
		}
	}

	adb.entries = adb.entries[:snapshot]

	return adb.stateAccessesCollector.RevertToIndex(snapshot)
}

// JournalLen will return the number of entries
func (adb *AccountsDB) JournalLen() int {
	adb.mutOp.Lock()
	defer adb.mutOp.Unlock()

	length := len(adb.entries)
	log.Trace("accountsDB.JournalLen",
		"length", length,
	)

	return length
}

// CommitInEpoch will commit the current trie state in the given epoch
func (adb *AccountsDB) CommitInEpoch(currentEpoch uint32, epochToCommit uint32) ([]byte, error) {
	adb.mutOp.Lock()
	defer func() {
		adb.mainTrie.GetStorageManager().SetEpochForPutOperation(currentEpoch)
		adb.mainTrie.GetStorageManager().GetStateStatsHandler().Reset()
		adb.mutOp.Unlock()
		adb.loadCodeMeasurements.resetAndPrint()
	}()

	adb.mainTrie.GetStorageManager().SetEpochForPutOperation(epochToCommit)

	return adb.commit()
}

func (adb *AccountsDB) printTrieStorageStatistics() {
	stats := adb.mainTrie.GetStorageManager().GetStateStatsHandler().ProcessingStats()
	if stats != nil {
		log.Debug("trie storage statistics",
			"stats", stats,
		)
	}

}

// Commit will persist all data inside the trie
func (adb *AccountsDB) Commit() ([]byte, error) {
	adb.mutOp.Lock()
	defer func() {
		adb.mutOp.Unlock()
		adb.loadCodeMeasurements.resetAndPrint()
	}()

	return adb.commit()
}

func (adb *AccountsDB) commit() (_ []byte, result error) {
	log.Trace("accountsDB.Commit started")
	if adb.protectedCommitFailure != nil {
		return nil, adb.protectedCommitFailure
	}
	if adb.rollbackFailure != nil {
		return nil, adb.rollbackFailure
	}
	if len(adb.protectedChildren) != 0 {
		defer func() {
			if result != nil {
				adb.protectedCommitFailure = result
			}
		}()
		if err := adb.commitProtectedChildren(); err != nil {
			return nil, err
		}
	}
	adb.entries = make([]JournalEntry, 0)

	oldHashes := make(common.ModifiedHashes)
	newHashes := make(common.ModifiedHashes)
	// Step 1. commit all data tries
	dataTries := adb.dataTries.GetAll()
	for i := 0; i < len(dataTries); i++ {
		err := adb.commitTrie(dataTries[i], oldHashes, newHashes)
		if err != nil {
			return nil, err
		}
	}
	adb.dataTries.Reset()

	oldRoot := adb.mainTrie.GetOldRoot()

	// Step 2. commit main trie
	err := adb.commitTrie(adb.mainTrie, oldHashes, newHashes)
	if err != nil {
		return nil, err
	}

	newRoot, err := adb.mainTrie.RootHash()
	if err != nil {
		log.Trace("accountsDB.Commit ended", "error", err.Error())
		return nil, err
	}

	err = adb.stateAccessesCollector.CommitCollectedAccesses(newRoot)
	if err != nil {
		return nil, err
	}

	err = adb.markForEviction(oldRoot, newRoot, oldHashes, newHashes)
	if err != nil {
		return nil, err
	}

	adb.lastRootHash = newRoot
	adb.obsoleteDataTrieHashes = make(map[string][][]byte)
	adb.protectedChildren = nil

	log.Trace("accountsDB.Commit ended", "root hash", newRoot)

	adb.printTrieStorageStatistics()

	return newRoot, nil
}

func (adb *AccountsDB) commitProtectedChildren() error {
	keys := make([]protectedChildKey, 0, len(adb.protectedChildren))
	for key := range adb.protectedChildren {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].address != keys[j].address {
			return keys[i].address < keys[j].address
		}
		return keys[i].record < keys[j].record
	})
	for _, key := range keys {
		child := adb.protectedChildren[key]
		account, err := adb.protectedChildAccount([]byte(key.address))
		if err != nil {
			return err
		}
		record, _, err := account.RetrieveValue([]byte(key.record))
		if err != nil {
			return err
		}
		root, err := child.trie.RootHash()
		if err != nil {
			return err
		}
		if !bytes.Equal(record, child.record) || !bytes.Equal(root, child.root) {
			return errProtectedChild
		}
	}
	for _, key := range keys {
		if err := adb.protectedChildren[key].trie.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func (adb *AccountsDB) markForEviction(
	oldRoot []byte,
	newRoot []byte,
	oldHashes common.ModifiedHashes,
	newHashes common.ModifiedHashes,
) error {
	if !adb.pruningEnabled {
		return nil
	}

	for _, hashes := range adb.obsoleteDataTrieHashes {
		for _, hash := range hashes {
			oldHashes[string(hash)] = struct{}{}
		}
	}

	return adb.storagePruningManager.MarkForEviction(oldRoot, newRoot, oldHashes, newHashes)
}

func (adb *AccountsDB) commitTrie(tr common.Trie, oldHashes common.ModifiedHashes, newHashes common.ModifiedHashes) error {
	if adb.pruningEnabled {
		oldTrieHashes := tr.GetObsoleteHashes()
		newTrieHashes, err := tr.GetDirtyHashes()
		if err != nil {
			return err
		}

		for _, hash := range oldTrieHashes {
			oldHashes[string(hash)] = struct{}{}
		}

		for hash := range newTrieHashes {
			newHashes[hash] = struct{}{}
		}
	}

	return tr.Commit()
}

// RootHash returns the main trie's root hash
func (adb *AccountsDB) RootHash() ([]byte, error) {
	rootHash, err := adb.getMainTrie().RootHash()
	log.Trace("accountsDB.RootHash",
		"root hash", rootHash,
		"err", err,
	)

	return rootHash, err
}

// RecreateTrie is used to reload the trie based on the provided options
func (adb *AccountsDB) RecreateTrie(options common.RootHashHolder) error {
	adb.mutOp.Lock()
	defer adb.mutOp.Unlock()

	err := adb.recreateTrie(options)
	if err != nil {
		return err
	}
	adb.lastRootHash = options.GetRootHash()

	return nil
}

// RecreateTrieIfNeeded is used to reload the trie based on the provided options if the root hash is different than the current one
func (adb *AccountsDB) RecreateTrieIfNeeded(options common.RootHashHolder) error {
	err := adb.recreateTrieIfNeeded(options)
	if err != nil {
		return err
	}

	adb.mutOp.Lock()
	adb.lastRootHash = options.GetRootHash()
	adb.mutOp.Unlock()

	return nil
}

func (adb *AccountsDB) recreateTrie(options common.RootHashHolder) error {
	log.Trace("accountsDB.RecreateTrie", "root hash holder", options.String())
	defer func() {
		log.Trace("accountsDB.RecreateTrie ended")
	}()

	adb.obsoleteDataTrieHashes = make(map[string][][]byte)
	adb.dataTries.Reset()
	adb.entries = make([]JournalEntry, 0)

	adb.stateAccessesCollector.Reset()
	newTrie, err := adb.mainTrie.Recreate(options)
	if err != nil {
		return err
	}
	if check.IfNil(newTrie) {
		return ErrNilTrie
	}

	adb.mainTrie = newTrie
	adb.protectedChildren = nil
	adb.protectedCommitFailure = nil
	adb.rollbackFailure = nil
	return nil
}

func (adb *AccountsDB) recreateTrieIfNeeded(options common.RootHashHolder) error {
	var mustRecover bool
	if adb.protectedChildRoot != nil {
		adb.mutOp.RLock()
		mustRecover = adb.protectedCommitFailure != nil
		adb.mutOp.RUnlock()
	}
	currentRootHash, err := adb.getMainTrie().RootHash()
	if err != nil && !mustRecover {
		return err
	}

	if !mustRecover && bytes.Equal(currentRootHash, options.GetRootHash()) {
		log.Trace("accountsDB.RecreateTrieIfNeeded - no need to recreate", "root hash", currentRootHash)
		return nil
	}

	adb.mutOp.Lock()
	defer adb.mutOp.Unlock()

	return adb.recreateTrie(options)
}

// RecreateAllTries recreates all the tries from the accounts DB
func (adb *AccountsDB) RecreateAllTries(rootHash []byte) (map[string]common.Trie, error) {
	leavesChannels := &common.TrieIteratorChannels{
		LeavesChan: make(chan core.KeyValueHolder, leavesChannelSize),
		ErrChan:    errChan.NewErrChanWrapper(),
	}
	mainTrie := adb.getMainTrie()
	err := mainTrie.GetAllLeavesOnChannel(
		leavesChannels,
		context.Background(),
		rootHash,
		keyBuilder.NewKeyBuilder(),
		parsers.NewMainTrieLeafParser(),
	)
	if err != nil {
		return nil, err
	}

	allTries, err := adb.recreateMainTrie(rootHash)
	if err != nil {
		return nil, err
	}

	for leaf := range leavesChannels.LeavesChan {
		userAccount, skipAccount, err := getUserAccountFromBytes(adb.accountFactory, adb.marshaller, leaf.Key(), leaf.Value())
		if err != nil {
			return nil, err
		}
		if skipAccount {
			continue
		}

		userAccountRootHash := userAccount.GetRootHash()
		if len(userAccountRootHash) > 0 {
			rootHashHolder := holders.NewDefaultRootHashesHolder(userAccountRootHash)
			dataTrie, errRecreate := mainTrie.Recreate(rootHashHolder)
			if errRecreate != nil {
				return nil, errRecreate
			}

			allTries[string(userAccountRootHash)] = dataTrie
		}
	}

	err = leavesChannels.ErrChan.ReadFromChanNonBlocking()
	if err != nil {
		return nil, err
	}

	if resolve := adb.ProtectedChildResolver(); resolve != nil {
		children, resolveErr := resolve(holders.NewDefaultRootHashesHolder(rootHash))
		if resolveErr != nil {
			return nil, resolveErr
		}
		for _, child := range children {
			if err = child.Verify(); err != nil {
				return nil, err
			}
			if common.IsEmptyTrie(child.root) {
				continue
			}
			childTrie, reopenErr := child.view.Recreate(holders.NewDefaultRootHashesHolder(child.root))
			if reopenErr != nil {
				return nil, reopenErr
			}
			allTries[string(child.root)] = childTrie
		}
	}
	return allTries, nil
}

// ProtectedChildResolver returns the resolver configured on this physical
// AccountsDB. In particular, it does not derive a locator from an epoch.
func (adb *AccountsDB) ProtectedChildResolver() ProtectedChildResolver {
	if adb.protectedCheckpoints == nil {
		return nil
	}
	return func(checkpoint common.RootHashHolder) ([]ProtectedChildReference, error) {
		return adb.resolveProtectedChildren(adb.getMainTrie(), checkpoint)
	}
}

func (adb *AccountsDB) resolveProtectedChildren(main common.Trie, checkpoint common.RootHashHolder) ([]ProtectedChildReference, error) {
	if check.IfNil(checkpoint) || len(checkpoint.GetRootHash()) != adb.hasher.Size() {
		return nil, errProtectedChild
	}
	locators, err := adb.protectedCheckpoints.Locate(holders.NewRootHashHolder(bytes.Clone(checkpoint.GetRootHash()), checkpoint.GetEpoch()))
	if err != nil {
		return nil, err
	}
	if len(locators) > adb.protectedCheckpoints.MaxLocators {
		return nil, errProtectedChild
	}
	if len(locators) == 0 {
		return nil, nil
	}
	view, err := main.Recreate(checkpoint)
	if err != nil {
		return nil, err
	}
	refs := make([]ProtectedChildReference, 0, len(locators))
	for _, locator := range locators {
		root, resolveErr := adb.resolveProtectedChild(view, locator)
		if resolveErr != nil {
			return nil, resolveErr
		}
		refs = append(refs, ProtectedChildReference{root: root, view: view, readNode: adb.protectedCheckpoints.ReadNode,
			hasher: adb.hasher, maxBytes: adb.protectedCheckpoints.MaxBytes})
	}
	return refs, nil
}

func (adb *AccountsDB) resolveProtectedChild(view common.Trie, locator ProtectedChildLocator) ([]byte, error) {
	if len(locator.Address) == 0 || len(locator.Record) == 0 || !bytes.HasPrefix(locator.Key, []byte(core.ProtectedKeyPrefix)) {
		return nil, errProtectedChild
	}
	accountBytes, _, err := view.Get(locator.Address)
	if err != nil {
		return nil, err
	}
	if len(accountBytes) == 0 {
		return nil, errProtectedChild
	}
	account, skip, err := getUserAccountFromBytes(adb.accountFactory, adb.marshaller, locator.Address, accountBytes)
	if err != nil {
		return nil, err
	}
	if skip || common.IsEmptyTrie(account.GetRootHash()) {
		return nil, errProtectedChild
	}
	dataTrie, err := view.Recreate(holders.NewDefaultRootHashesHolder(account.GetRootHash()))
	if err != nil {
		return nil, err
	}
	account.SetDataTrie(dataTrie)
	record, _, err := account.RetrieveValue(locator.Key)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(record, locator.Record) {
		return nil, errProtectedChild
	}
	return adb.decodeProtectedChildRoot(locator.Address, locator.Key, record)
}

func getUserAccountFromBytes(accountFactory AccountFactory, marshaller marshal.Marshalizer, address []byte, accountBytes []byte) (UserAccountHandler, bool, error) {
	account, err := accountFactory.CreateAccount(address)
	if err != nil {
		return nil, true, err
	}

	err = marshaller.Unmarshal(account, accountBytes)
	if err != nil {
		log.Trace("this must be a leaf with code", "err", err)
		return nil, true, nil
	}

	userAccount, ok := account.(UserAccountHandler)
	if !ok {
		return nil, true, nil
	}

	return userAccount, false, nil
}

func (adb *AccountsDB) recreateMainTrie(rootHash []byte) (map[string]common.Trie, error) {
	rootHashHolder := holders.NewDefaultRootHashesHolder(rootHash)
	recreatedTrie, err := adb.getMainTrie().Recreate(rootHashHolder)
	if err != nil {
		return nil, err
	}

	allTries := make(map[string]common.Trie)
	allTries[string(rootHash)] = recreatedTrie

	return allTries, nil
}

// GetTrie returns the trie that has the given rootHash
func (adb *AccountsDB) GetTrie(rootHash []byte) (common.Trie, error) {
	rootHashHolder := holders.NewDefaultRootHashesHolder(rootHash)
	return adb.getMainTrie().Recreate(rootHashHolder)
}

// journalize adds a new object to entries list.
func (adb *AccountsDB) journalize(entry JournalEntry) {
	if check.IfNil(entry) {
		return
	}

	adb.entries = append(adb.entries, entry)
	log.Trace("accountsDB.Journalize",
		"new length", len(adb.entries),
		"entry type", fmt.Sprintf("%T", entry),
	)

	err := adb.stateAccessesCollector.SetIndexToLatestStateAccesses(len(adb.entries))
	if err != nil {
		log.Trace("failed to set index to latest state accesses",
			"num journal entries", len(adb.entries),
			"error", err.Error(),
		)
	}

	if len(adb.entries) == 1 {
		adb.stackDebug = debug.Stack()
	}
}

// GetStackDebugFirstEntry will return the debug.Stack for the first entry from the adb.entries
func (adb *AccountsDB) GetStackDebugFirstEntry() []byte {
	adb.mutOp.RLock()
	defer adb.mutOp.RUnlock()

	return adb.stackDebug
}

// PruneTrie removes old values from the trie database
func (adb *AccountsDB) PruneTrie(rootHash []byte, identifier TriePruningIdentifier, handler PruningHandler) {
	log.Trace("accountsDB.PruneTrie", "root hash", rootHash)

	adb.mutOp.Lock()
	defer adb.mutOp.Unlock()

	if adb.protectedCheckpoints != nil {
		nodes, err := adb.retainedProtectedNodes()
		if err != nil {
			log.Error("protected child retention unavailable", "error", err)
			return
		}
		handler = protectedPruningHandler{PruningHandler: handler, keep: nodes}
	}
	adb.storagePruningManager.PruneTrie(rootHash, identifier, adb.mainTrie.GetStorageManager(), handler)
}

type protectedPruningHandler struct {
	PruningHandler
	keep common.ModifiedHashes
}

func (handler protectedPruningHandler) KeepProtectedTrieNode(hash string) bool {
	_, keep := handler.keep[hash]
	return keep
}

func (adb *AccountsDB) retainedProtectedNodes() (common.ModifiedHashes, error) {
	retention := adb.protectedCheckpoints
	checkpoints, err := retention.Retained()
	if err != nil {
		return nil, err
	}
	if len(checkpoints) == 0 || len(checkpoints) > retention.MaxCheckpoints {
		return nil, errProtectedChild
	}
	required := make(common.ModifiedHashes)
	budget := retention.MaxBytes
	hasCurrent := false
	for _, checkpoint := range checkpoints {
		refs, resolveErr := adb.resolveProtectedChildren(adb.mainTrie, checkpoint)
		if resolveErr != nil {
			return nil, resolveErr
		}
		hasCurrent = hasCurrent || bytes.Equal(adb.lastRootHash, checkpoint.GetRootHash())
		for _, ref := range refs {
			nodes := make(common.ModifiedHashes)
			if err = ref.collectNodes(nodes, &budget); err != nil {
				return nil, err
			}
			for hash := range nodes {
				required[hash] = struct{}{}
			}
		}
	}
	if !hasCurrent {
		return nil, errProtectedChild
	}
	return required, nil
}

// CancelPrune clears the trie's evictionWaitingList
func (adb *AccountsDB) CancelPrune(rootHash []byte, identifier TriePruningIdentifier) {
	log.Trace("accountsDB.CancelPrune", "root hash", rootHash)

	adb.mutOp.Lock()
	defer adb.mutOp.Unlock()

	adb.storagePruningManager.CancelPrune(rootHash, identifier, adb.mainTrie.GetStorageManager())
}

// GetEvictionWaitingListSize returns the number of entries in the eviction waiting list cache
func (adb *AccountsDB) GetEvictionWaitingListSize() int {
	adb.mutOp.RLock()
	defer adb.mutOp.RUnlock()
	return adb.storagePruningManager.EvictionWaitingListCacheLen()
}

// ResetPruning will reset all collected data needed for pruning
func (adb *AccountsDB) ResetPruning() {
	adb.mutOp.Lock()
	defer adb.mutOp.Unlock()

	adb.storagePruningManager.Reset()
}

// SnapshotState triggers the snapshotting process of the state trie
func (adb *AccountsDB) SnapshotState(rootHash []byte, epoch uint32) {
	adb.snapshotsManger.SnapshotState(rootHash, epoch, adb.getMainTrie().GetStorageManager())
}

func (adb *AccountsDB) getTrieStorageManagerAndLatestEpoch(mainTrie common.Trie) (common.StorageManager, uint32, error) {
	trieStorageManager := mainTrie.GetStorageManager()
	epoch, err := trieStorageManager.GetLatestStorageEpoch()
	if err != nil {
		return nil, 0, fmt.Errorf("%w while getting the latest storage epoch", err)
	}

	return trieStorageManager, epoch, nil
}

func emptyErrChanReturningHadContained(errChan chan error) bool {
	contained := false
	for {
		select {
		case <-errChan:
			contained = true
		default:
			return contained
		}
	}
}

// IsPruningEnabled returns true if state pruning is enabled
func (adb *AccountsDB) IsPruningEnabled() bool {
	return adb.pruningEnabled
}

// GetAllLeaves returns all the leaves from a given rootHash
func (adb *AccountsDB) GetAllLeaves(leavesChannels *common.TrieIteratorChannels, ctx context.Context, rootHash []byte, trieLeafParser common.TrieLeafParser) error {
	return adb.getMainTrie().GetAllLeavesOnChannel(leavesChannels, ctx, rootHash, keyBuilder.NewKeyBuilder(), trieLeafParser)
}

// Close will handle the closing of the underlying components
func (adb *AccountsDB) Close() error {
	adb.mutOp.Lock()
	defer adb.mutOp.Unlock()

	_ = adb.mainTrie.Close()
	return adb.storagePruningManager.Close()
}

// GetStatsForRootHash will get trie statistics for the given rootHash
func (adb *AccountsDB) GetStatsForRootHash(rootHash []byte) (common.TriesStatisticsCollector, error) {
	stats := statistics.NewTrieStatisticsCollector()
	mainTrie := adb.getMainTrie()

	tr, ok := mainTrie.(common.TrieStats)
	if !ok {
		return nil, fmt.Errorf("invalid trie, type is %T", mainTrie)
	}

	collectStats(tr, stats, rootHash, "", common.MainTrie)

	iteratorChannels := &common.TrieIteratorChannels{
		LeavesChan: make(chan core.KeyValueHolder, leavesChannelSize),
		ErrChan:    errChan.NewErrChanWrapper(),
	}
	err := mainTrie.GetAllLeavesOnChannel(
		iteratorChannels,
		context.Background(),
		rootHash,
		keyBuilder.NewKeyBuilder(),
		parsers.NewMainTrieLeafParser(),
	)
	if err != nil {
		return nil, err
	}

	for leaf := range iteratorChannels.LeavesChan {
		userAccount, skipAccount, err := getUserAccountFromBytes(adb.accountFactory, adb.marshaller, leaf.Key(), leaf.Value())
		if err != nil {
			return nil, err
		}
		if skipAccount {
			continue
		}

		if common.IsEmptyTrie(userAccount.GetRootHash()) {
			continue
		}

		accountAddress, err := adb.addressConverter.Encode(userAccount.AddressBytes())
		if err != nil {
			return nil, err
		}

		collectStats(tr, stats, userAccount.GetRootHash(), accountAddress, common.DataTrie)
	}

	err = iteratorChannels.ErrChan.ReadFromChanNonBlocking()
	if err != nil {
		return nil, err
	}

	return stats, nil
}

func collectStats(
	tr common.TrieStats,
	stats common.TriesStatisticsCollector,
	rootHash []byte,
	address string,
	trieType common.TrieType,
) {
	trieStats, err := tr.GetTrieStats(address, rootHash)
	if err != nil {
		log.Error(err.Error())
		return
	}
	stats.Add(trieStats, trieType)

	log.Debug(strings.Join(trieStats.ToString(), " "))
}

// SetTxHashForLatestStateAccesses will return the state changes since the last call of this method
func (adb *AccountsDB) SetTxHashForLatestStateAccesses(txHash []byte) {
	adb.stateAccessesCollector.AddTxHashToCollectedStateAccesses(txHash)
}

// IsSnapshotInProgress returns true if there is a snapshot in progress
func (adb *AccountsDB) IsSnapshotInProgress() bool {
	return adb.snapshotsManger.IsSnapshotInProgress()
}

// IsInterfaceNil returns true if there is no value under the interface
func (adb *AccountsDB) IsInterfaceNil() bool {
	return adb == nil
}
