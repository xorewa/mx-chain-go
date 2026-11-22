package drwa

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/trie"
	"github.com/multiversx/mx-chain-go/vm"
	"github.com/stretchr/testify/require"
	"sync"
	"testing"
)

// Synthetic A/C groups and appointment only. Existing independently framed
// literal is copied unchanged from qual_drwa_authority_set_version_test.go;
// its retained chronology/provenance limitations remain. No native authority.
const qualStageAG6 = "0a2d445257412f494e495449414c5f50524f4752414d4d455f4150504f494e544d454e542f63616e646964617465310a2001010101010101010101010101010101010101010101010101010101010101010a0770726f6772616d0add020a25445257412f415554484f524954595f5345545f56455253494f4e2f63616e646964617465310a2041414141414141414141414141414141414141414141414141414141414141410a0800000000000000000a0e454432353531395f4d5f4f465f4e0a0800000000000000030aaa010a208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c0a208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3940a20ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d10a20ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c0a206e7a1cdd29b0b78fd13af4c5598feff4ef2a97166e3ca6f2e4fbfccd80505bf10a3d0a1061646d697373696f6e006f70617175650a2001010101010101010101010101010101010101010101010101010101010101010a0770726f6772616d0a000a000ada020a25445257412f415554484f524954595f5345545f56455253494f4e2f63616e646964617465310a2042424242424242424242424242424242424242424242424242424242424242420a0800000000000000010a0e454432353531395f4d5f4f465f4e0a0800000000000000030aaa010a20d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c97787370a20204040e364c10f2bec9c1fe500a1cd4c247c89d650a01ed7e82caba867877c210a2066cd608b928b88e50e0efeaa33faf1c43cefe07294b0b87e9fe0aba6a3cf76330a2020828bf5c5bdcacb684863336c202fb5599da48be5596615742170705beca9f70a20d54207da194977dcf46adbfec2bc2e75b52d5a8a42184fedfdc00024f0e3e8da0a3a0a0d696e646570656e64656e74c3a90a2001010101010101010101010101010101010101010101010101010101010101010a0770726f6772616d0a000a000a20abababababababababababababababababababababababababababababababab"

func qualStageALimits() *InitialProgrammeLimits {
	return &InitialProgrammeLimits{Files: 2, FileBytes: 4096, AggregateBytes: 8192, RecordBytes: 4096, FieldBytes: 2048, RoleBytes: 64, Members: 10, Records: 100, RetainedBytes: 65536, NewRecordsPerEpoch: 100, AdmissionRole: []byte("admission\x00opaque"), IndependentRole: []byte("independent\xc3\xa9")}
}
func qualStageARaw(t *testing.T) []byte {
	t.Helper()
	b, e := hex.DecodeString(qualStageAG6)
	require.NoError(t, e)
	return b
}

func qualStageAData(t *testing.T) ([]InitialProgrammeEvidence, *InitialProgrammeLimits) {
	t.Helper()
	l := qualStageALimits()
	e, err := DecodeInitialProgrammeEvidence(qualStageARaw(t), "synthetic", "integrity-only", l, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b())
	require.NoError(t, err)
	return []InitialProgrammeEvidence{e}, l
}

// Independent literal field-1 framing for owner/programme, not codec.frame.
func qualStageAKey() []byte {
	return append(append([]byte("ELRONDDRWA@scopedAdmission@initial@\x0a\x20"), bytes.Repeat([]byte{1}, 32)...), []byte("\x0a\x07program")...)
}
func qualStageASize(raw []byte) uint64 {
	return uint64(len("ELRONDDRWA@registry@count") + 8 + len("ELRONDDRWA@membershipIndex@count") + 8 + len("ELRONDDRWA@scopedAdmission@budget") + 32 + len(qualStageAKey()) + len(raw))
}
func TestQualDRWAInitialProgrammeState(t *testing.T) {
	t.Run("nil_is_no_op_without_store_or_limits", func(t *testing.T) { require.NoError(t, InitializeProgrammeGenesis(nil, nil, nil, nil, nil, 17)) })
	t.Run("exact_records_budget_original_commit_and_reopen", func(t *testing.T) {
		args := qualReaderArgs(false)
		db := qualGenesisAccountsFromArgs(t, args)
		input, l := qualStageAData(t)
		raw := bytes.Clone(input[0].raw)
		size := qualStageASize(raw)
		l.Records = 4
		l.NewRecordsPerEpoch = 4
		l.RetainedBytes = size
		require.NoError(t, InitializeProgrammeGenesis(db, input, l, args.Marshaller, args.Hasher, 17))
		require.Positive(t, db.JournalLen())
		a, e := db.GetExistingAccount(core.SystemAccountAddress)
		require.NoError(t, e)
		u := a.(state.UserAccountHandler)
		for _, key := range []string{"ELRONDDRWA@registry@count", "ELRONDDRWA@membershipIndex@count"} {
			v, _, e := u.RetrieveValue([]byte(key))
			require.NoError(t, e)
			require.Equal(t, make([]byte, 8), v)
		}
		v, _, e := u.RetrieveValue(qualStageAKey())
		require.NoError(t, e)
		require.Equal(t, raw, v)
		want := make([]byte, 32)
		binary.BigEndian.PutUint64(want, 4)
		binary.BigEndian.PutUint64(want[8:], size)
		binary.BigEndian.PutUint64(want[16:], 17)
		binary.BigEndian.PutUint64(want[24:], 4)
		v, _, e = u.RetrieveValue([]byte("ELRONDDRWA@scopedAdmission@budget"))
		require.NoError(t, e)
		require.Equal(t, want, v)
		root, e := db.Commit()
		require.NoError(t, e)
		reopened := qualGenesisAccountsFromArgs(t, args)
		require.NoError(t, reopened.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
		a, e = reopened.GetExistingAccount(core.SystemAccountAddress)
		require.NoError(t, e)
		v, _, e = a.(state.UserAccountHandler).RetrieveValue(qualStageAKey())
		require.NoError(t, e)
		require.Equal(t, raw, v)
		require.ErrorIs(t, InitializeProgrammeGenesis(db, input, l, args.Marshaller, args.Hasher, 17), errInvalidGenesisState)
	})

	m := &marshal.GogoProtoMarshalizer{}
	h := blake2b.NewBlake2b()
	t.Run("nil_no_store", func(t *testing.T) { require.NoError(t, InitializeProgrammeGenesis(nil, nil, nil, nil, nil, 17)) })
	for _, auto := range []bool{false, true} {
		t.Run(fmt.Sprint(auto), func(t *testing.T) {
			db := qualGenesisAccounts(t, auto)
			input, l := qualStageAData(t)
			raw := qualStageARaw(t)
			l.Records = 4
			l.RetainedBytes = qualStageASize(raw)
			l.NewRecordsPerEpoch = 4
			require.NoError(t, InitializeProgrammeGenesis(db, input, l, m, h, 17))
			a, err := db.GetExistingAccount(core.SystemAccountAddress)
			require.NoError(t, err)
			u := a.(state.UserAccountHandler)
			actual, _, err := u.RetrieveValue(qualStageAKey())
			require.NoError(t, err)
			require.Equal(t, raw, actual)
			budget, _, err := u.RetrieveValue([]byte("ELRONDDRWA@scopedAdmission@budget"))
			require.NoError(t, err)
			want := make([]byte, 32)
			binary.BigEndian.PutUint64(want, 4)
			binary.BigEndian.PutUint64(want[8:], qualStageASize(raw))
			binary.BigEndian.PutUint64(want[16:], 17)
			binary.BigEndian.PutUint64(want[24:], 4)
			require.Equal(t, want, budget)
			for _, key := range []string{"ELRONDDRWA@registry@count", "ELRONDDRWA@membershipIndex@count"} {
				v, _, e := u.RetrieveValue([]byte(key))
				require.NoError(t, e)
				require.Equal(t, make([]byte, 8), v)
			}
			require.ErrorIs(t, InitializeProgrammeGenesis(db, input, l, m, h, 17), ErrUncommittedState)
			root, err := db.Commit()
			require.NoError(t, err)
			require.NoError(t, db.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
			require.ErrorIs(t, InitializeProgrammeGenesis(db, input, l, m, h, 17), errInvalidGenesisState)
		})
	}
	for _, name := range []string{"missing", "count", "bytes", "rate", "duplicate", "malformed", "aggregate", "role"} {
		t.Run(name, func(t *testing.T) {
			db := qualGenesisAccounts(t, false)
			input, l := qualStageAData(t)
			before, err := db.RootHash()
			require.NoError(t, err)
			switch name {
			case "missing":
				l = nil
			case "count":
				l.Records = 3
			case "bytes":
				l.RetainedBytes = qualStageASize(input[0].raw) - 1
			case "rate":
				l.NewRecordsPerEpoch = 3
			case "duplicate":
				input = append(input, input[0])
			case "malformed":
				input[0].raw = []byte("not G6")
			case "aggregate":
				l.AggregateBytes = l.FileBytes
				input = append(input, input[0])
				input[0].raw = bytes.Repeat([]byte{1}, 4096)
			case "role":
				l.AdmissionRole = []byte("wrong")
			}
			require.Error(t, InitializeProgrammeGenesis(db, input, l, m, h, 17))
			after, e := db.RootHash()
			require.NoError(t, e)
			require.Equal(t, before, after)
			require.Zero(t, db.JournalLen())
		})
	}
	// Every native SaveKeyValue and both SaveAccount calls may fail AFTER
	// mutation. The original journal must remove the entire prefix.
	for fail := 1; fail <= 6; fail++ {
		t.Run(fmt.Sprintf("write_%d", fail), func(t *testing.T) {
			db := qualGenesisAccounts(t, false)
			input, l := qualStageAData(t)
			fault := errors.New("synthetic late save fault")
			calls := 0
			a := &qualStageAFault{AccountsAdapter: db, calls: &calls, fail: fail, fault: fault}
			before, e := db.RootHash()
			require.NoError(t, e)
			require.ErrorIs(t, InitializeProgrammeGenesis(a, input, l, m, h, 17), fault)
			after, e := db.RootHash()
			require.NoError(t, e)
			require.Equal(t, before, after)
			require.Zero(t, db.JournalLen())
			_, e = db.GetExistingAccount(core.SystemAccountAddress)
			require.ErrorIs(t, e, state.ErrAccNotFound)
		})
	}
}

// Synthetic original-header coordinates and appointment groups only. The
// literal G6/key and independent identity framing retain their earlier limits;
// this fixture is not a canonical genesis, authority or proof-service admission.
type qualD20InitialProofFixture struct {
	db                *state.AccountsDB
	identity          *DeploymentIdentity
	witness           AccountItemWitness
	domain, root, raw []byte
	budget            int
}

func qualD20CopyInitialWitness(w AccountItemWitness) AccountItemWitness {
	copyNodes := func(input [][]byte) [][]byte {
		output := make([][]byte, len(input))
		for i, v := range input {
			output[i] = bytes.Clone(v)
		}
		return output
	}
	return AccountItemWitness{Header: bytes.Clone(w.Header), ExecutedHeader: bytes.Clone(w.ExecutedHeader),
		AccountProof: copyNodes(w.AccountProof), DataProof: copyNodes(w.DataProof)}
}

func qualD20InitialProof(t *testing.T, auto bool) *qualD20InitialProofFixture {
	t.Helper()
	args := qualReaderArgs(auto)
	db := qualGenesisAccountsFromArgs(t, args)
	raw, key := qualStageARaw(t), qualStageAKey()
	a, err := db.LoadAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	u := a.(state.UserAccountHandler)
	// Seed the independently retained literal directly through native storage;
	// neither the initializer nor the reader generates the expected G6/key.
	require.NoError(t, u.SaveKeyValue(key, raw))
	require.NoError(t, db.SaveAccount(u))
	root, err := db.Commit()
	require.NoError(t, err)
	producer, err := trie.NewTrie(args.StorageManager, args.Marshaller, args.Hasher, args.EnableEpochsHandler, 5)
	require.NoError(t, err)
	main, err := producer.Recreate(holders.NewDefaultRootHashesHolder(root))
	require.NoError(t, err)
	accountProof, _, err := main.GetProof(core.SystemAccountAddress)
	require.NoError(t, err)
	a, err = db.GetExistingAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	proofKey := key
	if auto {
		proofKey = args.Hasher.Compute(string(key))
	}
	dataProof, _, err := a.(state.UserAccountHandler).DataTrie().(common.Trie).GetProof(proofKey)
	require.NoError(t, err)
	fields, bounds := qualA72IdentityInput(t)
	fields[3], err = args.Marshaller.Marshal(&block.MetaBlock{Epoch: 17, RootHash: root})
	require.NoError(t, err)
	fields[4] = args.Hasher.Compute(string(fields[3]))
	preimage := append(append([]byte("DRWA/NETWORK/v1"), fields[1]...), fields[4]...)
	fields[5] = args.Hasher.Compute(string(preimage))
	encoded := qualRecordFrame(fields...)
	pin := sha256.Sum256(encoded)
	identity, err := qualA72DecodeIdentity(encoded, pin[:], fields[1], 17, bounds)
	require.NoError(t, err)
	witness := qualD20CopyInitialWitness(AccountItemWitness{AccountProof: accountProof, DataProof: dataProof})
	budget := 0
	for _, nodes := range [][][]byte{witness.AccountProof, witness.DataProof} {
		for _, node := range nodes {
			budget += len(node)
		}
	}
	return &qualD20InitialProofFixture{db: db, identity: identity, witness: witness,
		domain: bytes.Clone(fields[5]), root: bytes.Clone(root), raw: bytes.Clone(raw), budget: budget}
}

type qualD20ProofPutFailure struct {
	common.StorageManager
	failure error
}

func (s *qualD20ProofPutFailure) Put([]byte, []byte) error { return s.failure }

func TestQualD20OriginalInitialProgrammeProof(t *testing.T) {
	for _, auto := range []bool{false, true} {
		t.Run(fmt.Sprint(auto), func(t *testing.T) {
			f := qualD20InitialProof(t, auto)
			owner, programme := bytes.Repeat([]byte{1}, 32), []byte("program")
			valid := func(reader *ResultAccountReader) {
				got, err := reader.readInitialProgrammeItem(f.identity, f.domain, owner, programme,
					qualD20CopyInitialWitness(f.witness), f.budget, qualStageALimits().RecordBytes)
				require.NoError(t, err)
				require.Equal(t, f.raw, got)
			}
			faults := []string{"nil_reader", "zero_reader", "missing_identity", "wrong_domain", "wrong_chain",
				"wrong_genesis_hash", "changed_header", "wrong_epoch", "parallel_header", "parallel_executed_header",
				"wrong_owner", "wrong_programme", "missing_account_proof", "missing_data_proof",
				"bad_account_proof", "bad_data_proof", "proof_budget_minus_one", "body_budget_minus_one",
				"zero_proof_bound", "zero_record_bound", "proof_cache_put_error"}
			for _, fault := range faults {
				t.Run(fault, func(t *testing.T) {
					reader, err := NewResultAccountReader(qualReaderArgs(auto))
					require.NoError(t, err)
					valid(reader)
					selected := reader
					identity := *f.identity
					selectedIdentity := &identity
					domain, scopeOwner, scopeProgramme := bytes.Clone(f.domain), bytes.Clone(owner), bytes.Clone(programme)
					witness := qualD20CopyInitialWitness(f.witness)
					proofLimit, recordLimit := f.budget, qualStageALimits().RecordBytes
					expected := ErrInvalidAccountWitness
					restore := func() {}
					switch fault {
					case "nil_reader":
						selected = nil
						expected = vm.ErrDRWAExecution
					case "zero_reader":
						selected = &ResultAccountReader{}
						expected = vm.ErrDRWAExecution
					case "missing_identity":
						selectedIdentity = nil
						expected = ErrDeploymentIdentity
					case "wrong_domain":
						domain[0] ^= 1
						expected = ErrDeploymentIdentity
					case "wrong_chain":
						identity.chainID = bytes.Clone(identity.chainID)
						identity.chainID[0] ^= 1
						expected = ErrDeploymentIdentity
					case "wrong_genesis_hash":
						identity.genesisHash = bytes.Clone(identity.genesisHash)
						identity.genesisHash[0] ^= 1
						expected = ErrDeploymentIdentity
					case "changed_header":
						identity.header = bytes.Clone(identity.header)
						identity.header[len(identity.header)-1] ^= 1
						expected = ErrDeploymentIdentity
					case "wrong_epoch":
						identity.epoch++
						expected = ErrDeploymentIdentity
					case "parallel_header":
						witness.Header = []byte("untrusted parallel header")
					case "parallel_executed_header":
						witness.ExecutedHeader = []byte("untrusted parallel execution header")
					case "wrong_owner":
						scopeOwner[0] ^= 1
					case "wrong_programme":
						scopeProgramme = []byte("other programme")
					case "missing_account_proof":
						witness.AccountProof = nil
					case "missing_data_proof":
						witness.DataProof = nil
					case "bad_account_proof":
						witness.AccountProof[0][len(witness.AccountProof[0])-1] ^= 1
					case "bad_data_proof":
						witness.DataProof[0][len(witness.DataProof[0])-1] ^= 1
					case "proof_budget_minus_one":
						proofLimit--
					case "body_budget_minus_one":
						recordLimit = len(f.raw) - 1
					case "zero_proof_bound":
						proofLimit = 0
						expected = ErrInitialProgrammeLimits
					case "zero_record_bound":
						recordLimit = 0
						expected = ErrInitialProgrammeLimits
					case "proof_cache_put_error":
						failure := errors.New("synthetic dedicated proof-cache put failure")
						original := reader.args.StorageManager
						reader.args.StorageManager = &qualD20ProofPutFailure{StorageManager: original, failure: failure}
						restore = func() { reader.args.StorageManager = original }
						expected = failure
					}
					before, err := f.db.RootHash()
					require.NoError(t, err)
					journal := f.db.JournalLen()
					got, err := selected.readInitialProgrammeItem(selectedIdentity, domain, scopeOwner, scopeProgramme,
						witness, proofLimit, recordLimit)
					restore()
					require.ErrorIs(t, err, expected)
					require.Nil(t, got)
					valid(reader)
					after, err := f.db.RootHash()
					require.NoError(t, err)
					require.Equal(t, before, after)
					require.Equal(t, journal, f.db.JournalLen())
				})
			}
		})
	}
}

func TestQualD20OriginalInitialProgrammeReadIsolation(t *testing.T) {
	for _, auto := range []bool{false, true} {
		t.Run(fmt.Sprint(auto), func(t *testing.T) {
			f := qualD20InitialProof(t, auto)
			owner, programme := bytes.Repeat([]byte{1}, 32), []byte("program")
			reader, err := NewResultAccountReader(qualReaderArgs(auto))
			require.NoError(t, err)
			read := func(r *ResultAccountReader) []byte {
				got, e := r.readInitialProgrammeItem(f.identity, f.domain, owner, programme,
					f.witness, f.budget, qualStageALimits().RecordBytes)
				require.NoError(t, e)
				require.Equal(t, f.raw, got)
				return got
			}
			returned := read(reader)
			returned[0] ^= 1
			read(reader)
			// Deliberately bypass DRWA's writer guard in this native fixture.
			// This distinguishes original supplied proof from current local data;
			// it proves neither lawful replacement nor production pruning/restart.
			a, err := f.db.GetExistingAccount(core.SystemAccountAddress)
			require.NoError(t, err)
			u := a.(state.UserAccountHandler)
			require.NoError(t, u.SaveKeyValue(qualStageAKey(), []byte("synthetic changed current value")))
			require.NoError(t, f.db.SaveAccount(u))
			current, err := f.db.Commit()
			require.NoError(t, err)
			require.NotEqual(t, f.root, current)
			rebuilt, err := NewResultAccountReader(qualReaderArgs(auto))
			require.NoError(t, err)
			read(rebuilt)
			shard := qualNativeReaderFixture(t, auto, 1)
			var workers sync.WaitGroup
			failures := make(chan error, 8)
			for worker := 0; worker < 8; worker++ {
				workers.Add(1)
				go func() {
					defer workers.Done()
					for iteration := 0; iteration < 16; iteration++ {
						got, e := reader.readInitialProgrammeItem(f.identity, f.domain, owner, programme,
							f.witness, f.budget, qualStageALimits().RecordBytes)
						if e != nil || !bytes.Equal(got, f.raw) {
							failures <- fmt.Errorf("original-item read: %v", e)
							return
						}
						got, e = reader.Read(shard.anchor, 1, shard.address, shard.key, shard.w, shard.budget)
						if e != nil || !bytes.Equal(got, shard.expected) {
							failures <- fmt.Errorf("existing result-item read: %v", e)
							return
						}
					}
				}()
			}
			workers.Wait()
			close(failures)
			for e := range failures {
				require.NoError(t, e)
			}
			after, err := f.db.RootHash()
			require.NoError(t, err)
			require.Equal(t, current, after)
			require.Zero(t, f.db.JournalLen())
		})
	}
}
