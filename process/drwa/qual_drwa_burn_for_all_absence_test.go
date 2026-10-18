package drwa

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/enablers"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon/epochNotifier"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
)

// Expected model 4117ff54d390452ec650bcdea0165d546ee7f550043fbce718d020a14a152801
// and proposal02 were accepted by owner-directed Claude review before behavior.
// Earlier self-invoked reviews are self-checks only (ledger L43). Literal
// metadata and manually framed L41 records are independent expectations.
// Fixture epochs/shard counts/addresses/bounds are NOT production allocations.
type qualBurnFixture struct {
	b         *BurnForAllAbsence
	w         BurnForAllRegistrationWitness
	count     AccountItemWitness
	members   []BurnForAllMemberWitness
	args      ArgsBurnForAllAbsence
	localArgs ArgsResultAccountReader
	db        *state.AccountsDB
	fault     *qualRegistryMaterializationFault
	id        []byte
}

func qualBurnFixtureFor(t *testing.T, auto bool, family, fault string, prior []byte) *qualBurnFixture {
	t.Helper()
	a := qualReaderArgs(auto)
	source := qualGenesisAccountsFromArgs(t, a)
	u, err := source.LoadAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	account := u.(state.UserAccountHandler)
	_, encoded, digest, intent, v := qualCreationIntent(family)
	id := []byte("TOKEN-abcdef")
	association := [][]byte{id, intent, digest, encoded, bytes.Repeat([]byte{0x22}, 32)}
	consumed := [][]byte{encoded, []byte("CONSUMED"), id}
	activation := [][]byte{id, intent, []byte("BootstrapDeny")}
	switch fault {
	case "association-token":
		association[0] = []byte("OTHER-abcdef")
	case "association-id":
		association[1] = bytes.Repeat([]byte{9}, 32)
	case "association-digest":
		association[2] = bytes.Repeat([]byte{9}, 32)
	case "association-body":
		association[3] = qualRecordFrame([]byte("malformed"))
	case "association-manager":
		association[4] = bytes.Repeat([]byte{9}, 32)
	case "manager-width":
		association[4] = []byte{9}
	case "intent-body":
		consumed[0] = qualRecordFrame([]byte("malformed"))
	case "intent-status":
		consumed[1] = []byte("OPEN")
	case "intent-token":
		consumed[2] = []byte("OTHER-abcdef")
	case "activation":
		activation[2] = []byte("ACTIVE")
	}
	values := map[string][]byte{
		"ELRONDDRWA@registry@count":                        {0, 0, 0, 0, 0, 0, 0, 1},
		"ELRONDDRWA@registry@member@TOKEN-abcdef":          {1},
		"ELRONDDRWA@registration@token@TOKEN-abcdef":       qualRecordFrame(association...),
		"ELRONDDRWA@registration@intent@" + string(intent): qualRecordFrame(consumed...),
		"ELRONDDRWA@registration@activation@TOKEN-abcdef":  qualRecordFrame(activation...),
	}
	if fault == "missing-association" {
		delete(values, "ELRONDDRWA@registration@token@TOKEN-abcdef")
	}
	// Hostile source snapshot: valid registration proofs alone grant no
	// classification authority. This is not a canonical registration outcome.
	if fault == "unclassified-registration" {
		values["ELRONDDRWA@registry@count"] = make([]byte, 8)
		delete(values, "ELRONDDRWA@registry@member@TOKEN-abcdef")
	}
	for k, val := range values {
		require.NoError(t, account.SaveKeyValue([]byte(k), val))
	}
	require.NoError(t, source.SaveAccount(account))
	root, err := source.Commit()
	require.NoError(t, err)
	tr, err := source.GetTrie(root)
	require.NoError(t, err)
	proof := func(key []byte) AccountItemWitness {
		p, _, e := tr.GetProof(core.SystemAccountAddress)
		require.NoError(t, e)
		if fault == "missing-association" && string(key) == "ELRONDDRWA@registration@token@TOKEN-abcdef" {
			return AccountItemWitness{AccountProof: p}
		}
		u, e := source.GetExistingAccount(core.SystemAccountAddress)
		require.NoError(t, e)
		logical := key
		if auto {
			logical = a.Hasher.Compute(string(key))
		}
		d, _, e := u.(state.UserAccountHandler).DataTrie().(common.Trie).GetProof(logical)
		require.NoError(t, e)
		return AccountItemWitness{AccountProof: p, DataProof: d}
	}
	w := BurnForAllRegistrationWitness{Association: proof([]byte("ELRONDDRWA@registration@token@TOKEN-abcdef")),
		Intent: proof(append([]byte("ELRONDDRWA@registration@intent@"), intent...)), Activation: proof([]byte("ELRONDDRWA@registration@activation@TOKEN-abcdef")),
		Profile: v.profile, Name: v.name, Ticker: v.ticker, Decimals: 6}
	count := proof([]byte("ELRONDDRWA@registry@count"))
	var members []BurnForAllMemberWitness
	if fault != "unclassified-registration" {
		members = []BurnForAllMemberWitness{{TokenID: id, Proof: proof([]byte("ELRONDDRWA@registry@member@TOKEN-abcdef"))}}
	}
	budget := 0
	proofs := []AccountItemWitness{count, w.Association, w.Intent, w.Activation}
	for _, member := range members {
		proofs = append(proofs, member.Proof)
	}
	for _, p := range proofs {
		for _, nodes := range [][][]byte{p.AccountProof, p.DataProof} {
			for _, n := range nodes {
				budget += len(n)
			}
		}
	}
	c := qualNativeMetaContext(t)
	c.references = nil
	c.predecessor.LastExecutionResult.ExecutionResult.BaseExecutionResult.RootHash = root
	c.encode(t)
	localArgs := qualReaderArgs(auto)
	db := qualGenesisAccountsFromArgs(t, localArgs)
	s, err := newProtectedState(db)
	require.NoError(t, err)
	require.NoError(t, s.provisionGenesis())
	if len(prior) > 0 {
		u, e := db.GetExistingAccount(core.SystemAccountAddress)
		require.NoError(t, e)
		require.NoError(t, u.(state.UserAccountHandler).SaveKeyValue([]byte("ELRONDesdtTOKEN-abcdef"), prior))
		require.NoError(t, db.SaveAccount(u))
	}
	_, err = db.Commit()
	require.NoError(t, err)
	adapter := &qualRegistryMaterializationFault{AccountsAdapter: db}
	reader, err := NewResultAccountReader(qualReaderArgs(auto))
	require.NoError(t, err)
	flags, err := enablers.NewEnableEpochsHandler(config.EnableEpochs{ESDTMetadataContinuousCleanupEnableEpoch: 5, DynamicESDTEnableEpoch: 7}, &epochNotifier.EpochNotifierStub{})
	require.NoError(t, err)
	args := ArgsBurnForAllAbsence{Accounts: adapter, Reader: reader, Marshaller: a.Marshaller, Hasher: a.Hasher, Validator: c.c.validator,
		EnableEpochsHandler: flags, CandidateHash: c.candidateHash, Candidate: c.candidateBytes, PredecessorHash: c.predecessorHash, Predecessor: c.predecessorBytes,
		MaxEver: 1, ProofByteLimit: budget, RecordByteLimit: 4096}
	b, err := NewBurnForAllAbsence(args)
	require.NoError(t, err)
	return &qualBurnFixture{b, w, count, members, args, localArgs, db, adapter, id}
}

func qualBurnValue(t *testing.T, db state.AccountsAdapter, id []byte) []byte {
	t.Helper()
	a, e := db.GetExistingAccount(core.SystemAccountAddress)
	require.NoError(t, e)
	v, _, e := a.(state.UserAccountHandler).RetrieveValue(append([]byte("ELRONDesdt"), id...))
	require.NoError(t, e)
	return v
}
func qualBurnInput(id []byte, function string) *vmcommon.ContractCallInput {
	return &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: bytes.Clone(core.ESDTSCAddress), CallValue: big.NewInt(0), Arguments: [][]byte{bytes.Clone(id)}, GasProvided: 100}, RecipientAddr: bytes.Clone(core.SystemAccountAddress), Function: function}
}
func qualBurnPrepare(t *testing.T, f *qualBurnFixture) {
	t.Helper()
	require.NoError(t, f.b.Prepare(context.Background(), f.count, f.members))
}

func TestQualDRWARegistryRegistrationBurnForAllNativeVectors(t *testing.T) {
	vectors := []struct {
		family        string
		before, after []byte
	}{
		{core.FungibleESDT, nil, []byte{0, 0}},
		{core.FungibleESDT, []byte{4, 0}, []byte{0, 0}},
		{core.FungibleESDT, []byte{5, 1}, []byte{1, 1}},
		{core.NonFungibleESDTv2, []byte{6, 3}, []byte{2, 3}},
		{core.DynamicMetaESDT, []byte{7, 8}, []byte{3, 8}},
		{core.DynamicNFTESDT, []byte{3, 6}, []byte{3, 6}},
	}
	for _, auto := range []bool{false, true} {
		for i, v := range vectors {
			t.Run(fmt.Sprintf("auto_%t/vector_%d", auto, i), func(t *testing.T) {
				f := qualBurnFixtureFor(t, auto, v.family, "", v.before)
				qualBurnPrepare(t, f)
				require.False(t, f.b.protected.IsActive())
				require.False(t, f.b.unset.IsActive(), "actual native SendAlways is off")
				require.NoError(t, f.b.Normalize(f.id, f.w))
				require.Equal(t, v.after, qualBurnValue(t, f.db, f.id))
				require.False(t, f.b.metadata.IsBurnForAll([]byte("ELRONDesdtTOKEN-abcdef")))
				require.False(t, f.b.protected.IsActive())
				for _, epoch := range []uint32{4, 5, 6} {
					f.args.EnableEpochsHandler.(vmcommon.EpochSubscriberHandler).EpochConfirmed(epoch, 0)
					require.Equal(t, epoch >= 5, f.args.EnableEpochsHandler.IsFlagEnabled(common.ESDTMetadataContinuousCleanupFlag))
					require.Equal(t, epoch >= 5, f.b.set.IsActive())
					for _, function := range []string{vmcommon.BuiltInFunctionESDTSetBurnRoleForAll, vmcommon.BuiltInFunctionESDTUnSetBurnRoleForAll, vmcommon.BuiltInFunctionESDTSetBurnRoleForAll} {
						out, e := f.b.ProcessBuiltinFunction(qualBurnInput(f.id, function))
						require.Error(t, e)
						require.Nil(t, out)
						require.Equal(t, v.after, qualBurnValue(t, f.db, f.id))
					}
				}
				require.NoError(t, f.b.Normalize(f.id, f.w))
				roots, _, e := f.b.Commit()
				require.NoError(t, e)
				require.Error(t, f.b.Normalize(f.id, f.w))
				_, e = f.b.ProcessBuiltinFunction(qualBurnInput(f.id, vmcommon.BuiltInFunctionESDTSetBurnRoleForAll))
				require.Error(t, e)
				// Recreate concrete native AccountsDB/trie from retained storage and roots.
				reopened := qualGenesisAccountsFromArgs(t, f.localArgs)
				require.NoError(t, reopened.RecreateTrie(holders.NewDefaultRootHashesHolder(roots[0])))
				f.args.Accounts = reopened
				f.b, e = NewBurnForAllAbsence(f.args)
				require.NoError(t, e)
				qualBurnPrepare(t, f)
				_, e = f.b.ProcessBuiltinFunction(qualBurnInput(f.id, vmcommon.BuiltInFunctionESDTSetBurnRoleForAll))
				require.Error(t, e)
				require.Equal(t, v.after, qualBurnValue(t, reopened, f.id))
				require.NoError(t, f.b.Normalize(f.id, f.w))
			})
		}
	}
}

func TestQualDRWARegistryRegistrationBurnForAllProofDenials(t *testing.T) {
	faults := []string{"association-token", "association-id", "association-digest", "association-body", "association-manager", "manager-width", "intent-body", "intent-status", "intent-token", "activation", "missing-association",
		"profile", "network", "family", "manager", "property", "name", "ticker", "decimals", "account-proof", "data-proof", "proof-budget", "record-budget", "header-in-proof", "ordinary", "malformed-metadata", "reserved-metadata", "wrong-type"}
	for _, auto := range []bool{false, true} {
		for _, fault := range faults {
			t.Run(fmt.Sprintf("auto_%t/%s", auto, fault), func(t *testing.T) {
				prior := []byte{4, 0}
				if fault == "malformed-metadata" {
					prior = []byte{4}
				}
				if fault == "reserved-metadata" {
					prior = []byte{0x84, 0}
				}
				if fault == "wrong-type" {
					prior = []byte{4, 8}
				}
				f := qualBurnFixtureFor(t, auto, core.FungibleESDT, fault, prior)
				qualBurnPrepare(t, f)
				switch fault {
				case "profile":
					f.w.Profile[0] ^= 1
				case "network", "family", "manager", "property":
					fields := qualCreationProfileFields(core.FungibleESDT)
					i := map[string]int{"network": 1, "family": 3, "manager": 2, "property": 4}[fault]
					fields[i] = []byte("wrong")
					f.w.Profile = qualRecordFrame(fields...)
				case "name":
					f.w.Name = []byte("OtherToken")
				case "ticker":
					f.w.Ticker = []byte("OTHER")
				case "decimals":
					f.w.Decimals++
				case "account-proof":
					f.w.Association.AccountProof[0][0] ^= 1
				case "data-proof":
					f.w.Intent.DataProof[0][0] ^= 1
				case "proof-budget":
					n := 0
					for _, w := range []AccountItemWitness{f.w.Association, f.w.Intent, f.w.Activation} {
						for _, nodes := range [][][]byte{w.AccountProof, w.DataProof} {
							for _, v := range nodes {
								n += len(v)
							}
						}
					}
					f.b.transport.proofByteLimit = n - 1
				case "record-budget":
					f.w.Name = bytes.Repeat([]byte{1}, 4097)
				case "header-in-proof":
					f.w.Association.Header = []byte("forged")
				case "ordinary":
					f.id = []byte("OTHER-abcdef")
				}
				before, e := f.db.RootHash()
				require.NoError(t, e)
				n := f.db.JournalLen()
				require.Error(t, f.b.Normalize(f.id, f.w))
				after, e := f.db.RootHash()
				require.NoError(t, e)
				require.Equal(t, before, after)
				require.Equal(t, n, f.db.JournalLen())
				require.Equal(t, prior, qualBurnValue(t, f.db, []byte("TOKEN-abcdef")))
			})
		}
	}
}

func TestQualDRWARegistryRegistrationBurnForAllLifecycle(t *testing.T) {
	for _, fault := range []string{"unprepared", "partial", "cancelled", "save", "rollback", "abort", "abort-failure", "wrong-context"} {
		t.Run(fault, func(t *testing.T) {
			f := qualBurnFixtureFor(t, false, core.FungibleESDT, "", []byte{4, 0})
			if fault == "wrong-context" {
				f.args.CandidateHash = bytes.Clone(f.args.CandidateHash)
				f.args.CandidateHash[0] ^= 1
				b, e := NewBurnForAllAbsence(f.args)
				require.Error(t, e)
				require.Nil(t, b)
				return
			}
			if fault == "unprepared" {
				require.Error(t, f.b.Normalize(f.id, f.w))
				_, e := f.b.ProcessBuiltinFunction(qualBurnInput([]byte("OTHER-abcdef"), vmcommon.BuiltInFunctionESDTSetBurnRoleForAll))
				require.Error(t, e)
				return
			}
			if fault == "partial" {
				require.Error(t, f.b.Prepare(context.Background(), f.count, nil))
				require.Error(t, f.b.Normalize(f.id, f.w))
				return
			}
			if fault == "cancelled" {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				require.Error(t, f.b.Prepare(ctx, f.count, f.members))
				return
			}
			qualBurnPrepare(t, f)
			before, e := f.db.RootHash()
			require.NoError(t, e)
			saveFault := errors.New("native false save failed after mutation")
			rollbackFault := errors.New("native undo failed after undo")
			if fault == "save" || fault == "rollback" {
				f.fault.saveAt = f.fault.saves + 1
				f.fault.saveError = saveFault
				if fault == "rollback" {
					f.fault.rollbackError = rollbackFault
				}
				require.ErrorIs(t, f.b.Normalize(f.id, f.w), saveFault)
				after, e := f.db.RootHash()
				require.NoError(t, e)
				require.Equal(t, before, after)
				require.Equal(t, []byte{4, 0}, qualBurnValue(t, f.db, f.id))
				if fault == "rollback" {
					_, _, e = f.b.Commit()
					require.ErrorIs(t, e, rollbackFault)
					require.Error(t, f.b.Normalize(f.id, f.w))
					require.NoError(t, f.b.Recover())
					require.Error(t, f.b.Normalize(f.id, f.w))
				} else {
					f.fault.saveAt = 0
					require.NoError(t, f.b.Normalize(f.id, f.w))
				}
				return
			}
			require.NoError(t, f.b.Normalize(f.id, f.w))
			if fault == "abort-failure" {
				f.fault.rollbackError = rollbackFault
				require.ErrorIs(t, f.b.Abort(), rollbackFault)
			} else {
				require.NoError(t, f.b.Abort())
			}
			require.Error(t, f.b.Normalize(f.id, f.w))
			require.Equal(t, []byte{4, 0}, qualBurnValue(t, f.db, f.id))
		})
	}
}

func TestQualDRWARegistryRegistrationBurnForAllOrdinaryAndConcurrent(t *testing.T) {
	f := qualBurnFixtureFor(t, false, core.FungibleESDT, "", nil)
	qualBurnPrepare(t, f)
	require.NoError(t, f.b.Normalize(f.id, f.w))
	ordinary := []byte("OTHER-abcdef")
	control := qualGenesisAccounts(t, false)
	a, e := control.LoadAccount(core.SystemAccountAddress)
	require.NoError(t, e)
	require.NoError(t, a.(state.UserAccountHandler).SaveKeyValue([]byte("sentinel"), []byte{1}))
	require.NoError(t, control.SaveAccount(a))
	_, e = control.Commit()
	require.NoError(t, e)
	for _, epoch := range []uint32{4, 5, 6} {
		f.args.EnableEpochsHandler.(vmcommon.EpochSubscriberHandler).EpochConfirmed(epoch, 0)
		for _, function := range []string{vmcommon.BuiltInFunctionESDTSetBurnRoleForAll, vmcommon.BuiltInFunctionESDTUnSetBurnRoleForAll, vmcommon.BuiltInFunctionESDTSetBurnRoleForAll} {
			native, e := builtInFunctions.NewESDTGlobalSettingsFunc(control, f.args.Marshaller, function == vmcommon.BuiltInFunctionESDTSetBurnRoleForAll, function, func() bool { return f.args.EnableEpochsHandler.IsFlagEnabled(common.SendAlwaysFlag) })
			require.NoError(t, e)
			for _, value := range []int64{0, 1, -1} {
				for _, arity := range []int{1, 0, 2} {
					for _, wrong := range []string{"", "caller", "recipient"} {
						input := qualBurnInput(ordinary, function)
						input.CallValue = big.NewInt(value)
						if arity == 0 {
							input.Arguments = nil
						}
						if arity == 2 {
							input.Arguments = append(input.Arguments, []byte{1})
						}
						if wrong == "caller" {
							input.CallerAddr = []byte("forged")
						}
						if wrong == "recipient" {
							input.RecipientAddr = []byte("wrong")
						}
						before, e := f.db.RootHash()
						require.NoError(t, e)
						controlBefore, e := control.RootHash()
						require.NoError(t, e)
						want, we := native.ProcessBuiltinFunction(nil, nil, input)
						got, ge := f.b.ProcessBuiltinFunction(input)
						require.Equal(t, we, ge, "epoch=%d function=%s value=%d arity=%d wrong=%s", epoch, function, value, arity, wrong)
						require.Equal(t, want, got)
						require.Equal(t, qualBurnValue(t, control, ordinary), qualBurnValue(t, f.db, ordinary))
						if value != 0 {
							require.ErrorIs(t, we, builtInFunctions.ErrBuiltInFunctionCalledWithValue)
						} else if arity != 1 {
							require.ErrorIs(t, we, builtInFunctions.ErrInvalidArguments)
						}
						if we != nil {
							after, e := f.db.RootHash()
							require.NoError(t, e)
							require.Equal(t, before, after)
							controlAfter, e := control.RootHash()
							require.NoError(t, e)
							require.Equal(t, controlBefore, controlAfter)
						}
					}
				}
			}
		}
	}
	// The independent native control ends true after UNSET then SET.
	require.Equal(t, []byte{4, 0}, qualBurnValue(t, control, ordinary))
	require.Equal(t, []byte{0, 0}, qualBurnValue(t, f.db, f.id))
	var wg sync.WaitGroup
	results := make(chan [2]error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			normalizeErr := f.b.Normalize(f.id, f.w)
			_, toggleErr := f.b.ProcessBuiltinFunction(qualBurnInput(f.id, vmcommon.BuiltInFunctionESDTSetBurnRoleForAll))
			results <- [2]error{normalizeErr, toggleErr}
		}()
	}
	wg.Wait()
	close(results)
	for result := range results {
		require.NoError(t, result[0])
		require.Error(t, result[1])
	}
	require.Equal(t, []byte{0, 0}, qualBurnValue(t, f.db, f.id))
}
