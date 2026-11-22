package drwa

import (
	"bytes"
	"encoding/binary"
	"math"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// InitializeProgrammeGenesis stages DATA in the original fresh-genesis Accounts
// adapter before any other mutation. The caller alone owns native Commit and
// header publication; this function never commits or installs current authority.
// Import/live/startup repair is forbidden. An empty trie is a necessary state
// check, not proof of lawful fresh-genesis ownership or appointment.
func InitializeProgrammeGenesis(accounts state.AccountsAdapter, input []InitialProgrammeEvidence,
	limits *InitialProgrammeLimits, marshaller marshal.Marshalizer, hasher hashing.Hasher, epoch uint32) error {
	if len(input) == 0 {
		return nil
	}
	stage, err := PrepareInitialProgrammeGenesis(accounts, input, limits, nil, marshaller, hasher, epoch)
	if err != nil {
		return err
	}
	boundary, err := NewRollbackContainment(accounts)
	if err != nil {
		return err
	}
	return boundary.Execute(func() (*vmcommon.VMOutput, error) {
		return nil, stage()
	})
}

func initialProgrammeMinimum(input config.DRWAMinimumGenesis) minimumGenesis {
	return minimumGenesis{
		profileDigest:      input.ProfileDigest,
		releaseDigest:      input.ReleaseDigest,
		maxEverTokens:      input.MaxEverTokens,
		registryProofBytes: input.RegistryProofBytes,
	}
}

// ValidateInitialProgrammeMinimum checks existing experimental layout bounds.
func ValidateInitialProgrammeMinimum(input config.DRWAMinimumGenesis) error {
	if !initialProgrammeMinimum(input).valid() {
		return errInvalidGenesisState
	}
	return nil
}

// PrepareInitialProgrammeGenesis validates and freezes the closed write set.
// The original metachain owner runs it inside its native journal lifetime.
// The operation never opens a second journal, commits or authorizes an appointment.
func PrepareInitialProgrammeGenesis(accounts state.AccountsAdapter, input []InitialProgrammeEvidence,
	limits *InitialProgrammeLimits, minimum *config.DRWAMinimumGenesis, marshaller marshal.Marshalizer,
	hasher hashing.Hasher, epoch uint32) (func() error, error) {
	if len(input) == 0 {
		// This configured route requires programme data. The ordinary caller
		// with no minimum profile or programmes bypasses this operation.
		return nil, ErrInitialProgrammeLimits
	}
	var profile minimumGenesis
	hasMinimum := minimum != nil
	if hasMinimum {
		profile = initialProgrammeMinimum(*minimum)
		if !profile.valid() {
			return nil, errInvalidGenesisState
		}
	}
	limits = limits.Clone()
	if limits.Validate() != nil || len(input) > limits.Files {
		return nil, ErrInitialProgrammeLimits
	}
	codec, err := newRegistrationRecords(accounts, marshaller, hasher, limits.RecordBytes)
	if err != nil {
		return nil, err
	}
	writes := []scopedAdmissionWrite{
		{[]byte(registryCountKey), make([]byte, 8)},
		{[]byte(localMembershipCountKey), make([]byte, 8)},
		{[]byte(scopedAdmissionPrefix + "budget"), make([]byte, 32)},
	}
	seen := make(map[string]struct{}, len(input))
	total := 0
	for _, e := range input {
		if len(e.raw) > limits.AggregateBytes-total {
			return nil, ErrInitialProgrammeLimits
		}
		total += len(e.raw)
		x, err := DecodeInitialProgrammeEvidence(e.raw, e.path, e.pin, limits, marshaller, hasher)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(x.owner, e.owner) || !bytes.Equal(x.programme, e.programme) {
			return nil, errInvalidRegistrationRecord
		}
		identity, err := codec.frame(x.owner, x.programme)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[string(identity)]; duplicate {
			return nil, errInvalidRegistrationRecord
		}
		seen[string(identity)] = struct{}{}
		writes = append(writes, scopedAdmissionWrite{append([]byte(scopedAdmissionPrefix+"initial@"), identity...), x.raw})
	}
	count := uint64(len(writes))
	var size uint64
	for _, w := range writes {
		if len(w.key) > limits.RecordBytes || len(w.value) > limits.RecordBytes {
			return nil, ErrInitialProgrammeLimits
		}
		n := uint64(len(w.key)) + uint64(len(w.value))
		if n > math.MaxUint64-size {
			return nil, ErrInitialProgrammeLimits
		}
		size += n
	}
	if count > limits.Records || size > limits.RetainedBytes || count > limits.NewRecordsPerEpoch {
		return nil, ErrInitialProgrammeLimits
	}
	budget := writes[2].value
	binary.BigEndian.PutUint64(budget, count)
	binary.BigEndian.PutUint64(budget[8:], size)
	binary.BigEndian.PutUint64(budget[16:], uint64(epoch))
	binary.BigEndian.PutUint64(budget[24:], count)
	if accounts.JournalLen() != 0 {
		return nil, ErrUncommittedState
	}
	root, err := accounts.RootHash()
	if err != nil {
		return nil, err
	}
	if !common.IsEmptyTrie(root) {
		return nil, errInvalidGenesisState
	}
	return func() error {
		if hasMinimum {
			if err := codec.state.provisionMinimumGenesis(profile); err != nil {
				return err
			}
		} else if err := codec.state.provisionGenesis(); err != nil {
			return err
		}
		account, err := codec.state.systemAccount()
		if err != nil {
			return err
		}
		// The selected provisioner writes the first two records exactly once.
		for _, w := range writes[2:] {
			if err := account.SaveKeyValue(w.key, bytes.Clone(w.value)); err != nil {
				return err
			}
		}
		return accounts.SaveAccount(account)
	}, nil
}

// readInitialProgrammeItem verifies native account/data membership relative to
// the independently admitted original metachain-genesis identity. The technical
// identity record/pin alone establishes neither canonical genesis nor lawful
// appointment. Its native owner still owes that admission, the original proof
// locator/retention and native release configuration, plus the actual current
// operation/header/store lease and funding before any installation.
//
// Only the existing dedicated proof cache is used. No live accounts adapter,
// witness-selected header/root/address/key or new decoder/store is introduced.
// A historical read is not permission to advance an ended lifecycle.
func (r *ResultAccountReader) readInitialProgrammeItem(identity *DeploymentIdentity,
	domain, owner, programme []byte, w AccountItemWitness, proofByteLimit, recordByteLimit int) ([]byte, error) {
	if r == nil || check.IfNil(r.args.Hasher) || check.IfNil(r.args.Marshaller) ||
		check.IfNil(r.args.StorageManager) || check.IfNil(r.proofTrie) || check.IfNil(r.accountFactory) {
		return nil, vm.ErrDRWAExecution
	}
	r.mut.Lock()
	defer r.mut.Unlock()
	hashBytes := r.args.Hasher.Size()
	if hashBytes <= 0 {
		return nil, vm.ErrDRWAExecution
	}
	if identity == nil || len(identity.raw) == 0 || len(identity.header) == 0 ||
		len(identity.genesisHash) != hashBytes || len(domain) != hashBytes ||
		!bytes.Equal(domain, identity.domain) {
		return nil, ErrDeploymentIdentity
	}
	if proofByteLimit <= 0 || recordByteLimit <= 0 {
		return nil, ErrInitialProgrammeLimits
	}
	if len(owner) != len(core.SystemAccountAddress) || len(programme) == 0 ||
		len(programme) > recordByteLimit || len(w.Header) != 0 || len(w.ExecutedHeader) != 0 {
		return nil, ErrInvalidAccountWitness
	}
	genesisHash := r.args.Hasher.Compute(string(identity.header))
	actualDomain, err := common.ComputeDRWANetworkDomain(identity.chainID, genesisHash, r.args.Hasher)
	if err != nil || !bytes.Equal(genesisHash, identity.genesisHash) || !bytes.Equal(actualDomain, domain) {
		return nil, ErrDeploymentIdentity
	}
	header := &block.MetaBlock{}
	if err = r.args.Marshaller.Unmarshal(header, identity.header); err != nil || header.GetEpoch() != identity.epoch ||
		len(header.RootHash) != hashBytes {
		return nil, ErrDeploymentIdentity
	}
	canonical, err := r.args.Marshaller.Marshal(header)
	if err != nil || !bytes.Equal(canonical, identity.header) {
		return nil, ErrDeploymentIdentity
	}
	if _, err = registryProofBytes(w, proofByteLimit); err != nil {
		return nil, err
	}
	codec := &registrationRecords{marshaller: r.args.Marshaller, hasher: r.args.Hasher, maxBytes: recordByteLimit}
	scope, err := codec.frame(owner, programme)
	if err != nil {
		return nil, ErrInvalidAccountWitness
	}
	key := append([]byte(scopedAdmissionPrefix+"initial@"), scope...)
	value, err := r.readAccountItem(header.RootHash, core.SystemAccountAddress, key, w)
	if err != nil {
		return nil, err
	}
	if len(value) > recordByteLimit {
		return nil, ErrInvalidAccountWitness
	}
	return value, nil
}
