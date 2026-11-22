package drwa

import (
	"bytes"
	"encoding/binary"
	"math"

	"github.com/multiversx/mx-chain-core-go/core"
)

// Experimental native protected-key layout under R7, not a release-format
// allocation. Part A 2.6 requires these genesis inputs before enforcement;
// 7.2/AM-011 still owns every non-genesis plane/release transition.
const genesisPlaneKey = core.ProtectedKeyPrefix + "DRWA@plane@state"
const minimumProfileKey = core.ProtectedKeyPrefix + "DRWA@profile@minimum"
const maxEverTokensKey = core.ProtectedKeyPrefix + "DRWA@param@maxEverRegulatedTokens"
const registryProofBytesKey = core.ProtectedKeyPrefix + "DRWA@param@registryProofBytes"

// minimumGenesis is the DRWA-defined input for the bounded first-classification
// experiment. Profile and release identities bind external immutable manifests;
// this component cannot accept them, allocate an identity or enable operations.
// The finite proof budget is the existing registryTransport input, not a new
// proof mechanism. Numerical choices belong to the experimental input manifest.
type minimumGenesis struct {
	profileDigest      [32]byte
	releaseDigest      [32]byte
	maxEverTokens      uint64
	registryProofBytes uint64
}

func (g minimumGenesis) valid() bool {
	return g.profileDigest != [32]byte{} && g.releaseDigest != [32]byte{} && g.maxEverTokens > 0 && g.registryProofBytes > 0 && g.registryProofBytes <= uint64(math.MaxInt)
}

// provisionMinimumGenesis extends the sole existing genesis owner. It must run
// under that owner's exclusive RollbackContainment.Execute on a fresh store.
// Save failures may have mutated native state: callers must retain the original
// error and abort/roll back, never publish a partially provisioned profile.
// No startup, mode transition, native dispatch or ordinary caller is wired here.
func (s *protectedState) provisionMinimumGenesis(g minimumGenesis) error {
	if !g.valid() {
		return errInvalidGenesisState
	}
	if err := s.provisionGenesis(); err != nil {
		return err
	}
	account, err := s.systemAccount()
	if err != nil {
		return err
	}
	plane := append([]byte("NORMAL"), make([]byte, 8)...)
	plane = append(plane, g.releaseDigest[:]...)
	capValue, budgetValue := make([]byte, 8), make([]byte, 8)
	binary.BigEndian.PutUint64(capValue, g.maxEverTokens)
	binary.BigEndian.PutUint64(budgetValue, g.registryProofBytes)
	for _, item := range []struct {
		key   string
		value []byte
	}{
		{genesisPlaneKey, plane}, {minimumProfileKey, g.profileDigest[:]},
		{maxEverTokensKey, capValue}, {registryProofBytesKey, budgetValue},
	} {
		if err = account.SaveKeyValue([]byte(item.key), item.value); err != nil {
			return err
		}
	}
	return s.accounts.SaveAccount(account)
}

// readMinimumGenesis reads only this initialized genesis layout. It is not a
// runtime plane-state reader or a readiness ACK. Native stores and manifest
// identities must already have their owning provenance before any consumer.
func (s *protectedState) readMinimumGenesis() (minimumGenesis, error) {
	var g minimumGenesis
	account, err := s.systemAccount()
	if err != nil {
		return g, err
	}
	read := func(key string, n int) ([]byte, error) {
		value, _, e := account.RetrieveValue([]byte(key))
		if e != nil {
			return nil, e
		}
		if len(value) != n {
			return nil, errInvalidGenesisState
		}
		return value, nil
	}
	plane, err := read(genesisPlaneKey, 46)
	if err != nil {
		return g, err
	}
	if !bytes.Equal(plane[:14], append([]byte("NORMAL"), make([]byte, 8)...)) {
		return g, errInvalidGenesisState
	}
	copy(g.releaseDigest[:], plane[14:])
	profile, err := read(minimumProfileKey, 32)
	if err != nil {
		return g, err
	}
	copy(g.profileDigest[:], profile)
	capValue, err := read(maxEverTokensKey, 8)
	if err != nil {
		return g, err
	}
	g.maxEverTokens = binary.BigEndian.Uint64(capValue)
	budgetValue, err := read(registryProofBytesKey, 8)
	if err != nil {
		return g, err
	}
	g.registryProofBytes = binary.BigEndian.Uint64(budgetValue)
	if !g.valid() {
		return minimumGenesis{}, errInvalidGenesisState
	}
	return g, nil
}
