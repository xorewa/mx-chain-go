package node

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/process/drwa"
	"github.com/multiversx/mx-chain-go/update"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

// Synthetic A/C groups and appointment only. Existing independently framed
// literal is copied unchanged from qual_drwa_authority_set_version_test.go;
// its retained chronology/provenance limitations remain. No native authority.
const qualStageAG6 = "0a2d445257412f494e495449414c5f50524f4752414d4d455f4150504f494e544d454e542f63616e646964617465310a2001010101010101010101010101010101010101010101010101010101010101010a0770726f6772616d0add020a25445257412f415554484f524954595f5345545f56455253494f4e2f63616e646964617465310a2041414141414141414141414141414141414141414141414141414141414141410a0800000000000000000a0e454432353531395f4d5f4f465f4e0a0800000000000000030aaa010a208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c0a208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3940a20ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d10a20ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c0a206e7a1cdd29b0b78fd13af4c5598feff4ef2a97166e3ca6f2e4fbfccd80505bf10a3d0a1061646d697373696f6e006f70617175650a2001010101010101010101010101010101010101010101010101010101010101010a0770726f6772616d0a000a000ada020a25445257412f415554484f524954595f5345545f56455253494f4e2f63616e646964617465310a2042424242424242424242424242424242424242424242424242424242424242420a0800000000000000010a0e454432353531395f4d5f4f465f4e0a0800000000000000030aaa010a20d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c97787370a20204040e364c10f2bec9c1fe500a1cd4c247c89d650a01ed7e82caba867877c210a2066cd608b928b88e50e0efeaa33faf1c43cefe07294b0b87e9fe0aba6a3cf76330a2020828bf5c5bdcacb684863336c202fb5599da48be5596615742170705beca9f70a20d54207da194977dcf46adbfec2bc2e75b52d5a8a42184fedfdc00024f0e3e8da0a3a0a0d696e646570656e64656e74c3a90a2001010101010101010101010101010101010101010101010101010101010101010a0770726f6772616d0a000a000a20abababababababababababababababababababababababababababababababab"

func qualStageALimits() *drwa.InitialProgrammeLimits {
	return &drwa.InitialProgrammeLimits{Files: 2, FileBytes: 4096, AggregateBytes: 8192, RecordBytes: 4096, FieldBytes: 2048, RoleBytes: 64, Members: 10, Records: 100, RetainedBytes: 65536, NewRecordsPerEpoch: 100, AdmissionRole: []byte("admission\x00opaque"), IndependentRole: []byte("independent\xc3\xa9")}
}
func qualStageARaw(t *testing.T) []byte {
	t.Helper()
	b, e := hex.DecodeString(qualStageAG6)
	require.NoError(t, e)
	return b
}

func TestQualDRWAInitialProgrammeNodeFlow(t *testing.T) {
	m := &marshal.GogoProtoMarshalizer{}
	h := blake2b.NewBlake2b()
	out, e := loadInitialProgrammeData(nil, nil, m, h)
	require.NoError(t, e)
	require.Nil(t, out)
	// Nonempty programme bytes require explicit bounded native inputs.
	out, e = loadInitialProgrammeData([]config.DRWAInitialProgrammeInput{{Path: "/must-not-be-opened"}}, nil, m, h)
	require.ErrorIs(t, e, drwa.ErrInitialProgrammeLimits)
	require.Nil(t, out)
	raw := qualStageARaw(t)
	p := filepath.Join(t.TempDir(), "g6")
	require.NoError(t, os.WriteFile(p, raw, 0600))
	in := []config.DRWAInitialProgrammeInput{{Path: p, SHA256: fmt.Sprintf("%x", sha256.Sum256(raw))}}
	out, e = loadInitialProgrammeData(in, qualStageALimits(), m, h)
	require.NoError(t, e)
	copy := drwa.CloneInitialProgrammeEvidence(out)
	out[0] = drwa.InitialProgrammeEvidence{}
	in[0].Path = "other"
	require.NoError(t, os.WriteFile(p, []byte("changed"), 0600))
	require.Equal(t, raw, copy[0].Raw())
}

// The untouched native entry rejects an absent version before using the core
// providers. Optional DRWA data must not introduce an earlier dependency.
func TestQualDRWAInitialProgrammeUnconfiguredNativeValidationOrder(t *testing.T) {
	r := &nodeRunner{configs: &config.Configs{GeneralConfig: &config.Config{}, FlagsConfig: &config.ContextFlagsConfig{}}}
	var err error
	require.NotPanics(t, func() { _, err = r.CreateManagedProcessComponents(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil) })
	require.ErrorIs(t, err, update.ErrEmptyVersionString)
}

func TestQualDRWAManagedInitialProgrammeInputBoundary(t *testing.T) {
	cfg := &config.Configs{GeneralConfig: &config.Config{}, FlagsConfig: &config.ContextFlagsConfig{}}
	r := &nodeRunner{configs: cfg}
	cfg.GeneralConfig.GeneralSettings.DRWAInitialProgrammeInputs = []config.DRWAInitialProgrammeInput{{Path: filepath.Join(t.TempDir(), "absent")}}
	_, err := r.CreateManagedProcessComponents(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	require.ErrorIs(t, err, drwa.ErrInitialProgrammeLimits)
	cfg.GeneralConfig.GeneralSettings.DRWAInitialProgrammeInputs = nil
	cfg.DRWAInitialProgrammeStartup = &config.DRWAInitialProgrammeStartup{Limits: *qualStageALimits()}
	_, err = r.CreateManagedProcessComponents(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	require.ErrorIs(t, err, drwa.ErrInitialProgrammeLimits)
}

func TestQualDRWAManagedInitialProgrammeLimitsClone(t *testing.T) {
	startup := &config.DRWAInitialProgrammeStartup{Limits: *qualStageALimits()}
	copy := startup.Clone()
	startup.Limits.AdmissionRole[0] = 0
	startup.Limits.IndependentRole[0] = 0
	startup.Limits.Files = 0
	require.Equal(t, *qualStageALimits(), copy.Limits)
}

func TestQualDRWAOriginalStartupRefusesNativeCleanupAndCycleReuse(t *testing.T) {
	cfg := &config.Configs{
		FlagsConfig: &config.ContextFlagsConfig{CleanupStorage: true},
		DRWAInitialProgrammeStartup: &config.DRWAInitialProgrammeStartup{},
	}
	r := &nodeRunner{configs: cfg}
	// Deliberately omit other startup providers. Refusal must precede
	// accessing native paths or components that can touch the datastore.
	require.ErrorIs(t, r.Start(), drwa.ErrDeploymentIdentity)
	r.drwaOriginalCycleStarted.Store(true)
	stop, err := r.executeOneComponentCreationCycle(nil)
	require.True(t, stop)
	require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
}
