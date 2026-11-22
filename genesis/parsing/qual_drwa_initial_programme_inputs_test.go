package parsing

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/process/drwa"
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

func TestQualDRWAInitialProgrammeLoader(t *testing.T) {
	raw := qualStageARaw(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "g6")
	require.NoError(t, os.WriteFile(path, raw, 0600))
	pin := fmt.Sprintf("%x", sha256.Sum256(raw))
	in := []config.DRWAInitialProgrammeInput{{Path: path, SHA256: pin}}
	load := func(in []config.DRWAInitialProgrammeInput, l *drwa.InitialProgrammeLimits) ([]drwa.InitialProgrammeEvidence, error) {
		return LoadDRWAInitialProgrammeInputs(in, l, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b())
	}
	t.Run("nil_ordinary", func(t *testing.T) { out, e := load(nil, nil); require.NoError(t, e); require.Nil(t, out) })
	t.Run("freeze_and_source", func(t *testing.T) {
		out, e := load(in, qualStageALimits())
		require.NoError(t, e)
		require.Len(t, out, 1)
		require.Equal(t, raw, out[0].Raw())
		p, h := out[0].Source()
		require.Equal(t, path, p)
		require.Equal(t, pin, h)
		out[0].Raw()[0] ^= 1
		require.Equal(t, raw, out[0].Raw())
		require.NoError(t, os.WriteFile(path, []byte("changed"), 0600))
		require.Equal(t, raw, out[0].Raw())
		_, e = load(in, qualStageALimits())
		require.Error(t, e)
		require.NoError(t, os.WriteFile(path, raw, 0600))
	})
	for _, name := range []string{"missing_limits", "wrong_pin", "missing", "relative", "directory", "symlink", "parent_symlink", "oversize", "aggregate", "count", "duplicate", "noncanonical", "truncated"} {
		t.Run(name, func(t *testing.T) {
			x := append([]config.DRWAInitialProgrammeInput(nil), in...)
			l := qualStageALimits()
			switch name {
			case "missing_limits":
				l = nil
			case "wrong_pin":
				x[0].SHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte("other")))
			case "missing":
				x[0].Path = filepath.Join(dir, "absent")
			case "relative":
				x[0].Path = "g6"
			case "directory":
				x[0].Path = dir
			case "symlink":
				link := filepath.Join(dir, "link")
				require.NoError(t, os.Symlink(path, link))
				x[0].Path = link
			case "parent_symlink":
				d := t.TempDir()
				link := filepath.Join(d, "link")
				require.NoError(t, os.Symlink(dir, link))
				x[0].Path = filepath.Join(link, "g6")
			case "oversize":
				l.FileBytes = len(raw) - 1
			case "aggregate":
				l.FileBytes = len(raw)
				l.AggregateBytes = len(raw)
				x = append(x, x[0])
			case "count":
				l.Files = 1
				x = append(x, x[0])
			case "duplicate":
				x = append(x, x[0])
			case "noncanonical", "truncated":
				b := bytes.Clone(raw)
				if name == "noncanonical" {
					b = append(b, 0x10, 0)
				} else {
					b = b[:len(b)-1]
				}
				p := filepath.Join(t.TempDir(), "bad")
				require.NoError(t, os.WriteFile(p, b, 0600))
				x[0] = config.DRWAInitialProgrammeInput{Path: p, SHA256: fmt.Sprintf("%x", sha256.Sum256(b))}
			}
			out, e := load(x, l)
			require.Error(t, e)
			require.Nil(t, out)
		})
	}
	t.Run("same_bytes_different_path", func(t *testing.T) {
		p := filepath.Join(dir, "other")
		require.NoError(t, os.WriteFile(p, raw, 0600))
		x := []config.DRWAInitialProgrammeInput{{Path: p, SHA256: pin}}
		out, e := load(x, qualStageALimits())
		require.NoError(t, e)
		require.Equal(t, raw, out[0].Raw())
	})
}
