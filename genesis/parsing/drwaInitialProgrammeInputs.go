package parsing

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/process/drwa"
)

var errInitialProgrammeFile = errors.New("invalid DRWA initial programme input file")

// LoadDRWAInitialProgrammeInputs reads ONLY explicit absolute regular files.
// SHA256 is file integrity, not a protocol digest or appointment authority.
func LoadDRWAInitialProgrammeInputs(inputs []config.DRWAInitialProgrammeInput, limits *drwa.InitialProgrammeLimits,
	marshaller marshal.Marshalizer, hasher hashing.Hasher) ([]drwa.InitialProgrammeEvidence, error) {
	if len(inputs) == 0 {
		return nil, nil
	}
	limits = limits.Clone()
	if limits.Validate() != nil || len(inputs) > limits.Files {
		return nil, drwa.ErrInitialProgrammeLimits
	}
	var result []drwa.InitialProgrammeEvidence
	total := 0
	seen := make(map[string]struct{}, len(inputs))
	for _, input := range inputs {
		if !filepath.IsAbs(input.Path) || filepath.Clean(input.Path) != input.Path {
			return nil, errInitialProgrammeFile
		}
		// Reject symlinks in every path component; never follow directory leads.
		for p := input.Path; ; p = filepath.Dir(p) {
			info, err := os.Lstat(p)
			if err != nil {
				return nil, err
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return nil, errInitialProgrammeFile
			}
			if p == filepath.Dir(p) {
				break
			}
		}
		pin, err := hex.DecodeString(input.SHA256)
		if err != nil || len(input.SHA256) != 64 || len(pin) != sha256.Size {
			return nil, errInitialProgrammeFile
		}
		before, err := os.Lstat(input.Path)
		if err != nil {
			return nil, err
		}
		if !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > int64(limits.FileBytes) || before.Size() > int64(limits.AggregateBytes-total) {
			return nil, errInitialProgrammeFile
		}
		f, err := os.Open(input.Path)
		if err != nil {
			return nil, err
		}
		opened, err := f.Stat()
		if err != nil || !os.SameFile(before, opened) || !opened.Mode().IsRegular() {
			_ = f.Close()
			return nil, errInitialProgrammeFile
		}
		raw, readErr := io.ReadAll(io.LimitReader(f, int64(limits.FileBytes)+1))
		after, statErr := f.Stat()
		closeErr := f.Close()
		if readErr != nil {
			return nil, readErr
		}
		if statErr != nil {
			return nil, statErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		current, err := os.Lstat(input.Path)
		if err != nil {
			return nil, err
		}
		if len(raw) > limits.FileBytes || len(raw) > limits.AggregateBytes-total || !os.SameFile(before, current) ||
			!os.SameFile(opened, after) || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
			return nil, errInitialProgrammeFile
		}
		digest := sha256.Sum256(raw)
		if !bytes.Equal(digest[:], pin) {
			return nil, errInitialProgrammeFile
		}
		e, err := drwa.DecodeInitialProgrammeEvidence(raw, input.Path, input.SHA256, limits, marshaller, hasher)
		if err != nil {
			return nil, err
		}
		// Length-delimited identity uses two separate string components, not an
		// ambiguous concatenation or a new protocol hash.
		key := hex.EncodeToString(e.Owner()) + ":" + hex.EncodeToString(e.Programme())
		if _, duplicate := seen[key]; duplicate {
			return nil, errInitialProgrammeFile
		}
		seen[key] = struct{}{}
		total += len(raw)
		result = append(result, e)
	}
	return result, nil
}
