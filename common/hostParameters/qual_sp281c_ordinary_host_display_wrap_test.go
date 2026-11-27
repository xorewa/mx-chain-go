package hostParameters

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinaryHostDisplayWrap(t *testing.T) {
	t.Parallel()

	// These are invented presentation labels, not observed host information.
	first := strings.Repeat("a", 41)
	second := strings.Repeat("b", 41)
	third := strings.Repeat("c", 41)
	fourth := strings.Repeat("d", 41)
	labels := []string{first, second, third, fourth, "tail"}
	info := &HostInfo{
		AppVersion:      "sample",
		CPUModel:        "synthetic",
		CPUNumLogical:   2,
		CPUFlags:        labels,
		CPUMaxFreqInMHz: 1200,
		MemorySize:      "1 GB",
	}

	wantRows := [][]string{
		{"Parameter", "Value"},
		{"App version", "sample"},
		{"CPU model", "synthetic"},
		{"CPU numLogical", "2"},
		{"CPU flags", first + " " + second},
		{"", third + " " + fourth},
		{"", "tail"},
		{"CPU maxFreq", "1200 MHz"},
		{"Memory size", "1 GB"},
	}

	var rows [][]string
	for _, line := range strings.Split(info.ToDisplayTable(), "\r\n") {
		if strings.HasPrefix(line, "|") {
			cells := strings.Split(line, "|")
			require.Len(t, cells, 4)
			rows = append(rows, []string{strings.TrimSpace(cells[1]), strings.TrimSpace(cells[2])})
		}
	}
	require.Equal(t, wantRows, rows)

	require.Equal(t, [][]string{
		{"App version", "sample"},
		{"CPU model", "synthetic"},
		{"CPU numLogical", "2"},
		{"CPU flags", strings.Join(labels, " ")},
		{"CPU maxFreq", "1200 MHz"},
		{"Memory size", "1 GB"},
	}, info.ToStrings())
}

func TestQualSP281COrdinaryHostDisplayEmptyFlags(t *testing.T) {
	t.Parallel()

	info := &HostInfo{
		AppVersion:      "sample",
		CPUModel:        "synthetic",
		CPUNumLogical:   2,
		CPUFlags:        []string{},
		CPUMaxFreqInMHz: 1200,
		MemorySize:      "1 GB",
	}

	var rows [][]string
	for _, line := range strings.Split(info.ToDisplayTable(), "\r\n") {
		if strings.HasPrefix(line, "|") {
			cells := strings.Split(line, "|")
			require.Len(t, cells, 4)
			rows = append(rows, []string{strings.TrimSpace(cells[1]), strings.TrimSpace(cells[2])})
		}
	}
	require.Equal(t, [][]string{
		{"Parameter", "Value"},
		{"App version", "sample"},
		{"CPU model", "synthetic"},
		{"CPU numLogical", "2"},
		{"CPU maxFreq", "1200 MHz"},
		{"Memory size", "1 GB"},
	}, rows)

	require.Equal(t, [][]string{
		{"App version", "sample"},
		{"CPU model", "synthetic"},
		{"CPU numLogical", "2"},
		{"CPU flags", ""},
		{"CPU maxFreq", "1200 MHz"},
		{"Memory size", "1 GB"},
	}, info.ToStrings())
}
