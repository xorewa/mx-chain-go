package f1t

import (
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"
)

var ErrDiagnostics = errors.New("F1-T diagnostics invalidated campaign")

const (
	TotalDiagnosticDecisions = 1044
	holmAlphaDenominator     = 100
)

var diagnosticBlockSizes = [...]int{576, 576, 576, 575, 575, 575, 575, 575}

var binomialRows sync.Map
var runDistributions sync.Map

type ExactPValue struct {
	Numerator   string `json:"numerator"`
	Denominator string `json:"denominator"`
}

type DiagnosticDecision struct {
	ID           string      `json:"id"`
	CellID       string      `json:"cell_id"`
	BlockPair    string      `json:"block_pair,omitempty"`
	PValue       ExactPValue `json:"p_value"`
	EffectiveN   int         `json:"effective_n"`
	TiesExcluded int         `json:"ties_excluded"`
	HolmRank     int         `json:"holm_rank"`
	Rejected     bool        `json:"rejected"`
}

type DiagnosticsReport struct {
	Schema           string               `json:"schema"`
	Status           string               `json:"status"`
	Decisions        []DiagnosticDecision `json:"decisions"`
	TotalTests       int                  `json:"total_tests"`
	RuntimeCredit    int                  `json:"authoritative_runtime_credit"`
	IIDProved        bool                 `json:"iid_proved"`
	StationaryProved bool                 `json:"stationarity_proved"`
}

type exactDecision struct {
	DiagnosticDecision
	p *big.Rat
}

func EvaluateCampaignDiagnostics(observations []Observation) (DiagnosticsReport, error) {
	expectedCells := len(profileCatalog) * len(pathCatalog) * len(loadCatalog)
	cells := make(map[string][]Observation, expectedCells)
	for _, observation := range observations {
		if observation.Kind != ObservationCalibration {
			continue
		}
		key := diagnosticCellID(observation.Profile, observation.Path, observation.Load)
		cells[key] = append(cells[key], observation)
	}
	if len(cells) != expectedCells {
		return DiagnosticsReport{}, ErrDiagnostics
	}
	decisions := make([]exactDecision, 0, TotalDiagnosticDecisions)
	for _, profile := range profileCatalog {
		for _, path := range pathCatalog {
			for _, load := range loadCatalog {
				cellID := diagnosticCellID(profile, path, load)
				cell := cells[cellID]
				if len(cell) != SamplesPerProfilePathLoad {
					return DiagnosticsReport{}, ErrDiagnostics
				}
				sort.Slice(cell, func(i, j int) bool { return cell[i].Index < cell[j].Index })
				latencies := make([]uint64, len(cell))
				for index, observation := range cell {
					if observation.Index != uint64(index+1) || observation.DurableAckNS < observation.IntentRawNS {
						return DiagnosticsReport{}, ErrDiagnostics
					}
					latencies[index] = observation.DurableAckNS - observation.IntentRawNS
				}
				cellDecisions, err := evaluateDiagnosticCell(cellID, latencies)
				if err != nil {
					return DiagnosticsReport{}, err
				}
				decisions = append(decisions, cellDecisions...)
			}
		}
	}
	if len(decisions) != TotalDiagnosticDecisions {
		return DiagnosticsReport{}, ErrDiagnostics
	}
	result, anyRejected, err := applyHolm(decisions)
	if err != nil {
		return DiagnosticsReport{}, err
	}
	report := DiagnosticsReport{Schema: "DRWA_S1_F1T_DIAGNOSTICS_V1", Status: "PASS_NO_PREDECLARED_DIAGNOSTIC_REJECTED",
		Decisions: result, TotalTests: len(result)}
	if anyRejected {
		report.Status = "INVALIDATED_DIAGNOSTIC_REJECTION"
		return report, ErrDiagnostics
	}
	return report, nil
}

func applyHolm(decisions []exactDecision) ([]DiagnosticDecision, bool, error) {
	if len(decisions) != TotalDiagnosticDecisions {
		return nil, false, ErrDiagnostics
	}
	sort.Slice(decisions, func(i, j int) bool {
		comparison := decisions[i].p.Cmp(decisions[j].p)
		if comparison != 0 {
			return comparison < 0
		}
		if decisions[i].ID != decisions[j].ID {
			return decisions[i].ID < decisions[j].ID
		}
		if decisions[i].CellID != decisions[j].CellID {
			return decisions[i].CellID < decisions[j].CellID
		}
		return decisions[i].BlockPair < decisions[j].BlockPair
	})
	rejectionOpen := true
	anyRejected := false
	result := make([]DiagnosticDecision, len(decisions))
	for index := range decisions {
		denominator := int64(holmAlphaDenominator * (TotalDiagnosticDecisions - index))
		threshold := new(big.Rat).SetFrac64(1, denominator)
		rejected := rejectionOpen && decisions[index].p.Cmp(threshold) <= 0
		if !rejected {
			rejectionOpen = false
		} else {
			anyRejected = true
		}
		decisions[index].HolmRank = index + 1
		decisions[index].Rejected = rejected
		result[index] = decisions[index].DiagnosticDecision
	}
	return result, anyRejected, nil
}

func evaluateDiagnosticCell(cellID string, values []uint64) ([]exactDecision, error) {
	if len(values) != SamplesPerProfilePathLoad || !validDiagnosticBlockSizes(diagnosticBlockSizes[:]) {
		return nil, ErrDiagnostics
	}
	blocks := make([][]uint64, 0, len(diagnosticBlockSizes))
	offset := 0
	for _, size := range diagnosticBlockSizes {
		blocks = append(blocks, values[offset:offset+size])
		offset += size
	}
	decisions := make([]exactDecision, 0, 29)
	for earlier := 0; earlier < len(blocks); earlier++ {
		for later := earlier + 1; later < len(blocks); later++ {
			successes, effective, ties := 0, 0, 0
			for position := 0; position < 575; position++ {
				switch {
				case blocks[later][position] > blocks[earlier][position]:
					successes++
					effective++
				case blocks[later][position] < blocks[earlier][position]:
					effective++
				default:
					ties++
				}
			}
			p, resolution, err := exactSignP(successes, effective)
			if err != nil || resolution.Cmp(firstHolmThreshold()) > 0 {
				return nil, ErrDiagnostics
			}
			pair := fmt.Sprintf("%d-%d", earlier+1, later+1)
			decisions = append(decisions, newExactDecision("BLOCK_PAIR_SIGN_EXACT_V1", cellID, pair, p, effective, ties))
		}
	}
	p, resolution, effective, ties, err := exactRunsP(values)
	if err != nil || resolution.Cmp(firstHolmThreshold()) > 0 {
		return nil, ErrDiagnostics
	}
	decisions = append(decisions, newExactDecision("MEDIAN_EXCLUDED_EXACT_RUNS_V1", cellID, "", p, effective, ties))
	return decisions, nil
}

func validDiagnosticBlockSizes(sizes []int) bool {
	if len(sizes) != len(diagnosticBlockSizes) {
		return false
	}
	total := 0
	for index, size := range sizes {
		if size != diagnosticBlockSizes[index] {
			return false
		}
		total += size
	}
	return total == SamplesPerProfilePathLoad
}

func exactSignP(successes, effective int) (*big.Rat, *big.Rat, error) {
	if effective <= 17 || successes < 0 || successes > effective {
		return nil, nil, ErrDiagnostics
	}
	row := binomialRow(effective)
	lower := new(big.Int)
	for index := 0; index <= successes; index++ {
		lower.Add(lower, row[index])
	}
	upper := new(big.Int)
	for index := successes; index <= effective; index++ {
		upper.Add(upper, row[index])
	}
	tail := lower
	if upper.Cmp(lower) < 0 {
		tail = upper
	}
	numerator := new(big.Int).Lsh(new(big.Int).Set(tail), 1)
	denominator := new(big.Int).Lsh(big.NewInt(1), uint(effective))
	if numerator.Cmp(denominator) > 0 {
		numerator.Set(denominator)
	}
	p := new(big.Rat).SetFrac(numerator, denominator)
	minimum := new(big.Rat).SetFrac(big.NewInt(1), new(big.Int).Lsh(big.NewInt(1), uint(effective-1)))
	return p, minimum, nil
}

func exactRunsP(values []uint64) (*big.Rat, *big.Rat, int, int, error) {
	ordered := append([]uint64(nil), values...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	median := ordered[len(ordered)/2]
	labels := make([]bool, 0, len(values))
	low, high, ties := 0, 0, 0
	for _, value := range values {
		switch {
		case value < median:
			labels = append(labels, false)
			low++
		case value > median:
			labels = append(labels, true)
			high++
		default:
			ties++
		}
	}
	if low == 0 || high == 0 || len(labels) < 2 {
		return nil, nil, 0, ties, ErrDiagnostics
	}
	runs := 1
	for index := 1; index < len(labels); index++ {
		if labels[index] != labels[index-1] {
			runs++
		}
	}
	distribution := runsDistribution(low, high)
	observed := distribution[runs]
	if observed == nil || observed.Sign() == 0 {
		return nil, nil, 0, ties, ErrDiagnostics
	}
	total := new(big.Int).Binomial(int64(low+high), int64(low))
	numerator := new(big.Int)
	minimumCount := (*big.Int)(nil)
	for _, count := range distribution {
		if count.Sign() == 0 {
			continue
		}
		if count.Cmp(observed) <= 0 {
			numerator.Add(numerator, count)
		}
		if minimumCount == nil || count.Cmp(minimumCount) < 0 {
			minimumCount = new(big.Int).Set(count)
		}
	}
	minimumNumerator := new(big.Int)
	for _, count := range distribution {
		if count.Sign() > 0 && count.Cmp(minimumCount) == 0 {
			minimumNumerator.Add(minimumNumerator, count)
		}
	}
	return new(big.Rat).SetFrac(numerator, total), new(big.Rat).SetFrac(minimumNumerator, total), low + high, ties, nil
}

func runsDistribution(low, high int) map[int]*big.Int {
	key := [2]int{low, high}
	if cached, ok := runDistributions.Load(key); ok {
		return cached.(map[int]*big.Int)
	}
	result := make(map[int]*big.Int)
	maximumRuns := 2*min(low, high) + 1
	for runs := 2; runs <= maximumRuns; runs++ {
		count := new(big.Int)
		if runs%2 == 0 {
			k := runs / 2
			count.Mul(binomial(low-1, k-1), binomial(high-1, k-1)).Lsh(count, 1)
		} else {
			k := (runs - 1) / 2
			left := new(big.Int).Mul(binomial(low-1, k), binomial(high-1, k-1))
			right := new(big.Int).Mul(binomial(low-1, k-1), binomial(high-1, k))
			count.Add(left, right)
		}
		result[runs] = count
	}
	actual, _ := runDistributions.LoadOrStore(key, result)
	return actual.(map[int]*big.Int)
}

func binomial(n, k int) *big.Int {
	if n < 0 || k < 0 || k > n {
		return new(big.Int)
	}
	return new(big.Int).Binomial(int64(n), int64(k))
}

func binomialRow(n int) []*big.Int {
	if cached, ok := binomialRows.Load(n); ok {
		return cached.([]*big.Int)
	}
	row := make([]*big.Int, n+1)
	row[0] = big.NewInt(1)
	for k := 1; k <= n; k++ {
		row[k] = new(big.Int).Mul(row[k-1], big.NewInt(int64(n-k+1)))
		row[k].Quo(row[k], big.NewInt(int64(k)))
	}
	actual, _ := binomialRows.LoadOrStore(n, row)
	return actual.([]*big.Int)
}

func firstHolmThreshold() *big.Rat {
	return new(big.Rat).SetFrac64(1, holmAlphaDenominator*TotalDiagnosticDecisions)
}

func newExactDecision(id, cellID, pair string, p *big.Rat, effective, ties int) exactDecision {
	return exactDecision{DiagnosticDecision: DiagnosticDecision{ID: id, CellID: cellID, BlockPair: pair,
		PValue: ExactPValue{Numerator: p.Num().String(), Denominator: p.Denom().String()}, EffectiveN: effective, TiesExcluded: ties}, p: p}
}

func diagnosticCellID(profile Profile, path Path, load LoadCell) string {
	return fmt.Sprintf("%s/%s/%s", profile, path, load)
}
