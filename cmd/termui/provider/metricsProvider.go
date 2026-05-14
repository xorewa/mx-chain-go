package provider

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/multiversx/mx-chain-go/common"
	logger "github.com/multiversx/mx-chain-logger-go"
)

var log = logger.GetOrCreate("termui/provider")

var newHTTPClient = func() *http.Client {
	return &http.Client{}
}

const (
	AccountsSnapshotNumNodesMetric = "AccountsSnapshotNumNodesMetric"

	statusMetricsUrlSuffix          = "/node/status"
	bootstrapStatusMetricsUrlSuffix = "/node/bootstrapstatus"

	trieStatisticsMetricsUrlSuffix = "/network/trie-statistics/"

	// ISSUE-027: cap polled-metrics response body so a misbehaving
	// local node cannot OOM the termui process. Real responses are
	// well under 1 MiB; 16 MiB is generous headroom.
	maxMetricsResponseBytes = 16 * 1024 * 1024
)

type statusMetricsResponseData struct {
	Response map[string]interface{} `json:"metrics"`
}

type responseFromApi struct {
	Data  statusMetricsResponseData `json:"data"`
	Error string                    `json:"error"`
	Code  string                    `json:"code"`
}

type trieStatisticsResponseData struct {
	AccountSnapshotsNumNodes uint64 `json:"accounts-snapshot-num-nodes"`
}

type responseFromGatewayApi struct {
	Data  trieStatisticsResponseData `json:"data"`
	Error string                     `json:"error"`
	Code  string                     `json:"code"`
}

// StatusMetricsProvider is the struct that will handle initializing the presenter and fetching updated metrics from the node
type StatusMetricsProvider struct {
	presenter       PresenterHandler
	nodeAddress     string
	gatewayAddress  string
	fetchInterval   int
	shardID         string
	numTrieNodesSet bool
}

// NewStatusMetricsProvider will return a new instance of a StatusMetricsProvider
func NewStatusMetricsProvider(
	presenter PresenterHandler,
	nodeAddress string,
	fetchInterval int,
) (*StatusMetricsProvider, error) {
	if len(nodeAddress) == 0 {
		return nil, fmt.Errorf("%w for node address", ErrInvalidAddressLength)
	}
	if fetchInterval < 1 {
		return nil, ErrInvalidFetchInterval
	}
	if presenter == nil {
		return nil, ErrNilTermuiPresenter
	}

	return &StatusMetricsProvider{
		presenter:     presenter,
		nodeAddress:   formatUrlAddress(nodeAddress),
		fetchInterval: fetchInterval,
	}, nil
}

// StartUpdatingData will update data from the API at a given interval
func (smp *StatusMetricsProvider) StartUpdatingData() {
	go func() {
		for {
			smp.updateMetrics()
			time.Sleep(time.Duration(smp.fetchInterval) * time.Millisecond)
		}
	}()
}

func (smp *StatusMetricsProvider) updateMetrics() {
	smp.fetchAndApplyMetrics(statusMetricsUrlSuffix)
	smp.fetchAndApplyBootstrapMetrics(bootstrapStatusMetricsUrlSuffix)

	if smp.shardID != "" && smp.gatewayAddress != "" {
		metricsURLSuffix := trieStatisticsMetricsUrlSuffix + smp.shardID
		statusMetricsURL := smp.gatewayAddress + metricsURLSuffix

		if !smp.numTrieNodesSet {
			smp.fetchAndApplyGatewayStatusMetrics(statusMetricsURL)
		}
	}
}

func (smp *StatusMetricsProvider) fetchAndApplyGatewayStatusMetrics(statusMetricsURL string) {
	foundErrors := false
	numTrieNodes, err := smp.loadMetricsFromGatewayApi(statusMetricsURL)
	if err != nil {
		log.Info("fetch from Gateway API",
			"path", statusMetricsURL,
			"error", err.Error())
		foundErrors = true
	}

	err = smp.setPresenterValue(AccountsSnapshotNumNodesMetric, float64(numTrieNodes))
	if err != nil {
		log.Info("termui metric set",
			"error", err.Error())
		foundErrors = true
	}

	if !foundErrors {
		smp.numTrieNodesSet = true
	}
}

func (smp *StatusMetricsProvider) fetchAndApplyBootstrapMetrics(metricsPath string) {
	metricsMap, err := smp.loadMetricsFromApi(metricsPath)
	if err != nil {
		log.Debug("fetch from API",
			"path", metricsPath,
			"error", err.Error())
		return
	}

	smp.applyMetricsToPresenter(metricsMap)

	smp.setShardID(metricsMap)
	smp.setGatewayAddress(metricsMap)
}

func (smp *StatusMetricsProvider) setGatewayAddress(metricsMap map[string]interface{}) {
	if smp.gatewayAddress != "" {
		return
	}

	gatewayAddressVal, ok := metricsMap[common.MetricGatewayMetricsEndpoint]
	if !ok {
		log.Debug("unable to fetch gateway address endpoint metric from map")
		return
	}

	gatewayAddress, ok := gatewayAddressVal.(string)
	if !ok {
		log.Debug("wrong type assertion gateway address")
		return
	}

	smp.gatewayAddress = gatewayAddress
}

func (smp *StatusMetricsProvider) setShardID(metricsMap map[string]interface{}) {
	if smp.shardID != "" {
		return
	}

	shardIDVal, ok := metricsMap[common.MetricShardId]
	if !ok {
		log.Debug("unable to fetch shard id metric from map")
		return
	}

	shardID, ok := shardIDVal.(float64)
	if !ok {
		log.Debug("wrong type assertion shard id")
		return
	}

	smp.shardID = fmt.Sprint(shardID)
}

func (smp *StatusMetricsProvider) fetchAndApplyMetrics(metricsPath string) {
	metricsMap, err := smp.loadMetricsFromApi(metricsPath)
	if err != nil {
		log.Debug("fetch from API",
			"path", metricsPath,
			"error", err.Error())
		return
	}

	smp.applyMetricsToPresenter(metricsMap)
}

func (smp *StatusMetricsProvider) loadMetricsFromApi(metricsPath string) (map[string]interface{}, error) {
	client := newHTTPClient()

	statusMetricsUrl := smp.nodeAddress + metricsPath
	resp, err := client.Get(statusMetricsUrl)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = resp.Body.Close()
		if err != nil {
			log.Error("close response body", "error", err.Error())
		}
	}()

	// ISSUE-027: cap metrics response body. Real metrics JSON is
	// under a few MiB; 16 MiB is generous headroom while preventing
	// a misbehaving local node from OOM-ing the termui process.
	responseBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxMetricsResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(responseBytes)) > maxMetricsResponseBytes {
		return nil, fmt.Errorf("metrics response exceeds %d bytes", maxMetricsResponseBytes)
	}

	var metricsResponse responseFromApi
	err = json.Unmarshal(responseBytes, &metricsResponse)
	if err != nil {
		return nil, err
	}

	return metricsResponse.Data.Response, nil
}

func (smp *StatusMetricsProvider) loadMetricsFromGatewayApi(statusMetricsUrl string) (uint64, error) {
	client := newHTTPClient()

	resp, err := client.Get(statusMetricsUrl)
	if err != nil {
		return 0, err
	}
	defer func() {
		err = resp.Body.Close()
		if err != nil {
			log.Error("close response body", "error", err.Error())
		}
	}()

	// ISSUE-027: cap gateway-api response body (same rationale as above).
	responseBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxMetricsResponseBytes+1))
	if err != nil {
		return 0, err
	}
	if int64(len(responseBytes)) > maxMetricsResponseBytes {
		return 0, fmt.Errorf("gateway metrics response exceeds %d bytes", maxMetricsResponseBytes)
	}

	var metricsResponse responseFromGatewayApi
	err = json.Unmarshal(responseBytes, &metricsResponse)
	if err != nil {
		return 0, err
	}

	return metricsResponse.Data.AccountSnapshotsNumNodes, nil
}

func (smp *StatusMetricsProvider) applyMetricsToPresenter(metricsMap map[string]interface{}) {
	var err error
	for key, value := range metricsMap {
		err = smp.setPresenterValue(key, value)
		if err != nil {
			log.Debug("termui metric set",
				"error", err.Error())
		}
	}
}

func (smp *StatusMetricsProvider) setPresenterValue(key string, value interface{}) error {
	switch v := value.(type) {
	case float64:
		// json unmarshal treats all the numbers (in a field interface{}) as floats, so we need to cast it to uint64
		// because it is the numeric type used by the presenter
		smp.presenter.SetUInt64Value(key, uint64(v))
	case string:
		smp.presenter.SetStringValue(key, v)
	default:
		return ErrTypeAssertionFailed
	}

	return nil
}

func formatUrlAddress(address string) string {
	httpPrefix := "http://"
	if !strings.HasPrefix(address, "http") {
		address = httpPrefix + address
	}

	suffix := "/"
	if strings.HasSuffix(address, suffix) {
		address = address[:len(address)-1]
	}

	return address
}
