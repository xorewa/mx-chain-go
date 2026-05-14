package provider

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

type closeTracker struct {
	io.Reader
	closed bool
}

func (ct *closeTracker) Close() error {
	ct.closed = true
	return nil
}

func TestStatusMetricsProvider_LoadMetricsFromApiShouldCapResponseAndCloseBody(t *testing.T) {
	largeBody := bytes.Repeat([]byte("a"), maxMetricsResponseBytes+1)
	body := &closeTracker{Reader: bytes.NewReader(largeBody)}

	oldNewHTTPClient := newHTTPClient
	newHTTPClient = func() *http.Client {
		return &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				require.Equal(t, "http://observer/node/status", req.URL.String())
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       body,
				}, nil
			}),
		}
	}
	defer func() {
		newHTTPClient = oldNewHTTPClient
	}()

	smp := &StatusMetricsProvider{nodeAddress: "http://observer"}
	metrics, err := smp.loadMetricsFromApi(statusMetricsUrlSuffix)

	require.Nil(t, metrics)
	require.ErrorContains(t, err, "metrics response exceeds")
	require.True(t, body.closed)
}

func TestStatusMetricsProvider_LoadMetricsFromGatewayApiShouldCapResponseAndCloseBody(t *testing.T) {
	largeBody := bytes.Repeat([]byte("a"), maxMetricsResponseBytes+1)
	body := &closeTracker{Reader: bytes.NewReader(largeBody)}

	oldNewHTTPClient := newHTTPClient
	newHTTPClient = func() *http.Client {
		return &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				require.Equal(t, "http://gateway/network/trie-statistics/0", req.URL.String())
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       body,
				}, nil
			}),
		}
	}
	defer func() {
		newHTTPClient = oldNewHTTPClient
	}()

	smp := &StatusMetricsProvider{}
	value, err := smp.loadMetricsFromGatewayApi("http://gateway/network/trie-statistics/0")

	require.Zero(t, value)
	require.ErrorContains(t, err, "gateway metrics response exceeds")
	require.True(t, body.closed)
}

func TestStatusMetricsProvider_LoadMetricsFromApiShouldDecodeMetrics(t *testing.T) {
	body := &closeTracker{Reader: bytes.NewReader([]byte(`{"data":{"metrics":{"erd_nonce":7,"erd_node_type":"observer"}}}`))}

	oldNewHTTPClient := newHTTPClient
	newHTTPClient = func() *http.Client {
		return &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       body,
				}, nil
			}),
		}
	}
	defer func() {
		newHTTPClient = oldNewHTTPClient
	}()

	smp := &StatusMetricsProvider{nodeAddress: "http://observer"}
	metrics, err := smp.loadMetricsFromApi(statusMetricsUrlSuffix)

	require.Nil(t, err)
	require.Equal(t, float64(7), metrics["erd_nonce"])
	require.Equal(t, "observer", metrics["erd_node_type"])
	require.True(t, body.closed)
}
