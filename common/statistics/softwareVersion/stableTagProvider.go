package softwareVersion

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type stableTagProvider struct {
	stableTagLocation string
	httpClient        *http.Client
}

// NewStableTagProvider returns a new instance of stableTagProvider
func NewStableTagProvider(stableTagLocation string) *stableTagProvider {
	transport := &http.Transport{
		DisableKeepAlives: true,
	}

	return &stableTagProvider{
		stableTagLocation: stableTagLocation,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
	}
}

// FetchTagVersion will call the provided URL and will fetch the software version
func (stp *stableTagProvider) FetchTagVersion() (string, error) {
	resp, err := stp.httpClient.Get(stp.stableTagLocation)
	if err != nil {
		return "", err
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			log.Debug(err.Error())
		}
	}()

	// ISSUE-027: cap upstream-version-tag response body. The expected
	// payload is a small JSON describing the latest release tag.
	// 1 MiB is far more than the GitHub releases API produces in
	// practice; preventing a compromised or proxied upstream from
	// streaming a multi-GiB body into memory.
	const maxStableTagResponseBytes = 1 * 1024 * 1024
	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxStableTagResponseBytes+1))
	if err != nil {
		return "", err
	}
	if int64(len(respBytes)) > maxStableTagResponseBytes {
		return "", fmt.Errorf("stable-tag response exceeds %d bytes", maxStableTagResponseBytes)
	}

	var tag tagVersion
	if err = json.Unmarshal(respBytes, &tag); err != nil {
		return "", err
	}

	return tag.TagVersion, nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (stp *stableTagProvider) IsInterfaceNil() bool {
	return stp == nil
}
