package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/stretchr/testify/require"
)

// R7 source label for producer-selected fixture inputs bound throughout this file:
// Experimental R7 fixture inputs: trie concurrency 1, five-second waits and alice/bob request identities.
// Register: XV-SP2-81B3C-SWEEP-NODE-API-MIDDLEWARE-QUAL-GATE-G12; owner replaces or confirms before testnet
// admission.
// Native constants, structural indices/counters and derived assertions retain their source-defined meaning.

func TestQualGateG12BusyResponseShape(t *testing.T) {
	r := gin.New()
	installTrieLimiters(r, config.TrieOperationsConfig{MaxConcurrentRequests: 1})
	r.GET("/address/:address/keys", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"keys": []string{}}) })
	w := &blockedTrieResponse{deadlineRecorder: newDeadlineRecorder(), started: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/address/alice/keys", nil))
	}()
	defer func() {
		close(w.release)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("held request did not exit")
		}
	}()
	select {
	case <-w.started:
	case <-time.After(5 * time.Second):
		t.Fatal("first route did not acquire admission")
	}
	busy := newDeadlineRecorder()
	r.ServeHTTP(busy, httptest.NewRequest(http.MethodGet, "/address/bob/keys", nil))
	t.Logf("raw busy reply: HTTP %d %s", busy.Code, busy.Body.String())
	require.Equal(t, 429, busy.Code)
	require.JSONEq(t, `{"data":null,"error":"too many concurrent trie operations","code":"system_busy"}`, busy.Body.String())
}
