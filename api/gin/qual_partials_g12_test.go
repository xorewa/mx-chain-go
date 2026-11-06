package gin

import (
	"fmt"
	ginFramework "github.com/gin-gonic/gin"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
)

// R7 source label for producer-selected fixture inputs bound throughout this file:
// Experimental R7 fixture inputs: antiflood capacities 100, reset interval 3600, trie concurrency 1 and
// synthetic address 00. Register: XV-SP2-81B3C-SWEEP-NODE-API-GIN-QUAL-PARTIALS-G12; owner replaces or
// confirms before testnet admission.
// Native constants, structural indices/counters and derived assertions retain their source-defined meaning.

func TestQualPartialsG12ActualAdmissionAssembly(t *testing.T) {
	for _, antiflood := range []bool{false, true} {
		t.Run(fmt.Sprintf("antiflood_%t", antiflood), func(t *testing.T) {
			args := createMockArgsNewWebServer()
			args.ApiConfig.Logging.LoggingEnabled = false
			args.AntiFloodConfig.WebServerAntifloodEnabled = antiflood
			args.AntiFloodConfig.SameSourceRequests = 100
			args.AntiFloodConfig.SimultaneousRequests = 100
			args.AntiFloodConfig.SameSourceResetIntervalInSec = 3600
			args.TrieOperations = config.TrieOperationsConfig{MaxConcurrentRequests: 1}
			ws, e := NewGinWebServerHandler(args)
			require.NoError(t, e)
			processors, e := ws.createMiddlewareLimiters()
			require.NoError(t, e)
			if ws.cancelFunc != nil {
				defer ws.cancelFunc()
			}
			r := ginFramework.New()
			for _, p := range processors {
				r.Use(p.MiddlewareHandlerFunc())
			}
			calls := 0
			r.GET("/address/:address/keys", func(c *ginFramework.Context) { calls++; c.Status(http.StatusOK) })
			r.GET("/network/esdts", func(c *ginFramework.Context) {
				w := &trieDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
				r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/address/00/keys", nil))
				require.Equal(t, http.StatusTooManyRequests, w.Code, "actual assembled trie admission")
				require.JSONEq(t, `{"data":null,"error":"too many concurrent trie operations","code":"system_busy"}`, w.Body.String())
				require.True(t, w.Flushed)
				c.Status(http.StatusOK)
			})
			outer := &trieDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
			r.ServeHTTP(outer, httptest.NewRequest(http.MethodGet, "/network/esdts", nil))
			require.Equal(t, http.StatusOK, outer.Code)
			require.Zero(t, calls, "busy listing cannot reach handler")
			next := &trieDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
			r.ServeHTTP(next, httptest.NewRequest(http.MethodGet, "/address/00/keys", nil))
			require.Equal(t, http.StatusOK, next.Code)
			require.Equal(t, 1, calls, "admission released after response")
		})
	}
}
