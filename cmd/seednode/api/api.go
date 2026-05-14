package api

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/api/logs"
	logger "github.com/multiversx/mx-chain-logger-go"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var log = logger.GetOrCreate("seednode/api")

// Start will boot up the api and appropriate routes, handlers and validators
func Start(restApiInterface string, marshalizer marshal.Marshalizer, p2pPrometheusMetricsEnabled bool) error {
	ws := gin.Default()
	// ISSUE-026: previously `cors.Default()` (wildcard) was used. Even
	// though the seednode API is typically bootstrap infrastructure,
	// the same restrictive-default pattern as the indexer / chain-go
	// REST applies. See issues/ISSUE-015.
	corsCfg := cors.DefaultConfig()
	corsCfg.AllowOriginFunc = isAllowedCORSOrigin
	corsCfg.AddAllowHeaders("Authorization")
	ws.Use(cors.New(corsCfg))

	registerRoutes(ws, marshalizer, p2pPrometheusMetricsEnabled)

	return ws.Run(restApiInterface)
}

func registerRoutes(ws *gin.Engine, marshalizer marshal.Marshalizer, p2pPrometheusMetricsEnabled bool) {
	registerLoggerWsRoute(ws, marshalizer, p2pPrometheusMetricsEnabled)
}

func registerLoggerWsRoute(ws *gin.Engine, marshalizer marshal.Marshalizer, p2pPrometheusMetricsEnabled bool) {
	// ISSUE-026 / ISSUE-016: previously the upgrader's CheckOrigin returned
	// true unconditionally (accept-all). Apply the same loopback-only
	// Origin check used by the REST CORS layer and add a HandshakeTimeout
	// so a slow TCP client cannot tie up the goroutine indefinitely.
	upgrader := websocket.Upgrader{
		HandshakeTimeout: 10 * time.Second,
		CheckOrigin:      isAllowedWebSocketOrigin,
	}

	ws.GET("/log", func(c *gin.Context) {
		conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			log.Error(err.Error())
			return
		}

		ls, err := logs.NewLogSender(marshalizer, conn, log)
		if err != nil {
			log.Error(err.Error())
			return
		}

		ls.StartSendingBlocking()
	})

	if p2pPrometheusMetricsEnabled {
		ws.GET("/debug/metrics/prometheus", gin.WrapH(promhttp.Handler()))
	}
}

// isAllowedCORSOrigin permits only same-host (loopback) Origins for the
// seednode REST surface. See issues/ISSUE-015 and ISSUE-026.
func isAllowedCORSOrigin(origin string) bool {
	parsedOrigin, err := url.Parse(origin)
	if err != nil {
		return false
	}
	hostname := strings.ToLower(parsedOrigin.Hostname())
	return hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1"
}

// isAllowedWebSocketOrigin requires the WS Origin to share the same host
// as the request target. Empty Origin (non-browser clients) is rejected
// for the seednode log surface — anyone needing to read logs at this
// level can do so from the same host with no Origin header. See
// issues/ISSUE-016 and ISSUE-026.
func isAllowedWebSocketOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	parsedOrigin, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return parsedOrigin.Host == r.Host
}
