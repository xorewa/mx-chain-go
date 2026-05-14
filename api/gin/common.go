package gin

import (
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/gorilla/websocket"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/marshal"
	apiErrors "github.com/multiversx/mx-chain-go/api/errors"
	"github.com/multiversx/mx-chain-go/api/logs"
	"github.com/multiversx/mx-chain-go/config"
	"gopkg.in/go-playground/validator.v8"
)

// ISSUE-016: bounds on the chain-go /log WebSocket surface. These exist
// to keep a single misbehaving (or malicious) reader from monopolising
// the goroutine pool or holding TCP slots open indefinitely.
const (
	logWSMaxConcurrentStreams int32         = 64
	logWSHandshakeTimeout     time.Duration = 10 * time.Second
)

// activeLogWSStreams counts currently-open /log WebSocket connections.
// Bounded by logWSMaxConcurrentStreams; 65th connection is rejected with
// 429.
var activeLogWSStreams int32

type validatorInput struct {
	Name      string
	Validator validator.Func
}

// skValidator validates a secret key from user input for correctness
func skValidator(
	_ *validator.Validate,
	_ reflect.Value,
	_ reflect.Value,
	_ reflect.Value,
	_ reflect.Type,
	_ reflect.Kind,
	_ string,
) bool {
	return true
}

func checkArgs(args ArgsNewWebServer) error {
	if check.IfNil(args.Facade) {
		return fmt.Errorf("%w: %s", apiErrors.ErrCannotCreateGinWebServer, apiErrors.ErrNilFacadeHandler.Error())
	}

	return nil
}

func isLogRouteEnabled(routesConfig config.ApiRoutesConfig) bool {
	logConfig, ok := routesConfig.APIPackages["log"]
	if !ok {
		return false
	}

	for _, cfg := range logConfig.Routes {
		if cfg.Name == "/log" && cfg.Open {
			return true
		}
	}

	return false
}

func registerValidators() error {
	validators := []validatorInput{
		{
			Name:      "skValidator",
			Validator: skValidator,
		},
	}
	for _, validatorFunc := range validators {
		v, ok := binding.Validator.Engine().(*validator.Validate)
		if ok {
			err := v.RegisterValidation(validatorFunc.Name, validatorFunc.Validator)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func registerLoggerWsRoute(ws *gin.Engine, marshalizer marshal.Marshalizer) {
	// ISSUE-016: previously the upgrader was constructed inside the
	// handler with CheckOrigin set to a function that returned true
	// unconditionally — every browser-adjacent caller could stream
	// the node's logs cross-origin. Now: build the upgrader once with
	// HandshakeTimeout + a strict same-host Origin check.
	upgrader := websocket.Upgrader{
		HandshakeTimeout: logWSHandshakeTimeout,
		CheckOrigin:      isAllowedLogWSOrigin,
	}

	ws.GET("/log", func(c *gin.Context) {
		// Per-connection cap. The 65th concurrent reader is rejected with
		// 429 so an attacker cannot pin goroutines + TCP slots
		// indefinitely. counter is decremented in the StartSendingBlocking
		// defer below.
		if atomic.AddInt32(&activeLogWSStreams, 1) > logWSMaxConcurrentStreams {
			atomic.AddInt32(&activeLogWSStreams, -1)
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "too many log streams"})
			return
		}
		defer atomic.AddInt32(&activeLogWSStreams, -1)

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
}

// isAllowedLogWSOrigin requires the WS Origin header to share the same
// host as the request target. Empty Origin is rejected for the /log
// surface — anyone reading logs at this level can do so from the same
// host with no browser between them. See issues/ISSUE-016.
func isAllowedLogWSOrigin(r *http.Request) bool {
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
