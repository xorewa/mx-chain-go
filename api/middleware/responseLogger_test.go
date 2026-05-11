package middleware

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/stretchr/testify/assert"
)

func startNodeServerResponseLogger(handler func(c *gin.Context), respLogMiddleware *responseLoggerMiddleware) *gin.Engine {
	ws := gin.New()
	ws.Use(cors.Default())
	ws.Use(respLogMiddleware.MiddlewareHandlerFunc())

	ginAddressRoutes := ws.Group("/address")
	ginAddressRoutes.Handle(http.MethodGet, "/:address/balance", handler)

	return ws
}

type responseLogFields struct {
	title    string
	path     string
	request  string
	duration time.Duration
	status   int
	response string
}

func TestNewResponseLoggerMiddleware(t *testing.T) {
	t.Parallel()

	rlm := NewResponseLoggerMiddleware(10)

	assert.False(t, check.IfNil(rlm))
}

func TestResponseLoggerMiddleware_DurationExceedsTimeout(t *testing.T) {
	t.Parallel()

	thresholdDuration := 10 * time.Millisecond
	addr := "testAddress"

	handlerFunc := func(c *gin.Context) {
		time.Sleep(thresholdDuration + 1*time.Millisecond)
		c.JSON(200, "ok")
	}

	rlf := responseLogFields{}
	printHandler := func(title string, path string, duration time.Duration, status int, request string, response string) {
		rlf.title = title
		rlf.path = path
		rlf.duration = duration
		rlf.status = status
		rlf.response = response
		rlf.request = request
	}

	rlm := NewResponseLoggerMiddleware(thresholdDuration)
	rlm.printRequestFunc = printHandler

	ws := startNodeServerResponseLogger(handlerFunc, rlm)

	req, _ := http.NewRequest("GET", fmt.Sprintf("/address/%s/balance", addr), nil)
	req.RemoteAddr = "bad address"
	resp := httptest.NewRecorder()
	ws.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)
	assert.True(t, strings.Contains(rlf.title, prefixDurationTooLong))
	assert.True(t, rlf.duration > thresholdDuration)
	assert.Equal(t, http.StatusOK, rlf.status)
}

func TestResponseLoggerMiddleware_BadRequest(t *testing.T) {
	t.Parallel()

	thresholdDuration := 10000 * time.Millisecond

	handlerFunc := func(c *gin.Context) {
		c.JSON(400, "bad request")
	}
	rlf := responseLogFields{}
	printHandler := func(title string, path string, duration time.Duration, status int, request string, response string) {
		rlf.title = title
		rlf.path = path
		rlf.duration = duration
		rlf.status = status
		rlf.response = response
		rlf.request = request
	}

	rlm := NewResponseLoggerMiddleware(thresholdDuration)
	rlm.printRequestFunc = printHandler

	ws := startNodeServerResponseLogger(handlerFunc, rlm)

	req, _ := http.NewRequest("GET", "/address//balance", nil)
	req.RemoteAddr = "bad address"
	resp := httptest.NewRecorder()
	ws.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.True(t, strings.Contains(rlf.title, prefixBadRequest))
	assert.True(t, rlf.duration < thresholdDuration)
	assert.Equal(t, http.StatusBadRequest, rlf.status)
}

func TestResponseLoggerMiddleware_InternalError(t *testing.T) {
	t.Parallel()

	expectedErr := errors.New("internal err")
	thresholdDuration := 10000 * time.Millisecond

	handlerFunc := func(c *gin.Context) {
		c.JSON(500, expectedErr.Error())
	}

	rlf := responseLogFields{}
	printHandler := func(title string, path string, duration time.Duration, status int, request string, response string) {
		rlf.title = title
		rlf.path = path
		rlf.duration = duration
		rlf.status = status
		rlf.response = response
		rlf.request = request
	}

	rlm := NewResponseLoggerMiddleware(thresholdDuration)
	rlm.printRequestFunc = printHandler

	ws := startNodeServerResponseLogger(handlerFunc, rlm)

	req, _ := http.NewRequest("GET", "/address/addr/balance", nil)
	req.RemoteAddr = "bad address"
	resp := httptest.NewRecorder()
	ws.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusInternalServerError, resp.Code)
	assert.True(t, strings.Contains(rlf.title, prefixInternalError))
	assert.True(t, rlf.duration < thresholdDuration)
	assert.Equal(t, http.StatusInternalServerError, rlf.status)
	assert.True(t, strings.Contains(rlf.response, removeWhitespacesFromString(expectedErr.Error())))
}

func TestResponseLoggerMiddleware_ShouldNotCallHandler(t *testing.T) {
	t.Parallel()

	thresholdDuration := 10000 * time.Millisecond

	handlerWasCalled := false
	printHandler := func(title string, path string, duration time.Duration, status int, request string, response string) {
		handlerWasCalled = true
	}

	rlm := NewResponseLoggerMiddleware(thresholdDuration)
	rlm.printRequestFunc = printHandler

	ws := startNodeServerResponseLogger(func(c *gin.Context) {}, rlm)

	req, _ := http.NewRequest("GET", "/address/addr/balance", nil)
	req.RemoteAddr = "bad address"
	resp := httptest.NewRecorder()
	ws.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)
	assert.False(t, handlerWasCalled)
}

func TestResponseLoggerMiddleware_PrepareLogPayloadTruncatesBeforeWhitespaceRemoval(t *testing.T) {
	t.Parallel()

	input := strings.Repeat(" ", loggedPayloadMaxLength*4) + "visible"

	assert.Empty(t, prepareLogPayload(input))
}

func TestResponseLoggerMiddleware_ReadsBoundedRequestForLogging(t *testing.T) {
	t.Parallel()

	thresholdDuration := 10000 * time.Millisecond
	rlf := responseLogFields{}
	printHandler := func(title string, path string, duration time.Duration, status int, request string, response string) {
		rlf.request = request
	}

	rlm := NewResponseLoggerMiddleware(thresholdDuration)
	rlm.printRequestFunc = printHandler

	ws := startNodeServerResponseLogger(func(c *gin.Context) {
		c.JSON(http.StatusBadRequest, "bad request")
	}, rlm)

	req, _ := http.NewRequest(http.MethodGet, "/address/addr/balance", io.NopCloser(strings.NewReader(strings.Repeat("a", loggedPayloadMaxLength*4))))
	resp := httptest.NewRecorder()
	ws.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Len(t, rlf.request, loggedPayloadMaxLength)
}

func TestBodyWriter_CapturesBoundedResponseForLogging(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	bw := bodyWriter{
		body:           bytes.NewBufferString(""),
		ResponseWriter: ctx.Writer,
	}
	payload := strings.Repeat("a", loggedPayloadMaxLength*4)

	written, err := bw.Write([]byte(payload))

	assert.NoError(t, err)
	assert.Equal(t, len(payload), written)
	assert.Len(t, bw.body.String(), loggedPayloadMaxLength+1)
	assert.Equal(t, payload, recorder.Body.String())
}
