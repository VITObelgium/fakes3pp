package middleware

import (
	"log/slog"
	"net/http"
)

type HealthChecker interface {
	//Check if a request is for health check purposes and if so take care of it
	//the reply communicates back whether it was a healthcheck.
	DoHealthcheckIfNeeded(w http.ResponseWriter, r *http.Request) (wasHealthCHeck bool)

	//At which level should health check activity be logged
	GetHCLogLvl() slog.Level
}

// A healthcheck function is like a closure that can execute whatever logic it wants
// It returns wether all is healthy as well as a body if it is OK or an err
// if there is an unexpected error during healthchecking
type HealthCheckFunction func() (isHealthy bool, okBody []byte, err error)

type pathBasedHC struct {
	//The path where to do healthcheck
	healthcheckPath string

	//The method used for health checking
	method string

	//The actual check
	healthCheckFunction HealthCheckFunction

	//The level used for this health check
	lvl slog.Level
}

// write a reply and if there are issues emit warning
func writeReply(w http.ResponseWriter, body []byte, replyPurpose string) {
	_, err := w.Write(body)
	if err != nil {
		slog.Warn("Could not write HTTP response body", "error", err, "replyPurpose", replyPurpose)
	}
}

func failHealthcheck(w http.ResponseWriter) {
	w.WriteHeader(http.StatusInternalServerError)
	writeReply(w, []byte("failed healthcheck"), "report failing healthcheck")
}

func (hc *pathBasedHC) GetHCLogLvl() slog.Level {
	return hc.lvl
}

func (hc *pathBasedHC) DoHealthcheckIfNeeded(w http.ResponseWriter, r *http.Request) (done bool) {
	if r.Method != hc.method {
		return false
	}
	if r.URL.Path != hc.healthcheckPath {
		return false
	}

	//Seems to be a healthcheck
	isHealthy, okBody, err := hc.healthCheckFunction()
	if err != nil {
		slog.Error("Failing healthcheck", "error", err)
		failHealthcheck(w)
	}
	if isHealthy {
		w.WriteHeader(http.StatusOK)
		writeReply(w, okBody, "report passsing healthcheck")
	} else {
		failHealthcheck(w)
	}
	return true
}

// Create a simple health checker which replies pong to get requests for /ping
func NewPingPongHealthCheck(hcLogLevel slog.Level) HealthChecker {
	pongBody := []byte("pong")
	healthCheckFunction := func() (isHealthy bool, okBody []byte, err error) {
		return true, pongBody, nil
	}
	pphc := pathBasedHC{
		healthcheckPath:     "/ping",
		method:              http.MethodGet,
		healthCheckFunction: healthCheckFunction,
		lvl:                 hcLogLevel,
	}
	return &pphc
}
