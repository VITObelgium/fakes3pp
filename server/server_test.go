package server_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/VITObelgium/fakes3pp/server"
	"github.com/VITObelgium/fakes3pp/testutils"
	"github.com/VITObelgium/fakes3pp/utils"
	io_prometheus_client "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"google.golang.org/protobuf/proto"
)


func CreateTestHandler(t testing.TB, sendSize int64) http.HandlerFunc{
	return func(w http.ResponseWriter, r *http.Request) {
		_, err := io.Copy(io.Discard, r.Body)
	
		if err != nil {
			t.Error("Got a problem when reading all the bytes")
			t.FailNow()
		}
		w.WriteHeader(http.StatusOK)
		_, err = io.Copy(w, testutils.NewNonDeterministicLimitedRandReadSeeker(sendSize))
		if err != nil {
			t.Error("vould not copy in random string")
			t.FailNow()
		}
	}
}

func isMetricOfInterest(metricName string) bool {
	if strings.HasPrefix(metricName, "go_") {
		return false
	} else if strings.HasPrefix(metricName, "process_") {
		return false
	}
	return true
}

func getMetrics(t testing.TB, r io.Reader) (metrics map[string][]*io_prometheus_client.Metric){
	var tp expfmt.TextParser
	notNormalized, err := tp.TextToMetricFamilies(r)
	if err != nil {
		t.Errorf("converting reader to metric families failed: %s", err)
		t.FailNow()
	}
	metrics = map[string][]*io_prometheus_client.Metric{}

	for _, metric := range notNormalized {
		if !isMetricOfInterest(*metric.Name) {
			continue
		}
		if metric.Help == nil {
			metric.Help = proto.String("")
		}
		metrics[*metric.Name] = metric.GetMetric()
	}
	return metrics
}

//Get metrics from a counter where n is the amount of actual metic measurements.
func getCounterMetric(t testing.TB, metricsPort int, metricName string) (n int, sum float64){
	res, err := http.Get(fmt.Sprintf("http://localhost:%d/metrics", metricsPort))
	if err != nil {
		t.Error("Cannot get metrics", "error", err)
		t.FailNow()
	}
	metricDict := getMetrics(t, res.Body)

	requestSizeBytesMetrics, ok := metricDict[metricName]
	if !ok {
		return 0, 0
	}
	n , sum = sumCounters(requestSizeBytesMetrics)
	return
}


//A test to make sure metrics are expose when metrics are enabled and they must be close to reality.
func TestCheckMetricsServer(t *testing.T) {
	//Given responseSize
	var responseSize int64 = 123043
	var sendSize int64 = 53421
	testPort := 8443
	metricsPort := 5555
	//Given a test server which sends a response of a given size and reads everythign
	s := server.NewBasicServer(testPort, "localhost", "", "", CreateTestHandler(t, int64(responseSize)))
	//Given it is started with metrics exposed
	wg, ts, err :=server.CreateAndAwaitHealthy(s, server.ServerOpts{MetricsPort: metricsPort})
	if err != nil {
		t.Error("Could not start server")
		t.FailNow()
	}
	//WHEN we do a request with a given size
	r, err := http.NewRequest("POST", fmt.Sprintf("http://localhost:%d", testPort), testutils.NewNonDeterministicLimitedRandReadSeeker(sendSize))
	if err != nil {
		t.Error("Could not create request")
		t.FailNow()
	}
	client := &http.Client{}
	res, err := client.Do(r)
	if err != nil {
		t.Error("Could not perform HTTP request", "error", err)
		t.FailNow()
	}

	defer utils.Close(res.Body, "TestCheckMetricsServer", r.Context())

	//THEN the metrics must become available in scrapes
	//At least within due time which should be rather fast
	n := 0 
	var requestSizeBytes float64
	for i := 0 ; i < 3 ; i++ { // First time fetching metrics make sure they have actually propagated.
		n, requestSizeBytes = getCounterMetric(t, metricsPort, "http_request_size_bytes")
		if n != 0 {
			break
		}
		time.Sleep(time.Millisecond * time.Duration(100))
	}

	//THEN there must be 1 measuring point for request size
	if n != 1 {
		if n < 1 {
			t.Error("There was not a single request performed")
		} else {
			t.Error("There was more than 1 request performed")
		}
	}
	//THEN the returned size should be close to the actual request size
	assertCloseEnough(t, sendSize, requestSizeBytes, 0.001)

	//THEN we have the same expectations for response size
	n, responseSizeBytes := getCounterMetric(t, metricsPort, "http_response_size_bytes")

	if n != 1 {
		if n < 1 {
			t.Error("There was not a single request performed")
		} else {
			t.Error("There was more than 1 request performed")
		}
	}
	assertCloseEnough(t, responseSize, responseSizeBytes, 0.001)

	//Then the counter for finished responses must be correct
	n, finishedRequests := getCounterMetric(t, metricsPort, "http_requests_finished_total")

	if n != 1 {
		if n < 1 {
			t.Error("There was not a single request performed")
		} else {
			t.Error("There was more than 1 request performed")
		}
	}
	assertCloseEnough(t, 1, finishedRequests, 0.001)
	err = ts.Shutdown(context.Background())
	if err != nil {
		t.Error("Got an error", err)
	}
	wg.Wait()
}

func sumCounters(metrics []*io_prometheus_client.Metric) (n int, sum float64) {
	n = 0
	for _, m := range metrics {
		n += 1
		counter := m.GetCounter()
		if counter == nil { continue }
		sum += *counter.Value
	}
	return n, sum
}

//percentage is how close it needs to be for example 0.01 means it should be +- 1 percent
func assertCloseEnough(t testing.TB, targetValue int64, actualValue float64, percentage float64) {
	lowerBound := float64(targetValue) - float64(targetValue) * float64(percentage)
	upperBound := float64(targetValue) + float64(targetValue) * float64(percentage)
	if actualValue < lowerBound {
		t.Errorf("Actual value too small expected %d, got %f", targetValue, actualValue)
	}
	if actualValue > upperBound {
		t.Errorf("Actual value too big expected %d, got %f", targetValue, actualValue)

	}
}
