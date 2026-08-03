package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/singleflight"
)

type fakeCache struct {
	mu      sync.Mutex
	values  map[string]string
	getErr  error
	setErr  error
	deleteN int
	setN    int
}

func (c *fakeCache) Get(_ context.Context, key string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.getErr != nil {
		return "", c.getErr
	}
	value, ok := c.values[key]
	if !ok {
		return "", redis.Nil
	}
	return value, nil
}

func (c *fakeCache) Set(_ context.Context, key, value string, _ time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setN++
	if c.setErr != nil {
		return c.setErr
	}
	c.values[key] = value
	return nil
}

func (c *fakeCache) Del(_ context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deleteN++
	delete(c.values, key)
	return nil
}

func abuseResponse(score, reports int) abuseResp {
	var response abuseResp
	response.Data.AbuseConfidenceScore = score
	response.Data.TotalReports = reports
	return response
}

func TestLookupAbuseDataTreatsInvalidCacheAsMiss(t *testing.T) {
	cache := &fakeCache{values: map[string]string{"abuseipdb:203.0.113.10": "not-json"}}
	var group singleflight.Group
	var queryN atomic.Int32
	want := abuseResponse(42, 3)

	got, err := lookupAbuseData(
		context.Background(), cache, &group,
		func(context.Context, string, string, int) (abuseResp, error) {
			queryN.Add(1)
			return want, nil
		},
		logger{level: levelError}, nil, "key", "203.0.113.10", 90, time.Hour,
	)
	if err != nil {
		t.Fatalf("lookupAbuseData() error = %v", err)
	}
	if got.response != want {
		t.Fatalf("lookupAbuseData() response = %+v, want %+v", got.response, want)
	}
	if got.source != lookupSourceAPI {
		t.Fatalf("lookupAbuseData() source = %q, want %q", got.source, lookupSourceAPI)
	}
	if queryN.Load() != 1 {
		t.Fatalf("query count = %d, want 1", queryN.Load())
	}
	if cache.deleteN != 1 {
		t.Fatalf("cache delete count = %d, want 1", cache.deleteN)
	}
	if cache.setN != 1 {
		t.Fatalf("cache set count = %d, want 1", cache.setN)
	}
}

func TestLookupAbuseDataCoalescesConcurrentMisses(t *testing.T) {
	cache := &fakeCache{values: make(map[string]string)}
	var group singleflight.Group
	var queryN atomic.Int32
	queryStarted := make(chan struct{})
	releaseQuery := make(chan struct{})
	query := func(context.Context, string, string, int) (abuseResp, error) {
		if queryN.Add(1) == 1 {
			close(queryStarted)
		}
		<-releaseQuery
		return abuseResponse(7, 1), nil
	}

	const requests = 32
	start := make(chan struct{})
	errs := make(chan error, requests)
	var wg sync.WaitGroup
	for range requests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := lookupAbuseData(
				context.Background(), cache, &group, query,
				logger{level: levelError}, nil, "key", "203.0.113.20", 90, time.Hour,
			)
			errs <- err
		}()
	}

	close(start)
	<-queryStarted
	close(releaseQuery)
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("lookupAbuseData() error = %v", err)
		}
	}
	if queryN.Load() != 1 {
		t.Fatalf("query count = %d, want 1", queryN.Load())
	}
}

func TestLookupAbuseDataReturnsDataWhenCacheWriteFails(t *testing.T) {
	cache := &fakeCache{values: make(map[string]string), setErr: errors.New("read only")}
	var group singleflight.Group
	want := abuseResponse(12, 2)

	got, err := lookupAbuseData(
		context.Background(), cache, &group,
		func(context.Context, string, string, int) (abuseResp, error) { return want, nil },
		logger{level: levelError}, nil, "key", "203.0.113.30", 90, time.Hour,
	)
	if err != nil {
		t.Fatalf("lookupAbuseData() error = %v", err)
	}
	if got.response != want {
		t.Fatalf("lookupAbuseData() response = %+v, want %+v", got.response, want)
	}
	if got.source != lookupSourceAPI {
		t.Fatalf("lookupAbuseData() source = %q, want %q", got.source, lookupSourceAPI)
	}
}

func TestLookupAbuseDataReportsCacheSource(t *testing.T) {
	cache := &fakeCache{
		values: map[string]string{
			"abuseipdb:203.0.113.40": `{"data":{"abuseConfidenceScore":18,"totalReports":4}}`,
		},
	}
	var group singleflight.Group

	got, err := lookupAbuseData(
		context.Background(), cache, &group,
		func(context.Context, string, string, int) (abuseResp, error) {
			t.Fatal("query called for cache hit")
			return abuseResp{}, nil
		},
		logger{level: levelError}, nil, "key", "203.0.113.40", 90, time.Hour,
	)
	if err != nil {
		t.Fatalf("lookupAbuseData() error = %v", err)
	}
	if got.response != abuseResponse(18, 4) {
		t.Fatalf("lookupAbuseData() response = %+v", got.response)
	}
	if got.source != lookupSourceCache {
		t.Fatalf("lookupAbuseData() source = %q, want %q", got.source, lookupSourceCache)
	}
}

func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		realIP     string
		forwarded  string
		remoteAddr string
		want       string
	}{
		{name: "real IP", realIP: "203.0.113.1", forwarded: "203.0.113.2", remoteAddr: "203.0.113.3:1234", want: "203.0.113.1"},
		{name: "first forwarded IP", forwarded: "203.0.113.2, 10.0.0.1", remoteAddr: "203.0.113.3:1234", want: "203.0.113.2"},
		{name: "remote address", remoteAddr: "203.0.113.3:1234", want: "203.0.113.3"},
		{name: "unqualified remote address", remoteAddr: "203.0.113.4", want: "203.0.113.4"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/check", nil)
			req.RemoteAddr = tt.remoteAddr
			req.Header.Set("X-Real-IP", tt.realIP)
			req.Header.Set("X-Forwarded-For", tt.forwarded)
			if got := clientIP(req); got != tt.want {
				t.Fatalf("clientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIPInCIDRs(t *testing.T) {
	_, privateNetwork, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}

	if !ipInCIDRs(net.ParseIP("10.1.2.3"), []*net.IPNet{privateNetwork}) {
		t.Fatal("private IP was not matched")
	}
	if ipInCIDRs(net.ParseIP("203.0.113.1"), []*net.IPNet{privateNetwork}) {
		t.Fatal("public IP matched private CIDR")
	}
}

func TestIsBlocked(t *testing.T) {
	tests := []struct {
		score, threshold int
		want             bool
	}{
		{score: 24, threshold: 25, want: false},
		{score: 25, threshold: 25, want: true},
		{score: 100, threshold: 25, want: true},
	}

	for _, tt := range tests {
		if got := isBlocked(tt.score, tt.threshold); got != tt.want {
			t.Fatalf("isBlocked(%d, %d) = %t, want %t", tt.score, tt.threshold, got, tt.want)
		}
	}
}

func TestCheckerReturnsDecisionHeadersAndStructuredContext(t *testing.T) {
	cache := &fakeCache{
		values: map[string]string{
			"abuseipdb:203.0.113.50": `{"data":{"abuseConfidenceScore":42,"totalReports":9}}`,
		},
	}
	var logs bytes.Buffer
	handler := &checker{
		threshold: 25,
		maxAge:    90,
		cacheTTL:  time.Hour,
		cache:     cache,
		query: func(context.Context, string, string, int) (abuseResp, error) {
			t.Fatal("query called for cache hit")
			return abuseResp{}, nil
		},
		logger: newLoggerWithWriter(levelInfo, logFormatJSON, &logs),
	}

	req := httptest.NewRequest(http.MethodGet, "http://auth/check", nil)
	req.Header.Set("X-Real-IP", "203.0.113.50")
	req.Header.Set("X-Forwarded-Host", "Example.COM")
	req.Header.Set("X-Forwarded-Method", "post")
	req.Header.Set("X-Forwarded-Uri", "/login?token=secret")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
	wantHeaders := map[string]string{
		headerAbuseDecision: "blocked",
		headerAbuseSource:   "cache",
		headerAbuseScore:    "42",
		headerAbuseReports:  "9",
	}
	for name, want := range wantHeaders {
		if got := recorder.Header().Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}

	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(logs.Bytes()), &entry); err != nil {
		t.Fatalf("decode JSON log: %v\n%s", err, logs.String())
	}
	wantFields := map[string]any{
		"event":     "auth_decision",
		"decision":  "blocked",
		"source":    "cache",
		"client_ip": "203.0.113.50",
		"host":      "example.com",
		"method":    "POST",
		"path":      "/login",
	}
	for name, want := range wantFields {
		if got := entry[name]; got != want {
			t.Errorf("log field %s = %#v, want %#v", name, got, want)
		}
	}
	if strings.Contains(logs.String(), "secret") {
		t.Fatal("sanitized log contains query parameter value")
	}
}

func TestCheckerReportsCIDRBypass(t *testing.T) {
	_, privateNetwork, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	handler := &checker{
		threshold: 25,
		skipCIDRs: []*net.IPNet{privateNetwork},
		logger:    newLoggerWithWriter(levelError, logFormatText, io.Discard),
	}
	req := httptest.NewRequest(http.MethodGet, "http://auth/check", nil)
	req.Header.Set("X-Real-IP", "10.1.2.3")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if got := recorder.Header().Get(headerAbuseDecision); got != "allowed" {
		t.Fatalf("%s = %q, want allowed", headerAbuseDecision, got)
	}
	if got := recorder.Header().Get(headerAbuseSource); got != "cidr" {
		t.Fatalf("%s = %q, want cidr", headerAbuseSource, got)
	}
}

func TestMetricsExposeDecisionAndCacheSource(t *testing.T) {
	metrics := newServiceMetrics()
	cache := &fakeCache{
		values: map[string]string{
			"abuseipdb:203.0.113.60": `{"data":{"abuseConfidenceScore":10,"totalReports":1}}`,
		},
	}
	handler := &checker{
		threshold: 25,
		maxAge:    90,
		cacheTTL:  time.Hour,
		cache:     cache,
		query: func(context.Context, string, string, int) (abuseResp, error) {
			t.Fatal("query called for cache hit")
			return abuseResp{}, nil
		},
		logger:  newLoggerWithWriter(levelError, logFormatText, io.Discard),
		metrics: metrics,
	}
	req := httptest.NewRequest(http.MethodGet, "http://auth/check", nil)
	req.Header.Set("X-Real-IP", "203.0.113.60")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	metricsRecorder := httptest.NewRecorder()
	metricsMux(metrics).ServeHTTP(metricsRecorder, httptest.NewRequest(http.MethodGet, "http://metrics/metrics", nil))
	body := metricsRecorder.Body.String()
	for _, metric := range []string{
		`goipabuse_decisions_total{decision="allowed",source="cache"} 1`,
		`goipabuse_cache_operations_total{operation="read",result="hit"} 1`,
		`goipabuse_score_count 1`,
	} {
		if !strings.Contains(body, metric) {
			t.Errorf("metrics output missing %q", metric)
		}
	}
}

func TestJSONLoggerSerializesErrorsAndFormats(t *testing.T) {
	var output bytes.Buffer
	logger := newLoggerWithWriter(levelInfo, logFormatJSON, &output)
	logger.Event(levelInfo, "test_event",
		field("error", errors.New("test failure")),
		field("log_level", levelWarn),
		field("log_format", logFormatJSON),
	)

	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &entry); err != nil {
		t.Fatalf("decode JSON log: %v", err)
	}
	if entry["error"] != "test failure" {
		t.Fatalf("error = %#v", entry["error"])
	}
	if entry["log_level"] != "WARN" {
		t.Fatalf("log_level = %#v", entry["log_level"])
	}
	if entry["log_format"] != "json" {
		t.Fatalf("log_format = %#v", entry["log_format"])
	}
}
