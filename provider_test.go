package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sync/singleflight"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestProviderQuotaSerializesFreshIPsAndResumes(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", fmt.Sprint(now.Add(time.Hour).Unix()))
		fmt.Fprint(w, `{"data":{"abuseConfidenceScore":0,"totalReports":0}}`)
	}))
	defer srv.Close()
	c := newProviderClient(srv.Client(), srv.URL, newServiceMetrics(), nil)
	c.now = func() time.Time { return now }
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); c.query(context.Background(), "secret", "8.8.8.8", 90) }()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("upstream calls=%d", calls.Load())
	}
	now = now.Add(time.Hour)
	if _, err := c.query(context.Background(), "secret", "8.8.4.4", 90); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatal("did not resume after reset")
	}
}
func TestProviderOutagePreservesCachedAllowAndBlock(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(429)
	}))
	defer srv.Close()
	cache := &fakeCache{values: map[string]string{}}
	for ip, score := range map[string]int{"1.1.1.1": 0, "9.9.9.9": 100} {
		raw, _ := json.Marshal(abuseResponse(score, 1))
		cache.values["abuseipdb:"+ip] = string(raw)
	}
	m := newServiceMetrics()
	c := newProviderClient(srv.Client(), srv.URL, m, cache)
	handler := &checker{cache: cache, query: c.query, threshold: 25, cacheTTL: time.Hour, metrics: m}
	for _, tc := range []struct {
		ip   string
		code int
	}{{"8.8.8.8", 503}, {"8.8.4.4", 503}, {"1.1.1.1", 200}, {"9.9.9.9", 403}} {
		req := httptest.NewRequest("GET", "/check", nil)
		req.Header.Set("X-Real-Ip", tc.ip)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != tc.code {
			t.Fatalf("%s code=%d want %d", tc.ip, rec.Code, tc.code)
		}
		if tc.code == 503 && rec.Header().Get("Retry-After") == "" {
			t.Fatal("missing Retry-After")
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("calls=%d", calls.Load())
	}
	// A new client restores cooldown from the same persistent cache.
	c2 := newProviderClient(srv.Client(), srv.URL, m, cache)
	_, err := c2.query(context.Background(), "key", "4.2.2.2", 90)
	var unavailable *providerUnavailable
	if !errors.As(err, &unavailable) || !unavailable.suppressed || calls.Load() != 1 {
		t.Fatalf("cooldown not restored: %v calls %d", err, calls.Load())
	}
	var group singleflight.Group
	_, _ = lookupAbuseData(context.Background(), cache, &group, c2.query, logger{}, m, "key", "4.2.2.1", 90, time.Hour)
	families, _ := m.registry.Gather()
	for _, f := range families {
		if f.GetName() == "goipabuse_api_requests_total" {
			for _, v := range f.Metric {
				if v.Counter.GetValue() != 1 {
					t.Fatalf("suppressed lookup counted as API call: %v", f)
				}
			}
		}
	}
}
func TestProviderRecoveryAndMalformedResponses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		wait   time.Duration
	}{{"server", 500, "", 30 * time.Second}, {"auth", 401, "", 5 * time.Minute}, {"invalid_json", 200, "broken", 30 * time.Second}, {"missing_score", 200, `{"data":{}}`, 30 * time.Second}, {"bad_score", 200, `{"data":{"abuseConfidenceScore":101,"totalReports":0}}`, 30 * time.Second}} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now().Truncate(time.Second)
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if calls == 1 {
					w.WriteHeader(tc.status)
					fmt.Fprint(w, tc.body)
				} else {
					fmt.Fprint(w, `{"data":{"abuseConfidenceScore":1,"totalReports":2}}`)
				}
			}))
			defer srv.Close()
			c := newProviderClient(srv.Client(), srv.URL, nil, nil)
			c.now = func() time.Time { return now }
			if _, err := c.query(context.Background(), "key", "8.8.8.8", 90); err == nil {
				t.Fatal("failed response allowed")
			}
			if _, err := c.query(context.Background(), "key", "8.8.4.4", 90); err == nil || calls != 1 {
				t.Fatal("cooldown failed")
			}
			now = now.Add(tc.wait)
			if got, err := c.query(context.Background(), "key", "8.8.4.4", 90); err != nil || got.Data.AbuseConfidenceScore != 1 || calls != 2 {
				t.Fatalf("recovery %v %v", got, err)
			}
		})
	}
}
func TestProviderCanceledQueueDoesNotSpendQuota(t *testing.T) {
	c := newProviderClient(http.DefaultClient, "http://unused.invalid", nil, nil)
	c.gate <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.query(ctx, "key", "8.8.8.8", 90); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func TestRetryTimeFormats(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, s := range []string{"90", now.Add(90 * time.Second).Format(http.TimeFormat)} {
		if got := retryTime(s, now); !got.Equal(now.Add(90 * time.Second)) {
			t.Fatal(got)
		}
	}
}

func TestQuota429HonorsLongerResetAndPersistsUnknownHeaderFallback(t *testing.T) {
	for _, headers := range []map[string]string{{"Retry-After": "60", "X-RateLimit-Reset": "7200"}, {}} {
		now := time.Unix(3600, 0)
		calls := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			for k, v := range headers {
				w.Header().Set(k, v)
			}
			w.WriteHeader(429)
		}))
		c := newProviderClient(srv.Client(), srv.URL, nil, nil)
		c.now = func() time.Time { return now }
		_, err := c.query(context.Background(), "key", "8.8.8.8", 90)
		var unavailable *providerUnavailable
		if !errors.As(err, &unavailable) || unavailable.until.Unix() != 7200 {
			t.Fatalf("quota resume=%v err=%v", c.state, err)
		}
		now = time.Unix(7199, 0)
		_, _ = c.query(context.Background(), "key", "8.8.4.4", 90)
		if calls != 1 {
			t.Fatal("lookup issued before cooldown expired")
		}
		srv.Close()
	}
}
