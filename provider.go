package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// providerClient owns the provider quota and recovery policy for this process.
// A single context-aware gate prevents fresh IPs from racing the last quota slot.
// Reputation cache hits never enter this gate.
type providerClient struct {
	client   *http.Client
	endpoint string
	gate     chan struct{}
	now      func() time.Time
	metrics  *serviceMetrics
	cache    cacheStore
	state    providerState
	loaded   bool
}
type providerState struct {
	Remaining int    `json:"remaining"`
	Reset     int64  `json:"reset"`
	Resume    int64  `json:"resume"`
	Reason    string `json:"reason"`
}
type providerUnavailable struct {
	until      time.Time
	reason     string
	suppressed bool
}

func (e *providerUnavailable) Error() string { return "provider unavailable: " + e.reason }

func newProviderClient(client *http.Client, endpoint string, metrics *serviceMetrics, cache cacheStore) *providerClient {
	return &providerClient{client: client, endpoint: endpoint, gate: make(chan struct{}, 1), now: time.Now, metrics: metrics, cache: cache, state: providerState{Remaining: -1}}
}
func (c *providerClient) publish() {
	if c.metrics == nil {
		return
	}
	c.metrics.quotaRemaining.Set(float64(c.state.Remaining))
	c.metrics.quotaReset.Set(float64(c.state.Reset))
	c.metrics.providerResume.Set(float64(c.state.Resume))
}
func (c *providerClient) persist(ctx context.Context) {
	c.publish()
	if c.cache == nil {
		return
	}
	ttl := time.Unix(max(c.state.Reset, c.state.Resume), 0).Sub(c.now())
	if ttl <= 0 {
		return
	}
	raw, _ := json.Marshal(c.state)
	if err := c.cache.Set(ctx, "abuseipdb:provider_state", string(raw), ttl); err != nil {
		c.metrics.recordCache("provider_write", "error")
	}
}
func (c *providerClient) query(ctx context.Context, key, ip string, maxAge int) (abuseResp, error) {
	queueCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	select {
	case c.gate <- struct{}{}:
	case <-queueCtx.Done():
		unavailable := &providerUnavailable{c.now().Add(time.Second), "busy", true}
		if ctx.Err() != nil {
			return abuseResp{}, errors.Join(ctx.Err(), unavailable)
		}
		if c.metrics != nil {
			c.metrics.suppressedCalls.Inc()
		}
		return abuseResp{}, unavailable
	}
	defer func() { <-c.gate }()
	if err := ctx.Err(); err != nil {
		return abuseResp{}, errors.Join(err, &providerUnavailable{c.now().Add(time.Second), "canceled", true})
	}
	if !c.loaded {
		if c.cache != nil {
			raw, err := c.cache.Get(ctx, "abuseipdb:provider_state")
			if err == nil {
				var s providerState
				if json.Unmarshal([]byte(raw), &s) == nil {
					c.state = s
				}
			}
		}
		c.loaded = true
	}
	now := c.now()
	if c.state.Resume > now.Unix() {
		if c.metrics != nil {
			c.metrics.suppressedCalls.Inc()
		}
		c.publish()
		return abuseResp{}, &providerUnavailable{time.Unix(c.state.Resume, 0), c.state.Reason, true}
	}
	if c.state.Reset <= now.Unix() {
		c.state.Remaining = -1
		c.state.Reset = 0
	}
	c.state.Resume = 0
	c.state.Reason = ""
	c.publish()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint, nil)
	if err != nil {
		return abuseResp{}, err
	}
	q := req.URL.Query()
	q.Set("ipAddress", ip)
	q.Set("maxAgeInDays", strconv.Itoa(maxAge))
	req.URL.RawQuery = q.Encode()
	req.Header.Set("Key", key)
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		// Caller cancellation is not evidence of a provider outage.
		if errors.Is(ctx.Err(), context.Canceled) {
			return abuseResp{}, ctx.Err()
		}
		return abuseResp{}, c.pause(ctx, now.Add(30*time.Second), "transport")
	}
	defer resp.Body.Close()
	remaining, validRemaining := nonnegativeHeader(resp.Header, "X-RateLimit-Remaining")
	if validRemaining {
		c.state.Remaining = int(remaining)
	}
	reset, validReset := nonnegativeHeader(resp.Header, "X-RateLimit-Reset")
	if validReset && reset > now.Unix() {
		c.state.Reset = reset
	}
	if resp.StatusCode == http.StatusTooManyRequests || validRemaining && remaining == 0 {
		until := now.Add(time.Hour)
		retry := retryTime(resp.Header.Get("Retry-After"), now)
		if c.state.Reset > now.Unix() {
			until = time.Unix(c.state.Reset, 0)
		}
		if retry.After(now) && (c.state.Reset <= now.Unix() || retry.After(until)) {
			until = retry
		}
		c.pause(ctx, until, "quota")
		if resp.StatusCode == http.StatusTooManyRequests {
			return abuseResp{}, &providerUnavailable{until, "quota", false}
		}
	}
	if resp.StatusCode != http.StatusOK {
		delay := 30 * time.Second
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			delay = 5 * time.Minute
		}
		until := now.Add(delay)
		if t := retryTime(resp.Header.Get("Retry-After"), now); t.After(until) {
			until = t
		}
		return abuseResp{}, c.pause(ctx, until, fmt.Sprintf("http_%d", resp.StatusCode))
	}
	var wire struct {
		Data *struct {
			Score   *int `json:"abuseConfidenceScore"`
			Reports *int `json:"totalReports"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wire); err != nil {
		return abuseResp{}, c.pause(ctx, now.Add(30*time.Second), "invalid_response")
	}
	if wire.Data == nil || wire.Data.Score == nil || wire.Data.Reports == nil || *wire.Data.Score < 0 || *wire.Data.Score > 100 || *wire.Data.Reports < 0 {
		return abuseResp{}, c.pause(ctx, now.Add(30*time.Second), "invalid_response")
	}
	var out abuseResp
	out.Data.AbuseConfidenceScore = *wire.Data.Score
	out.Data.TotalReports = *wire.Data.Reports
	c.persist(ctx)
	return out, nil
}
func (c *providerClient) pause(ctx context.Context, until time.Time, reason string) *providerUnavailable {
	if until.Unix() > c.state.Resume {
		c.state.Resume = until.Unix()
		c.state.Reason = reason
	}
	c.persist(ctx)
	return &providerUnavailable{time.Unix(c.state.Resume, 0), c.state.Reason, false}
}
func nonnegativeHeader(h http.Header, name string) (int64, bool) {
	s := h.Get(name)
	v, e := strconv.ParseInt(s, 10, 64)
	return v, s != "" && e == nil && v >= 0
}
func retryTime(value string, now time.Time) time.Time {
	if seconds, err := strconv.ParseInt(value, 10, 32); err == nil && seconds >= 0 {
		return now.Add(time.Duration(seconds) * time.Second)
	}
	t, _ := http.ParseTime(value)
	return t
}
