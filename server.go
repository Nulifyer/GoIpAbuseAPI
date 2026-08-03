package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	headerAbuseDecision = "X-Abuse-Decision"
	headerAbuseReports  = "X-Abuse-Reports"
	headerAbuseScore    = "X-Abuse-Score"
	headerAbuseSource   = "X-Abuse-Source"
)

type requestMetadata struct {
	clientIP string
	host     string
	method   string
	path     string
}

type checker struct {
	apiKey    string
	threshold int
	maxAge    int
	cacheTTL  time.Duration
	skipCIDRs []*net.IPNet
	cache     cacheStore
	query     abuseQueryFunc
	logger    logger
	metrics   *serviceMetrics
	group     singleflight.Group
}

func (c *checker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	requestDone := c.metrics.requestStarted()
	defer requestDone()

	metadata := metadataFromRequest(r)
	c.logger.Event(levelTrace, "auth_request", requestLogFields(metadata)...)

	if metadata.clientIP == "" {
		c.recordError(w, metadata, lookupSourceRequest, "missing client IP", http.StatusBadRequest, time.Since(started))
		return
	}

	ip := net.ParseIP(metadata.clientIP)
	if ip == nil {
		c.recordError(w, metadata, lookupSourceRequest, "invalid client IP", http.StatusBadRequest, time.Since(started))
		return
	}

	if ipInCIDRs(ip, c.skipCIDRs) {
		score, reports := 0, 0
		duration := time.Since(started)
		setDecisionHeaders(w, "allowed", lookupSourceCIDR, score, reports)
		c.metrics.recordDecision("allowed", lookupSourceCIDR, &score, duration)
		c.logDecision(levelInfo, metadata, "allowed", lookupSourceCIDR, score, reports, http.StatusOK, duration)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
		return
	}

	lookup, err := lookupAbuseData(
		r.Context(), c.cache, &c.group, c.query, c.logger, c.metrics,
		c.apiKey, metadata.clientIP, c.maxAge, c.cacheTTL,
	)
	if err != nil {
		source, message := lookupSourceService, "Internal error"
		switch {
		case errors.Is(err, errCacheLookup):
			source, message = lookupSourceCache, "Cache error"
		case errors.Is(err, errAbuseLookup):
			source, message = lookupSourceAPI, "AbuseIPDB error"
		}
		c.recordError(w, metadata, source, err.Error(), http.StatusBadGateway, time.Since(started))
		http.Error(w, message, http.StatusBadGateway)
		return
	}

	score := lookup.response.Data.AbuseConfidenceScore
	reports := lookup.response.Data.TotalReports
	decision := "allowed"
	status := http.StatusOK
	level := levelInfo
	if isBlocked(score, c.threshold) {
		decision = "blocked"
		status = http.StatusForbidden
		level = levelWarn
	}

	setDecisionHeaders(w, decision, lookup.source, score, reports)
	duration := time.Since(started)
	c.metrics.recordDecision(decision, lookup.source, &score, duration)
	c.logDecision(level, metadata, decision, lookup.source, score, reports, status, duration)
	if status == http.StatusForbidden {
		http.Error(w, fmt.Sprintf("Blocked (score=%d, reports=%d)", score, reports), status)
		return
	}

	w.WriteHeader(status)
	_, _ = w.Write([]byte("OK"))
}

func (c *checker) recordError(w http.ResponseWriter, metadata requestMetadata, source lookupSource, message string, status int, duration time.Duration) {
	w.Header().Set(headerAbuseDecision, "error")
	w.Header().Set(headerAbuseSource, string(source))
	c.metrics.recordDecision("error", source, nil, duration)
	fields := append(requestLogFields(metadata),
		field("decision", "error"),
		field("source", source),
		field("status", status),
		field("duration_ms", durationMilliseconds(duration)),
		field("error", message),
	)
	c.logger.Event(levelError, "auth_decision", fields...)
	if source == lookupSourceRequest {
		http.Error(w, message, status)
	}
}

func (c *checker) logDecision(level logLevel, metadata requestMetadata, decision string, source lookupSource, score, reports, status int, duration time.Duration) {
	fields := append(requestLogFields(metadata),
		field("decision", decision),
		field("source", source),
		field("score", score),
		field("reports", reports),
		field("threshold", c.threshold),
		field("status", status),
		field("duration_ms", durationMilliseconds(duration)),
	)
	c.logger.Event(level, "auth_decision", fields...)
}

func durationMilliseconds(duration time.Duration) float64 {
	return float64(duration.Microseconds()) / 1000
}

func requestLogFields(metadata requestMetadata) []logField {
	return []logField{
		field("client_ip", metadata.clientIP),
		field("host", metadata.host),
		field("method", metadata.method),
		field("path", metadata.path),
	}
}

func setDecisionHeaders(w http.ResponseWriter, decision string, source lookupSource, score, reports int) {
	w.Header().Set(headerAbuseDecision, decision)
	w.Header().Set(headerAbuseSource, string(source))
	w.Header().Set(headerAbuseScore, strconv.Itoa(score))
	w.Header().Set(headerAbuseReports, strconv.Itoa(reports))
}

func metadataFromRequest(r *http.Request) requestMetadata {
	method := strings.TrimSpace(r.Header.Get("X-Forwarded-Method"))
	if method == "" {
		method = r.Method
	}

	host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = r.Host
	}
	if first, _, found := strings.Cut(host, ","); found {
		host = first
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}

	requestURI := strings.TrimSpace(r.Header.Get("X-Forwarded-Uri"))
	if requestURI == "" {
		requestURI = r.URL.RequestURI()
	}

	return requestMetadata{
		clientIP: clientIP(r),
		host:     sanitizeLogText(host, 255),
		method:   sanitizeLogText(strings.ToUpper(method), 32),
		path:     sanitizedRequestPath(requestURI),
	}
}

func sanitizedRequestPath(requestURI string) string {
	if parsed, err := url.ParseRequestURI(requestURI); err == nil {
		path := parsed.EscapedPath()
		if path == "" {
			path = "/"
		}
		return sanitizeLogText(path, 2048)
	}

	path, _, _ := strings.Cut(requestURI, "?")
	path, _, _ = strings.Cut(path, "#")
	if path == "" {
		path = "/"
	}
	return sanitizeLogText(path, 2048)
}

func sanitizeLogText(value string, maxLength int) string {
	value = strings.ToValidUTF8(value, "�")
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
	if len(value) > maxLength {
		value = strings.ToValidUTF8(value[:maxLength], "�")
	}
	return value
}
