package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const abuseURL = "https://api.abuseipdb.com/api/v2/check"

type abuseResp struct {
	Data struct {
		AbuseConfidenceScore int `json:"abuseConfidenceScore"`
		TotalReports         int `json:"totalReports"`
	} `json:"data"`
}

type envHelper struct{}

var env envHelper

func (envHelper) GetStr(key, def string, required bool) string {
	val := os.Getenv(key)
	if val == "" {
		if required {
			log.Fatalf("missing %s", key)
		}
		return def
	}
	return val
}

func (envHelper) GetInt(key string, def int, required bool) int {
	val := os.Getenv(key)
	if val == "" {
		if required {
			log.Fatalf("missing %s", key)
		}
		return def
	}
	i, err := strconv.Atoi(val)
	if err != nil {
		if required {
			log.Fatalf("invalid %s", key)
		}
		return def
	}
	return i
}

type logLevel int

const (
	levelTrace logLevel = iota
	levelDebug
	levelInfo
	levelWarn
	levelError
)

func parseLogLevel(s string) logLevel {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "TRACE":
		return levelTrace
	case "DEBUG":
		return levelDebug
	case "INFO":
		return levelInfo
	case "WARN", "WARNING":
		return levelWarn
	case "ERROR":
		return levelError
	default:
		return levelInfo
	}
}

type logger struct {
	level logLevel
}

func (l logger) Tracef(format string, args ...any) {
	if l.level <= levelTrace {
		log.Printf("[TRACE] "+format, args...)
	}
}

func (l logger) Debugf(format string, args ...any) {
	if l.level <= levelDebug {
		log.Printf("[DEBUG] "+format, args...)
	}
}

func (l logger) Infof(format string, args ...any) {
	if l.level <= levelInfo {
		log.Printf("[INFO] "+format, args...)
	}
}

func (l logger) Warnf(format string, args ...any) {
	if l.level <= levelWarn {
		log.Printf("[WARN] "+format, args...)
	}
}

func (l logger) Errorf(format string, args ...any) {
	if l.level <= levelError {
		log.Printf("[ERROR] "+format, args...)
	}
}

func main() {
	apiKey := env.GetStr("ABUSEIPDB_API_KEY", "", true)
	threshold := env.GetInt("ABUSE_SCORE_THRESHOLD", 25, false)
	maxAge := env.GetInt("ABUSEIPDB_MAX_AGE_DAYS", 90, false)
	cacheTTL := time.Duration(env.GetInt("CACHE_TTL_SECONDS", 3600, false)) * time.Second
	valkeyURL := env.GetStr("VALKEY_URL", "redis://valkey:6379/0", false)
	port := env.GetInt("PORT", 8080, false)
	skipCIDRsRaw := env.GetStr(
		"DO_NOT_FORWARD_CIDRS",
		"10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,::1/128,fc00::/7",
		false,
	)
	skipCIDRs := mustParseCIDRs(skipCIDRsRaw)

	logLevel := env.GetStr("LOG_LEVEL", "INFO", false)
	logger := logger{level: parseLogLevel(logLevel)}
	logger.Infof("starting, log level=%s", strings.ToUpper(logLevel))

	opts, err := redis.ParseURL(valkeyURL)
	if err != nil {
		log.Fatalf("VALKEY_URL invalid: %v", err)
	}
	rdb := redis.NewClient(opts)

	http.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		logger.Tracef("incoming request method=%s path=%s remote=%s xff=%q", r.Method, r.URL.Path, r.RemoteAddr, r.Header.Get("X-Forwarded-For"))

		ipStr := clientIP(r)
		if ipStr == "" {
			logger.Warnf("missing client ip")
			http.Error(w, "No client IP", http.StatusBadRequest)
			return
		}

		ip := net.ParseIP(ipStr)
		if ip == nil {
			logger.Warnf("invalid client ip=%q", ipStr)
			http.Error(w, "Invalid client IP", http.StatusBadRequest)
			return
		}

		logger.Debugf("resolved client ip=%s", ipStr)

		if ipInCIDRs(ip, skipCIDRs) {
			logger.Infof("skip abuse check for ip=%s (in DO_NOT_FORWARD_CIDRS)", ipStr)
			w.Header().Set("X-Abuse-Score", "0")
			w.Header().Set("X-Abuse-Reports", "0")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
			return
		}

		ctx := r.Context()
		cacheKey := "abuseipdb:" + ipStr

		var data abuseResp
		if cached, err := rdb.Get(ctx, cacheKey).Result(); err == nil {
			logger.Debugf("cache hit ip=%s", ipStr)
			_ = json.Unmarshal([]byte(cached), &data)
		} else if !errors.Is(err, redis.Nil) {
			logger.Errorf("cache error ip=%s err=%v", ipStr, err)
			http.Error(w, "Cache error", http.StatusBadGateway)
			return
		} else {
			logger.Debugf("cache miss ip=%s", ipStr)
			start := time.Now()
			resp, err := queryAbuseIPDB(ctx, apiKey, ipStr, maxAge)
			if err != nil {
				logger.Errorf("abuseipdb error ip=%s err=%v", ipStr, err)
				http.Error(w, "AbuseIPDB error: "+err.Error(), http.StatusBadGateway)
				return
			}
			logger.Debugf("abuseipdb ok ip=%s latency=%s", ipStr, time.Since(start))
			data = resp
			raw, _ := json.Marshal(data)
			_ = rdb.Set(ctx, cacheKey, raw, cacheTTL).Err()
		}

		score := data.Data.AbuseConfidenceScore
		reports := data.Data.TotalReports

		w.Header().Set("X-Abuse-Score", strconv.Itoa(score))
		w.Header().Set("X-Abuse-Reports", strconv.Itoa(reports))

		logger.Infof("abuseipdb result ip=%s score=%d reports=%d threshold=%d", ipStr, score, reports, threshold)

		if score >= threshold {
			logger.Warnf("blocked ip=%s score=%d reports=%d", ipStr, score, reports)
			http.Error(w, fmt.Sprintf("Blocked (score=%d, reports=%d)", score, reports), http.StatusForbidden)
			return
		}
		logger.Debugf("allowed ip=%s score=%d reports=%d", ipStr, score, reports)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	log.Printf("listening on :%d", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), nil))
}

func mustParseCIDRs(raw string) []*net.IPNet {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	var nets []*net.IPNet
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		_, n, err := net.ParseCIDR(part)
		if err != nil {
			log.Fatalf("invalid CIDR in DO_NOT_FORWARD_CIDRS: %s", part)
		}
		nets = append(nets, n)
	}
	return nets
}

func ipInCIDRs(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func queryAbuseIPDB(ctx context.Context, apiKey, ip string, maxAge int) (abuseResp, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", abuseURL, nil)
	q := req.URL.Query()
	q.Set("ipAddress", ip)
	q.Set("maxAgeInDays", strconv.Itoa(maxAge))
	req.URL.RawQuery = q.Encode()

	req.Header.Set("Key", apiKey)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return abuseResp{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return abuseResp{}, fmt.Errorf("status %d", resp.StatusCode)
	}

	var out abuseResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return abuseResp{}, err
	}
	return out, nil
}

func clientIP(r *http.Request) string {
	if xrip := strings.TrimSpace(r.Header.Get("X-Real-Ip")); xrip != "" {
		return xrip
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
