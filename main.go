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
	"golang.org/x/sync/singleflight"
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

func (envHelper) GetBool(key string, def bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return def
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return def
	}
	return parsed
}

type cacheStore interface {
	Get(context.Context, string) (string, error)
	Set(context.Context, string, string, time.Duration) error
	Del(context.Context, string) error
}

type redisCache struct {
	client *redis.Client
}

func (c redisCache) Get(ctx context.Context, key string) (string, error) {
	return c.client.Get(ctx, key).Result()
}

func (c redisCache) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	return c.client.Set(ctx, key, value, ttl).Err()
}

func (c redisCache) Del(ctx context.Context, key string) error {
	return c.client.Del(ctx, key).Err()
}

type abuseQueryFunc func(context.Context, string, string, int) (abuseResp, error)

type lookupSource string

const (
	lookupSourceAPI     lookupSource = "api"
	lookupSourceCache   lookupSource = "cache"
	lookupSourceCIDR    lookupSource = "cidr"
	lookupSourceRequest lookupSource = "request"
	lookupSourceService lookupSource = "service"
)

type abuseLookup struct {
	response abuseResp
	source   lookupSource
}

var (
	errCacheLookup = errors.New("cache lookup failed")
	errAbuseLookup = errors.New("AbuseIPDB lookup failed")
)

func main() {
	apiKey := env.GetStr("ABUSEIPDB_API_KEY", "", true)
	threshold := env.GetInt("ABUSE_SCORE_THRESHOLD", 25, false)
	maxAge := env.GetInt("ABUSEIPDB_MAX_AGE_DAYS", 90, false)
	cacheTTL := time.Duration(env.GetInt("CACHE_TTL_SECONDS", 3600, false)) * time.Second
	valkeyURL := env.GetStr("VALKEY_URL", "redis://valkey:6379/0", false)
	port := env.GetInt("PORT", 8080, false)
	metricsEnabled := env.GetBool("METRICS_ENABLED", false)
	metricsAddr := env.GetStr("METRICS_ADDR", ":9090", false)
	skipCIDRsRaw := env.GetStr(
		"DO_NOT_FORWARD_CIDRS",
		"10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,::1/128,fc00::/7",
		false,
	)
	skipCIDRs := mustParseCIDRs(skipCIDRsRaw)

	logLevel := env.GetStr("LOG_LEVEL", "INFO", false)
	logFormat := env.GetStr("LOG_FORMAT", "text", false)
	logger := newLogger(logLevel, logFormat)
	logger.Event(levelInfo, "service_start",
		field("log_level", parseLogLevel(logLevel)),
		field("log_format", parseLogFormat(logFormat)),
	)

	opts, err := redis.ParseURL(valkeyURL)
	if err != nil {
		log.Fatalf("VALKEY_URL invalid: %v", err)
	}
	redis.SetLogger(redisLogger{logger: logger})
	rdb := redis.NewClient(opts)
	cache := redisCache{client: rdb}

	var metrics *serviceMetrics
	if metricsEnabled {
		metrics = newServiceMetrics()
		if err := startMetricsServer(metricsAddr, metrics, logger); err != nil {
			logger.Event(levelError, "metrics_server_error", field("address", metricsAddr), field("error", err))
			os.Exit(1)
		}
	}

	checkHandler := &checker{
		apiKey:    apiKey,
		threshold: threshold,
		maxAge:    maxAge,
		cacheTTL:  cacheTTL,
		skipCIDRs: skipCIDRs,
		cache:     cache,
		query:     queryAbuseIPDB,
		logger:    logger,
		metrics:   metrics,
	}
	mux := http.NewServeMux()
	mux.Handle("/check", checkHandler)
	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	logger.Event(levelInfo, "auth_server_listening", field("address", server.Addr))
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Event(levelError, "auth_server_error", field("error", err))
		os.Exit(1)
	}
}

func lookupAbuseData(
	ctx context.Context,
	cache cacheStore,
	group *singleflight.Group,
	query abuseQueryFunc,
	logger logger,
	metrics *serviceMetrics,
	apiKey, ip string,
	maxAge int,
	cacheTTL time.Duration,
) (abuseLookup, error) {
	cacheKey := "abuseipdb:" + ip
	value, err, shared := group.Do(cacheKey, func() (any, error) {
		cached, err := cache.Get(ctx, cacheKey)
		if err == nil {
			var data abuseResp
			if err := json.Unmarshal([]byte(cached), &data); err == nil {
				metrics.recordCache("read", "hit")
				logger.Debugf("cache hit ip=%s", ip)
				return abuseLookup{response: data, source: lookupSourceCache}, nil
			}

			metrics.recordCache("read", "invalid")
			logger.Warnf("invalid cache entry ip=%s; treating as cache miss", ip)
			if err := cache.Del(ctx, cacheKey); err != nil {
				metrics.recordCache("delete", "error")
				logger.Warnf("cache delete failed ip=%s err=%v", ip, err)
			} else {
				metrics.recordCache("delete", "success")
			}
		} else if !errors.Is(err, redis.Nil) {
			metrics.recordCache("read", "error")
			return abuseLookup{}, fmt.Errorf("%w: %v", errCacheLookup, err)
		} else {
			metrics.recordCache("read", "miss")
		}

		logger.Debugf("cache miss ip=%s", ip)
		start := time.Now()
		data, err := query(ctx, apiKey, ip, maxAge)
		if err != nil {
			metrics.recordAPI("error", time.Since(start))
			return abuseLookup{}, fmt.Errorf("%w: %v", errAbuseLookup, err)
		}
		metrics.recordAPI("success", time.Since(start))
		logger.Debugf("abuseipdb ok ip=%s latency=%s", ip, time.Since(start))

		raw, err := json.Marshal(data)
		if err != nil {
			logger.Warnf("cache encode failed ip=%s err=%v", ip, err)
			return abuseLookup{response: data, source: lookupSourceAPI}, nil
		}
		if err := cache.Set(ctx, cacheKey, string(raw), cacheTTL); err != nil {
			metrics.recordCache("write", "error")
			logger.Warnf("cache write failed ip=%s err=%v", ip, err)
		} else {
			metrics.recordCache("write", "success")
		}
		return abuseLookup{response: data, source: lookupSourceAPI}, nil
	})
	if shared {
		metrics.recordSharedLookup()
	}
	if err != nil {
		return abuseLookup{}, err
	}

	lookup, ok := value.(abuseLookup)
	if !ok {
		return abuseLookup{}, errors.New("unexpected lookup result")
	}
	return lookup, nil
}

func isBlocked(score, threshold int) bool {
	return score >= threshold
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
