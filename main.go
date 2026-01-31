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

func main() {
	apiKey := env.GetStr("ABUSEIPDB_API_KEY", "", true)
	threshold := env.GetInt("ABUSE_SCORE_THRESHOLD", 25, false)
	maxAge := env.GetInt("ABUSEIPDB_MAX_AGE_DAYS", 90, false)
	cacheTTL := time.Duration(env.GetInt("CACHE_TTL_SECONDS", 3600, false)) * time.Second
	valkeyURL := env.GetStr("VALKEY_URL", "redis://valkey:6379/0", false)

	opts, err := redis.ParseURL(valkeyURL)
	if err != nil {
		log.Fatalf("VALKEY_URL invalid: %v", err)
	}
	rdb := redis.NewClient(opts)

	http.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if ip == "" {
			http.Error(w, "No client IP", http.StatusBadRequest)
			return
		}

		ctx := r.Context()
		cacheKey := "abuseipdb:" + ip

		var data abuseResp
		if cached, err := rdb.Get(ctx, cacheKey).Result(); err == nil {
			_ = json.Unmarshal([]byte(cached), &data)
		} else if !errors.Is(err, redis.Nil) {
			http.Error(w, "Cache error", http.StatusBadGateway)
			return
		} else {
			resp, err := queryAbuseIPDB(ctx, apiKey, ip, maxAge)
			if err != nil {
				http.Error(w, "AbuseIPDB error: "+err.Error(), http.StatusBadGateway)
				return
			}
			data = resp
			raw, _ := json.Marshal(data)
			_ = rdb.Set(ctx, cacheKey, raw, cacheTTL).Err()
		}

		score := data.Data.AbuseConfidenceScore
		reports := data.Data.TotalReports

		w.Header().Set("X-Abuse-Score", strconv.Itoa(score))
		w.Header().Set("X-Abuse-Reports", strconv.Itoa(reports))

		if score >= threshold {
			http.Error(w, fmt.Sprintf("Blocked (score=%d, reports=%d)", score, reports), http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
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
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
