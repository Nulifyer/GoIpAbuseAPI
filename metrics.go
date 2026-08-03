package main

import (
	"errors"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const metricsNamespace = "goipabuse"

type serviceMetrics struct {
	registry            *prometheus.Registry
	decisions           *prometheus.CounterVec
	cacheOperations     *prometheus.CounterVec
	apiRequests         *prometheus.CounterVec
	apiDuration         prometheus.Histogram
	requestDuration     *prometheus.HistogramVec
	sharedLookupResults prometheus.Counter
	inFlight            prometheus.Gauge
	scores              prometheus.Histogram
}

func newServiceMetrics() *serviceMetrics {
	metrics := &serviceMetrics{
		registry: prometheus.NewRegistry(),
		decisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "decisions_total",
			Help:      "Total ForwardAuth decisions by decision and data source.",
		}, []string{"decision", "source"}),
		cacheOperations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "cache_operations_total",
			Help:      "Total cache operations by operation and result.",
		}, []string{"operation", "result"}),
		apiRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "api_requests_total",
			Help:      "Total AbuseIPDB API requests by result.",
		}, []string{"result"}),
		apiDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Name:      "api_request_duration_seconds",
			Help:      "AbuseIPDB API request duration in seconds.",
			Buckets:   prometheus.DefBuckets,
		}),
		requestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Name:      "request_duration_seconds",
			Help:      "ForwardAuth request duration in seconds by decision and data source.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"decision", "source"}),
		sharedLookupResults: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "singleflight_shared_results_total",
			Help:      "Total lookup results shared between concurrent requests for the same IP.",
		}),
		inFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "requests_in_flight",
			Help:      "Current number of ForwardAuth requests being processed.",
		}),
		scores: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Name:      "score",
			Help:      "Abuse confidence scores returned for ForwardAuth decisions.",
			Buckets:   []float64{0, 10, 25, 50, 75, 90, 100},
		}),
	}

	metrics.registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		metrics.decisions,
		metrics.cacheOperations,
		metrics.apiRequests,
		metrics.apiDuration,
		metrics.requestDuration,
		metrics.sharedLookupResults,
		metrics.inFlight,
		metrics.scores,
	)
	return metrics
}

func (m *serviceMetrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

func (m *serviceMetrics) requestStarted() func() {
	if m == nil {
		return func() {}
	}
	m.inFlight.Inc()
	return m.inFlight.Dec
}

func (m *serviceMetrics) recordDecision(decision string, source lookupSource, score *int, duration time.Duration) {
	if m == nil {
		return
	}
	m.decisions.WithLabelValues(decision, string(source)).Inc()
	m.requestDuration.WithLabelValues(decision, string(source)).Observe(duration.Seconds())
	if score != nil {
		m.scores.Observe(float64(*score))
	}
}

func (m *serviceMetrics) recordCache(operation, result string) {
	if m != nil {
		m.cacheOperations.WithLabelValues(operation, result).Inc()
	}
}

func (m *serviceMetrics) recordAPI(result string, duration time.Duration) {
	if m == nil {
		return
	}
	m.apiRequests.WithLabelValues(result).Inc()
	m.apiDuration.Observe(duration.Seconds())
}

func (m *serviceMetrics) recordSharedLookup() {
	if m != nil {
		m.sharedLookupResults.Inc()
	}
}

func metricsMux(metrics *serviceMetrics) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", metrics.Handler())
	mux.HandleFunc("/-/healthy", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len("OK\n")))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK\n"))
	})
	return mux
}

func startMetricsServer(address string, metrics *serviceMetrics, logger logger) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}

	server := &http.Server{
		Handler:           metricsMux(metrics),
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	logger.Event(levelInfo, "metrics_server_listening",
		field("address", listener.Addr().String()),
		field("path", "/metrics"),
	)
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Event(levelError, "metrics_server_error", field("error", err))
		}
	}()
	return nil
}
