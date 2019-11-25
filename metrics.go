package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	activeSessions = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "active_sessions",
		Help: "The current number of active sessions",
	})
	totalConnections = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "connections_total",
		Help: "The total number of connection attempts",
	}, []string{"ip"})
	totalSessions = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sessions_total",
		Help: "The total number of established sessions",
	}, []string{"user", "ip"})
)

func serveMetrics(bind string) {
	http.Handle("/metrics", promhttp.Handler())
	if err := http.ListenAndServe(bind, nil); err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		os.Exit(1)
	}
}
