package ipref

import (
	"sync"

	"github.com/coredns/coredns/plugin"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics exported by the ipref plugin.
var (
	RequestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: plugin.Namespace,
		Subsystem: "ipref",
		Name:      "request_duration_seconds",
		Buckets:   plugin.TimeBuckets,
		Help:      "Histogram of the time each request took.",
	}, []string{"server"})

	RcodeCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "ipref",
		Name:      "response_rcode_count_total",
		Help:      "Counter of rcodes made per request.",
	}, []string{"server", "rcode"})
)

var once sync.Once
