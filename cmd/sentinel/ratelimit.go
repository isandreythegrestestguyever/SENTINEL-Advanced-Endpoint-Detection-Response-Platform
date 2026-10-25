package main

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxRateLimitBuckets = 4096

type ratePolicy struct {
	rate  float64
	burst float64
}

type rateBucket struct {
	tokens   float64
	updated  time.Time
	lastSeen time.Time
}

type rateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]rateBucket
	policies map[string]ratePolicy
	now      func() time.Time
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{
		buckets: make(map[string]rateBucket),
		policies: map[string]ratePolicy{
			"ingest":           {rate: 120, burst: 240},
			"heartbeat":        {rate: 0.5, burst: 10},
			"simulation":       {rate: 0.1, burst: 6},
			"alert_update":     {rate: 2, burst: 20},
			"incident_update":  {rate: 2, burst: 20},
			"simulation_reset": {rate: 0.1, burst: 6},
		},
		now: time.Now,
	}
}

func (l *rateLimiter) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		class := rateClass(r.Method, r.URL.Path)
		if class == "" {
			next.ServeHTTP(w, r)
			return
		}
		key := class + ":" + clientAddress(r.RemoteAddr)
		allowed, retryAfter := l.allow(key, l.policies[class])
		if !allowed {
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (l *rateLimiter) allow(key string, policy ratePolicy) (bool, int) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	bucket, exists := l.buckets[key]
	if !exists {
		if len(l.buckets) >= maxRateLimitBuckets {
			for candidate, old := range l.buckets {
				if now.Sub(old.lastSeen) > 10*time.Minute {
					delete(l.buckets, candidate)
				}
			}
			if len(l.buckets) >= maxRateLimitBuckets {
				return false, 60
			}
		}
		bucket = rateBucket{tokens: policy.burst, updated: now, lastSeen: now}
	} else {
		elapsed := now.Sub(bucket.updated).Seconds()
		if elapsed > 0 {
			bucket.tokens += elapsed * policy.rate
			if bucket.tokens > policy.burst {
				bucket.tokens = policy.burst
			}
		}
		bucket.updated = now
		bucket.lastSeen = now
	}
	if bucket.tokens < 1 {
		retryAfter := int((1-bucket.tokens)/policy.rate) + 1
		l.buckets[key] = bucket
		return false, retryAfter
	}
	bucket.tokens--
	l.buckets[key] = bucket
	return true, 0
}

func rateClass(method, path string) string {
	switch {
	case method == http.MethodPost && path == "/api/ingest":
		return "ingest"
	case method == http.MethodPost && path == "/api/heartbeat":
		return "heartbeat"
	case method == http.MethodPost && path == "/api/simulate":
		return "simulation"
	case method == http.MethodPatch && strings.HasPrefix(path, "/api/alerts/"):
		return "alert_update"
	case method == http.MethodPatch && strings.HasPrefix(path, "/api/incidents/"):
		return "incident_update"
	case method == http.MethodDelete && strings.HasPrefix(path, "/api/simulations/"):
		return "simulation_reset"
	default:
		return ""
	}
}

func clientAddress(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil && host != "" {
		return host
	}
	if remoteAddr == "" {
		return "unknown"
	}
	return remoteAddr
}
