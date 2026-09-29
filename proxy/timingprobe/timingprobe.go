package timingprobe

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

func init() {
	caddy.RegisterModule(new(TimingProbe))
}

// TimingProbe is the http.handlers.timing_probe Caddy module.
type TimingProbe struct {
	// Persona is the active persona, kept in sync with the upstream on every switch.
	Persona string `json:"persona,omitempty"`

	PersonasRoot string `json:"personas_root,omitempty"`

	// ProbeRate is the fraction of eligible requests to hold; 0 is a true no-op.
	ProbeRate float64 `json:"probe_rate,omitempty"`

	// MinBaseline requests per session are never probed (floor of 3).
	MinBaseline int `json:"min_baseline,omitempty"`

	// SessionIdleSeconds bounds session tracking state (default 1800).
	SessionIdleSeconds float64 `json:"session_idle_seconds,omitempty"`

	// ForceAfter forces a probe after this many unprobed eligible requests (rare backstop).
	ForceAfter int `json:"force_after,omitempty"`

	p95Ms float64
	p99Ms float64

	mu       sync.Mutex
	sessions map[string]*sessionState

	rng randSource

	logger *zap.Logger
}

// randSource lets tests inject a scripted sequence.
type randSource interface {
	Float64() float64
}

type sessionState struct {
	requestCount  int
	eligibleCount int
	probedCount   int
	lastSeen      time.Time
}

type manifestFile struct {
	Timing struct {
		P95Ms float64 `yaml:"p95_ms"`
		P99Ms float64 `yaml:"p99_ms"`
	} `yaml:"timing"`
}

// CaddyModule returns the Caddy module information.
func (*TimingProbe) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.timing_probe",
		New: func() caddy.Module { return new(TimingProbe) },
	}
}

// Provision must succeed inert (ProbeRate 0) even without a manifest.
func (t *TimingProbe) Provision(ctx caddy.Context) error {
	t.logger = ctx.Logger()

	if t.MinBaseline < 3 {
		t.MinBaseline = 3
	}
	if t.SessionIdleSeconds <= 0 {
		t.SessionIdleSeconds = 1800.0
	}
	if t.PersonasRoot == "" {
		t.PersonasRoot = "/etc/chameleon/personas"
	}
	if t.ProbeRate < 0 {
		t.ProbeRate = 0
	}
	if t.ProbeRate > 1 {
		t.ProbeRate = 1
	}
	if t.ForceAfter <= 0 && t.ProbeRate > 0 {
		t.ForceAfter = int(math.Ceil(3.0 / t.ProbeRate))
	}

	if t.Persona != "" {
		p95, p99, err := loadTiming(t.PersonasRoot, t.Persona)
		if err != nil {
			if t.ProbeRate > 0 {
				return fmt.Errorf("timing_probe: probe_rate %.3f > 0 but timing manifest "+
					"unavailable for persona %q: %w", t.ProbeRate, t.Persona, err)
			}
			t.logger.Warn("timing manifest unavailable; harmless while probe_rate is 0",
				zap.String("persona", t.Persona), zap.Error(err))
		} else {
			t.p95Ms, t.p99Ms = p95, p99
		}
	} else if t.ProbeRate > 0 {
		return fmt.Errorf("timing_probe: probe_rate %.3f > 0 but no persona configured", t.ProbeRate)
	}

	if t.p99Ms < t.p95Ms {
		return fmt.Errorf("timing_probe: persona %q manifest has p99_ms (%v) < p95_ms (%v)",
			t.Persona, t.p99Ms, t.p95Ms)
	}

	if t.rng == nil {
		t.rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	t.sessions = make(map[string]*sessionState)

	go t.cleanupLoop(ctx)

	return nil
}

func loadTiming(root, persona string) (p95, p99 float64, err error) {
	path := filepath.Join(root, persona, "manifest.yml")
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, err
	}
	var m manifestFile
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return 0, 0, fmt.Errorf("parsing %s: %w", path, err)
	}
	if m.Timing.P95Ms <= 0 || m.Timing.P99Ms <= 0 {
		return 0, 0, fmt.Errorf("%s: timing.p95_ms/p99_ms missing or non-positive", path)
	}
	return m.Timing.P95Ms, m.Timing.P99Ms, nil
}

func (t *TimingProbe) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-time.Duration(t.SessionIdleSeconds * float64(time.Second)))
			t.mu.Lock()
			for ip, s := range t.sessions {
				if s.lastSeen.Before(cutoff) {
					delete(t.sessions, ip)
				}
			}
			t.mu.Unlock()
		}
	}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// decide applies baseline gating, the forced backstop, and the random roll.
func (t *TimingProbe) decide(ip string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	s, ok := t.sessions[ip]
	if !ok {
		s = &sessionState{}
		t.sessions[ip] = s
	}
	s.requestCount++
	s.lastSeen = time.Now()

	if t.ProbeRate <= 0 {
		return false
	}
	if s.requestCount <= t.MinBaseline {
		return false
	}

	s.eligibleCount++

	forced := s.probedCount == 0 && t.ForceAfter > 0 && s.eligibleCount >= t.ForceAfter
	rolled := t.rng.Float64() < t.ProbeRate

	if rolled || forced {
		s.probedCount++
		return true
	}
	return false
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (t *TimingProbe) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if !t.decide(clientIP(r)) {
		setProbeVars(r, false, nil, nil, nil)
		return next.ServeHTTP(w, r)
	}

	bw := newBufferedResponseWriter()
	if err := next.ServeHTTP(bw, r); err != nil {
		setProbeVars(r, false, nil, nil, nil)
		return err
	}

	delayMs := t.p95Ms + t.rng.Float64()*(t.p99Ms-t.p95Ms)
	delay := time.Duration(delayMs * float64(time.Millisecond))

	start := time.Now()
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-timer.C:
		// Measured elapsed time, not the intended delay.
		measuredMs := time.Since(start).Milliseconds()
		abandoned := false
		setProbeVars(r, true, &measuredMs, &abandoned, nil)
		return bw.flushTo(w)

	case <-r.Context().Done():
		abandonAfterMs := time.Since(start).Milliseconds()
		abandoned := true
		// On abandonment, record the intended delay (no measurement exists).
		intendedMs := int64(math.Round(delayMs))
		setProbeVars(r, true, &intendedMs, &abandoned, &abandonAfterMs)
		return r.Context().Err()
	}
}

// setProbeVars stores native types; the log_append handlers must run after this module.
func setProbeVars(r *http.Request, applied bool, delayMs *int64, abandoned *bool, abandonAfterMs *int64) {
	ctx := r.Context()
	caddyhttp.SetVar(ctx, "probe_applied", applied)
	caddyhttp.SetVar(ctx, "probe_delay_ms", nullableInt(delayMs))
	caddyhttp.SetVar(ctx, "client_abandoned", nullableBool(abandoned))
	caddyhttp.SetVar(ctx, "abandon_after_ms", nullableInt(abandonAfterMs))
}

// nullableInt/nullableBool return a real nil so the log gets null, not 0/false.
func nullableInt(v *int64) any {
	if v == nil {
		return nil
	}
	return *v
}

func nullableBool(v *bool) any {
	if v == nil {
		return nil
	}
	return *v
}

// bufferedResponseWriter holds the whole response so it can be released after the delay.
type bufferedResponseWriter struct {
	header      http.Header
	body        []byte
	statusCode  int
	wroteHeader bool
}

func newBufferedResponseWriter() *bufferedResponseWriter {
	return &bufferedResponseWriter{header: make(http.Header), statusCode: http.StatusOK}
}

func (b *bufferedResponseWriter) Header() http.Header { return b.header }

func (b *bufferedResponseWriter) WriteHeader(code int) {
	if !b.wroteHeader {
		b.statusCode = code
		b.wroteHeader = true
	}
}

func (b *bufferedResponseWriter) Write(p []byte) (int, error) {
	if !b.wroteHeader {
		b.WriteHeader(http.StatusOK)
	}
	b.body = append(b.body, p...)
	return len(p), nil
}

func (b *bufferedResponseWriter) flushTo(w http.ResponseWriter) error {
	dst := w.Header()
	for k, v := range b.header {
		dst[k] = v
	}
	w.WriteHeader(b.statusCode)
	_, err := w.Write(b.body)
	return err
}

// Interface guards.
var (
	_ caddy.Provisioner           = (*TimingProbe)(nil)
	_ caddyhttp.MiddlewareHandler = (*TimingProbe)(nil)
)
