package timingprobe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func caddyTestContext(t *testing.T) caddy.Context {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	return ctx
}

type scriptedRand struct {
	mu     sync.Mutex
	values []float64
	i      int
}

func (s *scriptedRand) Float64() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.values[s.i%len(s.values)]
	s.i++
	return v
}

type recordingHandler struct {
	calledAt time.Time
	body     string
	status   int
}

func (h *recordingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	h.calledAt = time.Now()
	status := h.status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write([]byte(h.body))
	return nil
}

func newProbe(t *testing.T, probeRate float64, p95, p99 float64) *TimingProbe {
	t.Helper()
	return &TimingProbe{
		ProbeRate:   probeRate,
		MinBaseline: 3,
		p95Ms:       p95,
		p99Ms:       p99,
		sessions:    make(map[string]*sessionState),
		rng:         &scriptedRand{values: []float64{0.0}}, // always "rolls" true by default
	}
}

func newRequest(ip string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = ip + ":12345"
	ctx := context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{})
	return r.WithContext(ctx)
}

func getVar(r *http.Request, key string) any {
	return caddyhttp.GetVar(r.Context(), key)
}

func getBoolVar(t *testing.T, r *http.Request, key string) bool {
	t.Helper()
	v, ok := getVar(r, key).(bool)
	if !ok {
		t.Fatalf("%s: expected a bool var, got %#v", key, getVar(r, key))
	}
	return v
}

func getIntVar(t *testing.T, r *http.Request, key string) int64 {
	t.Helper()
	v, ok := getVar(r, key).(int64)
	if !ok {
		t.Fatalf("%s: expected an int64 var, got %#v", key, getVar(r, key))
	}
	return v
}

// --- requirement 1: delay applied to the response, not the request ---

func TestDelayHoldsResponseNotRequest(t *testing.T) {
	tp := newProbe(t, 1.0, 50, 50) // fixed 50ms hold, always probe when eligible
	for i := 0; i < 3; i++ {
		req := newRequest("10.0.0.1")
		rec := httptest.NewRecorder()
		next := &recordingHandler{body: "baseline"}
		if err := tp.ServeHTTP(rec, req, next); err != nil {
			t.Fatalf("baseline request %d: %v", i, err)
		}
	}

	req := newRequest("10.0.0.1") // 4th request: past baseline, eligible
	rec := httptest.NewRecorder()
	next := &recordingHandler{body: "persona-response", status: 200}

	testStart := time.Now()
	if err := tp.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("probed request: %v", err)
	}
	totalElapsed := time.Since(testStart)
	backendLatency := next.calledAt.Sub(testStart)

	if backendLatency > 10*time.Millisecond {
		t.Errorf("backend was held before answering: %v (want near-instant)", backendLatency)
	}
	if totalElapsed < 45*time.Millisecond {
		t.Errorf("response was not held: total elapsed %v, want >= ~50ms", totalElapsed)
	}
	if rec.Body.String() != "persona-response" {
		t.Errorf("client did not receive the persona's actual response: got %q", rec.Body.String())
	}
}

// --- requirement 2: measured, not intended, duration ---

func TestProbeDelayMsIsMeasuredNotIntended(t *testing.T) {
	tp := newProbe(t, 1.0, 30, 30)
	for i := 0; i < 3; i++ {
		tp.ServeHTTP(httptest.NewRecorder(), newRequest("10.0.0.2"), &recordingHandler{})
	}
	req := newRequest("10.0.0.2")
	rec := httptest.NewRecorder()
	start := time.Now()
	if err := tp.ServeHTTP(rec, req, &recordingHandler{body: "x"}); err != nil {
		t.Fatal(err)
	}
	wallElapsed := time.Since(start)

	if !getBoolVar(t, req, "probe_applied") {
		t.Fatalf("expected probe_applied=true")
	}
	got := getIntVar(t, req, "probe_delay_ms")
	if got < 30 {
		t.Errorf("probe_delay_ms = %dms, want >= 30ms (the configured floor)", got)
	}
	if time.Duration(got)*time.Millisecond > wallElapsed+5*time.Millisecond {
		t.Errorf("probe_delay_ms (%dms) exceeds what was actually measured (%v)", got, wallElapsed)
	}
}

// --- requirement 3: context cancellation captured with timing ---

func TestClientAbandonmentRecordsTiming(t *testing.T) {
	tp := newProbe(t, 1.0, 200, 200) // long hold so cancellation clearly happens mid-hold
	for i := 0; i < 3; i++ {
		tp.ServeHTTP(httptest.NewRecorder(), newRequest("10.0.0.3"), &recordingHandler{})
	}

	req := newRequest("10.0.0.3")
	ctx, cancel := context.WithCancel(req.Context())
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	go func() {
		time.Sleep(40 * time.Millisecond)
		cancel()
	}()

	err := tp.ServeHTTP(rec, req, &recordingHandler{body: "should-not-be-delivered"})
	if err == nil {
		t.Fatal("expected ServeHTTP to return the context's cancellation error")
	}

	if !getBoolVar(t, req, "probe_applied") {
		t.Errorf("probe_applied should still be true -- the probe WAS applied, just abandoned")
	}
	if !getBoolVar(t, req, "client_abandoned") {
		t.Errorf("client_abandoned should be true")
	}
	intendedMs := getIntVar(t, req, "probe_delay_ms")
	if intendedMs < 150 || intendedMs > 250 {
		t.Errorf("probe_delay_ms = %dms, want the intended ~200ms hold this request was abandoned against",
			intendedMs)
	}
	abandonMs := getIntVar(t, req, "abandon_after_ms")
	if abandonMs < 35 || abandonMs > 200 {
		t.Errorf("abandon_after_ms = %d, want roughly ~40 (and well under the 200ms hold)", abandonMs)
	}
	if abandonMs >= intendedMs {
		t.Errorf("abandon_after_ms (%d) should be less than the intended hold (%d) -- "+
			"the client gave up before the delay elapsed", abandonMs, intendedMs)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("nothing should be written to a client that already disconnected, got %q", rec.Body.String())
	}
}

// --- requirement 5: probe_rate 0.0 is fully inert ---

func TestProbeRateZeroIsFullyInert(t *testing.T) {
	tp := newProbe(t, 0.0, 999, 999) // absurd delay to make any hold obvious if triggered
	tp.rng = &scriptedRand{values: []float64{0.0}}

	for i := 0; i < 20; i++ {
		req := newRequest("10.0.0.4")
		rec := httptest.NewRecorder()
		start := time.Now()
		if err := tp.ServeHTTP(rec, req, &recordingHandler{body: "ok"}); err != nil {
			t.Fatal(err)
		}
		if time.Since(start) > 10*time.Millisecond {
			t.Fatalf("request %d took %v with probe_rate=0 -- module is not inert", i, time.Since(start))
		}
		if getBoolVar(t, req, "probe_applied") {
			t.Errorf("request %d: probe_applied should be false", i)
		}
		for _, key := range []string{"probe_delay_ms", "client_abandoned", "abandon_after_ms"} {
			if getVar(req, key) != nil {
				t.Errorf("request %d: %s should be null, got %#v", i, key, getVar(req, key))
			}
		}
	}
}

// --- requirement 8: baseline exclusion ---

func TestBaselineRequestsAreNeverProbed(t *testing.T) {
	tp := newProbe(t, 1.0, 40, 40)
	tp.rng = &scriptedRand{values: []float64{0.0}} // would always roll true if eligible

	for i := 1; i <= 3; i++ {
		req := newRequest("10.0.0.5")
		rec := httptest.NewRecorder()
		start := time.Now()
		tp.ServeHTTP(rec, req, &recordingHandler{body: "x"})
		if time.Since(start) > 10*time.Millisecond {
			t.Errorf("baseline request %d was held (elapsed %v) -- should never be probed",
				i, time.Since(start))
		}
		if getBoolVar(t, req, "probe_applied") {
			t.Errorf("baseline request %d: probe_applied should be false", i)
		}
	}

	// The 4th request is past the minimum-3 baseline and must become eligible.
	req := newRequest("10.0.0.5")
	rec := httptest.NewRecorder()
	start := time.Now()
	tp.ServeHTTP(rec, req, &recordingHandler{body: "x"})
	if time.Since(start) < 30*time.Millisecond {
		t.Errorf("4th request should be probe-eligible and held, only took %v", time.Since(start))
	}
}

// --- requirement 7: randomised, not deterministic, assignment ---

func TestAssignmentIsRandomisedNotPositional(t *testing.T) {
	tp := newProbe(t, 0.5, 5, 5)
	seq := []float64{0.9, 0.1, 0.1, 0.9, 0.1, 0.9, 0.9, 0.1}
	tp.rng = &scriptedRand{values: seq}
	tp.ForceAfter = 1000 // disable the forced backstop for this test

	var got []bool
	for i := 0; i < len(seq); i++ {
		got = append(got, tp.decide("10.0.0.6"))
	}

	want := []bool{false, false, false, false, true, true, false, true}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("request %d: probe_applied = %v, want %v (full: %v)", i+1, got[i], want[i], got)
			break
		}
	}
}

// --- requirement 9: forced backstop for sessions that would otherwise get zero probes ---

func TestForcedProbeBackstop(t *testing.T) {
	tp := newProbe(t, 0.1, 20, 20)
	tp.ForceAfter = 5
	tp.rng = &scriptedRand{values: []float64{0.99}} // never rolls true on its own

	var forcedAt = -1
	for i := 1; i <= 10; i++ {
		req := newRequest("10.0.0.7")
		rec := httptest.NewRecorder()
		tp.ServeHTTP(rec, req, &recordingHandler{body: "x"})
		if getBoolVar(t, req, "probe_applied") {
			forcedAt = i
			break
		}
	}
	if forcedAt == -1 {
		t.Fatal("session never got a single probe despite the forced backstop")
	}
	// Baseline is 3, ForceAfter is 5 eligible requests -> forced on request 3+5=8.
	if forcedAt != 8 {
		t.Errorf("forced probe fired at request %d, want request 8 (3 baseline + 5 eligible)", forcedAt)
	}
}

func writeManifest(t *testing.T, root, persona string, p95, p99 float64) {
	t.Helper()
	dir := filepath.Join(root, persona)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := "timing:\n  p95_ms: " + strconv.FormatFloat(p95, 'f', -1, 64) +
		"\n  p99_ms: " + strconv.FormatFloat(p99, 'f', -1, 64) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "manifest.yml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestProvisionInertWithoutManifest(t *testing.T) {
	tp := &TimingProbe{
		ProbeRate:    0.0,
		Persona:      "moodle",
		PersonasRoot: t.TempDir(), // deliberately no manifest.yml written
	}
	if err := tp.Provision(caddyTestContext(t)); err != nil {
		t.Fatalf("Provision should succeed inert at probe_rate=0 even with no manifest: %v", err)
	}
	if tp.p95Ms != 0 || tp.p99Ms != 0 {
		t.Errorf("expected zero-value timing when manifest is absent, got p95=%v p99=%v", tp.p95Ms, tp.p99Ms)
	}
}

func TestProvisionRefusesHotWithoutManifest(t *testing.T) {
	tp := &TimingProbe{
		ProbeRate:    0.3,
		Persona:      "moodle",
		PersonasRoot: t.TempDir(),
	}
	if err := tp.Provision(caddyTestContext(t)); err == nil {
		t.Fatal("Provision should fail: probe_rate > 0 with no timing manifest available")
	}
}

func TestProvisionLoadsManifestAndAppliesDefaults(t *testing.T) {
	root := t.TempDir()
	writeManifest(t, root, "moodle", 120, 340)

	tp := &TimingProbe{
		ProbeRate:    0.3,
		Persona:      "moodle",
		PersonasRoot: root,
	}
	if err := tp.Provision(caddyTestContext(t)); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if tp.p95Ms != 120 || tp.p99Ms != 340 {
		t.Errorf("timing not loaded from manifest: got p95=%v p99=%v", tp.p95Ms, tp.p99Ms)
	}
	if tp.MinBaseline != 3 {
		t.Errorf("MinBaseline default = %d, want 3", tp.MinBaseline)
	}
	if tp.SessionIdleSeconds != 1800.0 {
		t.Errorf("SessionIdleSeconds default = %v, want 1800", tp.SessionIdleSeconds)
	}
	if tp.ForceAfter <= 0 {
		t.Errorf("ForceAfter should be auto-derived to a positive value when probe_rate > 0, got %d", tp.ForceAfter)
	}
}

func TestProvisionEnforcesMinimumBaselineOfThree(t *testing.T) {
	root := t.TempDir()
	writeManifest(t, root, "moodle", 100, 200)
	tp := &TimingProbe{ProbeRate: 0, Persona: "moodle", PersonasRoot: root, MinBaseline: 1}
	if err := tp.Provision(caddyTestContext(t)); err != nil {
		t.Fatal(err)
	}
	if tp.MinBaseline != 3 {
		t.Errorf("MinBaseline = %d, want the enforced floor of 3 even though 1 was configured", tp.MinBaseline)
	}
}

func TestProvisionClampsProbeRate(t *testing.T) {
	root := t.TempDir()
	writeManifest(t, root, "moodle", 100, 200)
	tp := &TimingProbe{ProbeRate: 5.0, Persona: "moodle", PersonasRoot: root}
	if err := tp.Provision(caddyTestContext(t)); err != nil {
		t.Fatal(err)
	}
	if tp.ProbeRate != 1.0 {
		t.Errorf("ProbeRate = %v, want clamped to 1.0", tp.ProbeRate)
	}
}

func TestSessionProbeCountTracked(t *testing.T) {
	tp := newProbe(t, 1.0, 1, 1)
	tp.rng = &scriptedRand{values: []float64{0.0}}
	for i := 0; i < 6; i++ {
		tp.ServeHTTP(httptest.NewRecorder(), newRequest("10.0.0.8"), &recordingHandler{body: "x"})
	}
	tp.mu.Lock()
	s := tp.sessions["10.0.0.8"]
	tp.mu.Unlock()
	if s.probedCount != 3 { // 6 requests - 3 baseline = 3 eligible, all probed at rate 1.0
		t.Errorf("probedCount = %d, want 3", s.probedCount)
	}
}
