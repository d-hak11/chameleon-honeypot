package traps

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func newRequest(method, path, body string, headers map[string]string) *http.Request {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
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

type passHandler struct {
	called  bool
	gotBody string
}

func (h *passHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	h.called = true
	if r.Body != nil {
		b, _ := io.ReadAll(r.Body)
		h.gotBody = string(b)
	}
	w.WriteHeader(http.StatusOK)
	return nil
}

func signedCookie(payload, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	return payload + "." + hex.EncodeToString(mac.Sum(nil))
}

func newTraps(cfg trapConfig) *Traps {
	return &Traps{Persona: "test", PersonasRoot: "/nonexistent", cfg: cfg}
}

var testCfg = trapConfig{
	AdminLoginPath:     "/admin/index.php",
	WeakUsername:       "admin",
	WeakPassword:       "admin123",
	TamperCheckPath:    "/login/index.php",
	TamperFieldName:    "anchor",
	CookieName:         "MOODLE_PREF",
	CookieDefaultValue: "light",
	CookieSecret:       "test-secret",
}

func TestWeakCredentialUsed(t *testing.T) {
	tr := newTraps(testCfg)
	body := url.Values{"username": {"admin"}, "password": {"admin123"}}.Encode()
	req := newRequest(http.MethodPost, "/admin/index.php", body, nil)
	h := &passHandler{}
	if err := tr.ServeHTTP(httptest.NewRecorder(), req, h); err != nil {
		t.Fatal(err)
	}
	if !h.called {
		t.Fatal("next handler was not called")
	}
	if h.gotBody != body {
		t.Errorf("downstream body not restored: got %q, want %q", h.gotBody, body)
	}
	if !getBoolVar(t, req, "trap_triggered") {
		t.Error("expected trap_triggered=true")
	}
	if got := getVar(req, "trap_id"); got != "weak_credential_used" {
		t.Errorf("trap_id = %#v, want weak_credential_used", got)
	}
}

func TestWrongCredentialAttempted(t *testing.T) {
	tr := newTraps(testCfg)
	body := url.Values{"username": {"admin"}, "password": {"hunter2"}}.Encode()
	req := newRequest(http.MethodPost, "/admin/index.php", body, nil)
	tr.ServeHTTP(httptest.NewRecorder(), req, &passHandler{})

	if !getBoolVar(t, req, "trap_triggered") {
		t.Error("expected trap_triggered=true -- any credential attempt on a path with no real backend is a hit")
	}
	if got := getVar(req, "trap_id"); got != "wrong_credential_attempted" {
		t.Errorf("trap_id = %#v, want wrong_credential_attempted -- must be distinguishable from the planted bait", got)
	}
}

func TestPlainGetToAdminPathTriggersNothingHere(t *testing.T) {
	tr := newTraps(testCfg)
	req := newRequest(http.MethodGet, "/admin/index.php", "", nil)
	tr.ServeHTTP(httptest.NewRecorder(), req, &passHandler{})
	if getBoolVar(t, req, "trap_triggered") {
		t.Error("GET to the admin path must not trigger the credential-inspection trap")
	}
}

func TestHiddenFieldModified(t *testing.T) {
	tr := newTraps(testCfg)
	body := url.Values{"anchor": {"tampered-value"}, "username": {"x"}}.Encode()
	req := newRequest(http.MethodPost, "/login/index.php", body, nil)
	tr.ServeHTTP(httptest.NewRecorder(), req, &passHandler{})

	if !getBoolVar(t, req, "trap_triggered") {
		t.Error("expected trap_triggered=true")
	}
	if got := getVar(req, "trap_id"); got != "hidden_field_modified" {
		t.Errorf("trap_id = %#v, want hidden_field_modified", got)
	}
	if !getBoolVar(t, req, "trap_field_modified") {
		t.Error("expected trap_field_modified=true")
	}
}

func TestHiddenFieldLeftEmptyIsCheckedNotTriggered(t *testing.T) {
	tr := newTraps(testCfg)
	body := url.Values{"anchor": {""}, "username": {"x"}}.Encode()
	req := newRequest(http.MethodPost, "/login/index.php", body, nil)
	tr.ServeHTTP(httptest.NewRecorder(), req, &passHandler{})

	if getBoolVar(t, req, "trap_triggered") {
		t.Error("an untouched (empty) hidden field must not count as a trigger")
	}
	if getVar(req, "trap_field_modified") != false {
		t.Errorf("trap_field_modified = %#v, want false (checked, found clean, not absent)",
			getVar(req, "trap_field_modified"))
	}
}

func TestHiddenFieldAbsentIsNilNotFalse(t *testing.T) {
	tr := newTraps(testCfg)
	body := url.Values{"username": {"x"}}.Encode() // no anchor field at all
	req := newRequest(http.MethodPost, "/login/index.php", body, nil)
	tr.ServeHTTP(httptest.NewRecorder(), req, &passHandler{})

	if getVar(req, "trap_field_modified") != nil {
		t.Errorf("trap_field_modified = %#v, want nil -- field wasn't present to check, "+
			"a different fact from 'present and clean'", getVar(req, "trap_field_modified"))
	}
}

func TestCookieValidIsNotTampered(t *testing.T) {
	tr := newTraps(testCfg)
	valid := signedCookie("light", "test-secret")
	req := newRequest(http.MethodGet, "/", "", map[string]string{"Cookie": "MOODLE_PREF=" + valid})
	tr.ServeHTTP(httptest.NewRecorder(), req, &passHandler{})

	if getBoolVar(t, req, "trap_triggered") {
		t.Error("a validly-signed, untouched cookie must not trigger the trap")
	}
}

func TestCookieTamperedValueDetected(t *testing.T) {
	tr := newTraps(testCfg)
	tampered := "dark." + strings.Repeat("00", 32) // wrong mac for this payload
	req := newRequest(http.MethodGet, "/", "", map[string]string{"Cookie": "MOODLE_PREF=" + tampered})
	tr.ServeHTTP(httptest.NewRecorder(), req, &passHandler{})

	if !getBoolVar(t, req, "trap_triggered") {
		t.Error("expected trap_triggered=true for a cookie with an invalid signature")
	}
	if got := getVar(req, "trap_id"); got != "fake_cookie_tampered" {
		t.Errorf("trap_id = %#v, want fake_cookie_tampered", got)
	}
}

func TestCookieMalformedValueIsTreatedAsTampered(t *testing.T) {
	tr := newTraps(testCfg)
	req := newRequest(http.MethodGet, "/", "", map[string]string{"Cookie": "MOODLE_PREF=not-even-shaped-right"})
	tr.ServeHTTP(httptest.NewRecorder(), req, &passHandler{})
	if !getBoolVar(t, req, "trap_triggered") {
		t.Error("a malformed cookie value (no payload.mac shape) must count as tampered")
	}
}

func TestNoCookiePresentTriggersNothing(t *testing.T) {
	tr := newTraps(testCfg)
	req := newRequest(http.MethodGet, "/", "", nil)
	tr.ServeHTTP(httptest.NewRecorder(), req, &passHandler{})
	if getBoolVar(t, req, "trap_triggered") {
		t.Error("a first-time visitor who never received the cookie must not be flagged")
	}
}

func TestCredentialTrapTakesPriorityOverCookieCheck(t *testing.T) {
	tr := newTraps(testCfg)
	body := url.Values{"username": {"admin"}, "password": {"admin123"}}.Encode()
	req := newRequest(http.MethodPost, "/admin/index.php", body,
		map[string]string{"Cookie": "MOODLE_PREF=dark." + strings.Repeat("00", 32)})
	tr.ServeHTTP(httptest.NewRecorder(), req, &passHandler{})
	if got := getVar(req, "trap_id"); got != "weak_credential_used" {
		t.Errorf("trap_id = %#v, want weak_credential_used (priority order)", got)
	}
}

func TestInertBeforeAnyPersonaConfigured(t *testing.T) {
	tr := &Traps{} // Provision never ran / no-op'd: cfg is the zero value
	req := newRequest(http.MethodPost, "/admin/index.php", "username=admin&password=admin123", nil)
	h := &passHandler{}
	if err := tr.ServeHTTP(httptest.NewRecorder(), req, h); err != nil {
		t.Fatal(err)
	}
	if !h.called {
		t.Fatal("next handler must still be called when no persona is configured")
	}
	if getVar(req, "trap_triggered") != nil {
		t.Errorf("no trap vars should be set before a persona is configured, got trap_triggered=%#v",
			getVar(req, "trap_triggered"))
	}
}
