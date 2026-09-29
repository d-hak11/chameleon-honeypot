package sourcehash

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func caddyTestContext(t *testing.T) caddy.Context {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	return ctx
}

func newRequest(ip string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = ip + ":54321"
	ctx := context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{})
	return r.WithContext(ctx)
}

type okHandler struct{}

func (okHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	w.WriteHeader(http.StatusOK)
	return nil
}

func provisioned(t *testing.T, salt string) *SourceHash {
	t.Helper()
	t.Setenv(SaltEnvVar, salt)
	s := new(SourceHash)
	if err := s.Provision(caddyTestContext(t)); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	return s
}

func TestProvisionRequiresSalt(t *testing.T) {
	t.Setenv(SaltEnvVar, "")
	s := new(SourceHash)
	if err := s.Provision(caddyTestContext(t)); err == nil {
		t.Fatal("Provision must fail closed with no salt -- an unsalted hash of " +
			"the IPv4 space is trivially reversible")
	}

	t.Setenv(SaltEnvVar, "tooshort")
	s2 := new(SourceHash)
	if err := s2.Provision(caddyTestContext(t)); err == nil {
		t.Fatal("Provision must reject a salt below the minimum length")
	}
}

func TestHashIsSaltedAndStable(t *testing.T) {
	const salt = "0123456789abcdef0123456789abcdef"
	s := provisioned(t, salt)

	req := newRequest("45.83.64.12")
	if err := s.ServeHTTP(httptest.NewRecorder(), req, okHandler{}); err != nil {
		t.Fatal(err)
	}
	got, _ := caddyhttp.GetVar(req.Context(), "source_hash").(string)

	want := sha256.Sum256([]byte(salt + "45.83.64.12"))
	if got != hex.EncodeToString(want[:]) {
		t.Errorf("hash = %q, want sha256(salt+ip) = %q", got, hex.EncodeToString(want[:]))
	}

	// Same address must map to the same key, or sessions cannot be grouped.
	req2 := newRequest("45.83.64.12")
	_ = s.ServeHTTP(httptest.NewRecorder(), req2, okHandler{})
	got2, _ := caddyhttp.GetVar(req2.Context(), "source_hash").(string)
	if got != got2 {
		t.Errorf("same address hashed differently: %q vs %q", got, got2)
	}

	s3 := provisioned(t, "ffffffffffffffffffffffffffffffff")
	req3 := newRequest("45.83.64.12")
	_ = s3.ServeHTTP(httptest.NewRecorder(), req3, okHandler{})
	got3, _ := caddyhttp.GetVar(req3.Context(), "source_hash").(string)
	if got == got3 {
		t.Error("hash did not change with the salt")
	}
}

func TestRawAddressNeverAppearsInVars(t *testing.T) {
	s := provisioned(t, "0123456789abcdef0123456789abcdef")
	const ip = "45.83.64.12"
	req := newRequest(ip)
	_ = s.ServeHTTP(httptest.NewRecorder(), req, okHandler{})

	vars, _ := req.Context().Value(caddyhttp.VarsCtxKey).(map[string]any)
	for k, v := range vars {
		if str, ok := v.(string); ok && str == ip {
			t.Errorf("raw address leaked into var %q", k)
		}
	}
}

func TestPrivateClassification(t *testing.T) {
	s := provisioned(t, "0123456789abcdef0123456789abcdef")

	for _, ip := range []string{
		"127.0.0.1", "172.17.0.1", "172.18.0.1", "172.20.0.1",
		"10.0.0.1", "192.168.1.50", "169.254.1.1",
	} {
		req := newRequest(ip)
		_ = s.ServeHTTP(httptest.NewRecorder(), req, okHandler{})
		if got, _ := caddyhttp.GetVar(req.Context(), "source_private").(bool); !got {
			t.Errorf("%s should be flagged as our own infrastructure", ip)
		}
	}

	for _, ip := range []string{"45.83.64.12", "8.8.8.8", "185.220.101.5"} {
		req := newRequest(ip)
		_ = s.ServeHTTP(httptest.NewRecorder(), req, okHandler{})
		if got, _ := caddyhttp.GetVar(req.Context(), "source_private").(bool); got {
			t.Errorf("%s must not be flagged private", ip)
		}
	}
}

func TestSaltIsNotReadFromConfig(t *testing.T) {
	if _, ok := os.LookupEnv(SaltEnvVar); !ok {
		t.Skip("salt env not set in this test process")
	}
}
