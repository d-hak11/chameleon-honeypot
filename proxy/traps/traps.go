package traps

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

func init() {
	caddy.RegisterModule(new(Traps))
}

// Traps is the http.handlers.traps Caddy module.
type Traps struct {
	// Persona is the active persona, kept in sync on every switch.
	Persona string `json:"persona,omitempty"`

	PersonasRoot string `json:"personas_root,omitempty"`

	cfg trapConfig
}

type trapConfig struct {
	AdminLoginPath     string `yaml:"admin_login_path"`
	WeakUsername       string `yaml:"weak_username"`
	WeakPassword       string `yaml:"weak_password"`
	TamperCheckPath    string `yaml:"tamper_check_path"`
	TamperFieldName    string `yaml:"tamper_field_name"`
	CookieName         string `yaml:"cookie_name"`
	CookieDefaultValue string `yaml:"cookie_default_value"`
	CookieSecret       string `yaml:"cookie_secret"`
}

type manifestFile struct {
	Traps trapConfig `yaml:"traps"`
}

// CaddyModule returns the Caddy module information.
func (*Traps) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.traps",
		New: func() caddy.Module { return new(Traps) },
	}
}

// SecretEnvVar overrides the manifest's dev-default cookie secret; rotate with tools/rotate_trap_secret.py.
const SecretEnvVar = "CHAMELEON_TRAP_SECRET"

// Provision loads the persona's trap config; runs on every config load (i.e. every switch).
func (t *Traps) Provision(ctx caddy.Context) error {
	logger := ctx.Logger()
	if t.PersonasRoot == "" {
		t.PersonasRoot = "/etc/chameleon/personas"
	}
	if t.Persona == "" {
		return nil
	}
	cfg, err := loadTrapConfig(t.PersonasRoot, t.Persona)
	if err != nil {
		return fmt.Errorf("traps: persona %q manifest traps block unavailable: %w", t.Persona, err)
	}
	if env := os.Getenv(SecretEnvVar); env != "" {
		cfg.CookieSecret = env
	} else if cfg.CookieSecret != "" {
		logger.Warn("traps: using the cookie secret committed in the persona manifest; "+
			"set "+SecretEnvVar+" (see tools/rotate_trap_secret.py) for any deployment "+
			"whose repository is or may become readable by someone you are collecting data on",
			zap.String("persona", t.Persona))
	}
	t.cfg = cfg
	return nil
}

func loadTrapConfig(root, persona string) (trapConfig, error) {
	path := filepath.Join(root, persona, "manifest.yml")
	raw, err := os.ReadFile(path)
	if err != nil {
		return trapConfig{}, err
	}
	var m manifestFile
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return trapConfig{}, fmt.Errorf("parsing %s: %w", path, err)
	}
	return m.Traps, nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (t *Traps) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if t.cfg.AdminLoginPath == "" {
		return next.ServeHTTP(w, r)
	}

	// Never downgrade trap vars set by the config-only robots route earlier in the chain.
	ctx := r.Context()
	triggered, _ := caddyhttp.GetVar(ctx, "trap_triggered").(bool)
	trapID, _ := caddyhttp.GetVar(ctx, "trap_id").(string)
	var fieldModified *bool

	switch {
	case r.Method == http.MethodPost && r.URL.Path == t.cfg.AdminLoginPath:
		if form, err := readForm(r); err == nil {
			triggered = true
			if form.Get("username") == t.cfg.WeakUsername && form.Get("password") == t.cfg.WeakPassword {
				trapID = "weak_credential_used"
			} else {
				trapID = "wrong_credential_attempted"
			}
		}

	case r.Method == http.MethodPost && r.URL.Path == t.cfg.TamperCheckPath && t.cfg.TamperFieldName != "":
		if form, err := readForm(r); err == nil {
			if val, present := form[t.cfg.TamperFieldName]; present {
				modified := len(val) > 0 && val[0] != ""
				fieldModified = &modified
				if modified {
					triggered = true
					trapID = "hidden_field_modified"
				}
			}
		}
	}

	if !triggered && t.cfg.CookieName != "" {
		if c, err := r.Cookie(t.cfg.CookieName); err == nil {
			if cookieTampered(c.Value, t.cfg.CookieSecret) {
				triggered = true
				trapID = "fake_cookie_tampered"
			}
		}
	}

	caddyhttp.SetVar(ctx, "trap_triggered", triggered)
	if trapID != "" {
		caddyhttp.SetVar(ctx, "trap_id", trapID)
	} else {
		caddyhttp.SetVar(ctx, "trap_id", nil)
	}
	if fieldModified != nil {
		caddyhttp.SetVar(ctx, "trap_field_modified", *fieldModified)
	} else {
		caddyhttp.SetVar(ctx, "trap_field_modified", nil)
	}

	return next.ServeHTTP(w, r)
}

// readForm parses the body without consuming it, so downstream still gets the original.
func readForm(r *http.Request) (url.Values, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16)) // 64KiB cap; these are small login forms
	if err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return url.ParseQuery(string(body))
}

// cookieTampered reports whether value fails HMAC verification; malformed counts as tampered.
func cookieTampered(value, secret string) bool {
	parts := strings.SplitN(value, ".", 2)
	if len(parts) != 2 {
		return true
	}
	payload, mac := parts[0], parts[1]
	given, err := hex.DecodeString(mac)
	if err != nil {
		return true
	}
	want := hmac.New(sha256.New, []byte(secret))
	want.Write([]byte(payload))
	return !hmac.Equal(given, want.Sum(nil))
}

// Interface guards.
var (
	_ caddy.Provisioner           = (*Traps)(nil)
	_ caddyhttp.MiddlewareHandler = (*Traps)(nil)
)
