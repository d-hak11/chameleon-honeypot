package sourcehash

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// SaltEnvVar is the environment variable holding the pseudonymisation salt.
const SaltEnvVar = "CHAMELEON_SOURCE_SALT"

// minSaltLen is a floor; generate 32 random bytes (make salt).
const minSaltLen = 16

func init() {
	caddy.RegisterModule(new(SourceHash))
}

// SourceHash is the http.handlers.source_hash Caddy module.
type SourceHash struct {
	salt   []byte
	logger interface{ Warn(string, ...any) }
}

// CaddyModule returns the Caddy module information.
func (*SourceHash) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.source_hash",
		New: func() caddy.Module { return new(SourceHash) },
	}
}

// Provision loads the salt from the environment and fails closed without one.
func (s *SourceHash) Provision(ctx caddy.Context) error {
	salt := os.Getenv(SaltEnvVar)
	if len(salt) < minSaltLen {
		return fmt.Errorf(
			"source_hash: %s must be set to at least %d characters "+
				"(generate one with `make salt`; it must not be committed)",
			SaltEnvVar, minSaltLen)
	}
	s.salt = []byte(salt)
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (s *SourceHash) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ip := clientIP(r)
	ctx := r.Context()
	caddyhttp.SetVar(ctx, "source_hash", s.hash(ip))
	caddyhttp.SetVar(ctx, "source_private", isPrivate(ip))
	return next.ServeHTTP(w, r)
}

func (s *SourceHash) hash(ip string) string {
	sum := sha256.Sum256(append(append([]byte{}, s.salt...), []byte(ip)...))
	return hex.EncodeToString(sum[:])
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// isPrivate reports whether addr is loopback/RFC1918/link-local (our own infra).
func isPrivate(ip string) bool {
	addr := net.ParseIP(ip)
	if addr == nil {
		return false
	}
	return addr.IsLoopback() ||
		addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsUnspecified()
}

// Interface guards.
var (
	_ caddy.Provisioner           = (*SourceHash)(nil)
	_ caddyhttp.MiddlewareHandler = (*SourceHash)(nil)
)
