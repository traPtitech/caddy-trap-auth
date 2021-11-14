package trapauth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/golang-jwt/jwt/v4"
	"go.uber.org/zap"
)

const (
	typeSoft = iota
	typeHard
)

var (
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)

func init() {
	caddy.RegisterModule(Middleware{})
	httpcaddyfile.RegisterHandlerDirective("trapauth", parseCaddyfile)
}

type Middleware struct {
	Redirect        string   `json:"redirect,omitempty"`
	TokenSource     string   `json:"token_source,omitempty"`
	SourceKey       string   `json:"source_key,omitempty"`
	AuthType        string   `json:"auth_type,omitempty"`
	UserHeader      string   `json:"user_header,omitempty"`
	NoStrip         bool     `json:"no_strip,omitempty"`
	AcceptUser      []string `json:"accept_user,omitempty"`
	InvalidateToken []string `json:"invalidate_token,omitempty"`

	at int
	ts tokenSource
}

func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "http.handlers.trapauth",
		New: func() caddy.Module {
			return &Middleware{
				AuthType:    "hard",
				UserHeader:  "X-Showcase-User",
				TokenSource: "cookie",
				SourceKey:   "traP_token",
			}
		},
	}
}

func (m *Middleware) Provision(ctx caddy.Context) error {
	switch strings.ToLower(m.AuthType) {
	case "hard":
		m.at = typeHard
	case "soft":
		m.at = typeSoft
	default:
		return fmt.Errorf("unsupported auth type: %s", m.AuthType)
	}

	switch strings.ToLower(m.TokenSource) {
	case "header":
		m.ts = &headerTokenSource{}
	case "cookie":
		if len(m.SourceKey) == 0 {
			return fmt.Errorf("cookie key is required")
		}
		m.ts = &cookieTokenSource{cookieName: m.SourceKey}
	default:
		return fmt.Errorf("unsupported token source: %s", m.TokenSource)
	}

	ctx.Logger(m).Info("traP authentication plugin is ready", zap.Any("config", m))
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Middleware
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		args := d.RemainingArgs()
		switch len(args) {
		case 0:
			for nesting := d.Nesting(); d.NextBlock(nesting); {
				switch d.Val() {
				case "redirect":
					args := d.RemainingArgs()
					if len(args) != 1 {
						return d.ArgErr()
					}
					m.Redirect = args[0]
				case "token_source":
					args := d.RemainingArgs()
					if len(args) != 1 {
						return d.ArgErr()
					}
					m.TokenSource = args[0]
				case "source_key":
					args := d.RemainingArgs()
					if len(args) != 1 {
						return d.ArgErr()
					}
					m.SourceKey = args[0]
				case "type":
					args := d.RemainingArgs()
					if len(args) != 1 {
						return d.ArgErr()
					}
					m.AuthType = args[0]
				case "user_header":
					args := d.RemainingArgs()
					if len(args) != 1 {
						return d.ArgErr()
					}
					m.UserHeader = args[0]
				case "no_strip":
					m.NoStrip = true
				case "accept_user":
					m.AcceptUser = d.RemainingArgs()
				case "invalidate_token":
					m.InvalidateToken = d.RemainingArgs()
				}
			}
		default:
			return d.ArgErr()
		}
	}
	return nil
}

func (m Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	r.Header.Del(m.UserHeader)

	tokenString := m.ts.ExtractToken(r)
	if len(tokenString) == 0 {
		return m.unauthorized(w, r, next)
	}

	// jwtのライブラリの実装によっては、仕様では許可されていないbase64のパディング(`=`)が
	// 付与されている場合があるので注意すること
	// jwt-goのv3.2.2以降ではパディングが付与されているものは、
	// デコードできないようになっているので、
	// ここでは特に処理をする必要はない
	// see https://wiki.trap.jp/SysAd/ops/2021-11-14
	if isArrayContained(m.InvalidateToken, tokenString) {
		return m.unauthorized(w, r, next)
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (i interface{}, e error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("invalid token")
		}
		return pubkey, nil
	})
	if err != nil || !token.Valid {
		return m.unauthorized(w, r, next)
	}

	if !m.NoStrip {
		m.ts.StripToken(r)
	}

	claims := token.Claims.(jwt.MapClaims)

	idRaw, ok := claims["id"]
	if !ok {
		idRaw, ok = claims["name"]
	}
	if !ok {
		return m.unauthorized(w, r, next)
	}

	id := idRaw.(string)

	if len(m.AcceptUser) > 0 {
		isAccepted := isArrayContained(m.AcceptUser, id)
		if !isAccepted {
			return m.unauthorized(w, r, next)
		}
	}

	r.Header.Set(m.UserHeader, id)

	return next.ServeHTTP(w, r)
}

func (m *Middleware) unauthorized(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if m.at == typeSoft {
		r.Header.Set(m.UserHeader, "-")
		return next.ServeHTTP(w, r)
	}
	if len(m.Redirect) > 0 {
		repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
		http.Redirect(w, r, repl.ReplaceAll(m.Redirect, ""), http.StatusSeeOther)
		return nil
	}
	return caddyhttp.Error(http.StatusUnauthorized, fmt.Errorf("not authenticated"))
}

func isArrayContained(strArr []string, str string) bool {
	isContained := false
	for _, s := range strArr {
		if str == s {
			isContained = true
			break
		}
	}
	return isContained
}
