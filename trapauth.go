package trapauth

import (
	"errors"
	"fmt"
	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
	"github.com/dgrijalva/jwt-go"
	"net/http"
)

type TrapAuth struct {
	rule Rule
	next httpserver.Handler
}

func init() {
	caddy.RegisterPlugin("trapauth", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {
	rule, err := parseConfiguration(c)
	if err != nil {
		return err
	}

	c.OnStartup(func() error {
		fmt.Println("traP authentication plugin is ready")
		return nil
	})

	s := httpserver.GetConfig(c)
	s.AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return &TrapAuth{
			rule: rule,
			next: next,
		}
	})

	return nil
}

func (h *TrapAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	rule := h.rule

	r.Header.Del(rule.userHeader)

	tokenString := rule.tokenSource.ExtractToken(r)
	if len(tokenString) == 0 {
		return h.unauthorized(w, r, rule)
	}

	if isArrayContained(rule.invalidateToken, tokenString) {
		return h.unauthorized(w, r, rule)
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (i interface{}, e error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("invalid token")
		}
		return pubkey, nil
	})
	if err != nil || !token.Valid {
		return h.unauthorized(w, r, rule)
	}

	if !rule.noStrip {
		rule.tokenSource.StripToken(r)
	}

	claims := token.Claims.(jwt.MapClaims)

	if idI, ok := claims["id"]; ok {
		r.Header.Set(rule.userHeader, idI.(string))
	} else if nameI, ok := claims["name"]; ok {
		r.Header.Set(rule.userHeader, nameI.(string))
	} else {
		return h.unauthorized(w, r, rule)
	}

	return h.next.ServeHTTP(w, r)
}

func (h *TrapAuth) unauthorized(w http.ResponseWriter, r *http.Request, rule Rule) (int, error) {
	if rule.authType == typeSoft {
		r.Header.Set(rule.userHeader, "-")
		return h.next.ServeHTTP(w, r)
	}
	if len(rule.redirect) > 0 {
		replacer := httpserver.NewReplacer(r, nil, "")
		http.Redirect(w, r, replacer.Replace(rule.redirect), http.StatusSeeOther)
		return http.StatusSeeOther, nil
	}
	return http.StatusUnauthorized, nil
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
