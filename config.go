package trapauth

import (
	"github.com/caddyserver/caddy"
)

const (
	typeSoft = iota
	typeHard
)

var defaultTokenSource = &cookieTokenSource{
	cookieName: "traP_token",
}

type Rule struct {
	redirect        string
	tokenSource     tokenSource
	authType        int
	userHeader      string
	noStrip         bool
	invalidateToken []string
}

func newDefaultRule() Rule {
	return Rule{
		redirect:        "",
		tokenSource:     defaultTokenSource,
		authType:        typeHard,
		userHeader:      "X-Showcase-User",
		noStrip:         false,
		invalidateToken: []string{},
	}
}

func parseConfiguration(c *caddy.Controller) (Rule, error) {
	var rule Rule
	for c.Next() {
		args := c.RemainingArgs()
		switch len(args) {
		case 0:
			r, err := parseBlock(c)
			if err != nil {
				return rule, err
			}
			rule = r
		default:
			return Rule{}, c.ArgErr()
		}
	}
	return rule, nil
}

func parseBlock(c *caddy.Controller) (Rule, error) {
	r := newDefaultRule()
	for c.NextBlock() {
		switch c.Val() {
		case "redirect":
			args := c.RemainingArgs()
			if len(args) != 1 {
				return Rule{}, c.ArgErr()
			}
			r.redirect = args[0]
		case "token_source":
			args := c.RemainingArgs()
			if len(args) < 1 {
				return Rule{}, c.ArgErr()
			}
			switch args[0] {
			case "header":
				r.tokenSource = &headerTokenSource{}
			case "cookie":
				if len(args) != 2 {
					return Rule{}, c.ArgErr()
				}
				r.tokenSource = &cookieTokenSource{
					cookieName: args[1],
				}
			default:
				return Rule{}, c.Errf("unsupported token_source: %s", args[0])
			}
		case "type":
			args := c.RemainingArgs()
			if len(args) != 1 {
				return Rule{}, c.ArgErr()
			}
			switch args[0] {
			case "soft":
				r.authType = typeSoft
			case "hard":
				r.authType = typeHard
			default:
				return Rule{}, c.Errf("unsupported type: %s", args[0])
			}
		case "user_header":
			args := c.RemainingArgs()
			if len(args) != 1 {
				return Rule{}, c.ArgErr()
			}
			r.userHeader = args[0]
		case "no_strip":
			r.noStrip = true
		case "invalidate_token":
			r.invalidateToken = c.RemainingArgs()
		}
	}
	return r, nil
}
