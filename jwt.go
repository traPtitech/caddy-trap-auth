package trapauth

import (
	"crypto/rsa"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt"
)

const pubkeyPEM = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAraewUw7V1hiuSgUvkly9
X+tcIh0e/KKqeFnAo8WR3ez2tA0fGwM+P8sYKHIDQFX7ER0c+ecTiKpo/Zt/a6AO
gB/zHb8L4TWMr2G4q79S1gNw465/SEaGKR8hRkdnxJ6LXdDEhgrH2ZwIPzE0EVO1
eFrDms1jS3/QEyZCJ72oYbAErI85qJDF/y/iRgl04XBK6GLIW11gpf8KRRAh4vuh
g5/YhsWUdcX+uDVthEEEGOikSacKZMFGZNi8X8YVnRyWLf24QTJnTHEv+0EStNrH
HnxCPX0m79p7tBfFC2ha2OYfOtA+94ZfpZXUi2r6gJZ+dq9FWYyA0DkiYPUq9QMb
OQIDAQAB
-----END PUBLIC KEY-----
`

var pubkey *rsa.PublicKey

type tokenSource interface {
	ExtractToken(r *http.Request) string
	StripToken(r *http.Request)
}

func init() {
	pubkey, _ = jwt.ParseRSAPublicKeyFromPEM([]byte(pubkeyPEM))
}

type headerTokenSource struct{}

func (hts *headerTokenSource) ExtractToken(r *http.Request) string {
	h := strings.Split(r.Header.Get("Authorization"), " ")
	if h[0] != "Bearer" || len(h) < 2 {
		return ""
	}
	return h[1]
}

func (hts *headerTokenSource) StripToken(r *http.Request) {
	r.Header.Del("Authorization")
}

type cookieTokenSource struct {
	cookieName string
}

func (cts *cookieTokenSource) ExtractToken(r *http.Request) string {
	c, err := r.Cookie(cts.cookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

func (cts *cookieTokenSource) StripToken(r *http.Request) {
	cookies := r.Cookies()
	r.Header.Del("Cookie")
	for _, v := range cookies {
		if v.Name == cts.cookieName {
			continue
		}
		r.AddCookie(v)
	}
}
