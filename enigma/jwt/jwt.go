// Package JWT is able to generate and validate json web tokens.
// Follows https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32
package jwt

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-errors/errors"
)

// TestCertificates are certificates used for testing and localhost.
// NOTE Only use these for tests!
var TestCertificates = [][]string{
	{"../../fosite-example/cert/rs256-private.pem",
		`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtn
SgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0i
cqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhC
PUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsAR
ap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKA
Rdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3
n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAy
MaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9
POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdE
KdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gM
IvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDn
FcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvY
mEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghj
FuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+U
I5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs
2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn
/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNT
OvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86
EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+
hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL0
4aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0Kcnckb
mDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ry
eBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3
CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+
9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq
-----END RSA PRIVATE KEY-----
`},
	{"../../fosite-example/cert/rs256-public.pem",
		`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41
fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7
mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBp
HssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2
XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3b
ODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy
7wIDAQAB
-----END PUBLIC KEY-----
`,
	},
}

// Enigma is responsible for generating and validating challenges.
type Enigma struct {
	PrivateKey []byte
	PublicKey  []byte
}

// LoadCertificate reads certificate from the specified file.
func LoadCertificate(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.Errorf("No path specified")
	}

	var rdr io.Reader
	if f, err := os.Open(path); err == nil {
		rdr = f
		defer f.Close()
	} else {
		return nil, err
	}
	return ioutil.ReadAll(rdr)
}

// Generate generates a new authorize code or returns an error. set secret
func (j *Enigma) Generate(claims Mapper, header Mapper) (string, string, error) {
	if header == nil || claims == nil {
		return "", "", errors.New("Either claims or header is nil.")
	}

	token := jwt.New(jwt.SigningMethodRS256)
	token.Claims = claims.ToMap()
	token.Header = assign(token.Header, header.ToMap())
	rsaKey, err := jwt.ParseRSAPrivateKeyFromPEM(j.PrivateKey)

	if err != nil {
		return "", "", err
	}

	var sig, sstr string
	if sstr, err = token.SigningString(); err != nil {
		return "", "", err
	}

	if sig, err = token.Method.Sign(sstr, rsaKey); err != nil {
		return "", "", err
	}

	return fmt.Sprintf("%s.%s", sstr, sig), sig, nil
}

// Validate : Validates a token and returns its signature or an error if the token is not valid.
func (j *Enigma) Validate(token string) (string, error) {
	split := strings.Split(token, ".")
	if len(split) != 3 {
		return "", errors.New("Header, body and signature must all be set")
	}

	if _, err := j.Decode(token); err != nil {
		return "", err
	}

	return split[2], nil
}

func (j *Enigma) Decode(token string) (*jwt.Token, error) {
	// Parse the token.
	parsedToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.Errorf("Unexpected signing method: %v", t.Header["alg"])
		}
		return jwt.ParseRSAPublicKeyFromPEM(j.PublicKey)
	})

	if err != nil {
		return nil, errors.Errorf("Couldn't parse token: %v", err)
	} else if !parsedToken.Valid {
		return nil, errors.Errorf("Token is invalid")
	}

	return parsedToken, err
}

func assign(a, b map[string]interface{}) map[string]interface{} {
	for k, w := range b {
		if _, ok := a[k]; ok {
			continue
		}
		a[k] = w
	}
	return a
}
