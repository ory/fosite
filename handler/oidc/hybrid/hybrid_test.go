package hybrid

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/fosite-example/store"
	"github.com/ory-am/fosite/handler/core/explicit"
	"github.com/ory-am/fosite/handler/core/implicit"
	oauthStrat "github.com/ory-am/fosite/handler/core/strategy"
	"github.com/ory-am/fosite/handler/oidc"
	"github.com/ory-am/fosite/handler/oidc/strategy"
	"github.com/ory-am/fosite/internal"
	"github.com/ory-am/fosite/token/hmac"
	"github.com/ory-am/fosite/token/jwt"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

var idStrategy = &strategy.DefaultStrategy{
	RS256JWTStrategy: &jwt.RS256JWTStrategy{
		PrivateKey: internal.MustRSAKey(),
	},
}

var hmacStrategy = &oauthStrat.HMACSHAStrategy{
	Enigma: &hmac.HMACStrategy{
		GlobalSecret: []byte("some-super-cool-secret-that-nobody-knows"),
	},
}

type defaultSession struct {
	Claims  *jwt.IDTokenClaims
	Headers *jwt.Headers
	*oauthStrat.HMACSession
}

func (s *defaultSession) IDTokenHeaders() *jwt.Headers {
	if s.Headers == nil {
		s.Headers = &jwt.Headers{}
	}
	return s.Headers
}

func (s *defaultSession) IDTokenClaims() *jwt.IDTokenClaims {
	if s.Claims == nil {
		s.Claims = &jwt.IDTokenClaims{}
	}
	return s.Claims
}

func TestHandleAuthorizeEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	aresp := fosite.NewAuthorizeResponse()
	areq := fosite.NewAuthorizeRequest()
	httpreq := &http.Request{Form: url.Values{}}
	h := OpenIDConnectHybridHandler{
		AuthorizeExplicitGrantHandler: &explicit.AuthorizeExplicitGrantHandler{
			AuthorizeCodeStrategy:     hmacStrategy,
			AccessTokenLifespan:       time.Hour,
			AuthCodeLifespan:          time.Hour,
			AccessTokenStrategy:       hmacStrategy,
			AuthorizeCodeGrantStorage: store.NewStore(),
		},
		AuthorizeImplicitGrantTypeHandler: &implicit.AuthorizeImplicitGrantTypeHandler{
			AccessTokenLifespan: time.Hour,
			AccessTokenStrategy: hmacStrategy,
			AccessTokenStorage:  store.NewStore(),
		},
		IDTokenHandleHelper: &oidc.IDTokenHandleHelper{
			IDTokenStrategy: idStrategy,
		},
	}
	for k, c := range []struct {
		description string
		setup       func()
		check       func()
		expectErr   error
	}{
		{
			description: "should not do anything because not a hybrid request",
			setup:       func() {},
		},
		{
			description: "should not do anything because not a hybrid request",
			setup: func() {
				areq.ResponseTypes = fosite.Arguments{"token", "id_token"}
			},
		},
		{
			description: "should fail because session not given",
			setup: func() {
				areq.ResponseTypes = fosite.Arguments{"token", "code"}
				areq.Client = &fosite.DefaultClient{
					GrantTypes:    fosite.Arguments{"authorization_code", "implicit"},
					ResponseTypes: fosite.Arguments{"token", "code", "id_token"},
				}
				areq.Scopes = fosite.Arguments{"openid"}
			},
			expectErr: oidc.ErrInvalidSession,
		},
		{
			description: "should fail because client missing response types",
			setup: func() {
				areq.ResponseTypes = fosite.Arguments{"token", "code", "id_token"}
				areq.Client = &fosite.DefaultClient{
					GrantTypes:    fosite.Arguments{"implicit"},
					ResponseTypes: fosite.Arguments{"token", "code", "id_token"},
				}
				areq.Session = &defaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject: "peter",
					},
					Headers:     &jwt.Headers{},
					HMACSession: &oauthStrat.HMACSession{},
				}
			},
			expectErr: fosite.ErrInvalidGrant,
		},
		{
			description: "should fail because nonce was not set",
			setup: func() {
				areq.Client = &fosite.DefaultClient{
					GrantTypes:    fosite.Arguments{"authorization_code", "implicit"},
					ResponseTypes: fosite.Arguments{"token", "code", "id_token"},
				}
			},
			expectErr: fosite.ErrInsufficientEntropy,
		},
		{
			description: "should fail because nonce was not set",
			setup: func() {
				areq.Form.Add("nonce", "some-foobar-nonce-win")
				areq.Client = &fosite.DefaultClient{
					GrantTypes:    fosite.Arguments{"authorization_code", "implicit"},
					ResponseTypes: fosite.Arguments{"token", "code", "id_token"},
				}
			},
		},
		{
			description: "should pass",
			setup: func() {
				areq.Client = &fosite.DefaultClient{
					GrantTypes:    fosite.Arguments{"authorization_code", "implicit"},
					ResponseTypes: fosite.Arguments{"token", "code", "id_token"},
				}
			},
			check: func() {
				assert.NotEmpty(t, aresp.GetFragment().Get("id_token"))
				assert.NotEmpty(t, aresp.GetFragment().Get("code"))
				assert.NotEmpty(t, aresp.GetFragment().Get("access_token"))
			},
		},
	} {
		c.setup()
		err := h.HandleAuthorizeEndpointRequest(nil, httpreq, areq, aresp)
		assert.True(t, errors.Cause(err) == c.expectErr, "(%d) %s\n%s\n%s", k, c.description, err, c.expectErr)
		t.Logf("Passed test case %d", k)
		if c.check != nil {
			c.check()
		}
	}
}
