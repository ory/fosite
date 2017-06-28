package openid

import (
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/internal"
	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/hmac"
	"github.com/ory/fosite/token/jwt"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

var idStrategy = &DefaultStrategy{
	RS256JWTStrategy: &jwt.RS256JWTStrategy{
		PrivateKey: internal.MustRSAKey(),
	},
}

var hmacStrategy = &oauth2.HMACSHAStrategy{
	Enigma: &hmac.HMACStrategy{
		GlobalSecret: []byte("some-super-cool-secret-that-nobody-knows"),
	},
}

type defaultSession struct {
	Claims  *jwt.IDTokenClaims
	Headers *jwt.Headers
	*fosite.DefaultSession
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

func TestHybrid_HandleAuthorizeEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	aresp := fosite.NewAuthorizeResponse()
	areq := fosite.NewAuthorizeRequest()
	h := OpenIDConnectHybridHandler{
		AuthorizeExplicitGrantHandler: &oauth2.AuthorizeExplicitGrantHandler{
			AuthorizeCodeStrategy:     hmacStrategy,
			AccessTokenLifespan:       time.Hour,
			AuthCodeLifespan:          time.Hour,
			AccessTokenStrategy:       hmacStrategy,
			AuthorizeCodeGrantStorage: storage.NewMemoryStore(),
		},
		AuthorizeImplicitGrantTypeHandler: &oauth2.AuthorizeImplicitGrantTypeHandler{
			AccessTokenLifespan: time.Hour,
			AccessTokenStrategy: hmacStrategy,
			AccessTokenStorage:  storage.NewMemoryStore(),
		},
		IDTokenHandleHelper: &IDTokenHandleHelper{
			IDTokenStrategy: idStrategy,
		},
		ScopeStrategy: fosite.HierarchicScopeStrategy,
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
					Scopes:        []string{"openid"},
				}
				areq.GrantedScopes = fosite.Arguments{"openid"}
			},
			expectErr: ErrInvalidSession,
		},
		{
			description: "should fail because client missing response types",
			setup: func() {
				areq.ResponseTypes = fosite.Arguments{"token", "code", "id_token"}
				areq.Client = &fosite.DefaultClient{
					GrantTypes:    fosite.Arguments{"implicit"},
					ResponseTypes: fosite.Arguments{"token", "code", "id_token"},
					Scopes:        []string{"openid"},
				}
				areq.Session = &defaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject: "peter",
					},
					Headers:        &jwt.Headers{},
					DefaultSession: new(fosite.DefaultSession),
				}
			},
			expectErr: fosite.ErrInvalidGrant,
		},
		{
			description: "should fail because nonce was not sufficient",
			setup: func() {
				areq.Client = &fosite.DefaultClient{
					GrantTypes:    fosite.Arguments{"authorization_code", "implicit"},
					ResponseTypes: fosite.Arguments{"token", "code", "id_token"},
					Scopes:        []string{"openid"},
				}
				areq.Form.Set("nonce", "short")
			},
			expectErr: fosite.ErrInsufficientEntropy,
		},
		{
			description: "should pass because nonce was set with sufficient entropy",
			setup: func() {
				areq.Form.Set("nonce", "some-foobar-nonce-win")
				areq.Client = &fosite.DefaultClient{
					GrantTypes:    fosite.Arguments{"authorization_code", "implicit"},
					ResponseTypes: fosite.Arguments{"token", "code", "id_token"},
					Scopes:        []string{"openid"},
				}
			},
		},
		{
			description: "should pass",
			setup:       func() {},
			check: func() {
				assert.NotEmpty(t, aresp.GetFragment().Get("id_token"))
				assert.NotEmpty(t, aresp.GetFragment().Get("code"))
				assert.NotEmpty(t, aresp.GetFragment().Get("access_token"))
			},
		},
	} {
		c.setup()
		err := h.HandleAuthorizeEndpointRequest(nil, areq, aresp)
		condition := errors.Cause(err) == c.expectErr
		assert.True(t, condition, "(%d) %s\n%s\n%s", k, c.description, err, c.expectErr)
		if condition {
			t.Logf("Passed test case %d", k)
		} else {
			t.Logf("Failed test case %d", k)
		}

		if c.check != nil {
			c.check()
		}
	}
}
