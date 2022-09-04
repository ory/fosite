package oauth2

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
	"github.com/stretchr/testify/require"
)

func TestAuthorizeCode_HandleDeviceAuthorizeEndpointRequest(t *testing.T) {

	for k, strategy := range map[string]CoreStrategy{
		"hmac": &hmacshaStrategy,
	} {
		t.Run("strategy="+k, func(t *testing.T) {
			store := storage.NewMemoryStore()
			handler := AuthorizeDeviceGrantTypeHandler{
				CoreStorage:           store,
				DeviceCodeStrategy:    hmacshaStrategy,
				UserCodeStrategy:      hmacshaStrategy,
				AccessTokenStrategy:   strategy,
				RefreshTokenStrategy:  strategy,
				AuthorizeCodeStrategy: strategy,
				Config: &fosite.Config{
					DeviceAndUserCodeLifespan:      time.Minute * 10,
					DeviceAuthTokenPollingInterval: time.Second * 10,
					DeviceVerificationURL:          "localhost",
					AccessTokenLifespan:            time.Hour,
					RefreshTokenLifespan:           time.Hour,
					ScopeStrategy:                  fosite.HierarchicScopeStrategy,
					AudienceMatchingStrategy:       fosite.DefaultAudienceMatchingStrategy,
					RefreshTokenScopes:             []string{"offline"},
				},
			}
			for _, c := range []struct {
				handler     AuthorizeDeviceGrantTypeHandler
				areq        *fosite.AuthorizeRequest
				breq        *fosite.AuthorizeRequest
				expire      time.Duration
				description string
				expectErr   error
				expect      func(t *testing.T, areq *fosite.AuthorizeRequest, aresp *fosite.AuthorizeResponse)
			}{
				{
					handler: handler,
					areq: &fosite.AuthorizeRequest{
						ResponseTypes: fosite.Arguments{""},
						Request:       *fosite.NewRequest(),
					},
					breq: &fosite.AuthorizeRequest{
						ResponseTypes: fosite.Arguments{""},
						Request:       *fosite.NewRequest(),
					},
					description: "should pass because not responsible for handling an empty response type",
					expire:      time.Minute * 10,
				},
				{
					handler: handler,
					areq: &fosite.AuthorizeRequest{
						ResponseTypes: fosite.Arguments{"foo"},
						Request:       *fosite.NewRequest(),
					},
					breq: &fosite.AuthorizeRequest{
						ResponseTypes: fosite.Arguments{""},
						Request:       *fosite.NewRequest(),
					},
					description: "should pass because not responsible for handling an invalid response type",
					expire:      time.Minute * 10,
				},
				{
					handler: handler,
					areq: &fosite.AuthorizeRequest{
						ResponseTypes: fosite.Arguments{"device_code"},
						Request: fosite.Request{
							Client: &fosite.DefaultClient{
								ID:         "Default",
								GrantTypes: fosite.Arguments{"code"},
							},
						},
					},
					breq: &fosite.AuthorizeRequest{
						ResponseTypes: fosite.Arguments{"device_code"},
						Request: fosite.Request{
							Client: &fosite.DefaultClient{
								ID:         "Default",
								GrantTypes: fosite.Arguments{"code"},
							},
						},
					},
					description: "should pass because not responsible for handling an invalid grant type",
					expire:      time.Minute * 10,
				},
				{
					handler: handler,
					areq: &fosite.AuthorizeRequest{
						ResponseTypes: fosite.Arguments{"device_code"},
						Request: fosite.Request{
							Client: &fosite.DefaultClient{
								ID:         "Default",
								GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
							},
							Form: url.Values{"user_code": {"ABC123"}},
						},
					},
					breq: &fosite.AuthorizeRequest{
						ResponseTypes: fosite.Arguments{"device_code"},
						Request: fosite.Request{
							Client: &fosite.DefaultClient{
								ID:         "Default",
								GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
							},
							Form: url.Values{"user_code": {"ABC123"}},
						},
					},
					description: "should pass as session and request have matching client id",
					expire:      time.Minute * 10,
				},
				{
					handler: handler,
					areq: &fosite.AuthorizeRequest{
						ResponseTypes: fosite.Arguments{"device_code"},
						Request: fosite.Request{
							Client: &fosite.DefaultClient{
								ID:         "Default",
								GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
							},
							Form: url.Values{"user_code": {"ABC123"}},
						},
					},
					breq: &fosite.AuthorizeRequest{
						ResponseTypes: fosite.Arguments{"device_code"},
						Request: fosite.Request{
							Client: &fosite.DefaultClient{
								ID:         "Broken",
								GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
							},
							Form: url.Values{"user_code": {"ABC123"}},
						},
					},
					description: "should fail due to a missmatch in session and request ClientID",
					expire:      time.Minute * 10,
					expectErr:   fosite.ErrInvalidGrant,
				},
				{
					handler: handler,
					areq: &fosite.AuthorizeRequest{
						ResponseTypes: fosite.Arguments{"device_code"},
						Request: fosite.Request{
							Client: &fosite.DefaultClient{
								ID:         "Default",
								GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
							},
							Form: url.Values{"user_code": {"ABC123"}},
						},
					},
					breq: &fosite.AuthorizeRequest{
						ResponseTypes: fosite.Arguments{"device_code"},
						Request: fosite.Request{
							Client: &fosite.DefaultClient{
								ID:         "Default",
								GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
							},
							Form: url.Values{"user_code": {"ABC123"}},
						},
					},
					description: "should fail due to expired user session",
					expire:      -(time.Minute * 10),
					//expectErr:   fosite.ErrTokenExpired,
				},
			} {
				t.Run("case="+c.description, func(t *testing.T) {

					c.areq.SetID("ID1")
					c.areq.Session = &fosite.DefaultSession{Subject: "A"}
					c.breq.Session = &fosite.DefaultSession{Subject: "A"}
					expireAt := time.Now().UTC().Add(c.expire)
					c.areq.Session.SetExpiresAt(fosite.UserCode, expireAt)
					userCodeSig := hmacshaStrategy.UserCodeSignature(context.Background(), c.areq.Form.Get("user_code"))
					store.CreateUserCodeSession(nil, userCodeSig, c.areq)

					aresp := fosite.NewAuthorizeResponse()
					err := c.handler.HandleAuthorizeEndpointRequest(nil, c.breq, aresp)
					if c.expectErr != nil {
						require.EqualError(t, err, c.expectErr.Error())
					} else {
						require.NoError(t, err)
					}

					if c.expect != nil {
						c.expect(t, c.areq, aresp)
					}
				})
			}
		})
	}
}
