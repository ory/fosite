package oauth2

import (
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
				AccessTokenStrategy:   strategy,
				RefreshTokenStrategy:  strategy,
				AuthorizeCodeStrategy: strategy,
				AccessTokenLifespan:   time.Minute * 60,
				RefreshTokenLifespan:  time.Minute * 120,
			}
			for _, c := range []struct {
				handler     AuthorizeDeviceGrantTypeHandler
				areq        *fosite.AuthorizeRequest
				breq        *fosite.AuthorizeRequest
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
					expectErr:   fosite.ErrInvalidGrant,
				},
			} {
				t.Run("case="+c.description, func(t *testing.T) {

					c.areq.SetID("ID1")
					store.CreateUserCodeSession(nil, c.areq.Form.Get("user_code"), c.areq)

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
