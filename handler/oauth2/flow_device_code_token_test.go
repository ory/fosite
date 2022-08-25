package oauth2

import (
	"net/url"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
	"github.com/stretchr/testify/require"
)

func TestAuthorizeCode_HandleDeviceTokenEndpointRequest(t *testing.T) {

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
				handler             AuthorizeDeviceGrantTypeHandler
				areq                *fosite.AccessRequest
				createDeviceSession bool
				description         string
				expectErr           error
				expect              func(t *testing.T, areq *fosite.AccessRequest)
			}{
				{
					handler: handler,
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"authorization_code"},
						Request: fosite.Request{
							Client:      &fosite.DefaultClient{ID: "foo", GrantTypes: []string{""}},
							Session:     &fosite.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					description:         "Should fail due to wrong grant type",
					expectErr:           fosite.ErrUnknownRequest,
					createDeviceSession: false,
				},
				{
					handler: handler,
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: fosite.Request{
							Client:      &fosite.DefaultClient{ID: "foo", GrantTypes: []string{""}},
							Session:     &fosite.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					description:         "Should fail due to no device_code supplied",
					expectErr:           fosite.ErrUnknownRequest,
					createDeviceSession: false,
				},
				{
					handler: handler,
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: fosite.Request{
							Client:      &fosite.DefaultClient{ID: "foo", GrantTypes: []string{""}},
							Session:     &fosite.DefaultSession{},
							RequestedAt: time.Now().UTC(),
							Form:        url.Values{"device_code": {"ABC1234"}},
						},
					},
					description:         "Should fail due to no user_code session available",
					expectErr:           fosite.ErrDeviceTokenPending,
					createDeviceSession: false,
				},
				{
					handler: handler,
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: fosite.Request{
							Client:      &fosite.DefaultClient{ID: "foo", GrantTypes: []string{""}},
							Session:     &fosite.DefaultSession{},
							RequestedAt: time.Now().UTC(),
							Form:        url.Values{"device_code": {"ABC1234"}},
						},
					},
					description:         "Should pass as device_code form data and session are available",
					createDeviceSession: true,
				},
			} {
				t.Run("case="+c.description, func(t *testing.T) {

					if c.createDeviceSession {
						c.areq.SetID("ID1")
						store.CreateDeviceCodeSession(nil, c.areq.Form.Get("device_code"), c.areq)
					}

					err := c.handler.HandleTokenEndpointRequest(nil, c.areq)
					if c.expectErr != nil {
						require.EqualError(t, err, c.expectErr.Error())
					} else {
						require.NoError(t, err)
					}

					if c.expect != nil {
						c.expect(t, c.areq)
					}
				})
			}
		})
	}
}

func TestAuthorizeCode_PopulateDeviceTokenEndpointResponse(t *testing.T) {

	for k, strategy := range map[string]CoreStrategy{
		"hmac": &hmacshaStrategy,
	} {
		t.Run("strategy="+k, func(t *testing.T) {
			store := storage.NewMemoryStore()
			offlineScope := []string{"offline"}
			handler := AuthorizeDeviceGrantTypeHandler{
				CoreStorage:           store,
				AccessTokenStrategy:   strategy,
				RefreshTokenStrategy:  strategy,
				AuthorizeCodeStrategy: strategy,
				AccessTokenLifespan:   time.Minute * 60,
				RefreshTokenLifespan:  time.Minute * 120,
				RefreshTokenScopes:    offlineScope,
			}
			for _, c := range []struct {
				handler             AuthorizeDeviceGrantTypeHandler
				areq                *fosite.AccessRequest
				createDeviceSession bool
				description         string
				expectErr           error
				expect              func(t *testing.T, areq *fosite.AccessRequest)
			}{
				{
					handler: handler,
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"authorization_code"},
						Request: fosite.Request{
							Client:      &fosite.DefaultClient{ID: "foo", GrantTypes: []string{""}},
							Session:     &fosite.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					description:         "Should fail due to wrong grant type",
					expectErr:           fosite.ErrUnknownRequest,
					createDeviceSession: false,
				}, {
					handler: handler,
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: fosite.Request{
							Client:      &fosite.DefaultClient{ID: "foo", GrantTypes: []string{""}},
							Session:     &fosite.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					description:         "Should fail due to no device_code supplied",
					expectErr:           fosite.ErrUnknownRequest,
					createDeviceSession: false,
				},
				{
					handler: handler,
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: fosite.Request{
							Client:      &fosite.DefaultClient{ID: "foo", GrantTypes: []string{""}},
							Session:     &fosite.DefaultSession{},
							RequestedAt: time.Now().UTC(),
							Form:        url.Values{"device_code": {"ABC1234"}},
						},
					},
					description:         "Should fail due to no user_code session available",
					expectErr:           fosite.ErrConsentRequired,
					createDeviceSession: false,
				},
				{
					handler: handler,
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: fosite.Request{
							Client:          &fosite.DefaultClient{ID: "foo", GrantTypes: []string{""}},
							Session:         &fosite.DefaultSession{},
							RequestedAt:     time.Now().UTC(),
							GrantedScope:    fosite.Arguments{"openid", "offline"},
							GrantedAudience: fosite.Arguments{"www.websitesite.com"},
							Form:            url.Values{"device_code": {"ABC1234"}},
						},
					},
					description:         "Should pass as device_code form data and session are available",
					createDeviceSession: true,
				},
			} {
				t.Run("case="+c.description, func(t *testing.T) {

					if c.createDeviceSession {
						c.areq.SetID("ID1")
						store.CreateDeviceCodeSession(nil, c.areq.Form.Get("device_code"), c.areq)
					}

					resp := fosite.NewAccessResponse()
					err := c.handler.PopulateTokenEndpointResponse(nil, c.areq, resp)
					if c.expectErr != nil {
						require.EqualError(t, err, c.expectErr.Error())
					} else {
						require.NoError(t, err)
					}

					accessToken := resp.GetAccessToken()
					refreshToken := resp.GetExtra("refresh_token")

					// Make sure we only create tokens if we have a device session available
					if c.createDeviceSession {
						require.NotEmpty(t, accessToken)
						require.NotEmpty(t, refreshToken)
					} else {
						require.Empty(t, accessToken)
						require.Empty(t, refreshToken)
					}

					if c.expect != nil {
						c.expect(t, c.areq)
					}
				})
			}
		})
	}
}
