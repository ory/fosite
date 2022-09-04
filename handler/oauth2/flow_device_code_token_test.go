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

func TestAuthorizeCode_HandleDeviceTokenEndpointRequest(t *testing.T) {

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
				handler             AuthorizeDeviceGrantTypeHandler
				areq                *fosite.AccessRequest
				breq                *fosite.AccessRequest
				createDeviceSession bool
				expire              time.Duration
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
							Session:     &fosite.DefaultSession{Subject: "A"},
							RequestedAt: time.Now().UTC(),
						},
					},
					breq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"authorization_code"},
						Request: fosite.Request{
							Client:      &fosite.DefaultClient{ID: "foo", GrantTypes: []string{""}},
							Session:     &fosite.DefaultSession{Subject: "A"},
							RequestedAt: time.Now().UTC(),
						},
					},
					description:         "Should fail due to wrong grant type",
					expectErr:           fosite.ErrUnknownRequest,
					createDeviceSession: false,
					expire:              time.Minute * 10,
				},
				{
					handler: handler,
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: fosite.Request{
							Client:      &fosite.DefaultClient{ID: "foo", GrantTypes: []string{""}},
							Session:     &fosite.DefaultSession{Subject: "A"},
							RequestedAt: time.Now().UTC(),
						},
					},
					breq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: fosite.Request{
							Client:      &fosite.DefaultClient{ID: "foo", GrantTypes: []string{""}},
							Session:     &fosite.DefaultSession{Subject: "A"},
							RequestedAt: time.Now().UTC(),
						},
					},
					description:         "Should fail due to no device_code supplied",
					expectErr:           fosite.ErrUnauthorizedClient,
					createDeviceSession: false,
					expire:              time.Minute * 10,
				},
				{
					handler: handler,
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: fosite.Request{
							Client:      &fosite.DefaultClient{ID: "foo", GrantTypes: []string{""}},
							Session:     &fosite.DefaultSession{Subject: "A"},
							RequestedAt: time.Now().UTC(),
							Form:        url.Values{"device_code": {"ABC1234"}},
						},
					},
					breq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: fosite.Request{
							Client:      &fosite.DefaultClient{ID: "foo", GrantTypes: []string{""}},
							Session:     &fosite.DefaultSession{Subject: "A"},
							RequestedAt: time.Now().UTC(),
							Form:        url.Values{"device_code": {"ABC1234"}},
						},
					},
					description:         "Should fail due to no user_code session available",
					expectErr:           fosite.ErrUnauthorizedClient,
					createDeviceSession: false,
					expire:              time.Minute * 10,
				},
				{
					handler: handler,
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: fosite.Request{
							Client:      &fosite.DefaultClient{ID: "foo", GrantTypes: []string{""}},
							Session:     &fosite.DefaultSession{Subject: "A"},
							RequestedAt: time.Now().UTC(),
							Form:        url.Values{"device_code": {"ABC1234"}},
						},
					},
					breq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: fosite.Request{
							Client:      &fosite.DefaultClient{ID: "foo", GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"}},
							Session:     &fosite.DefaultSession{Subject: "A"},
							RequestedAt: time.Now().UTC(),
							Form:        url.Values{"device_code": {"ABC1234"}},
						},
					},
					description:         "Should pass as device_code form data and session are available",
					createDeviceSession: true,
					expire:              time.Minute * 10,
				},
				{
					handler: handler,
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: fosite.Request{
							Client:      &fosite.DefaultClient{ID: "foo", GrantTypes: []string{""}},
							Session:     &fosite.DefaultSession{Subject: "A"},
							RequestedAt: time.Now().UTC(),
							Form:        url.Values{"device_code": {"ABC1234"}},
						},
					},
					breq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: fosite.Request{
							Client:      &fosite.DefaultClient{ID: "foo", GrantTypes: []string{""}},
							Session:     &fosite.DefaultSession{Subject: "A"},
							RequestedAt: time.Now().UTC(),
							Form:        url.Values{"device_code": {"ABC1234"}},
						},
					},
					description:         "Should fail as session expired",
					createDeviceSession: true,
					expire:              -(time.Minute * 10),
					expectErr:           fosite.ErrUnauthorizedClient,
				},
				{
					handler: handler,
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: fosite.Request{
							Client:      &fosite.DefaultClient{ID: "foo", GrantTypes: []string{""}},
							Session:     &fosite.DefaultSession{Subject: "A"},
							RequestedAt: time.Now().UTC(),
							Form:        url.Values{"device_code": {"ABC1234"}},
						},
					},
					breq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: fosite.Request{
							Client:      &fosite.DefaultClient{ID: "bar", GrantTypes: []string{""}},
							Session:     &fosite.DefaultSession{Subject: "A"},
							RequestedAt: time.Now().UTC(),
							Form:        url.Values{"device_code": {"ABC1234"}},
						},
					},
					description:         "Should fail as session and request clients do not match",
					createDeviceSession: true,
					expire:              time.Minute * 10,
					expectErr:           fosite.ErrUnauthorizedClient,
				},
			} {
				t.Run("case="+c.description, func(t *testing.T) {

					if c.createDeviceSession {
						c.areq.SetID("ID1")
						c.areq.Session = &fosite.DefaultSession{}
						expireAt := time.Now().UTC().Add(c.expire)
						c.areq.Session.SetExpiresAt(fosite.UserCode, expireAt)
						deviceSignature := hmacshaStrategy.DeviceCodeSignature(context.Background(), c.areq.Form.Get("device_code"))
						store.CreateDeviceCodeSession(nil, deviceSignature, c.areq)
					}

					err := c.handler.HandleTokenEndpointRequest(nil, c.breq)
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
					expectErr:           fosite.ErrInvalidRequest,
					createDeviceSession: false,
				},
				{
					handler: handler,
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: fosite.Request{
							Client:          &fosite.DefaultClient{ID: "foo", GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"}},
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

					c.areq.GetSession().SetExpiresAt(fosite.UserCode, time.Now().Add(time.Minute*5))
					if c.createDeviceSession {
						c.areq.SetID("ID1")
						deviceSig := hmacshaStrategy.DeviceCodeSignature(context.TODO(), c.areq.Form.Get("device_code"))
						store.CreateDeviceCodeSession(nil, deviceSig, c.areq)
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
