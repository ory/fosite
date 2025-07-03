// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/fosite"
)

func TestNone_HandleAuthorizeEndpointRequest(t *testing.T) {
	handler := NoneResponseTypeHandler{
		Config: &fosite.Config{
			ScopeStrategy:            fosite.HierarchicScopeStrategy,
			AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
		},
	}
	for _, c := range []struct {
		handler     NoneResponseTypeHandler
		areq        *fosite.AuthorizeRequest
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
			description: "should pass because not responsible for handling an empty response type",
		},
		{
			handler: handler,
			areq: &fosite.AuthorizeRequest{
				ResponseTypes: fosite.Arguments{"foo"},
				Request:       *fosite.NewRequest(),
			},
			description: "should pass because not responsible for handling an invalid response type",
		},
		{
			handler: handler,
			areq: &fosite.AuthorizeRequest{
				ResponseTypes: fosite.Arguments{"none"},
				Request: fosite.Request{
					Client: &fosite.DefaultClient{
						ResponseTypes: fosite.Arguments{"code", "none"},
						RedirectURIs:  []string{"http://asdf.com/cb"},
					},
				},
				RedirectURI: parseUrl("http://asdf.com/cb"),
			},
			description: "should fail because redirect uri is not https",
			expectErr:   fosite.ErrInvalidRequest,
		},
		{
			handler: handler,
			areq: &fosite.AuthorizeRequest{
				ResponseTypes: fosite.Arguments{"none"},
				Request: fosite.Request{
					Client: &fosite.DefaultClient{
						ResponseTypes: fosite.Arguments{"code", "none"},
						RedirectURIs:  []string{"https://asdf.com/cb"},
						Audience:      []string{"https://www.ory.sh/api"},
					},
					RequestedAudience: []string{"https://www.ory.sh/not-api"},
				},
				RedirectURI: parseUrl("https://asdf.com/cb"),
			},
			description: "should fail because audience doesn't match",
			expectErr:   fosite.ErrInvalidRequest,
		},
		{
			handler: handler,
			areq: &fosite.AuthorizeRequest{
				ResponseTypes: fosite.Arguments{"none"},
				Request: fosite.Request{
					Client: &fosite.DefaultClient{
						ResponseTypes: fosite.Arguments{"code", "none"},
						RedirectURIs:  []string{"https://asdf.de/cb"},
						Audience:      []string{"https://www.ory.sh/api"},
					},
					RequestedAudience: []string{"https://www.ory.sh/api"},
					GrantedScope:      fosite.Arguments{"a", "b"},
					Session: &fosite.DefaultSession{
						ExpiresAt: map[fosite.TokenType]time.Time{fosite.AccessToken: time.Now().UTC().Add(time.Hour)},
					},
					RequestedAt: time.Now().UTC(),
				},
				State:       "superstate",
				RedirectURI: parseUrl("https://asdf.de/cb"),
			},
			description: "should pass",
			expect: func(t *testing.T, areq *fosite.AuthorizeRequest, aresp *fosite.AuthorizeResponse) {
				assert.Equal(t, strings.Join(areq.GrantedScope, " "), aresp.GetParameters().Get("scope"))
				assert.Equal(t, areq.State, aresp.GetParameters().Get("state"))
				assert.Equal(t, fosite.ResponseModeQuery, areq.GetResponseMode())
			},
		},
		{
			handler: handler,
			areq: &fosite.AuthorizeRequest{
				ResponseTypes: fosite.Arguments{"none"},
				Request: fosite.Request{
					Client: &fosite.DefaultClient{
						ResponseTypes: fosite.Arguments{"none"},
						RedirectURIs:  []string{"https://asdf.de/cb"},
						Audience:      []string{"https://www.ory.sh/api"},
					},
					RequestedAudience: []string{"https://www.ory.sh/api"},
					GrantedScope:      fosite.Arguments{"a", "b"},
					Session: &fosite.DefaultSession{
						ExpiresAt: map[fosite.TokenType]time.Time{fosite.AccessToken: time.Now().UTC().Add(time.Hour)},
					},
					RequestedAt: time.Now().UTC(),
				},
				State:       "superstate",
				RedirectURI: parseUrl("https://asdf.de/cb"),
			},
			description: "should pass with no response types other than none",
			expect: func(t *testing.T, areq *fosite.AuthorizeRequest, aresp *fosite.AuthorizeResponse) {
				assert.Equal(t, strings.Join(areq.GrantedScope, " "), aresp.GetParameters().Get("scope"))
				assert.Equal(t, areq.State, aresp.GetParameters().Get("state"))
				assert.Equal(t, fosite.ResponseModeQuery, areq.GetResponseMode())
			},
		},
		{
			handler: NoneResponseTypeHandler{
				Config: &fosite.Config{
					ScopeStrategy:            fosite.HierarchicScopeStrategy,
					AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
					OmitRedirectScopeParam:   true,
				},
			},
			areq: &fosite.AuthorizeRequest{
				ResponseTypes: fosite.Arguments{"none"},
				Request: fosite.Request{
					Client: &fosite.DefaultClient{
						ResponseTypes: fosite.Arguments{"code", "none"},
						RedirectURIs:  []string{"https://asdf.de/cb"},
						Audience:      []string{"https://www.ory.sh/api"},
					},
					RequestedAudience: []string{"https://www.ory.sh/api"},
					GrantedScope:      fosite.Arguments{"a", "b"},
					Session: &fosite.DefaultSession{
						ExpiresAt: map[fosite.TokenType]time.Time{fosite.AccessToken: time.Now().UTC().Add(time.Hour)},
					},
					RequestedAt: time.Now().UTC(),
				},
				State:       "superstate",
				RedirectURI: parseUrl("https://asdf.de/cb"),
			},
			description: "should pass but no scope in redirect uri",
			expect: func(t *testing.T, areq *fosite.AuthorizeRequest, aresp *fosite.AuthorizeResponse) {
				assert.Empty(t, aresp.GetParameters().Get("scope"))
				assert.Equal(t, areq.State, aresp.GetParameters().Get("state"))
				assert.Equal(t, fosite.ResponseModeQuery, areq.GetResponseMode())
			},
		},
	} {
		t.Run("case="+c.description, func(t *testing.T) {
			aresp := fosite.NewAuthorizeResponse()
			err := c.handler.HandleAuthorizeEndpointRequest(context.Background(), c.areq, aresp)
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
}
