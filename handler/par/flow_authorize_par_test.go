package par

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing" //"time"

	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/token/hmac"

	//"github.com/golang/mock/gomock"
	"time"

	"github.com/ory/fosite" //"github.com/ory/fosite/internal"
	"github.com/ory/fosite/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var hmacshaStrategy = oauth2.HMACSHAStrategy{
	Enigma:                &hmac.HMACStrategy{GlobalSecret: []byte("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobar")},
	AccessTokenLifespan:   time.Hour * 24,
	AuthorizeCodeLifespan: time.Hour * 24,
}

func TestAuthorizeCode_PushAuthorizeRequest(t *testing.T) {
	requestURIPrefix := "urn:ietf:params:oauth:request_uri_diff:"
	requestURI := fmt.Sprintf("%s%s", requestURIPrefix, "abcdefgh")
	for k, _ := range map[string]oauth2.CoreStrategy{
		"hmac": &hmacshaStrategy,
	} {
		t.Run("strategy="+k, func(t *testing.T) {
			store := storage.NewMemoryStore()

			handler := AuthorizePARHandler{
				Storage:          store,
				RequestURIPrefix: requestURIPrefix,
			}

			for _, c := range []struct {
				handler     AuthorizePARHandler
				areq        *fosite.AuthorizeRequest
				description string
				setup       func(t *testing.T)
				expectErr   error
				expect      func(t *testing.T, areq *fosite.AuthorizeRequest, aresp *fosite.AuthorizeResponse)
			}{
				{
					handler: handler,
					areq: &fosite.AuthorizeRequest{
						Request: fosite.Request{
							Form: url.Values{
								"request_uri": []string{requestURI},
							},
							Session:     &fosite.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					description: "should succeed",
					setup: func(t *testing.T) {
						r := &fosite.AuthorizeRequest{
							ResponseTypes: fosite.Arguments{"code"},
							Request: fosite.Request{
								Client: &fosite.DefaultClient{
									ResponseTypes: fosite.Arguments{"code"},
									RedirectURIs:  []string{"https://asdf.de/cb"},
									Audience:      []string{"https://www.ory.sh/api"},
								},
								RequestedAudience: []string{"https://www.ory.sh/api"},
								RequestedScope:    fosite.Arguments{"a", "b"},
								Session: &fosite.DefaultSession{
									ExpiresAt: map[fosite.TokenType]time.Time{fosite.AccessToken: time.Now().UTC().Add(time.Hour)},
								},
								RequestedAt: time.Now().UTC(),
							},
							State:       "superstate",
							RedirectURI: parseURL("https://asdf.de/cb"),
						}

						err := handler.Storage.CreatePARSession(context.Background(), requestURI, r)
						require.NoError(t, err)
					},
					expect: func(t *testing.T, areq *fosite.AuthorizeRequest, aresp *fosite.AuthorizeResponse) {
						assert.Equal(t, "a b", strings.Join(areq.GetRequestedScopes(), " "))
						assert.Equal(t, "superstate", areq.GetState())
						// TODO: Add more
					},
				},
			} {
				t.Run("case="+c.description, func(t *testing.T) {
					if c.setup != nil {
						c.setup(t)
					}

					aresp := fosite.NewAuthorizeResponse()
					err := handler.HandleAuthorizeEndpointRequest(context.Background(), c.areq, aresp)
					if c.expectErr != nil {
						require.EqualError(t, err, c.expectErr.Error(), "%+v", err)
					} else {
						require.NoError(t, err, "%+v", err)
					}

					if c.expect != nil {
						c.expect(t, c.areq, aresp)
					}
				})
			}
		})
	}
}
