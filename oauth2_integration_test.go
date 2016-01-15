package fosite_test

import (
	"github.com/go-errors/errors"
	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	. "github.com/ory-am/fosite"
	"github.com/ory-am/fosite/enigma"
	"github.com/ory-am/fosite/handler/core/explicit"
	"github.com/ory-am/fosite/handler/core/strategy"
	. "github.com/ory-am/fosite/internal"
	"github.com/parnurzeal/gorequest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"
	goauth2 "golang.org/x/oauth2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

var clientID = "foo"
var clientSecret = "barbarbarbarbar"
var ts *httptest.Server

var mockStore *MockStorage
var mockClient *MockClient
var mockAuthStore *MockAuthorizeCodeGrantStorage
var mockAuthReq *MockAuthorizeRequester
var mockHasher *MockHasher

var defaultStrategy = &strategy.HMACSHAStrategy{
	Enigma: &enigma.HMACSHAEnigma{
		GlobalSecret: []byte("super-global-secret"),
	},
}

func TestFosite(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockStore = NewMockStorage(ctrl)
	mockClient = NewMockClient(ctrl)
	mockAuthStore = NewMockAuthorizeCodeGrantStorage(ctrl)
	mockAuthReq = NewMockAuthorizeRequester(ctrl)
	mockHasher = NewMockHasher(ctrl)
	defer ctrl.Finish()

	authExplicitHandler := &explicit.AuthorizeExplicitGrantTypeHandler{
		AccessTokenStrategy:   defaultStrategy,
		RefreshTokenStrategy:  defaultStrategy,
		AuthorizeCodeStrategy: defaultStrategy,
		Store: mockAuthStore,
	}

	oauth2 := NewFosite(mockStore)
	oauth2.Hasher = mockHasher
	oauth2.AuthorizeEndpointHandlers.Add("code", authExplicitHandler)
	oauth2.TokenEndpointHandlers.Add("code", authExplicitHandler)

	oauth2TestAuthorizeCodeWorkFlow(oauth2, t, func() {
		mockStore = NewMockStorage(ctrl)
		mockAuthReq = NewMockAuthorizeRequester(ctrl)
		mockClient = NewMockClient(ctrl)
		mockAuthStore = NewMockAuthorizeCodeGrantStorage(ctrl)
		mockHasher = NewMockHasher(ctrl)
		oauth2.Hasher = mockHasher
		oauth2.Store = mockStore
		authExplicitHandler.Store = mockAuthStore
	})
}

func oauth2TestAuthorizeCodeWorkFlow(oauth2 OAuth2Provider, t *testing.T, refreshMocks func()) {
	const workingClientID = "foo"
	const workingClientSecret = "secretsecretsecretsecret"
	const state = "secure-random-state"

	var workingClientHashedSecret = []byte("$2a$10$rUQDYblu3fytMb9aQ3soh.yKNe.17spWcY9fUkkvI9Nv7U1NJCMV2")
	var session = &struct {
		UserID string
	}{
		UserID: "foo",
	}

	router := mux.NewRouter()
	router.HandleFunc("/auth", authEndpoint(t, oauth2, session))
	router.HandleFunc("/cb", cbEndpoint(t))
	router.HandleFunc("/token", tokenEndpoint(t, oauth2))
	ts = httptest.NewServer(router)
	defer ts.Close()

	for k, c := range []struct {
		conf               goauth2.Config
		state              string
		expectBody         string
		expectStatusCode   int
		expectPath         string
		expectedTokenError bool
		mock               func()
	}{
		{
			conf: goauth2.Config{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				RedirectURL:  ts.URL + "/cb",
				Endpoint: goauth2.Endpoint{
					AuthURL: ts.URL + "/auth",
				},
			},
			state: state,
			mock: func() {
				mockStore.EXPECT().GetClient(gomock.Eq(clientID)).AnyTimes().Return(nil, errors.New("foo"))

				mockClient.EXPECT().GetHashedSecret().AnyTimes().Return(workingClientHashedSecret)
				mockClient.EXPECT().GetRedirectURIs().AnyTimes().Return([]string{ts.URL + "/cb"})

				mockAuthStore.EXPECT().GetAuthorizeCodeSession(gomock.Any(), gomock.Any()).AnyTimes().Return(nil, errors.New("foo"))
			},
			expectStatusCode:   http.StatusOK,
			expectPath:         "/auth",
			expectBody:         "{\n\t\"name\": \"invalid_client\",\n\t\"description\": \"Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method)\"\n}",
			expectedTokenError: true,
		},
		{
			conf: goauth2.Config{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				RedirectURL:  ts.URL + "/cb",
				Endpoint: goauth2.Endpoint{
					AuthURL:  ts.URL + "/auth",
					TokenURL: ts.URL + "/token",
				},
			},
			state: state,
			mock: func() {
				mockStore.EXPECT().GetClient(gomock.Eq(clientID)).AnyTimes().Return(mockClient, nil)

				mockHasher.EXPECT().Compare(gomock.Any(), gomock.Any()).Return(nil)

				mockClient.EXPECT().GetHashedSecret().AnyTimes().Return(workingClientHashedSecret)
				mockClient.EXPECT().GetRedirectURIs().AnyTimes().Return([]string{ts.URL + "/cb"})

				mockAuthStore.EXPECT().GetAuthorizeCodeSession(gomock.Any(), gomock.Any()).AnyTimes().Return(nil, errors.New("foo"))
			},
			expectStatusCode:   http.StatusOK,
			expectPath:         "/cb",
			expectBody:         "error: invalid_scope",
			expectedTokenError: true,
		},
		{
			conf: goauth2.Config{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				Scopes:       []string{DefaultRequiredScopeName},
				RedirectURL:  ts.URL + "/cb",
				Endpoint: goauth2.Endpoint{
					AuthURL:  ts.URL + "/auth",
					TokenURL: ts.URL + "/token",
				},
			},
			state: state,
			mock: func() {
				mockStore.EXPECT().GetClient(gomock.Eq(clientID)).AnyTimes().Return(mockClient, nil)

				mockHasher.EXPECT().Compare(gomock.Any(), gomock.Any()).Return(nil)

				mockClient.EXPECT().GetHashedSecret().AnyTimes().Return(workingClientHashedSecret)
				mockClient.EXPECT().GetRedirectURIs().AnyTimes().Return([]string{ts.URL + "/cb"})

				mockAuthStore.EXPECT().CreateAuthorizeCodeSession(gomock.Any(), gomock.Any()).Return(nil)
				mockAuthStore.EXPECT().GetAuthorizeCodeSession(gomock.Any(), gomock.Any()).AnyTimes().Return(nil, errors.New("foo"))
			},
			expectStatusCode:   http.StatusOK,
			expectPath:         "/cb",
			expectBody:         "code: ok",
			expectedTokenError: true,
		},
		{
			conf: goauth2.Config{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				RedirectURL:  ts.URL + "/cb",
				Scopes:       []string{DefaultRequiredScopeName},
				Endpoint: goauth2.Endpoint{
					AuthURL:  ts.URL + "/auth",
					TokenURL: ts.URL + "/token",
				},
			},
			state: state,
			mock: func() {
				mockStore.EXPECT().GetClient(gomock.Eq(clientID)).AnyTimes().Return(mockClient, nil)

				mockHasher.EXPECT().Compare(gomock.Any(), gomock.Any()).Return(nil)

				mockClient.EXPECT().GetID().AnyTimes().Return(clientID)
				mockClient.EXPECT().GetHashedSecret().AnyTimes().Return(workingClientHashedSecret)
				mockClient.EXPECT().GetRedirectURIs().AnyTimes().Return([]string{ts.URL + "/cb"})

				mockAuthStore.EXPECT().CreateAuthorizeCodeSession(gomock.Any(), gomock.Any()).AnyTimes().Return(nil)
				mockAuthStore.EXPECT().GetAuthorizeCodeSession(gomock.Any(), gomock.Any()).AnyTimes().Return(mockAuthReq, nil)
				mockAuthStore.EXPECT().CreateAccessTokenSession(gomock.Any(), gomock.Any()).AnyTimes().Return(nil)
				mockAuthStore.EXPECT().CreateRefreshTokenSession(gomock.Any(), gomock.Any()).AnyTimes().Return(nil)
				mockAuthStore.EXPECT().DeleteAuthorizeCodeSession(gomock.Any()).AnyTimes().Return(nil)

				mockAuthReq.EXPECT().GetClient().AnyTimes().Return(mockClient)
				mockAuthReq.EXPECT().GetRequestedAt().AnyTimes().Return(time.Now())
				mockAuthReq.EXPECT().GetRequestForm().AnyTimes().Return(url.Values{})
				mockAuthReq.EXPECT().GetSession().AnyTimes().Return(nil)
				mockAuthReq.EXPECT().GetScopes().Return([]string{DefaultRequiredScopeName})
			},
			expectStatusCode:   http.StatusOK,
			expectPath:         "/cb",
			expectBody:         "code: ok",
			expectedTokenError: false,
		},

		// TODO add a ton of tests for RFC conform tests. use factories! See https://github.com/ory-am/fosite/issues/13
	} {
		refreshMocks()
		c.mock()
		authurl := c.conf.AuthCodeURL(c.state)
		req := gorequest.New()
		resp, body, errs := req.Get(authurl).End()
		require.Len(t, errs, 0, "%s", errs)
		assert.Equal(t, c.expectPath, resp.Request.URL.Path)
		assert.Equal(t, c.expectBody, body)
		assert.Equal(t, c.expectStatusCode, resp.StatusCode)

		authorizeCode := resp.Request.URL.Query().Get("code")
		token, err := c.conf.Exchange(context.Background(), authorizeCode)
		assert.Equal(t, c.expectedTokenError, err != nil, "%d: %s", k, err)
		if !c.expectedTokenError {
			assert.NotNil(t, token)
		}
		t.Logf("Got token %s", token)
		t.Logf("Passed test case %d", k)
	}
}
