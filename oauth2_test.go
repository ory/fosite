package fosite_test

import (
	"github.com/go-errors/errors"
	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	. "github.com/ory-am/fosite"
	"github.com/ory-am/fosite/enigma"
	"github.com/ory-am/fosite/handler/authorize/explicit"
	. "github.com/ory-am/fosite/internal"
	"github.com/parnurzeal/gorequest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"
	goauth2 "golang.org/x/oauth2"
	"net/http"
	"net/http/httptest"
	"testing"
)

var clientID = "foo"
var clientSecret = "barbarbarbarbar"
var state = "random-state"
var ts *httptest.Server

var mockStore *MockStorage
var mockClient *MockClient
var mockAuthStore *MockAuthorizeStorage

func TestFosite(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockStore = NewMockStorage(ctrl)
	mockClient = NewMockClient(ctrl)
	mockAuthStore = NewMockAuthorizeStorage(ctrl)
	defer ctrl.Finish()

	authExplicitHandler := &explicit.AuthorizeExplicitEndpointHandler{
		Enigma: &enigma.HMACSHAEnigma{GlobalSecret: []byte("super-global-secret")},
		Store:  mockAuthStore,
	}
	oauth2 := &Fosite{
		Store: mockStore,
		AuthorizeEndpointHandlers: []AuthorizeEndpointHandler{
			authExplicitHandler,
		},
	}

	oauth2TestAuthorizeCodeWorkFlow(oauth2, t, func() {
		mockStore = NewMockStorage(ctrl)
		mockClient = NewMockClient(ctrl)
		mockAuthStore = NewMockAuthorizeStorage(ctrl)
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
	router.HandleFunc("/auth", func(rw http.ResponseWriter, req *http.Request) {
		ctx := context.Background()

		ar, err := oauth2.NewAuthorizeRequest(ctx, req)
		if err != nil {
			t.Logf("Request %s failed because %s", ar, err)
			oauth2.WriteAuthorizeError(rw, ar, err)
			return
		}

		// Normally, this would be the place where you would check if the user is logged in and gives his consent.
		// For this test, let's assume that the user exists, is logged in, and gives his consent...

		response, err := oauth2.NewAuthorizeResponse(ctx, req, ar, session)
		if err != nil {
			t.Logf("Response %s failed because %s", ar, err)
			oauth2.WriteAuthorizeError(rw, ar, err)
			return
		}

		oauth2.WriteAuthorizeResponse(rw, ar, response)
	})
	router.HandleFunc("/cb", func(rw http.ResponseWriter, req *http.Request) {
		t.Logf("Callback was called: %s", req.URL.String())
		q := req.URL.Query()
		if q.Get("code") == "" && q.Get("error") == "" {
			assert.NotEmpty(t, q.Get("code"))
			assert.NotEmpty(t, q.Get("error"))
		}

		if q.Get("code") != "" {
			rw.Write([]byte("code: ok"))
		}
		if q.Get("error") != "" {
			rw.Write([]byte("error: " + q.Get("error")))
		}
	})

	ts = httptest.NewServer(router)
	defer ts.Close()

	for k, c := range []struct {
		conf             goauth2.Config
		state            string
		expectBody       string
		expectStatusCode int
		expectPath       string
		mock             func()
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
				mockStore.EXPECT().GetClient(gomock.Eq(clientID)).AnyTimes().Return(mockClient, nil)
				mockClient.EXPECT().CompareSecretWith(gomock.Eq(clientSecret)).AnyTimes().Return(true)
				mockClient.EXPECT().GetHashedSecret().AnyTimes().Return(workingClientHashedSecret)
				mockClient.EXPECT().GetRedirectURIs().AnyTimes().Return([]string{ts.URL + "/cb"})
				mockAuthStore.EXPECT().CreateAuthorizeCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			},
			expectStatusCode: http.StatusOK,
			expectPath:       "/cb",
			expectBody:       "code: ok",
		},
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

				mockClient.EXPECT().CompareSecretWith(gomock.Eq(clientSecret)).AnyTimes().Return(true)
				mockClient.EXPECT().GetHashedSecret().AnyTimes().Return(workingClientHashedSecret)
				mockClient.EXPECT().GetRedirectURIs().AnyTimes().Return([]string{ts.URL + "/cb"})
			},
			expectStatusCode: http.StatusOK,
			expectPath:       "/auth",
			expectBody:       "{\n\t\"name\": \"invalid_client\",\n\t\"description\": \"Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method)\"\n}",
		},

		// TODO add a ton of tests for RFC conform tests. use factories! See https://github.com/ory-am/fosite/issues/13
	} {
		refreshMocks()
		c.mock()
		authurl := c.conf.AuthCodeURL(c.state)
		t.Logf("Passed test case %d", k)
		req := gorequest.New()
		resp, body, errs := req.Get(authurl).End()
		require.Len(t, errs, 0, "%s", errs)
		assert.Equal(t, c.expectPath, resp.Request.URL.Path)
		assert.Equal(t, c.expectBody, body)
		assert.Equal(t, c.expectStatusCode, resp.StatusCode)
	}
}
