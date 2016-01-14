package owner

import (
	"github.com/go-errors/errors"
	"github.com/golang/mock/gomock"
	"github.com/ory-am/common/pkg"
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/internal"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestValidateTokenEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockResourceOwnerPasswordCredentialsGrantStorage(ctrl)
	areq := internal.NewMockAccessRequester(ctrl)
	defer ctrl.Finish()

	h := ResourceOwnerPasswordCredentialsGrantHandler{
		Store:               store,
		AccessTokenLifespan: time.Hour,
	}
	for k, c := range []struct {
		mock      func()
		req       *http.Request
		expectErr error
	}{
		{
			mock: func() {
				areq.EXPECT().GetGrantType().Return("")
			},
		},
		{
			req: &http.Request{PostForm: url.Values{"username": {"peter"}}},
			mock: func() {
				areq.EXPECT().GetGrantType().Return("password")
			},
			expectErr: fosite.ErrInvalidRequest,
		},
		{
			req: &http.Request{PostForm: url.Values{"password": {"pan"}}},
			mock: func() {
				areq.EXPECT().GetGrantType().Return("password")
			},
			expectErr: fosite.ErrInvalidRequest,
		},
		{
			req: &http.Request{PostForm: url.Values{"username": {"peter"}, "password": {"pan"}}},
			mock: func() {
				areq.EXPECT().GetGrantType().Return("password")
				store.EXPECT().DoCredentialsAuthenticate("peter", "pan").Return(pkg.ErrNotFound)
			},
			expectErr: fosite.ErrInvalidRequest,
		},
		{
			req: &http.Request{PostForm: url.Values{"username": {"peter"}, "password": {"pan"}}},
			mock: func() {
				areq.EXPECT().GetGrantType().Return("password")
				store.EXPECT().DoCredentialsAuthenticate("peter", "pan").Return(errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			req: &http.Request{PostForm: url.Values{"username": {"peter"}, "password": {"pan"}}},
			mock: func() {
				areq.EXPECT().GetGrantType().Return("password")
				store.EXPECT().DoCredentialsAuthenticate("peter", "pan").Return(nil)
				areq.EXPECT().GetRequestForm().Return(url.Values{})
				areq.EXPECT().SetGrantTypeHandled("password")
			},
		},
	} {
		c.mock()
		err := h.ValidateTokenEndpointRequest(nil, c.req, areq)
		assert.True(t, errors.Is(c.expectErr, err), "%d\n%s\n%s", k, err, c.expectErr)
		t.Logf("Passed test case %d", k)
	}
}

func TestHandleTokenEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockResourceOwnerPasswordCredentialsGrantStorage(ctrl)
	chgen := internal.NewMockAccessTokenStrategy(ctrl)
	areq := internal.NewMockAccessRequester(ctrl)
	aresp := internal.NewMockAccessResponder(ctrl)
	//mockcl := internal.NewMockClient(ctrl)
	defer ctrl.Finish()

	h := ResourceOwnerPasswordCredentialsGrantHandler{
		Store:               store,
		AccessTokenStrategy: chgen,
		AccessTokenLifespan: time.Hour,
	}
	for k, c := range []struct {
		mock      func()
		req       *http.Request
		expectErr error
	}{
		{
			mock: func() {
				areq.EXPECT().GetGrantType().Return("")
			},
		},
		{
			mock: func() {
				areq.EXPECT().GetGrantType().Return("password")
				chgen.EXPECT().GenerateAccessToken(gomock.Any(), gomock.Any(), gomock.Any()).Return("", "", errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			mock: func() {
				areq.EXPECT().GetGrantType().Return("password")
				chgen.EXPECT().GenerateAccessToken(gomock.Any(), gomock.Any(), gomock.Any()).Return("", "foo", nil)
				store.EXPECT().CreateAccessTokenSession("foo", gomock.Any()).Return(errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			mock: func() {
				areq.EXPECT().GetGrantType().Return("password")
				chgen.EXPECT().GenerateAccessToken(gomock.Any(), gomock.Any(), gomock.Any()).Return("foo.bar", "", nil)
				store.EXPECT().CreateAccessTokenSession(gomock.Any(), gomock.Any()).Return(nil)

				aresp.EXPECT().SetAccessToken("foo.bar")
				aresp.EXPECT().SetTokenType("bearer")
				aresp.EXPECT().SetExtra("expires_in", gomock.Any())
				aresp.EXPECT().SetExtra("scope", gomock.Any())
				areq.EXPECT().GetGrantedScopes()
			},
		},
	} {
		c.mock()
		err := h.HandleTokenEndpointRequest(nil, c.req, areq, aresp)
		assert.True(t, errors.Is(c.expectErr, err), "%d\n%s\n%s", k, err, c.expectErr)
		t.Logf("Passed test case %d", k)
	}
}
