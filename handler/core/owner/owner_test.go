package owner

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/go-errors/errors"
	"github.com/golang/mock/gomock"
	"github.com/ory-am/common/pkg"
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/internal"
	"github.com/stretchr/testify/assert"
)

func TestHandleTokenEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockResourceOwnerPasswordCredentialsGrantStorage(ctrl)
	defer ctrl.Finish()

	areq := fosite.NewAccessRequest(nil)
	httpreq := &http.Request{PostForm: url.Values{}}

	h := ResourceOwnerPasswordCredentialsGrantHandler{
		Store:               store,
		AccessTokenLifespan: time.Hour,
	}
	for k, c := range []struct {
		description string
		setup       func()
		expectErr   error
	}{
		{
			description: "should pass because not responsible for handling the response type",
			setup: func() {
				areq.GrantTypes = fosite.Arguments{"123"}
			},
		},
		{
			description: "should fail because because invalid credentials",
			setup: func() {
				areq.GrantTypes = fosite.Arguments{"password"}
				httpreq.PostForm.Set("username", "peter")
				httpreq.PostForm.Set("password", "pan")
				store.EXPECT().Authenticate(nil, "peter", "pan").Return(pkg.ErrNotFound)
			},
			expectErr: fosite.ErrInvalidRequest,
		},
		{
			description: "should fail because because error on lookup",
			setup: func() {
				store.EXPECT().Authenticate(nil, "peter", "pan").Return(errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			description: "should pass",
			setup: func() {
				store.EXPECT().Authenticate(nil, "peter", "pan").Return(nil)
			},
		},
	} {
		c.setup()
		err := h.HandleTokenEndpointRequest(nil, httpreq, areq)
		assert.True(t, errors.Is(c.expectErr, err), "(%d) %s\n%s\n%s", k, c.description, err, c.expectErr)
		t.Logf("Passed test case %d", k)
	}
}

func TestPopulateTokenEndpointResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockResourceOwnerPasswordCredentialsGrantStorage(ctrl)
	chgen := internal.NewMockAccessTokenStrategy(ctrl)
	aresp := fosite.NewAccessResponse()
	defer ctrl.Finish()

	areq := fosite.NewAccessRequest(nil)
	httpreq := &http.Request{PostForm: url.Values{}}

	h := ResourceOwnerPasswordCredentialsGrantHandler{
		Store:               store,
		AccessTokenStrategy: chgen,
		AccessTokenLifespan: time.Hour,
	}
	for k, c := range []struct {
		description string
		setup       func()
		expectErr   error
	}{
		{
			description: "should pass because not responsible for handling the response type",
			setup: func() {
				areq.GrantTypes = fosite.Arguments{""}
			},
		},
		{
			description: "should pass",
			setup: func() {
				areq.GrantTypes = fosite.Arguments{"password"}
				chgen.EXPECT().GenerateAccessToken(nil, httpreq, areq).Return("tokenfoo.bar", "bar", nil)
				store.EXPECT().CreateAccessTokenSession(nil, "bar", areq).Return(nil)
			},
		},
	} {
		c.setup()
		err := h.PopulateTokenEndpointResponse(nil, httpreq, areq, aresp)
		assert.True(t, errors.Is(c.expectErr, err), "(%d) %s\n%s\n%s", k, c.description, err, c.expectErr)
		t.Logf("Passed test case %d", k)
	}
}
