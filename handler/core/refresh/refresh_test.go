package refresh

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
	store := internal.NewMockRefreshTokenGrantStorage(ctrl)
	chgen := internal.NewMockRefreshTokenStrategy(ctrl)
	defer ctrl.Finish()

	areq := fosite.NewAccessRequest(nil)
	httpreq := &http.Request{PostForm: url.Values{}}

	h := RefreshTokenGrantHandler{
		RefreshTokenGrantStorage: store,
		RefreshTokenStrategy:     chgen,
		AccessTokenLifespan:      time.Hour,
	}
	for k, c := range []struct {
		description string
		setup       func()
		expectErr   error
	}{
		{
			description: "should fail because not responsible",
			expectErr:   fosite.ErrUnknownRequest,
			setup: func() {
				areq.GrantTypes = fosite.Arguments{"123"}
			},
		},
		{
			description: "should fail because token does not validate",
			setup: func() {
				areq.GrantTypes = fosite.Arguments{"refresh_token"}
				httpreq.PostForm.Add("refresh_token", "some.refreshtokensig")
				chgen.EXPECT().ValidateRefreshToken(nil, areq, "some.refreshtokensig").Return("", errors.New(""))
			},
			expectErr: fosite.ErrInvalidRequest,
		},
		{
			description: "should fail because token can't be found",
			setup: func() {
				chgen.EXPECT().ValidateRefreshToken(nil, areq, "some.refreshtokensig").AnyTimes().Return("refreshtokensig", nil)
				store.EXPECT().GetRefreshTokenSession(nil, "refreshtokensig", nil).Return(nil, pkg.ErrNotFound)
			},
			expectErr: fosite.ErrInvalidRequest,
		},
		{
			description: "should fail because token lookup failed",
			setup: func() {
				store.EXPECT().GetRefreshTokenSession(nil, "refreshtokensig", nil).Return(nil, errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			description: "should fail because client mismatches",
			setup: func() {
				areq.Client = &fosite.DefaultClient{ID: "foo"}
				store.EXPECT().GetRefreshTokenSession(nil, "refreshtokensig", nil).Return(&fosite.Request{Client: &fosite.DefaultClient{ID: ""}}, nil)
			},
			expectErr: fosite.ErrInvalidRequest,
		},
		{
			description: "should pass",
			setup: func() {
				store.EXPECT().GetRefreshTokenSession(nil, "refreshtokensig", nil).Return(&fosite.Request{Client: &fosite.DefaultClient{ID: "foo"}}, nil)
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
	store := internal.NewMockRefreshTokenGrantStorage(ctrl)
	rcts := internal.NewMockRefreshTokenStrategy(ctrl)
	acts := internal.NewMockAccessTokenStrategy(ctrl)
	areq := fosite.NewAccessRequest(nil)
	aresp := internal.NewMockAccessResponder(ctrl)
	httpreq := &http.Request{PostForm: url.Values{}}
	defer ctrl.Finish()

	areq.Client = &fosite.DefaultClient{}
	h := RefreshTokenGrantHandler{
		RefreshTokenGrantStorage: store,
		RefreshTokenStrategy:     rcts,
		AccessTokenStrategy:      acts,
		AccessTokenLifespan:      time.Hour,
	}
	for k, c := range []struct {
		description string
		setup       func()
		expectErr   error
	}{
		{
			description: "should fail because not responsible",
			expectErr:   fosite.ErrUnknownRequest,
			setup: func() {
				areq.GrantTypes = fosite.Arguments{"313"}
			},
		},
		{
			description: "should fail because validation fails",
			setup: func() {
				areq.GrantTypes = fosite.Arguments{"refresh_token"}
				httpreq.PostForm.Add("refresh_token", "foo.reftokensig")
				rcts.EXPECT().ValidateRefreshToken(nil, areq, "foo.reftokensig").Return("", errors.New(""))
			},
			expectErr: fosite.ErrInvalidRequest,
		},
		{
			description: "should fail because access token generation fails",
			setup: func() {
				rcts.EXPECT().ValidateRefreshToken(nil, areq, "foo.reftokensig").AnyTimes().Return("reftokensig", nil)
				acts.EXPECT().GenerateAccessToken(nil, areq).Return("", "", errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			description: "should fail because access token generation fails",
			setup: func() {
				acts.EXPECT().GenerateAccessToken(nil, areq).AnyTimes().Return("access.atsig", "atsig", nil)
				rcts.EXPECT().GenerateRefreshToken(nil, areq).Return("", "", errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			description: "should fail because persisting fails",
			setup: func() {
				rcts.EXPECT().GenerateRefreshToken(nil, areq).AnyTimes().Return("refresh.resig", "resig", nil)
				store.EXPECT().PersistRefreshTokenGrantSession(nil, "reftokensig", "atsig", "resig", areq).Return(errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			description: "should pass",
			setup: func() {
				store.EXPECT().PersistRefreshTokenGrantSession(nil, "reftokensig", "atsig", "resig", areq).AnyTimes().Return(nil)

				aresp.EXPECT().SetAccessToken("access.atsig")
				aresp.EXPECT().SetTokenType("bearer")
				aresp.EXPECT().SetExpiresIn(gomock.Any())
				aresp.EXPECT().SetScopes(gomock.Any())
				aresp.EXPECT().SetExtra("refresh_token", "refresh.resig")
			},
		},
	} {
		c.setup()
		err := h.PopulateTokenEndpointResponse(nil, httpreq, areq, aresp)
		assert.True(t, errors.Is(c.expectErr, err), "(%d) %s\n%s\n%s", k, c.description, err, c.expectErr)
		t.Logf("Passed test case %d", k)
	}
}
