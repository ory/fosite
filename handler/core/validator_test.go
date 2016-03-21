package core

import (
	"testing"
	"github.com/golang/mock/gomock"
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/internal"
	"github.com/stretchr/testify/assert"
	"net/http"
	"github.com/go-errors/errors"
)

func TestValidateRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockAccessTokenStorage(ctrl)
	chgen := internal.NewMockAccessTokenStrategy(ctrl)
	areq := fosite.NewAccessRequest(nil)
	defer ctrl.Finish()

	v := &CoreValidator{
		AccessTokenStrategy: chgen,
		AccessTokenStorage: store,
	}
	httpreq := &http.Request{Header: http.Header{}}

	for k, c := range []struct {
		description string
		setup       func()
		expectErr   error
	}{
		{
			description: "should fail because no authorization header set",
			expectErr:   fosite.ErrUnknownRequest,
			setup: func() {},
		},
		{
			description: "should fail because no bearer token set",
			expectErr:   fosite.ErrUnknownRequest,
			setup: func() {
				httpreq.Header.Set("Authorization", "bearer")
			},
		},
		{
			description: "should fail because validator fails",
			setup: func() {
				httpreq.Header.Set("Authorization", "bearer 1234")
				chgen.EXPECT().ValidateAccessToken(nil, "1234", httpreq, areq).Return("", errors.New(""))
			},
			expectErr:   fosite.ErrRequestUnauthorized,
		},
		{
			description: "should fail because retrieval fails",
			setup: func() {
				chgen.EXPECT().ValidateAccessToken(nil, "1234", httpreq, areq).Return("asdf", nil)
				store.EXPECT().GetAccessTokenSession(nil, "asdf", nil).Return(nil, errors.New(""))
			},
			expectErr:   fosite.ErrRequestUnauthorized,
		},
		{
			description: "should pass",
			setup: func() {
				chgen.EXPECT().ValidateAccessToken(nil, "1234", httpreq, areq).Return("asdf", nil)
				store.EXPECT().GetAccessTokenSession(nil, "asdf", nil).Return(areq, nil)
			},
		},
	} {
		c.setup()
		err := v.ValidateRequest(nil, httpreq, areq)
		assert.True(t, errors.Is(c.expectErr, err), "(%d) %s\n%s\n%s", k, c.description, err, c.expectErr)
		t.Logf("Passed test case %d", k)
	}
}