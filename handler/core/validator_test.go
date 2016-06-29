package core

import (
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/internal"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestValidateRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockAccessTokenStorage(ctrl)
	chgen := internal.NewMockAccessTokenStrategy(ctrl)
	areq := fosite.NewAccessRequest(nil)
	defer ctrl.Finish()

	v := &CoreValidator{
		AccessTokenStrategy: chgen,
		AccessTokenStorage:  store,
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
			setup:       func() {},
		},
		{
			description: "should fail because no bearer token set",
			expectErr:   fosite.ErrUnknownRequest,
			setup: func() {
				httpreq.Header.Set("Authorization", "bearer")
			},
		},
		{
			description: "should fail because retrieval fails",
			setup: func() {
				httpreq.Header.Set("Authorization", "bearer 1234")
				chgen.EXPECT().AccessTokenSignature("1234").AnyTimes().Return("asdf")
				store.EXPECT().GetAccessTokenSession(nil, "asdf", nil).Return(nil, nil, errors.New(""))
			},
			expectErr: fosite.ErrRequestUnauthorized,
		},
		{
			description: "should fail because validation fails",
			setup: func() {
				store.EXPECT().GetAccessTokenSession(nil, "asdf", nil).AnyTimes().Return(nil, areq, nil)
				chgen.EXPECT().ValidateAccessToken(nil, areq, "1234").Return(errors.New(""))
			},
			expectErr: fosite.ErrRequestUnauthorized,
		},
		{
			description: "should pass",
			setup: func() {
				chgen.EXPECT().ValidateAccessToken(nil, areq, "1234").Return(nil)
			},
		},
	} {
		c.setup()
		_, err := v.ValidateRequest(nil, httpreq, areq)
		assert.True(t, errors.Cause(err) == c.expectErr, "(%d) %s\n%s\n%s", k, c.description, err, c.expectErr)
		t.Logf("Passed test case %d", k)
	}
}
