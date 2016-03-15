package core_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/go-errors/errors"
	"github.com/golang/mock/gomock"
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/internal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	. "github.com/ory-am/fosite/handler/core"
)

func TestIssueAccessToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	areq := &fosite.AccessRequest{}
	aresp := &fosite.AccessResponse{Extra: map[string]interface{}{}}
	accessStrat := internal.NewMockAccessTokenStrategy(ctrl)
	accessStore := internal.NewMockAccessTokenStorage(ctrl)
	httpReq := &http.Request{}
	defer ctrl.Finish()

	helper := HandleHelper{
		AccessTokenStorage:               accessStore,
		AccessTokenStrategy: accessStrat,
		AccessTokenLifespan: time.Hour,
	}

	for k, c := range []struct {
		mock func()
		err  error
	}{
		{
			mock: func() {
				accessStrat.EXPECT().GenerateAccessToken(nil, httpReq, areq).Return("", "", errors.New(""))
			},
			err: fosite.ErrServerError,
		},
		{
			mock: func() {
				accessStrat.EXPECT().GenerateAccessToken(nil, httpReq, areq).Return("token", "signature", nil)
				accessStore.EXPECT().CreateAccessTokenSession(nil, "signature", areq).Return(errors.New(""))
			},
			err: fosite.ErrServerError,
		},
		{
			mock: func() {
				accessStrat.EXPECT().GenerateAccessToken(nil, httpReq, areq).Return("token", "signature", nil)
				accessStore.EXPECT().CreateAccessTokenSession(nil, "signature", areq).Return(nil)
			},
			err: nil,
		},
	} {
		c.mock()
		err := helper.IssueAccessToken(nil, httpReq, areq, aresp)
		require.Equal(t, err == nil, c.err == nil)
		if c.err != nil {
			assert.EqualError(t, err, c.err.Error(), "Case %d", k)
		}
	}
}
