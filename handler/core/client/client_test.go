package client

import (
	"github.com/go-errors/errors"
	"github.com/golang/mock/gomock"
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/client"
	"github.com/ory-am/fosite/enigma"
	"github.com/ory-am/fosite/internal"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
	"time"
)

func TestValidateTokenEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockClientCredentialsGrantStorage(ctrl)
	chgen := internal.NewMockEnigma(ctrl)
	areq := internal.NewMockAccessRequester(ctrl)
	defer ctrl.Finish()

	h := ClientCredentialsGrantHandler{
		Store:               store,
		Enigma:              chgen,
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
				areq.EXPECT().GetGrantType().Return("client_credentials")
				areq.EXPECT().SetGrantTypeHandled("client_credentials")
			},
		},
	} {
		c.mock()
		err := h.ValidateTokenEndpointRequest(nil, c.req, areq, nil)
		assert.True(t, errors.Is(c.expectErr, err), "%d\n%s\n%s", k, err, c.expectErr)
		t.Logf("Passed test case %d", k)
	}
}

func HandleTokenEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockClientCredentialsGrantStorage(ctrl)
	chgen := internal.NewMockEnigma(ctrl)
	areq := internal.NewMockAccessRequester(ctrl)
	aresp := internal.NewMockAccessResponder(ctrl)
	//mockcl := internal.NewMockClient(ctrl)
	defer ctrl.Finish()

	h := ClientCredentialsGrantHandler{
		Store:               store,
		Enigma:              chgen,
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
			expectErr: fosite.ErrServerError,
		},
		{
			mock: func() {
				areq.EXPECT().GetGrantType().Return("client_credentials")
				areq.EXPECT().GetClient().Return(&client.SecureClient{})
				chgen.EXPECT().GenerateChallenge(gomock.Any()).Return(nil, errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			mock: func() {
				areq.EXPECT().GetGrantType().Return("client_credentials")
				areq.EXPECT().GetClient().Return(&client.SecureClient{})
				chgen.EXPECT().GenerateChallenge(gomock.Any()).Return(nil, nil)
				store.EXPECT().CreateAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			mock: func() {
				areq.EXPECT().GetGrantType().Return("client_credentials")
				areq.EXPECT().GetClient().Return(&client.SecureClient{})
				chgen.EXPECT().GenerateChallenge(gomock.Any()).Return(&enigma.Challenge{}, nil)
				store.EXPECT().CreateAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				aresp.EXPECT().SetAccessToken(".")
				aresp.EXPECT().SetTokenType("bearer")
				aresp.EXPECT().SetExtra("expires_in", gomock.Any())
				aresp.EXPECT().SetExtra("scope", gomock.Any())
			},
		},
	} {
		c.mock()
		err := h.HandleTokenEndpointRequest(nil, c.req, areq, aresp, nil)
		assert.True(t, errors.Is(c.expectErr, err), "%d\n%s\n%s", k, err, c.expectErr)
		t.Logf("Passed test case %d", k)
	}
}
