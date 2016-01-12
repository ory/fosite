package implicit_test

import (
	"github.com/go-errors/errors"
	"github.com/golang/mock/gomock"
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/client"
	"github.com/ory-am/fosite/enigma"
	. "github.com/ory-am/fosite/handler/core/implicit"
	"github.com/ory-am/fosite/internal"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func TestAuthorizeImplicitEndpointHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockImplicitGrantStorage(ctrl)
	chgen := internal.NewMockEnigma(ctrl)
	areq := internal.NewMockAuthorizeRequester(ctrl)
	aresp := internal.NewMockAuthorizeResponder(ctrl)
	defer ctrl.Finish()

	h := AuthorizeImplicitGrantTypeHandler{
		Store:               store,
		Enigma:              chgen,
		AccessTokenLifespan: time.Hour,
	}
	for k, c := range []struct {
		mock      func()
		req       *http.Request
		expectErr error
	}{
		{mock: func() { areq.EXPECT().GetResponseTypes().Return(fosite.Arguments{}) }},
		{
			mock: func() {
				areq.EXPECT().GetResponseTypes().Return(fosite.Arguments{"token"})
				areq.EXPECT().GetClient().Return(&client.SecureClient{})
				chgen.EXPECT().GenerateChallenge(gomock.Any()).Return(nil, errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			req: &http.Request{Form: url.Values{}},
			mock: func() {
				areq.EXPECT().GetResponseTypes().Return(fosite.Arguments{"token"})
				areq.EXPECT().GetClient().Return(&client.SecureClient{})
				chgen.EXPECT().GenerateChallenge(gomock.Any()).Return(&enigma.Challenge{Signature: "foo"}, nil)
				store.EXPECT().CreateImplicitAccessTokenSession("foo", gomock.Any(), gomock.Any()).Return(errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			req: &http.Request{Form: url.Values{}},
			mock: func() {
				areq.EXPECT().GetResponseTypes().Return(fosite.Arguments{"token"})
				areq.EXPECT().GetClient().Return(&client.SecureClient{})
				chgen.EXPECT().GenerateChallenge(gomock.Any()).Return(&enigma.Challenge{Signature: "foo"}, nil)
				store.EXPECT().CreateImplicitAccessTokenSession("foo", gomock.Any(), gomock.Any()).Return(nil)

				aresp.EXPECT().AddFragment("access_token", gomock.Any())
				aresp.EXPECT().AddFragment("expires_in", strconv.Itoa(int(h.AccessTokenLifespan/time.Second)))
				aresp.EXPECT().AddFragment("token_type", "bearer")
				aresp.EXPECT().AddFragment("state", gomock.Any())
				aresp.EXPECT().AddFragment("scope", gomock.Any())
				areq.EXPECT().SetResponseTypeHandled("token")
				areq.EXPECT().GetState()
				areq.EXPECT().GetGrantedScopes()
			},
			expectErr: nil,
		},
	} {
		c.mock()
		err := h.HandleAuthorizeEndpointRequest(nil, c.req, areq, aresp, nil)
		assert.True(t, errors.Is(c.expectErr, err), "%d\n%s\n%s", k, err, c.expectErr)
		t.Logf("Passed test case %d", k)
	}
}
