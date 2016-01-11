package explicit

import (
	"github.com/go-errors/errors"
	"github.com/golang/mock/gomock"
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/client"
	"github.com/ory-am/fosite/enigma"
	"github.com/ory-am/fosite/internal"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/url"
	"testing"
)

func TestHandleAuthorizeEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockAuthorizeExplicitStorage(ctrl)
	chgen := internal.NewMockEnigma(ctrl)
	areq := internal.NewMockAuthorizeRequester(ctrl)
	aresp := internal.NewMockAuthorizeResponder(ctrl)
	defer ctrl.Finish()

	h := AuthorizeExplicitEndpointHandler{
		Store:  store,
		Enigma: chgen,
	}
	for k, c := range []struct {
		mock      func()
		req       *http.Request
		expectErr error
	}{
		{
			mock: func() {
				areq.EXPECT().GetResponseTypes().Return(fosite.Arguments{})
			},
		},
		{
			mock: func() {
				areq.EXPECT().GetResponseTypes().Return(fosite.Arguments{"foo"})
			},
		},
		{
			mock: func() {
				areq.EXPECT().GetResponseTypes().Return(fosite.Arguments{"code"})
				areq.EXPECT().GetClient().Return(&client.SecureClient{Secret: []byte("foosecret")})
				chgen.EXPECT().GenerateChallenge(gomock.Eq([]byte("foosecret"))).Return(nil, fosite.ErrServerError)
			},
			expectErr: fosite.ErrServerError,
		},
		{
			req: &http.Request{Form: url.Values{"redirect_uri": {"foobar"}}},
			mock: func() {
				areq.EXPECT().GetResponseTypes().Return(fosite.Arguments{"code"})
				areq.EXPECT().GetClient().Return(&client.SecureClient{Secret: []byte("foosecret")})
				chgen.EXPECT().GenerateChallenge(gomock.Eq([]byte("foosecret"))).Return(&enigma.Challenge{}, nil)
				store.EXPECT().CreateAuthorizeCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(fosite.ErrTemporarilyUnavailable)
			},
			expectErr: fosite.ErrServerError,
		},
		{
			req: &http.Request{Form: url.Values{"redirect_uri": {"foobar"}}},
			mock: func() {
				areq.EXPECT().GetResponseTypes().Return(fosite.Arguments{"code"})
				areq.EXPECT().GetClient().Return(&client.SecureClient{Secret: []byte("foosecret")})
				chgen.EXPECT().GenerateChallenge(gomock.Eq([]byte("foosecret"))).Return(&enigma.Challenge{Key: "foo", Signature: "bar"}, nil)
				store.EXPECT().CreateAuthorizeCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				aresp.EXPECT().AddQuery(gomock.Eq("code"), gomock.Eq("foo.bar"))
				aresp.EXPECT().AddQuery(gomock.Eq("scope"), gomock.Any())
				aresp.EXPECT().AddQuery(gomock.Eq("state"), gomock.Any())
				areq.EXPECT().SetResponseTypeHandled(gomock.Eq("code"))
				areq.EXPECT().GetScopes()
				areq.EXPECT().GetState()
			},
		},
	} {
		c.mock()
		err := h.HandleAuthorizeEndpointRequest(nil, c.req, areq, aresp, nil)
		assert.True(t, errors.Is(c.expectErr, err), "%d\n%s\n%s", k, err, c.expectErr)
		t.Logf("Passed test case %d", k)
	}
}
