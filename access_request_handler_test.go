package fosite_test

import (
	"encoding/base64"
	"fmt"
	"github.com/go-errors/errors"
	"github.com/golang/mock/gomock"
	"github.com/ory-am/common/pkg"
	. "github.com/ory-am/fosite"
	"github.com/ory-am/fosite/internal"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/context"
	"net/http"
	"net/url"
	"testing"
)

func TestNewAccessRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockStorage(ctrl)
	client := internal.NewMockClient(ctrl)
	handler := internal.NewMockTokenEndpointHandler(ctrl)
	defer ctrl.Finish()

	fosite := &Fosite{Store: store}
	for k, c := range []struct {
		header    http.Header
		form      url.Values
		mock      func()
		method    string
		expectErr error
		expect    *AccessRequest
		handlers  TokenEndpointHandlers
	}{
		{
			header:    http.Header{},
			expectErr: ErrInvalidRequest,
			method:    "POST",
			mock:      func() {},
		},
		{
			header: http.Header{},
			method: "POST",
			form: url.Values{
				"grant_type": {"foo"},
			},
			mock:      func() {},
			expectErr: ErrInvalidRequest,
		},
		{
			header: http.Header{},
			method: "POST",
			form: url.Values{
				"grant_type": {"foo"},
				"client_id":  {"foo"},
			},
			expectErr: ErrInvalidRequest,
			mock:      func() {},
		},
		{
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			method: "POST",
			form: url.Values{
				"grant_type": {"foo"},
			},
			expectErr: ErrInvalidClient,
			mock: func() {
				store.EXPECT().GetClient(gomock.Eq("foo")).Return(nil, errors.New(""))
			},
		},
		{
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			method: "GET",
			form: url.Values{
				"grant_type": {"foo"},
			},
			expectErr: ErrInvalidRequest,
			mock:      func() {},
		},
		{
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			method: "POST",
			form: url.Values{
				"grant_type": {"foo"},
			},
			expectErr: ErrInvalidClient,
			mock: func() {
				store.EXPECT().GetClient(gomock.Eq("foo")).Return(nil, errors.New(""))
			},
		},
		{
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			method: "POST",
			form: url.Values{
				"grant_type": {"foo"},
			},
			expectErr: ErrInvalidClient,
			mock: func() {
				store.EXPECT().GetClient(gomock.Eq("foo")).Return(client, nil)
				client.EXPECT().CompareSecretWith(gomock.Eq([]byte("bar"))).Return(false)
			},
		},
		{
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			method: "POST",
			form: url.Values{
				"grant_type": {"foo"},
			},
			expectErr: ErrServerError,
			mock: func() {
				store.EXPECT().GetClient(gomock.Eq("foo")).Return(client, nil)
				client.EXPECT().CompareSecretWith(gomock.Eq([]byte("bar"))).Return(true)
				handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(ErrServerError)
			},
			handlers: TokenEndpointHandlers{handler},
		},
		{
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			method: "POST",
			form: url.Values{
				"grant_type": {"foo"},
			},
			expectErr: ErrUnsupportedGrantType,
			mock: func() {
				store.EXPECT().GetClient(gomock.Eq("foo")).Return(client, nil)
				client.EXPECT().CompareSecretWith(gomock.Eq([]byte("bar"))).Return(true)
				handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			},
			handlers: TokenEndpointHandlers{handler},
		},
		{
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			method: "POST",
			form: url.Values{
				"grant_type": {"foo"},
			},
			expectErr: ErrUnsupportedGrantType,
			mock: func() {
				store.EXPECT().GetClient(gomock.Eq("foo")).Return(client, nil)
				client.EXPECT().CompareSecretWith(gomock.Eq([]byte("bar"))).Return(true)
				handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ context.Context, _ *http.Request, a AccessRequester, _ interface{}) {
					a.SetGrantTypeHandled("bar")
				}).Return(nil)
			},
			handlers: TokenEndpointHandlers{handler},
		},
		{
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			method: "POST",
			form: url.Values{
				"grant_type": {"foo"},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Eq("foo")).Return(client, nil)
				client.EXPECT().CompareSecretWith(gomock.Eq([]byte("bar"))).Return(true)
				handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ context.Context, _ *http.Request, a AccessRequester, _ interface{}) {
					a.SetGrantTypeHandled("foo")
				}).Return(nil)
			},
			handlers: TokenEndpointHandlers{handler},
			expect: &AccessRequest{
				GrantType:        "foo",
				HandledGrantType: []string{"foo"},
				Client:           client,
			},
		},
	} {
		r := &http.Request{
			Header:   c.header,
			PostForm: c.form,
			Form:     c.form,
			Method:   c.method,
		}
		c.mock()
		ctx := NewContext()
		fosite.TokenEndpointHandlers = c.handlers
		ar, err := fosite.NewAccessRequest(ctx, r, &struct{}{})
		is := errors.Is(c.expectErr, err)
		assert.True(t, is, "%d\nwant: %s \ngot: %s", k, c.expectErr, err)
		if !is {
			t.Logf("Error occured: %s", err.(*errors.Error).ErrorStack())
		}
		if err == nil {
			pkg.AssertObjectKeysEqual(t, c.expect, ar, "GrantType", "Client")
			assert.NotNil(t, ar.GetRequestedAt())
		}
		t.Logf("Passed test case %d", k)
	}
}

func basicAuth(username, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", username, password)))
}
