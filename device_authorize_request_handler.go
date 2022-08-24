package fosite

import (
	"context"
	"net/http"
	"strings"

	"github.com/ory/fosite/i18n"
	"github.com/ory/x/errorsx"
)

func (f *Fosite) NewDeviceAuthorizeRequest(ctx context.Context, req *http.Request) (Requester, error) {

	request := NewRequest()
	request.Lang = i18n.GetLangFromRequest(f.MessageCatalog, req)

	if err := req.ParseMultipartForm(1 << 20); err != nil && err != http.ErrNotMultipart {
		return request, errorsx.WithStack(ErrInvalidRequest.WithHint("Unable to parse HTTP body, make sure to send a properly formatted form request body.").WithWrap(err).WithDebug(err.Error()))
	}
	request.Form = req.PostForm

	client, err := f.Store.GetClient(ctx, request.GetRequestForm().Get("client_id"))
	if err != nil {
		return request, errorsx.WithStack(ErrInvalidClient.WithHint("The requested OAuth 2.0 Client does not exist.").WithWrap(err).WithDebug(err.Error()))
	}
	request.Client = client

	if err := f.validateDeviceAuthorizeScope(req, request); err != nil {
		return request, err
	}

	return request, nil
}

func (f *Fosite) validateDeviceAuthorizeScope(_ *http.Request, request *Request) error {
	scope := RemoveEmpty(strings.Split(request.Form.Get("scope"), " "))
	for _, permission := range scope {
		if !f.ScopeStrategy(request.Client.GetScopes(), permission) {
			return errorsx.WithStack(ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", permission))
		}
	}
	request.SetRequestedScopes(scope)
	return nil
}
