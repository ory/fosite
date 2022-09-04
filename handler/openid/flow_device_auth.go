package openid

import (
	"context"

	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/x/errorsx"

	"github.com/ory/fosite"
)

type OpenIDConnectDeviceHandler struct {
	CoreStorage        oauth2.CoreStorage
	DeviceCodeStrategy oauth2.DeviceCodeStrategy
	UserCodeStrategy   oauth2.UserCodeStrategy

	OpenIDConnectRequestStorage   OpenIDConnectRequestStorage
	OpenIDConnectRequestValidator *OpenIDConnectRequestValidator

	Config fosite.Configurator

	*IDTokenHandleHelper
}

func (c *OpenIDConnectDeviceHandler) HandleAuthorizeEndpointRequest(ctx context.Context, ar fosite.AuthorizeRequester, resp fosite.AuthorizeResponder) error {
	if !(ar.GetGrantedScopes().Has("openid") && ar.GetResponseTypes().ExactOne("device_code")) {
		return nil
	}

	if !ar.GetClient().GetGrantTypes().Has("urn:ietf:params:oauth:grant-type:device_code") {
		return nil
	}

	userCode := ar.GetRequestForm().Get("user_code")
	userCodeSignature := c.UserCodeStrategy.UserCodeSignature(ctx, userCode)

	userSession, err := c.CoreStorage.GetUserCodeSession(ctx, userCodeSignature, fosite.NewRequest().Session)
	if err != nil {
		return errorsx.WithStack(fosite.ErrNotFound.WithDebug("User session not found."))
	}

	deviceSession, err := c.CoreStorage.GetDeviceCodeSession(ctx, userSession.GetID(), fosite.NewRequest().Session)
	if err != nil {
		return errorsx.WithStack(fosite.ErrNotFound.WithDebug("The devicve code has not been issued yet."))
	}

	if len(deviceSession.GetID()) == 0 {
		return errorsx.WithStack(fosite.ErrMisconfiguration.WithDebug("The devicve code has not been issued yet, indicating a broken code configuration."))
	}

	if err := c.OpenIDConnectRequestValidator.ValidatePrompt(ctx, ar); err != nil {
		return err
	}

	// The device code is stored in the ID field of the requester, use this to build the OpenID session as the token endpoint will not know about the user_code
	if err := c.OpenIDConnectRequestStorage.CreateOpenIDConnectSession(ctx, userSession.GetID(), ar.Sanitize(oidcParameters)); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	return nil
}
