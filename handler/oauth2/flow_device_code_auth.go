package oauth2

import (
	"context"
	"fmt"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/x/errorsx"
)

type AuthorizeDeviceGrantTypeHandler struct {
	CoreStorage           CoreStorage
	AccessTokenStrategy   AccessTokenStrategy
	RefreshTokenStrategy  RefreshTokenStrategy
	AuthorizeCodeStrategy AuthorizeCodeStrategy
	RefreshTokenScopes    []string
	AccessTokenLifespan   time.Duration
	RefreshTokenLifespan  time.Duration
}

func (c *AuthorizeDeviceGrantTypeHandler) HandleAuthorizeEndpointRequest(ctx context.Context, ar fosite.AuthorizeRequester, resp fosite.AuthorizeResponder) error {

	if !ar.GetResponseTypes().ExactOne("device_code") {
		return nil
	}

	if !ar.GetClient().GetGrantTypes().Has("urn:ietf:params:oauth:grant-type:device_code") {
		return nil
	}

	fmt.Println("HandleAuthorizeEndpointRequest ++")

	resp.AddParameter("state", ar.GetState())

	user_code := ar.GetRequestForm().Get("user_code")
	fmt.Println("HandleAuthorizeEndpointRequest : user_code = " + user_code)

	session, err := c.CoreStorage.GetUserCodeSession(ctx, user_code, ar.GetSession())
	if err != nil {
		return err
	}

	fmt.Println("HandleAuthorizeEndpointRequest : original client id = " + session.GetClient().GetID())
	if session.GetClient().GetID() != ar.GetClient().GetID() {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("The OAuth 2.0 Client ID from this request does not match the one from the authorize request."))
	}

	// FIX
	//if time.Now().After(session.GetSession().GetExpiresAt(fosite.UserCode)) {
	//	return fmt.Errorf("Device request expired")
	//}

	err = c.CoreStorage.CreateDeviceCodeSession(ctx, session.GetID(), ar)
	if err != nil {
		return errorsx.WithStack(err)
	}

	ar.SetResponseTypeHandled("device_code")
	return nil
}
