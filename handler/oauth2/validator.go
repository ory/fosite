package oauth2

import (
	"fmt"

	"github.com/ory-am/fosite"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
)

type CoreValidator struct {
	CoreStrategy
	CoreStorage
	ScopeStrategy fosite.ScopeStrategy
}

func (c *CoreValidator) ValidateToken(ctx context.Context, token string, tokenType fosite.TokenType, accessRequest fosite.AccessRequester, scopes []string) error {
	switch tokenType {
	case fosite.AccessToken:
		return c.validateAccessToken(ctx, token, accessRequest, scopes)
	case fosite.RefreshToken:
		return c.validateRefreshToken(ctx, token, accessRequest)
	case fosite.AuthorizeCode:
		return c.validateAuthorizeCode(ctx, token, accessRequest)
	default:
		return errors.Wrap(fosite.ErrUnknownRequest, "")
	}
}

func (c *CoreValidator) validateAccessToken(ctx context.Context, token string, accessRequest fosite.AccessRequester, scopes []string) error {
	sig := c.CoreStrategy.AccessTokenSignature(token)
	or, err := c.CoreStorage.GetAccessTokenSession(ctx, sig, accessRequest.GetSession())
	if err != nil {
		fmt.Printf("%s", err)
		return errors.Wrap(fosite.ErrRequestUnauthorized, err.Error())
	} else if err := c.CoreStrategy.ValidateAccessToken(ctx, or, token); err != nil {
		fmt.Printf("%s", err)
		return errors.Wrap(fosite.ErrRequestUnauthorized, err.Error())
	}

	for _, scope := range scopes {
		if !c.ScopeStrategy(or.GetGrantedScopes(), scope) {
			return errors.Wrap(fosite.ErrInvalidScope, "")
		}
	}

	accessRequest.Merge(or)
	return nil
}

func (c *CoreValidator) validateRefreshToken(ctx context.Context, token string, accessRequest fosite.AccessRequester) error {
	sig := c.CoreStrategy.AccessTokenSignature(token)
	if or, err := c.CoreStorage.GetAccessTokenSession(ctx, sig, accessRequest.GetSession()); err != nil {
		return errors.Wrap(fosite.ErrRequestUnauthorized, err.Error())
	} else if err := c.CoreStrategy.ValidateAccessToken(ctx, or, token); err != nil {
		return errors.Wrap(fosite.ErrRequestUnauthorized, err.Error())
	} else {
		accessRequest.Merge(or)
	}

	return nil
}

func (c *CoreValidator) validateAuthorizeCode(ctx context.Context, token string, accessRequest fosite.AccessRequester) error {
	sig := c.CoreStrategy.AccessTokenSignature(token)
	if or, err := c.CoreStorage.GetAccessTokenSession(ctx, sig, accessRequest.GetSession()); err != nil {
		return errors.Wrap(fosite.ErrRequestUnauthorized, err.Error())
	} else if err := c.CoreStrategy.ValidateAccessToken(ctx, or, token); err != nil {
		return errors.Wrap(fosite.ErrRequestUnauthorized, err.Error())
	} else {
		accessRequest.Merge(or)
	}

	return nil
}
