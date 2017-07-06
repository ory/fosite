package oauth2

import (
	"context"

	"github.com/ory/fosite"
	"github.com/pkg/errors"
)

type CoreValidator struct {
	CoreStrategy
	CoreStorage
	ScopeStrategy fosite.ScopeStrategy
}

func (c *CoreValidator) IntrospectToken(ctx context.Context, token string, tokenType fosite.TokenType, accessRequest fosite.AccessRequester, scopes []string) (err error) {
	switch tokenType {
	case fosite.RefreshToken:
		if err = c.introspectRefreshToken(ctx, token, accessRequest, scopes); err == nil {
			return nil
		} else if err = c.introspectAccessToken(ctx, token, accessRequest, scopes); err == nil {
			return nil
		}
		return err
	}

	if err = c.introspectAccessToken(ctx, token, accessRequest, scopes); err == nil {
		return nil
	} else if err := c.introspectRefreshToken(ctx, token, accessRequest, scopes); err == nil {
		return nil
	}

	return err
}

func matchScopes(ss fosite.ScopeStrategy, granted, scopes []string) error {
	for _, scope := range scopes {
		if scope == "" {
			continue
		}

		if !ss(granted, scope) {
			return errors.Wrapf(fosite.ErrInvalidScope, "Scope %s was not granted", scope)
		}
	}

	return nil
}

func (c *CoreValidator) introspectAccessToken(ctx context.Context, token string, accessRequest fosite.AccessRequester, scopes []string) error {
	sig := c.CoreStrategy.AccessTokenSignature(token)
	or, err := c.CoreStorage.GetAccessTokenSession(ctx, sig, accessRequest.GetSession())
	if err != nil {
		return errors.Wrap(fosite.ErrRequestUnauthorized, err.Error())
	} else if err := c.CoreStrategy.ValidateAccessToken(ctx, or, token); err != nil {
		return err
	}

	if err := matchScopes(c.ScopeStrategy, or.GetGrantedScopes(), scopes); err != nil {
		return err
	}

	accessRequest.Merge(or)
	return nil
}

func (c *CoreValidator) introspectRefreshToken(ctx context.Context, token string, accessRequest fosite.AccessRequester, scopes []string) error {
	sig := c.CoreStrategy.RefreshTokenSignature(token)
	or, err := c.CoreStorage.GetRefreshTokenSession(ctx, sig, accessRequest.GetSession())

	if err != nil {
		return errors.Wrap(fosite.ErrRequestUnauthorized, err.Error())
	} else if err := c.CoreStrategy.ValidateRefreshToken(ctx, or, token); err != nil {
		return err
	}

	if err := matchScopes(c.ScopeStrategy, or.GetGrantedScopes(), scopes); err != nil {
		return err
	}

	accessRequest.Merge(or)
	return nil
}
