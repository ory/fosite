/*
 * Copyright © 2017-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author		Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @Copyright 	2017-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 *
 */

package fosite

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/ory/x/errorsx"

	"github.com/ory/fosite/i18n"
	"github.com/ory/fosite/token/jwt"
	"github.com/pkg/errors"
	jose "gopkg.in/square/go-jose.v2"
)

// ClientAuthenticationStrategy provides a method signature for authenticating a client request
type ClientAuthenticationStrategy func(context.Context, *http.Request, url.Values) (Client, error)

const clientAssertionJWTBearerType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

func (f *Fosite) findClientPublicJWK(oidcClient OpenIDConnectClient, t *jwt.Token, expectsRSAKey bool) (interface{}, error) {
	if set := oidcClient.GetJSONWebKeys(); set != nil {
		return findPublicKey(t, set, expectsRSAKey)
	}

	if location := oidcClient.GetJSONWebKeysURI(); len(location) > 0 {
		keys, err := f.JWKSFetcherStrategy.Resolve(location, false)
		if err != nil {
			return nil, err
		}

		if key, err := findPublicKey(t, keys, expectsRSAKey); err == nil {
			return key, nil
		}

		keys, err = f.JWKSFetcherStrategy.Resolve(location, true)
		if err != nil {
			return nil, err
		}

		return findPublicKey(t, keys, expectsRSAKey)
	}

	return nil, errorsx.WithStack(ErrInvalidClient.WithHintID(i18n.ErrHintMissingJWK))
}

// AuthenticateClient authenticates client requests using the configured strategy
// `Fosite.ClientAuthenticationStrategy`, if nil it uses `Fosite.DefaultClientAuthenticationStrategy`
func (f *Fosite) AuthenticateClient(ctx context.Context, r *http.Request, form url.Values) (Client, error) {
	if f.ClientAuthenticationStrategy == nil {
		return f.DefaultClientAuthenticationStrategy(ctx, r, form)
	}
	return f.ClientAuthenticationStrategy(ctx, r, form)
}

// DefaultClientAuthenticationStrategy provides the fosite's default client authentication strategy,
// HTTP Basic Authentication and JWT Bearer
func (f *Fosite) DefaultClientAuthenticationStrategy(ctx context.Context, r *http.Request, form url.Values) (Client, error) {
	if assertionType := form.Get("client_assertion_type"); assertionType == clientAssertionJWTBearerType {
		assertion := form.Get("client_assertion")
		if len(assertion) == 0 {
			return nil, errorsx.WithStack(ErrInvalidRequest.WithHintID(i18n.ErrHintMissingClientAssertion, clientAssertionJWTBearerType))
		}

		var clientID string
		var client Client

		token, err := jwt.ParseWithClaims(assertion, jwt.MapClaims{}, func(t *jwt.Token) (interface{}, error) {
			var err error
			clientID, _, err = clientCredentialsFromRequestBody(form, false)
			if err != nil {
				return nil, err
			}

			if clientID == "" {
				claims := t.Claims
				if sub, ok := claims["sub"].(string); !ok {
					return nil, errorsx.WithStack(ErrInvalidClient.WithHintID(i18n.ErrHintMissingClientAssertionSubject))
				} else {
					clientID = sub
				}
			}

			client, err = f.Store.GetClient(ctx, clientID)
			if err != nil {
				return nil, errorsx.WithStack(ErrInvalidClient.WithWrap(err).WithDebug(err.Error()))
			}

			oidcClient, ok := client.(OpenIDConnectClient)
			if !ok {
				return nil, errorsx.WithStack(ErrInvalidRequest.WithHintID(i18n.ErrHintOIDCAuthMethodsNotAllowed))
			}

			switch oidcClient.GetTokenEndpointAuthMethod() {
			case "private_key_jwt":
				break
			case "none":
				return nil, errorsx.WithStack(ErrInvalidClient.WithHintID(i18n.ErrHintNoClientAuthAllowed))
			case "client_secret_post":
				fallthrough
			case "client_secret_basic":
				return nil, errorsx.WithStack(ErrInvalidClient.WithHintID(i18n.ErrHintClientAssertionNotSupported, oidcClient.GetTokenEndpointAuthMethod()))
			case "client_secret_jwt":
				fallthrough
			default:
				return nil, errorsx.WithStack(ErrInvalidClient.WithHintID(i18n.ErrHintClientAuthNotSupported, oidcClient.GetTokenEndpointAuthMethod()))
			}

			if oidcClient.GetTokenEndpointAuthSigningAlgorithm() != fmt.Sprintf("%s", t.Header["alg"]) {
				return nil, errorsx.WithStack(ErrInvalidClient.WithHintID(i18n.ErrHintClientAssertionSigningAlgNotSupported, t.Header["alg"], oidcClient.GetTokenEndpointAuthSigningAlgorithm()))
			}
			switch t.Method {
			case jose.RS256, jose.RS384, jose.RS512:
				return f.findClientPublicJWK(oidcClient, t, true)
			case jose.ES256, jose.ES384, jose.ES512:
				return f.findClientPublicJWK(oidcClient, t, false)
			case jose.PS256, jose.PS384, jose.PS512:
				return f.findClientPublicJWK(oidcClient, t, true)
			case jose.HS256, jose.HS384, jose.HS512:
				return nil, errorsx.WithStack(ErrInvalidClient.WithHintID(i18n.ErrHintClientAuthClientSecretJWTNotSupported))
			default:
				return nil, errorsx.WithStack(ErrInvalidClient.WithHintID(i18n.ErrHintClientAssertionSigningAlgNotSupported, t.Header["alg"]))
			}
		})
		if err != nil {
			// Do not re-process already enhanced errors
			var e *jwt.ValidationError
			if errors.As(err, &e) {
				if e.Inner != nil {
					return nil, e.Inner
				}
				return nil, errorsx.WithStack(ErrInvalidClient.WithHintID(i18n.ErrHintClientAssertionVerifyError).WithWrap(err).WithDebug(err.Error()))
			}
			return nil, err
		} else if err := token.Claims.Valid(); err != nil {
			return nil, errorsx.WithStack(ErrInvalidClient.WithHintID(i18n.ErrHintClientAssertionClaimsVerifyError).WithWrap(err).WithDebug(err.Error()))
		}

		claims := token.Claims
		var jti string
		if !claims.VerifyIssuer(clientID, true) {
			return nil, errorsx.WithStack(ErrInvalidClient.WithHintID(i18n.ErrHintInvalidClientAssertionIssuer))
		} else if f.TokenURL == "" {
			return nil, errorsx.WithStack(ErrMisconfiguration.WithHintID(i18n.ErrHintMissingTokenEndpointURL))
		} else if sub, ok := claims["sub"].(string); !ok || sub != clientID {
			return nil, errorsx.WithStack(ErrInvalidClient.WithHintID(i18n.ErrHintInvalidClientAssertionSubject))
		} else if jti, ok = claims["jti"].(string); !ok || len(jti) == 0 {
			return nil, errorsx.WithStack(ErrInvalidClient.WithHintID(i18n.ErrHintMissingClientAssertionJTI))
		} else if f.Store.ClientAssertionJWTValid(ctx, jti) != nil {
			return nil, errorsx.WithStack(ErrJTIKnown.WithHintID(i18n.ErrHintClientAssertionJTIReused))
		}

		// type conversion according to jwt.MapClaims.VerifyExpiresAt
		var expiry int64
		err = nil
		switch exp := claims["exp"].(type) {
		case float64:
			expiry = int64(exp)
		case int64:
			expiry = exp
		case json.Number:
			expiry, err = exp.Int64()
		default:
			err = ErrInvalidClient.WithHintID(i18n.ErrHintInvalidClientAssertionExpiryTimeType)
		}

		if err != nil {
			return nil, errorsx.WithStack(err)
		}
		if err := f.Store.SetClientAssertionJWT(ctx, jti, time.Unix(expiry, 0)); err != nil {
			return nil, err
		}

		if auds, ok := claims["aud"].([]interface{}); !ok {
			if !claims.VerifyAudience(f.TokenURL, true) {
				return nil, errorsx.WithStack(ErrInvalidClient.WithHintID(i18n.ErrHintInvalidClientAssertionAudience, f.TokenURL))
			}
		} else {
			var found bool
			for _, aud := range auds {
				if a, ok := aud.(string); ok && a == f.TokenURL {
					found = true
					break
				}
			}

			if !found {
				return nil, errorsx.WithStack(ErrInvalidClient.WithHintID(i18n.ErrHintInvalidClientAssertionAudience, f.TokenURL))
			}
		}

		return client, nil
	} else if len(assertionType) > 0 {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHintID(i18n.ErrHintInvalidClientAssertionType, assertionType))
	}

	clientID, clientSecret, err := clientCredentialsFromRequest(r, form)
	if err != nil {
		return nil, err
	}

	client, err := f.Store.GetClient(ctx, clientID)
	if err != nil {
		return nil, errorsx.WithStack(ErrInvalidClient.WithWrap(err).WithDebug(err.Error()))
	}

	if oidcClient, ok := client.(OpenIDConnectClient); !ok {
		// If this isn't an OpenID Connect client then we actually don't care about any of this, just continue!
	} else if ok && form.Get("client_id") != "" && form.Get("client_secret") != "" && oidcClient.GetTokenEndpointAuthMethod() != "client_secret_post" {
		return nil, errorsx.WithStack(ErrInvalidClient.WithHintID(i18n.ErrHintClientAuthNotSupportedDuplicate, oidcClient.GetTokenEndpointAuthMethod(), "client_secret_post"))
	} else if _, _, basicOk := r.BasicAuth(); basicOk && ok && oidcClient.GetTokenEndpointAuthMethod() != "client_secret_basic" {
		return nil, errorsx.WithStack(ErrInvalidClient.WithHintID(i18n.ErrHintClientAuthNotSupportedDuplicate, oidcClient.GetTokenEndpointAuthMethod(), "client_secret_basic"))
	} else if ok && oidcClient.GetTokenEndpointAuthMethod() != "none" && client.IsPublic() {
		return nil, errorsx.WithStack(ErrInvalidClient.WithHintID(i18n.ErrHintClientAuthNotSupportedDuplicate, oidcClient.GetTokenEndpointAuthMethod(), "none"))
	}

	if client.IsPublic() {
		return client, nil
	}

	// Enforce client authentication
	if err := f.checkClientSecret(ctx, client, []byte(clientSecret)); err != nil {
		return nil, errorsx.WithStack(ErrInvalidClient.WithWrap(err).WithDebug(err.Error()))
	}

	return client, nil
}

func (f *Fosite) checkClientSecret(ctx context.Context, client Client, clientSecret []byte) error {
	var err error
	err = f.Hasher.Compare(ctx, client.GetHashedSecret(), clientSecret)
	if err == nil {
		return nil
	}
	cc, ok := client.(ClientWithSecretRotation)
	if !ok {
		return err
	}
	for _, hash := range cc.GetRotatedHashes() {
		err = f.Hasher.Compare(ctx, hash, clientSecret)
		if err == nil {
			return nil
		}
	}

	return err
}

func findPublicKey(t *jwt.Token, set *jose.JSONWebKeySet, expectsRSAKey bool) (interface{}, error) {
	keys := set.Keys
	if len(keys) == 0 {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHintID(i18n.ErrHintMissingJWK))
	}

	kid, ok := t.Header["kid"].(string)
	if ok {
		keys = set.Key(kid)
	}

	if len(keys) == 0 {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHintID(i18n.ErrHintJWTKidNotFound, kid))
	}

	for _, key := range keys {
		if key.Use != "sig" {
			continue
		}
		if expectsRSAKey {
			if k, ok := key.Key.(*rsa.PublicKey); ok {
				return k, nil
			}
		} else {
			if k, ok := key.Key.(*ecdsa.PublicKey); ok {
				return k, nil
			}
		}
	}

	if expectsRSAKey {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHintID(i18n.ErrHintJWSKeyNotFoundForAlg, "RSA", kid))
	} else {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHintID(i18n.ErrHintJWSKeyNotFoundForAlg, "ECDSA", kid))
	}
}

func clientCredentialsFromRequest(r *http.Request, form url.Values) (clientID, clientSecret string, err error) {
	if id, secret, ok := r.BasicAuth(); !ok {
		return clientCredentialsFromRequestBody(form, true)
	} else if clientID, err = url.QueryUnescape(id); err != nil {
		return "", "", errorsx.WithStack(ErrInvalidRequest.WithHintID(i18n.ErrHintHTTPAuthzURLDecodeFailed, "client id").WithWrap(err).WithDebug(err.Error()))
	} else if clientSecret, err = url.QueryUnescape(secret); err != nil {
		return "", "", errorsx.WithStack(ErrInvalidRequest.WithHintID(i18n.ErrHintHTTPAuthzURLDecodeFailed, "client secret").WithWrap(err).WithDebug(err.Error()))
	}

	return clientID, clientSecret, nil
}

func clientCredentialsFromRequestBody(form url.Values, forceID bool) (clientID, clientSecret string, err error) {
	clientID = form.Get("client_id")
	clientSecret = form.Get("client_secret")

	if clientID == "" && forceID {
		return "", "", errorsx.WithStack(ErrInvalidRequest.WithHintID(i18n.ErrHintMissingClientCredentials))
	}

	return clientID, clientSecret, nil
}
