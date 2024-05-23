// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	fjwt "github.com/ory/fosite/token/jwt"
	"github.com/ory/x/errorsx"
)

// JWTValidationConfig provides configuration to validate JWTs
type JWTValidationConfig struct {
	// AllowedSigningKeys are the key IDs that are allowed to verify a JWT
	AllowedSigningKeys []string `json:"kids"`

	// AllowedSigningAlgs are the algorithms allowed for a signed JWT
	AllowedSigningAlgs []string `json:"algs"`

	// JSONWebKeysURI is the remote URI from which the JWKS is fetched
	JSONWebKeysURI string `json:"jwks_uri"`

	// JSONWebKeys in place of JSONWebKeyURI
	JSONWebKeys *jose.JSONWebKeySet `json:"jwks"`

	// NoneAlgAllowed indicates if the signing algorithm can be "none"
	NoneAlgAllowed bool `json:"none"`
}

// ValidateParsedAssertionWithClient validates the parsed assertion based on the jwks_uri, jwks etc. configured on the client
func ValidateParsedAssertionWithClient(ctx context.Context, config Configurator, assertion string, token *fjwt.Token, parsedToken *jwt.JSONWebToken, oidcClient OpenIDConnectClient, isNoneAlgAllowed bool) (
	*fjwt.Token, *jwt.JSONWebToken, error) {

	jwksURI := oidcClient.GetJSONWebKeysURI()
	jwks := oidcClient.GetJSONWebKeys()
	allowedKeys := []string{}
	if c, ok := oidcClient.(ClientWithAllowedVerificationKeys); ok {
		allowedKeys = c.AllowedVerificationKeys()
	}

	return ValidateParsedAssertion(ctx, config, assertion, token, parsedToken, &JWTValidationConfig{
		AllowedSigningKeys: allowedKeys,
		AllowedSigningAlgs: []string{oidcClient.GetTokenEndpointAuthSigningAlgorithm()},
		JSONWebKeysURI:     jwksURI,
		JSONWebKeys:        jwks,
		NoneAlgAllowed:     isNoneAlgAllowed,
	})
}

// ValidateParsedAssertion validates the parsed assertion based on the jwks_uri, jwks etc. that is passed in
func ValidateParsedAssertion(ctx context.Context, config Configurator, assertion string, token *fjwt.Token, parsedToken *jwt.JSONWebToken, verificationConfig *JWTValidationConfig) (
	*fjwt.Token, *jwt.JSONWebToken, error) {

	var err error
	baseError := getBaseError(ctx)
	assertionType := getAssertionType(ctx)

	var jwtStrategy fjwt.Strategy
	if c, ok := config.(JWTStrategyProvider); ok {
		jwtStrategy = c.GetJWTStrategy(ctx)
	}

	if jwtStrategy != nil && len(token.Method) == 0 { // JWE
		alg, _ := token.Header["alg"].(string)
		enc, _ := token.Header["enc"].(string)
		assertion, err = jwtStrategy.DecryptWithSettings(ctx,
			&fjwt.KeyContext{
				EncryptionKeyID:            parsedToken.Headers[0].KeyID,
				EncryptionAlgorithm:        alg,
				EncryptionContentAlgorithm: enc,
			},
			assertion)
		if err != nil {
			return nil, nil, errorsx.WithStack(baseError.WithHintf("Unable to verify the integrity of the '%s' value.", assertionType).WithWrap(err).WithDebug(err.Error()))
		}

		var mapClaims fjwt.MapClaims = fjwt.MapClaims{}

		if cty, ok := token.Header["cty"].(string); ok && strings.ToUpper(cty) == "JWT" { // Nested JWT

			parsedToken, err = jwt.ParseSigned(assertion)
			if err != nil {
				return nil, nil, errorsx.WithStack(baseError.WithHintf("Unable to verify the integrity of the '%s' value.", assertionType).WithWrap(err).WithDebug(err.Error()))
			}

			if err := parsedToken.UnsafeClaimsWithoutVerification(&mapClaims); err != nil {
				return nil, nil, errorsx.WithStack(baseError.WithHintf("Unable to verify the integrity of the '%s' value.", assertionType).WithWrap(err).WithDebug(err.Error()))
			}
			token.Claims = mapClaims
			token.Method = jose.SignatureAlgorithm(parsedToken.Headers[0].Algorithm)
			token.Header["kid"] = parsedToken.Headers[0].KeyID // When using jwks, the `kid` is read from token object

		} else { // Only encrypted, not signed
			if err := json.Unmarshal([]byte(assertion), &mapClaims); err != nil {
				return nil, nil, errorsx.WithStack(baseError.WithHintf("Unable to verify the integrity of the '%s' value.", assertionType).WithWrap(err).WithDebug(err.Error()))
			}
			token.Claims = mapClaims
			err = validateJWTClaims(ctx, mapClaims, assertionType, baseError)
			if err != nil {
				return nil, nil, err
			}

			return token, parsedToken, nil
		}
	}

	if token.Method == fjwt.SigningMethodNone {
		if !verificationConfig.NoneAlgAllowed {
			return nil, nil, errorsx.WithStack(baseError.WithHintf("'none' is disallowed as a signing method of the '%s'.", assertionType))
		}

		return token, parsedToken, nil
	}

	claims := token.Claims
	signingAlg := parsedToken.Headers[0].Algorithm
	if len(verificationConfig.AllowedSigningAlgs) > 0 && !Arguments(verificationConfig.AllowedSigningAlgs).Has(signingAlg) {
		return nil, nil, errorsx.WithStack(baseError.WithHintf("The 'alg' used in the '%s' is not allowed.", assertionType))
	}

	signingKey := parsedToken.Headers[0].KeyID
	if len(verificationConfig.AllowedSigningKeys) > 0 && !Arguments(verificationConfig.AllowedSigningKeys).Has(signingKey) {
		return nil, nil, errorsx.WithStack(baseError.WithHintf("The 'kid' used in the '%s' is not allowed.", assertionType))
	}

	// Validate signature
	if verificationConfig.JSONWebKeysURI == "" && verificationConfig.JSONWebKeys == nil {
		if jwtStrategy == nil {
			return nil, nil, errorsx.WithStack(baseError.WithHintf("Unable to verify the integrity of the '%s' value.", assertionType).WithWrap(err).WithDebug(err.Error()))
		}

		_, err := jwtStrategy.ValidateWithSettings(ctx,
			&fjwt.KeyContext{
				SigningKeyID:     parsedToken.Headers[0].KeyID,
				SigningAlgorithm: parsedToken.Headers[0].Algorithm,
			},
			assertion)
		if err != nil {
			return nil, nil, errorsx.WithStack(baseError.WithHintf("Unable to verify the integrity of the '%s' value.", assertionType).WithWrap(err).WithDebug(err.Error()))
		}
	} else {
		var key interface{}
		var err error
		switch token.Method {
		case jose.RS256, jose.RS384, jose.RS512:
			key, err = findPublicJWK(ctx, config, token, verificationConfig.JSONWebKeysURI, verificationConfig.JSONWebKeys, true, baseError)
			if err != nil {
				return nil, nil, wrapSigningKeyFailure(
					baseError.WithHint("Unable to retrieve RSA signing key from the JSON Web Key Set."), err)
			}
		case jose.ES256, jose.ES384, jose.ES512:
			key, err = findPublicJWK(ctx, config, token, verificationConfig.JSONWebKeysURI, verificationConfig.JSONWebKeys, false, baseError)
			if err != nil {
				return nil, nil, wrapSigningKeyFailure(
					baseError.WithHint("Unable to retrieve ECDSA signing key from the JSON Web Key Set."), err)
			}
		case jose.PS256, jose.PS384, jose.PS512:
			key, err = findPublicJWK(ctx, config, token, verificationConfig.JSONWebKeysURI, verificationConfig.JSONWebKeys, true, baseError)
			if err != nil {
				return nil, nil, wrapSigningKeyFailure(
					baseError.WithHint("Unable to retrieve RSA signing key from the JSON Web Key Set."), err)
			}
		default:
			return nil, nil, errorsx.WithStack(baseError.WithHintf("The '%s' uses unsupported signing algorithm '%s'.", assertionType, token.Method))
		}

		// To verify signature go-jose requires a pointer to
		// public key instead of the public key value.
		// The pointer values provides that pointer.
		// E.g. transform rsa.PublicKey -> *rsa.PublicKey
		key = pointer(key)

		// verify signature with returned key
		if err := parsedToken.Claims(key, &claims); err != nil {
			return nil, nil, errorsx.WithStack(baseError.WithHintf("Unable to verify the integrity of the '%s' value.", assertionType).WithWrap(err).WithDebug(err.Error()))
		}
	}

	err = validateJWTClaims(ctx, claims, assertionType, baseError)
	if err != nil {
		return nil, nil, err
	}

	return token, parsedToken, nil
}

func validateJWTClaims(ctx context.Context, claims fjwt.MapClaims, assertionType string, baseError *RFC6749Error) error {
	// Validate claims
	// This validation is performed to be backwards compatible
	// with jwt-go library behavior
	if err := claims.Valid(); err != nil {
		if e, ok := err.(*fjwt.ValidationError); ok {
			// return a more precise error
			if e.Has(fjwt.ValidationErrorExpired) {
				return errorsx.WithStack(baseError.WithHintf("The '%s' has expired.", assertionType).WithWrap(err).WithDebug(err.Error()))
			}

			if e.Has(fjwt.ValidationErrorIssuedAt) {
				return errorsx.WithStack(baseError.WithHintf("The 'iat' claim in '%s' is in the future.", assertionType).WithWrap(err).WithDebug(err.Error()))
			}

			if e.Has(fjwt.ValidationErrorNotValidYet) {
				return errorsx.WithStack(baseError.WithHintf("The '%s' is not valid yet.", assertionType).WithWrap(err).WithDebug(err.Error()))
			}
		}

		return errorsx.WithStack(baseError.WithHintf("Invalid claims in the '%s'.", assertionType).WithWrap(err).WithDebug(err.Error()))
	}

	return nil
}

func newToken(assertion string, assertionType string, baseError *RFC6749Error) (*fjwt.Token, *jwt.JSONWebToken, bool, error) {
	var err error
	var parsedToken *jwt.JSONWebToken

	isJWE := false // assume it's signed
	parsedToken, err = jwt.ParseSigned(assertion)
	if err != nil {
		parsedToken, err = jwt.ParseEncrypted(assertion) // probably it's encrypted
		if err != nil {
			return nil, nil, false, errorsx.WithStack(baseError.WithHintf("Unable to verify the integrity of the '%s' value.", assertionType).WithWrap(err).WithDebug(err.Error()))
		}

		isJWE = true
	}

	token := &fjwt.Token{
		Header: map[string]interface{}{},
		Method: "",
	}

	if !isJWE {
		var claims fjwt.MapClaims = fjwt.MapClaims{}
		if err := parsedToken.UnsafeClaimsWithoutVerification(&claims); err != nil {
			return nil, nil, false, errorsx.WithStack(baseError.WithHintf("Unable to verify the integrity of the '%s' value.", assertionType).WithWrap(err).WithDebug(err.Error()))
		}
		token.Claims = claims
	}

	if len(parsedToken.Headers) != 1 {
		return nil, nil, false, errorsx.WithStack(baseError.WithHintf("The '%s' value is expected to contain only one header.", assertionType))
	}

	// copy headers
	h := parsedToken.Headers[0]
	token.Header["alg"] = h.Algorithm
	if h.KeyID != "" {
		token.Header["kid"] = h.KeyID
	}
	for k, v := range h.ExtraHeaders {
		token.Header[string(k)] = v
	}

	if !isJWE {
		token.Method = jose.SignatureAlgorithm(h.Algorithm)
	}

	return token, parsedToken, isJWE, nil
}

func findPublicKey(t *fjwt.Token, set *jose.JSONWebKeySet, expectsRSAKey bool, baseError *RFC6749Error) (interface{}, error) {
	keys := set.Keys
	if len(keys) == 0 {
		return nil, errorsx.WithStack(baseError.WithHint("The retrieved JSON Web Key Set does not contain any keys"))
	}

	kid, ok := t.Header["kid"].(string)
	if ok {
		keys = set.Key(kid)
	}

	if len(keys) == 0 {
		return nil, errorsx.WithStack(baseError.WithHintf("The JSON Web Token uses signing key with kid '%s', which could not be found.", kid))
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
		return nil, errorsx.WithStack(baseError.WithHintf("Unable to find RSA public key with use='sig' for kid '%s' in JSON Web Key Set.", kid))
	}

	return nil, errorsx.WithStack(baseError.WithHintf("Unable to find ECDSA public key with use='sig' for kid '%s' in JSON Web Key Set.", kid))
}

func findPublicJWK(ctx context.Context, config Configurator, t *fjwt.Token, jwksURI string, jwks *jose.JSONWebKeySet, expectsRSAKey bool, baseError *RFC6749Error) (interface{}, error) {
	if jwks != nil {
		return findPublicKey(t, jwks, expectsRSAKey, baseError)
	}

	keys, err := config.GetJWKSFetcherStrategy(ctx).Resolve(ctx, jwksURI, false)
	if err != nil {
		return nil, err
	}

	if key, err := findPublicKey(t, keys, expectsRSAKey, baseError); err == nil {
		return key, nil
	}

	keys, err = config.GetJWKSFetcherStrategy(ctx).Resolve(ctx, jwksURI, true)
	if err != nil {
		return nil, errorsx.WithStack(baseError.WithHintf(fmt.Sprintf("%s", err)))
	}

	return findPublicKey(t, keys, expectsRSAKey, baseError)
}

// if underline value of v is not a pointer
// it creates a pointer of it and returns it
func pointer(v interface{}) interface{} {
	if reflect.ValueOf(v).Kind() != reflect.Ptr {
		value := reflect.New(reflect.ValueOf(v).Type())
		value.Elem().Set(reflect.ValueOf(v))
		return value.Interface()
	}
	return v
}

func getBaseError(ctx context.Context) *RFC6749Error {
	if e, ok := ctx.Value(BaseErrorContextKey).(*RFC6749Error); ok {
		return e
	}

	return ErrInvalidClient
}

func getAssertionType(ctx context.Context) string {
	if at, ok := ctx.Value(AssertionTypeContextKey).(string); ok {
		return at
	}

	return "assertion"
}
