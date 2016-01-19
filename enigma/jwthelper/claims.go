package jwthelper

/*******************************************************************************
*													   Claims helper context                             *
*                           																									 *
*        Makes transitions of claims easier throught the implementation        *
*		  RFC: https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32      *
*******************************************************************************/

import (
	"encoding/json"
	"time"

	"github.com/go-errors/errors"
	"github.com/pborman/uuid"
)

// ClaimsContext : The context in which the claims are handled
type ClaimsContext map[string]interface{}

var reservedClaimNames = map[string]string{
	"sub": "sub",
	"iat": "iat",
	"iss": "iss",
	"nbf": "nbf",
	"aud": "aud",
	"exp": "exp",
	"jti": "jti",
}

// NewClaimsContext : Dezignated initializer of the ClaimsContext handler
func NewClaimsContext(issuer string, subject string, audience string,
	expiresAt time.Time, notBefore time.Time, issuedAt time.Time,
	userClaims map[string]interface{}) (*ClaimsContext, error) {

	var allClaims = ClaimsContext{}
	// Validate the user claims too check if the user has specified any reserved key-names
	for key, value := range userClaims {
		if val, ok := reservedClaimNames[key]; ok {
			return nil, errors.Errorf("Reserved claim key %s cannot be used in public claims", val)
		}

		// If no collission, append to the claims
		allClaims[key] = value
	}

	allClaims["sub"] = subject
	allClaims["iat"] = issuedAt.Unix()
	allClaims["iss"] = issuer
	allClaims["nbf"] = notBefore.Unix()
	allClaims["aud"] = audience
	allClaims["exp"] = expiresAt.Unix()
	allClaims["jti"] = uuid.New()

	return &allClaims, nil
}

/******************************************************************************/
/*                               Conveniences                                 */
/******************************************************************************/

// AssertExpired : Checks if JWT is expired
func (c ClaimsContext) AssertExpired() bool {
	return c.GetExpiresAt().Before(time.Now())
}

// AssertNotYetValid : Maskes sure that the JWT is not used before valid date
func (c ClaimsContext) AssertNotYetValid() bool {
	return c.GetNotBefore().After(time.Now())
}

// GetSubject : Returns the subject
func (c ClaimsContext) GetSubject() string {
	return c.GetAsString("sub")
}

// GetIssuedAt : Returns when the JWT was issued
func (c ClaimsContext) GetIssuedAt() time.Time {
	return c.GetAsTime("iat")
}

// GetNotBefore : Returns the time before which the JWT MUST NOT be accepted for processing
func (c ClaimsContext) GetNotBefore() time.Time {
	return c.GetAsTime("nbf")
}

// GetAudience : Retuens the designated autdience the token was issued for
func (c ClaimsContext) GetAudience() string {
	return c.GetAsString("aud")
}

// GetExpiresAt : Returns when the token will expire
func (c ClaimsContext) GetExpiresAt() time.Time {
	return c.GetAsTime("exp")
}

// GetIssuer : Returs the issuer (will in OAuth case be the client id)
func (c ClaimsContext) GetIssuer() string {
	return c.GetAsString("iss")
}

// String : Marshals the claims and returns them as a string representation
func (c ClaimsContext) String() (string, error) {
	result, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return string(result), nil
}

// GetAsString : Gets arbitary key-value pair from the claims and tries to return a string
func (c ClaimsContext) GetAsString(key string) string {
	if s, ok := c[key]; ok {
		if r, ok := s.(string); ok {
			return r
		}
	}
	return ""
}

// GetAsTime : Gets arbitary key-value pair from the claims and tries to return a time construct
func (c ClaimsContext) GetAsTime(key string) time.Time {
	ret := &time.Time{}
	if s, ok := c[key]; ok {
		if r, ok := s.(time.Time); ok {
			return r
		} else if p, ok := s.(int64); ok {
			return time.Unix(p, 0)
		} else if p, ok := s.(float64); ok {
			return time.Unix(int64(p), 0)
		}
	}
	return *ret
}
