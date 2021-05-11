package jwt

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
)

func TestParseInvalidReturnsToken(t *testing.T) {
	key := MustRSAKey()
	token, _, err := generateToken(MapClaims{
		"aud": "foo",
		"exp": time.Now().UTC().Add(-time.Hour).Unix(),
		"iat": time.Now().UTC().Add(-2 * time.Hour).Unix(),
		"sub": "nestor",
	}, NewHeaders(), jose.RS256, key)

	require.NoError(t, err)
	require.NotEmpty(t, token)

	ptoken, err := Parse(token, func(*Token) (interface{}, error) { return &key.PublicKey, nil })
	require.Error(t, err)
	var verr *ValidationError
	require.True(t, errors.As(err, &verr))
	require.NotZero(t, verr.Errors&ValidationErrorExpired, "%+v", verr)
	require.NotEmpty(t, ptoken)
}

func TestUnsignedToken(t *testing.T) {
	key := UnsafeAllowNoneSignatureType
	token := NewWithClaims(SigningMethodNone, MapClaims{
		"aud": "foo",
		"exp": time.Now().UTC().Add(time.Hour).Unix(),
		"iat": time.Now().UTC().Unix(),
		"sub": "nestor",
	})
	rawToken, err := token.SignedString(key)
	require.NoError(t, err)
	require.NotEmpty(t, rawToken)
	parts := strings.Split(rawToken, ".")
	require.Len(t, parts, 3)
	require.Empty(t, parts[2])
}
