package jwthelper

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestValidClaimsContext(t *testing.T) {
	userClaims := ClaimsContext{"user-id": "123456"}
	ctx, err := NewClaimsContext("fosite/auth", "Peter", "peter@ory-am.com", time.Now().Add(time.Hour), time.Now(), time.Now(), userClaims)
	assert.Nil(t, err)

	assert.Equal(t, "fosite/auth", ctx.GetIssuer())
	assert.NotEqual(t, "fosite/token", ctx.GetIssuer())
	assert.Equal(t, "Peter", ctx.GetSubject())
	assert.NotEqual(t, "Alex", ctx.GetSubject())
	assert.Equal(t, "peter@ory-am.com", ctx.GetAudience())
	assert.NotEqual(t, "alex@test.com", ctx.GetAudience())

	assert.Equal(t, time.Now().Day(), ctx.GetNotBefore().Day())
	assert.Equal(t, time.Now().Day(), ctx.GetIssuedAt().Day())
	assert.Equal(t, time.Now().Day(), ctx.GetExpiresAt().Day())

	assert.Empty(t, ctx.GetAsString("doesnotexist"))
	assert.Equal(t, time.Time{}, ctx.GetAsTime("doesnotexist"))
	stringRep, err := ctx.String()
	assert.Nil(t, err)
	assert.NotEmpty(t, stringRep)
}

func TestInvalidClaimsContext(t *testing.T) {
	userClaims := ClaimsContext{"sub": "the \"sub\" field cannot be passed to claims context since it's a reserved claim"}
	_, err := NewClaimsContext("fosite/auth", "Peter", "peter@ory-am.com", time.Now().Add(time.Hour), time.Now(), time.Now(), userClaims)
	t.Logf("%s", err.Error())
	assert.NotNil(t, err)
}
