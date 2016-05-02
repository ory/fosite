package strategy

import (
	"net/http"

	"time"

	"github.com/go-errors/errors"
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/token/jwt"
	"golang.org/x/net/context"
)

const defaultExpiryTime = time.Hour

// IDTokenSession is a session container for the id token
type IDTokenSession struct {
	Claims  *jwt.IDTokenClaims
	Headers *jwt.Header
}

type DefaultIDTokenStrategy struct {
	*jwt.RS256JWTStrategy

	Expiry time.Duration
	Issuer string
}

func (h DefaultIDTokenStrategy) GenerateIDToken(_ context.Context, _ *http.Request, requester fosite.Requester) (token string, err error) {
	if h.Expiry == 0 {
		h.Expiry = defaultExpiryTime
	}

	sess, ok := requester.GetSession().(*IDTokenSession)
	if !ok {
		return "", errors.New("Session must be of type IDTokenContainer")
	}

	if sess.Claims == nil {
		return "", errors.New("Claims must not be nil")
	}

	if requester.GetRequestForm().Get("max_age") != "" && (sess.Claims.AuthTime.IsZero() || sess.Claims.AuthTime.After(time.Now())) {
		return "", errors.New("Authentication time claim is required when max_age is set and can not be in the future")
	} else if sess.Claims.Subject == "" {
		return "", errors.New("Subject claim can not be empty")
	} else if sess.Claims.ExpiresAt.IsZero() {
		sess.Claims.ExpiresAt = time.Now().Add(h.Expiry)
	} else if sess.Claims.ExpiresAt.Before(time.Now()) {
		return "", errors.New("Expiry claim can not be in the past")
	}

	nonce := requester.GetRequestForm().Get("nonce")
	// OPTIONAL. String value used to associate a Client session with an ID Token, and to mitigate replay attacks.
	// Although optional, this is considered good practice and therefore enforced.
	if len(nonce) < fosite.MinParameterEntropy {
		// We're assuming that using less then 8 characters for the state can not be considered "unguessable"
		return "", errors.New(fosite.ErrInsufficientEntropy)
	}

	sess.Claims.Nonce = nonce
	sess.Claims.Audience = requester.GetClient().GetID()
	sess.Claims.IssuedAt = time.Now()

	token, _, err = h.RS256JWTStrategy.Generate(sess.Claims, sess.Headers)
	return token, err
}
