package oauth2

import (
	"time"
)

type HMACSessionContainer interface {
	// AccessTokenExpiresAt returns the access token's expiry.
	AccessTokenExpiresAt(fallback time.Time) time.Time

	// AccessTokenExpiresAt returns the authorize code's expiry.
	AuthorizeCodeExpiresAt(fallback time.Time) time.Time
}

// HMACSession Container for the HMAC session.
type HMACSession struct {
	AccessTokenExpiry   time.Time
	AuthorizeCodeExpiry time.Time
}

func (s *HMACSession) AccessTokenExpiresAt(fallback time.Time) time.Time {
	if s == nil {
		return fallback
	} else if s.AccessTokenExpiry.IsZero() {
		return fallback
	}
	return s.AccessTokenExpiry
}

func (s *HMACSession) AuthorizeCodeExpiresAt(fallback time.Time) time.Time {
	if s == nil {
		return fallback
	} else if s.AuthorizeCodeExpiry.IsZero() {
		return fallback
	}
	return s.AuthorizeCodeExpiry
}
