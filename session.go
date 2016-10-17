package fosite

import "time"

// Session is an interface that is used to store session data between OAuth2 requests. It can be used to look up
// when a session expires or what the subject's name was.
type Session interface {
	// SetExpiresAt sets the expiration time of a token.
	//
	//  session.SetExpiresAt(fosite.AccessToken, time.Now().Add(time.Hour))
	SetExpiresAt(key TokenType, exp time.Time)

	// SetExpiresAt returns expiration time of a token if set, or time.IsZero() if not.
	//
	//  session.GetExpiresAt(fosite.AccessToken)
	GetExpiresAt(key TokenType) time.Time

	// GetUsername returns the username, if set. This is optional and only used during token introspection.
	GetUsername() string

	// GetSubject returns the subject, if set. This is optional and only used during token introspection.
	GetSubject() string
}

// DefaultSession is a default implementation of the session interface.
type DefaultSession struct {
	ExpiresAt map[TokenType]time.Time
	Username  string
	Subject   string
}

func (s *DefaultSession) SetExpiresAt(key TokenType, exp time.Time) {
	if s.ExpiresAt == nil {
		s.ExpiresAt = make(map[TokenType]time.Time)
	}
	s.ExpiresAt[key] = exp
}

func (s *DefaultSession) GetExpiresAt(key TokenType) time.Time {
	if s.ExpiresAt == nil {
		s.ExpiresAt = make(map[TokenType]time.Time)
	}

	if _, ok := s.ExpiresAt[key]; !ok {
		return time.Time{}
	}
	return s.ExpiresAt[key]
}

func (s *DefaultSession) GetUsername() string {
	if s == nil {
		return ""
	}
	return s.Username
}

func (s *DefaultSession) GetSubject() string {
	if s == nil {
		return ""
	}

	return s.Subject
}
