// Copyright © 2017 Aeneas Rekkas <aeneas+oss@aeneas.io>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fosite

import (
	"time"

	"github.com/mohae/deepcopy"
)

// Session is an interface that is used to store session data between OAuth2 requests. It can be used to look up
// when a session expires or what the subject's name was.
type Session interface {
	// SetExpiresAt sets the expiration time of a token.
	//
	//  session.SetExpiresAt(fosite.AccessToken, time.Now().UTC().Add(time.Hour))
	SetExpiresAt(key TokenType, exp time.Time)

	// SetExpiresAt returns expiration time of a token if set, or time.IsZero() if not.
	//
	//  session.GetExpiresAt(fosite.AccessToken)
	GetExpiresAt(key TokenType) time.Time

	// GetUsername returns the username, if set. This is optional and only used during token introspection.
	GetUsername() string

	// GetSubject returns the subject, if set. This is optional and only used during token introspection.
	GetSubject() string

	// SetCodeChallenge sets the code_challenge value
	SetCodeChallenge(code string)

	// GetCodeChallenge returns the code challenge value
	GetCodeChallenge() string

	// SetCodeChallengeMethod sets the code_challenge_method value
	SetCodeChallengeMethod(code string)

	// GetCodeChallengeMethod returns the code challenge method value
	GetCodeChallengeMethod() string

	// Clone clones the session.
	Clone() Session
}

// DefaultSession is a default implementation of the session interface.
type DefaultSession struct {
	ExpiresAt           map[TokenType]time.Time
	Username            string
	Subject             string
	CodeChallenge       string
	CodeChallengeMethod string
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

func (s *DefaultSession) SetCodeChallenge(code string) {
	s.CodeChallenge = code
}

func (s *DefaultSession) GetCodeChallenge() string {
	if s == nil {
		return ""
	}

	return s.CodeChallenge
}

func (s *DefaultSession) SetCodeChallengeMethod(method string) {
	s.CodeChallengeMethod = method
}

func (s *DefaultSession) GetCodeChallengeMethod() string {
	if s == nil {
		return ""
	}

	return s.CodeChallengeMethod
}

func (s *DefaultSession) Clone() Session {
	if s == nil {
		return nil
	}

	return deepcopy.Copy(s).(Session)
}
