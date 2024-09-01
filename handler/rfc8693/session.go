// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import "github.com/ory/fosite/handler/openid"

// Session is required to support token exchange
type Session interface {
	// SetSubject sets the session's subject.
	SetSubject(subject string)

	SetActorToken(token map[string]interface{})

	GetActorToken() map[string]interface{}

	SetSubjectToken(token map[string]interface{})

	GetSubjectToken() map[string]interface{}

	SetAct(act map[string]interface{})

	AccessTokenClaimsMap() map[string]interface{}
}

type DefaultSession struct {
	*openid.DefaultSession

	ActorToken   map[string]interface{} `json:"-"`
	SubjectToken map[string]interface{} `json:"-"`
	Extra        map[string]interface{} `json:"extra,omitempty"`
}

func (s *DefaultSession) SetActorToken(token map[string]interface{}) {
	s.ActorToken = token
}

func (s *DefaultSession) GetActorToken() map[string]interface{} {
	return s.ActorToken
}

func (s *DefaultSession) SetSubjectToken(token map[string]interface{}) {
	s.SubjectToken = token
}

func (s *DefaultSession) GetSubjectToken() map[string]interface{} {
	return s.SubjectToken
}

func (s *DefaultSession) SetAct(act map[string]interface{}) {
	s.Extra["act"] = act
}

func (s *DefaultSession) AccessTokenClaimsMap() map[string]interface{} {
	tokenObject := map[string]interface{}{
		"sub":      s.GetSubject(),
		"username": s.GetUsername(),
	}

	for k, v := range s.Extra {
		tokenObject[k] = v
	}

	return tokenObject
}
