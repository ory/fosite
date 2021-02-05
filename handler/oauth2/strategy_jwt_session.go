/*
 * Copyright © 2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
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
 * @copyright 	2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 *
 */

package oauth2

import (
	"time"

	"github.com/mohae/deepcopy"

	"github.com/ory/fosite"
	"github.com/ory/fosite/token/jwt"
)

type JWTSessionContainer interface {
	// GetJWTClaims returns the claims.
	GetJWTClaims() jwt.JWTClaimsContainer

	// GetJWTHeader returns the header.
	GetJWTHeader() *jwt.Headers

	fosite.Session
}

// JWTSession Container for the JWT session.
type JWTSession struct {
	JWTClaims *jwt.JWTClaims
	JWTHeader *jwt.Headers
	ExpiresAt map[fosite.TokenType]time.Time
	Username  string
	Subject   string
}

func (j *JWTSession) GetJWTClaims() jwt.JWTClaimsContainer {
	if j.JWTClaims == nil {
		j.JWTClaims = &jwt.JWTClaims{}
	}
	return j.JWTClaims
}

func (j *JWTSession) GetJWTHeader() *jwt.Headers {
	if j.JWTHeader == nil {
		j.JWTHeader = &jwt.Headers{}
	}
	return j.JWTHeader
}

func (j *JWTSession) SetExpiresAt(key fosite.TokenType, exp time.Time) {
	if j.ExpiresAt == nil {
		j.ExpiresAt = make(map[fosite.TokenType]time.Time)
	}
	j.ExpiresAt[key] = exp
}

func (j *JWTSession) GetExpiresAt(key fosite.TokenType) time.Time {
	if j.ExpiresAt == nil {
		j.ExpiresAt = make(map[fosite.TokenType]time.Time)
	}

	if _, ok := j.ExpiresAt[key]; !ok {
		return time.Time{}
	}
	return j.ExpiresAt[key]
}

func (j *JWTSession) GetUsername() string {
	if j == nil {
		return ""
	}
	return j.Username
}

func (j *JWTSession) SetSubject(subject string) {
	j.Subject = subject
}

func (j *JWTSession) GetSubject() string {
	if j == nil {
		return ""
	}

	return j.Subject
}

func (j *JWTSession) Clone() fosite.Session {
	if j == nil {
		return nil
	}

	return deepcopy.Copy(j).(fosite.Session)
}
