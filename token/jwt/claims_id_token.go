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

package jwt

import (
	"time"

	"github.com/pborman/uuid"
)

// IDTokenClaims represent the claims used in open id connect requests
type IDTokenClaims struct {
	JTI                                 string                 `json:"jti"`
	Issuer                              string                 `json:"iss"`
	Subject                             string                 `json:"sub"`
	Audience                            []string               `json:"aud"`
	Nonce                               string                 `json:"nonce"`
	ExpiresAt                           time.Time              `json:"exp"`
	IssuedAt                            time.Time              `json:"iat"`
	RequestedAt                         time.Time              `json:"rat"`
	AuthTime                            time.Time              `json:"auth_time"`
	AccessTokenHash                     string                 `json:"at_hash"`
	AuthenticationContextClassReference string                 `json:"acr"`
	AuthenticationMethodsReferences     []string               `json:"amr"`
	CodeHash                            string                 `json:"c_hash"`
	Extra                               map[string]interface{} `json:"ext"`
}

// ToMap will transform the headers to a map structure
func (c *IDTokenClaims) ToMap() map[string]interface{} {
	var ret = Copy(c.Extra)

	if c.Subject != "" {
		ret["sub"] = c.Subject
	} else {
		delete(ret, "sub")
	}

	if c.Issuer != "" {
		ret["iss"] = c.Issuer
	} else {
		delete(ret, "iss")
	}

	if c.JTI != "" {
		ret["jti"] = c.JTI
	} else {
		ret["jti"] = uuid.New()
	}

	if len(c.Audience) > 0 {
		ret["aud"] = c.Audience
	} else {
		ret["aud"] = []string{}
	}

	if !c.IssuedAt.IsZero() {
		ret["iat"] = c.IssuedAt.Unix()
	} else {
		delete(ret, "iat")
	}

	if !c.ExpiresAt.IsZero() {
		ret["exp"] = c.ExpiresAt.Unix()
	} else {
		delete(ret, "exp")
	}

	if !c.RequestedAt.IsZero() {
		ret["rat"] = c.RequestedAt.Unix()
	} else {
		delete(ret, "rat")
	}

	if len(c.Nonce) > 0 {
		ret["nonce"] = c.Nonce
	} else {
		delete(ret, "nonce")
	}

	if len(c.AccessTokenHash) > 0 {
		ret["at_hash"] = c.AccessTokenHash
	} else {
		delete(ret, "at_hash")
	}

	if len(c.CodeHash) > 0 {
		ret["c_hash"] = c.CodeHash
	} else {
		delete(ret, "c_hash")
	}

	if !c.AuthTime.IsZero() {
		ret["auth_time"] = c.AuthTime.Unix()
	} else {
		delete(ret, "auth_time")
	}

	if len(c.AuthenticationContextClassReference) > 0 {
		ret["acr"] = c.AuthenticationContextClassReference
	} else {
		delete(ret, "acr")
	}

	if len(c.AuthenticationMethodsReferences) > 0 {
		ret["amr"] = c.AuthenticationMethodsReferences
	} else {
		delete(ret, "amr")
	}

	return ret

}

// Add will add a key-value pair to the extra field
func (c *IDTokenClaims) Add(key string, value interface{}) {
	if c.Extra == nil {
		c.Extra = make(map[string]interface{})
	}
	c.Extra[key] = value
}

// Get will get a value from the extra field based on a given key
func (c *IDTokenClaims) Get(key string) interface{} {
	return c.ToMap()[key]
}

// ToMapClaims will return a jwt-go MapClaims representation
func (c IDTokenClaims) ToMapClaims() MapClaims {
	return c.ToMap()
}
