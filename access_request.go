// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

type AccessRequest struct {
	GrantTypes       Arguments `json:"grantTypes" gorethink:"grantTypes"`
	HandledGrantType Arguments `json:"handledGrantType" gorethink:"handledGrantType"`

	JWTClaims map[string]interface{} `json:"jwt_claims" gorethink:"jwtClaims"`

	Request
}

func NewAccessRequest(session Session) *AccessRequest {
	r := &AccessRequest{
		GrantTypes:       Arguments{},
		HandledGrantType: Arguments{},
		Request:          *NewRequest(),
	}
	r.Session = session
	return r
}

func (a *AccessRequest) GetGrantTypes() Arguments {
	return a.GrantTypes
}

func (a *AccessRequest) GetJWTClaims() map[string]interface{} {
	return a.JWTClaims
}

func (a *AccessRequest) SetJWTClaims(claims map[string]interface{}) {
	a.JWTClaims = claims
}
