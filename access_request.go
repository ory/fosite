// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

type AccessRequest struct {
	GrantTypes       Arguments `json:"grantTypes" gorethink:"grantTypes"`
	HandledGrantType Arguments `json:"handledGrantType" gorethink:"handledGrantType"`

	RefreshTokenRequestedScope Arguments
	RefreshTokenGrantedScope   Arguments

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

func (a *AccessRequest) GetRefreshTokenRequestedScopes() (scopes Arguments) {
	if a.RefreshTokenRequestedScope == nil {
		return a.RequestedScope
	}

	return a.RefreshTokenRequestedScope
}

func (a *AccessRequest) SetRefreshTokenRequestedScopes(scopes Arguments) {
	a.RefreshTokenRequestedScope = scopes
}

func (a *AccessRequest) GetRefreshTokenGrantedScopes() (scopes Arguments) {
	if a.RefreshTokenGrantedScope == nil {
		return a.GrantedScope
	}

	return a.RefreshTokenGrantedScope
}

func (a *AccessRequest) SetRefreshTokenGrantedScopes(scopes Arguments) {
	a.RefreshTokenGrantedScope = scopes
}
