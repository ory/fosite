package fosite

import (
	"net/url"
)

// AuthorizeRequest is an implementation of AuthorizeRequester
type AuthorizeRequest struct {
	ResponseTypes        Arguments
	RedirectURI          *url.URL
	State                string
	HandledResponseTypes Arguments

	Request
}

func (d *AuthorizeRequest) IsRedirectURIValid() bool {
	if d.GetRedirectURI() == nil {
		return false
	}

	raw := d.GetRedirectURI().String()
	if d.GetClient() == nil {
		return false
	}

	redirectURI, err := MatchRedirectURIWithClientRedirectURIs(raw, d.GetClient())
	if err != nil {
		return false
	}
	return IsValidRedirectURI(redirectURI)
}

func (d *AuthorizeRequest) GetResponseTypes() Arguments {
	return d.ResponseTypes
}

func (d *AuthorizeRequest) GetState() string {
	return d.State
}

func (d *AuthorizeRequest) GetRedirectURI() *url.URL {
	return d.RedirectURI
}

func (d *AuthorizeRequest) SetResponseTypeHandled(name string) {
	d.HandledResponseTypes = append(d.HandledResponseTypes, name)
}

func (d *AuthorizeRequest) DidHandleAllResponseTypes() bool {
	for _, rt := range d.ResponseTypes {
		if !d.HandledResponseTypes.Has(rt) {
			return false
		}
	}

	return len(d.ResponseTypes) > 0
}
