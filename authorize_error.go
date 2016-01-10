package fosite

import (
	"github.com/ory-am/common/pkg"
	"net/http"
)

const minStateLength = 8

func (c *Fosite) WriteAuthorizeError(rw http.ResponseWriter, ar AuthorizeRequester, err error) {
	rfcerr := ErrorToRFC6749Error(err)

	if !ar.IsRedirectURIValid() {
		pkg.WriteIndentJSON(rw, rfcerr)
		return
	}

	redirectURI := ar.GetRedirectURI()
	query := redirectURI.Query()
	query.Add("error", rfcerr.Name)
	query.Add("error_description", rfcerr.Description)
	redirectURI.RawQuery = query.Encode()

	rw.Header().Add("Location", redirectURI.String())
	rw.WriteHeader(http.StatusFound)
}
