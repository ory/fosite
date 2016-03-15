package fosite

import (
	"encoding/json"
	"net/http"
)

func (c *Fosite) WriteAuthorizeError(rw http.ResponseWriter, ar AuthorizeRequester, err error) {
	rfcerr := ErrorToRFC6749Error(err)

	if !ar.IsRedirectURIValid() {
		js, err := json.MarshalIndent(rfcerr, "", "\t")
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(rfcerr.StatusCode)
		rw.Write(js)
		return
	}

	redirectURI := ar.GetRedirectURI()
	query := redirectURI.Query()
	query.Add("error", rfcerr.Name)
	query.Add("error_description", rfcerr.Description)
	query.Add("state", ar.GetState())
	redirectURI.RawQuery = query.Encode()

	rw.Header().Add("Location", redirectURI.String())
	rw.WriteHeader(http.StatusFound)
}
