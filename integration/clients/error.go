// Copyright © 2022 Ory Corp

package clients

import (
	"fmt"
	"net/http"
)

type RequestError struct {
	Response *http.Response
	Body     []byte
}

func (r *RequestError) Error() string {
	return fmt.Sprintf("oauth2: cannot fetch token: %v\nResponse: %s", r.Response.Status, r.Body)
}
