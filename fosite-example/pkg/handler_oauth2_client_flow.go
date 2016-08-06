package pkg

import (
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

func ClientEndpoint(c clientcredentials.Config) func(rw http.ResponseWriter, req *http.Request) {
	return func(rw http.ResponseWriter, req *http.Request) {
		rw.Write([]byte("<h1>Client Credentials Grant</h1>"))
		token, err := c.Token(oauth2.NoContext)
		if err != nil {
			rw.Write([]byte(fmt.Sprintf(`<p>I tried to get a token but received an error: %s</p>`, err.Error())))
			return
		}
		rw.Write([]byte(fmt.Sprintf(`<p>Awesome, you just received an access token!<br><br>%s<br><br><strong>more info:</strong><br><br>%s</p>`, token.AccessToken, token)))
		rw.Write([]byte(`<p><a href="/">Go back</a></p>`))
	}
}
