package pkg

import (
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
)

func OwnerHandler(c oauth2.Config) func(rw http.ResponseWriter, req *http.Request) {
	return func(rw http.ResponseWriter, req *http.Request) {
		rw.Write([]byte("<h1>Resource Owner Password Credentials Grant</h1>"))
		req.ParseForm()
		if req.Form.Get("username") == "" || req.Form.Get("password") == "" {
			rw.Write([]byte(`<form method="post">
			<ul>
				<li>
					<input type="text" name="username" placeholder="username"/> <small>try "peter"</small>
				</li>
				<li>
					<input type="password" name="password" placeholder="password"/> <small>try "secret"</small><br>
				</li>
				<li>
					<input type="submit" />
				</li>
			</ul>
		</form>`))
			rw.Write([]byte(`<p><a href="/">Go back</a></p>`))
			return
		}

		token, err := c.PasswordCredentialsToken(oauth2.NoContext, req.Form.Get("username"), req.Form.Get("password"))
		if err != nil {
			rw.Write([]byte(fmt.Sprintf(`<p>I tried to get a token but received an error: %s</p>`, err.Error())))
			rw.Write([]byte(`<p><a href="/">Go back</a></p>`))
			return
		}
		rw.Write([]byte(fmt.Sprintf(`<p>Awesome, you just received an access token!<br><br>%s<br><br><strong>more info:</strong><br><br>%s</p>`, token.AccessToken, token)))
		rw.Write([]byte(`<p><a href="/">Go back</a></p>`))
	}
}
