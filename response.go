package fosite
import "net/http"

type Response struct {
	Type string
	Headers string
	Output map[string]interface{}
}

func (r *Response) GetRedirectURL() {
/*
	if r.Type != REDIRECT {
		return "", errors.New("Not a redirect response")
	}

	u, err := url.Parse(r.URL)
	if err != nil {
		return "", err
	}

	// add parameters
	q := u.Query()
	for n, v := range r.Output {
		q.Set(n, fmt.Sprint(v))
	}
	if r.RedirectInFragment {
		u.RawQuery = ""
		u.Fragment, err = url.QueryUnescape(q.Encode())
		if err != nil {
			return "", err
		}
	} else {
		u.RawQuery = q.Encode()
	}

	return u.String(), nil*/
}

func WriteResponse(r *Response, w http.ResponseWriter) {

}