package fosite

import "net/http"

// Response defines fosite's response model
type Response struct {
	Type           string
	Headers        http.Header
	StatusCode     int
	Err            error
	BypassRedirect bool
	Output         map[string]interface{}
}

// Set sets a key value pair inside Response.Output.
func (r *Response) Set(key string, value interface{}) {
	r.Output[key] = value
}
