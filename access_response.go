package fosite

type AccessResponder interface {
	SetExtra(key string, value interface{})
	GetExtra(key string) interface{}
	SetAccessToken(string)
	SetTokenType(string)
	GetAccessToken() string
	GetTokenType() string
}
