package code

type AuthorizeCodeSession struct {
	Signature     []byte
	ResponseTypes []string
	ClientID      string
	Scopes        []string
	RedirectURI   string
	State         string
}
