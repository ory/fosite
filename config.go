package fosite

type Config struct {
	AllowedAuthorizeResponseTypes []string
	AllowedTokenResponseTypes []string
	Lifetime int32
	Store Storage
}

func NewDefaultConfig() *Config {
	return &Config{
		AllowedAuthorizeResponseTypes: []string{"code", "token", "id_token"},
		AllowedTokenResponseTypes: []string{},
		Lifetime: 3600,
	}
}