package oauth2

type TokenRevocationStorage interface {
	RefreshTokenStrategy
	RefreshTokenStorage
	AccessTokenStorage
	AccessTokenStrategy
}
