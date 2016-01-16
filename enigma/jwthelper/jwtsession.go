package jwthelper

// JWTSession : Interface for the JWT type session
type JWTSession struct {
	JWTClaimsCtx ClaimsContext
	JWTHeaders   map[string]interface{}
}
