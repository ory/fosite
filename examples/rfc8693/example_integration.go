package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/rfc8693"
	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/hmac"
)

// This example shows how to integrate RFC 8693 Token Exchange with Fosite
func main() {
	// Setup storage with RFC 8693 support
	store := &ExampleStorage{
		MemoryStore: storage.NewMemoryStore(),
	}

	// Configure Fosite with token exchange enabled
	config := &fosite.Config{
		AccessTokenLifespan:   time.Hour,
		RefreshTokenLifespan:  time.Hour * 24 * 30,
		AuthorizeCodeLifespan: time.Minute * 15,
		GlobalSecret:          []byte("my-global-secret"),

		// Enable RFC 8693 Token Exchange
		TokenExchangeEnabled: true,
		TokenExchangeTokenTypes: []string{
			rfc8693.TokenTypeAccessToken,
			rfc8693.TokenTypeRefreshToken,
		},

		ScopeStrategy:            fosite.HierarchicScopeStrategy,
		AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
	}

	// Create Fosite instance with RFC 8693 support
	oauth2Provider := compose.Compose(
		config,
		store,
		&hmac.HMACStrategy{
			Config: &fosite.Config{GlobalSecret: []byte("my-global-secret")},
		},

		// Include the RFC 8693 factory
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2AuthorizeImplicitFactory,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.RFC8693TokenExchangeFactory,
	)

	// Create a test client
	client := &fosite.DefaultClient{
		ID:     "test-client",
		Secret: []byte("test-secret"),
		GrantTypes: fosite.Arguments{
			"authorization_code",
			"refresh_token",
			"client_credentials",
			rfc8693.GrantTypeTokenExchange,
		},
		ResponseTypes: fosite.Arguments{"code", "token"},
		Scopes:        fosite.Arguments{"read", "write", "admin"},
		Audience:      fosite.Arguments{"api.example.com"},
	}

	// Store the client
	store.Clients["test-client"] = client

	// Setup HTTP server
	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		handleTokenEndpoint(w, r, oauth2Provider)
	})

	fmt.Println("OAuth2 server with RFC 8693 Token Exchange running on :8080")
	fmt.Println("Example token exchange request:")
	fmt.Println("POST /token")
	fmt.Println("Content-Type: application/x-www-form-urlencoded")
	fmt.Println("")
	fmt.Println("grant_type=urn:ietf:params:oauth:grant-type:token-exchange")
	fmt.Println("&subject_token=<existing_access_token>")
	fmt.Println("&subject_token_type=urn:ietf:params:oauth:token-type:access_token")
	fmt.Println("&scope=read")
	fmt.Println("&client_id=test-client")
	fmt.Println("&client_secret=test-secret")

	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleTokenEndpoint(w http.ResponseWriter, r *http.Request, oauth2Provider fosite.OAuth2Provider) {
	ctx := context.Background()

	// Parse the request
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	// Create session for the request
	session := &fosite.DefaultSession{}

	// Handle the token request
	accessRequest, err := oauth2Provider.NewAccessRequest(ctx, r, session)
	if err != nil {
		oauth2Provider.WriteAccessError(ctx, w, accessRequest, err)
		return
	}

	// Handle the token response
	accessResponse, err := oauth2Provider.NewAccessResponse(ctx, accessRequest)
	if err != nil {
		oauth2Provider.WriteAccessError(ctx, w, accessRequest, err)
		return
	}

	// Write the response
	oauth2Provider.WriteAccessResponse(ctx, w, accessRequest, accessResponse)
}
