package compose

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/rfc8693"
	"github.com/ory/fosite/storage"
)

func TestRFC8693TokenExchangeFactory(t *testing.T) {
	config := &fosite.Config{
		AccessTokenLifespan:     time.Hour,
		RefreshTokenLifespan:    time.Hour * 24 * 30,
		AuthorizeCodeLifespan:   time.Minute * 15,
		GlobalSecret:            []byte("test-global-secret-32-bytes-long"),
		TokenExchangeEnabled:    true,
		TokenExchangeTokenTypes: []string{rfc8693.TokenTypeAccessToken},
		ScopeStrategy:           fosite.HierarchicScopeStrategy,
		AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
	}

	store := storage.NewMemoryStore()
	strategy := NewOAuth2HMACStrategy(config)

	t.Run("factory creates handler when enabled", func(t *testing.T) {
		provider := Compose(
			config,
			store,
			strategy,
			RFC8693TokenExchangeFactory,
		)

		require.NotNil(t, provider)

		// Check that the handler was added
		assert.Greater(t, len(provider.TokenEndpointHandlers()), 0)

		// Find the RFC 8693 handler
		var rfc8693Handler *rfc8693.Handler
		for _, handler := range provider.TokenEndpointHandlers() {
			if h, ok := handler.(*rfc8693.Handler); ok {
				rfc8693Handler = h
				break
			}
		}

		require.NotNil(t, rfc8693Handler, "RFC 8693 handler should be registered")
		assert.Equal(t, config, rfc8693Handler.Config)
		assert.Equal(t, store, rfc8693Handler.Storage)
		assert.NotNil(t, rfc8693Handler.HandleHelper)
	})

	t.Run("factory skips when disabled", func(t *testing.T) {
		disabledConfig := &fosite.Config{
			AccessTokenLifespan:     time.Hour,
			GlobalSecret:            []byte("test-global-secret-32-bytes-long"),
			TokenExchangeEnabled:    false, // Disabled
			ScopeStrategy:           fosite.HierarchicScopeStrategy,
			AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
		}

		provider := Compose(
			disabledConfig,
			store,
			strategy,
			RFC8693TokenExchangeFactory,
		)

		require.NotNil(t, provider)

		// Check that no RFC 8693 handler was added when disabled
		for _, handler := range provider.TokenEndpointHandlers() {
			_, isRFC8693Handler := handler.(*rfc8693.Handler)
			assert.False(t, isRFC8693Handler, "RFC 8693 handler should not be registered when disabled")
		}
	})

	t.Run("factory with full compose integration", func(t *testing.T) {
		// Test that the factory works with the full Compose function
		provider := Compose(
			config,
			store,
			strategy,
			OAuth2AuthorizeExplicitFactory,
			OAuth2ClientCredentialsGrantFactory,
			RFC8693TokenExchangeFactory,
		)

		require.NotNil(t, provider)

		// Verify that the provider has the RFC 8693 handler
		var foundRFC8693Handler bool
		for _, handler := range provider.TokenEndpointHandlers() {
			if _, ok := handler.(*rfc8693.Handler); ok {
				foundRFC8693Handler = true
				break
			}
		}

		assert.True(t, foundRFC8693Handler, "RFC 8693 handler should be present in composed provider")

		// Verify that other handlers are also present (sanity check)
		assert.Greater(t, len(provider.TokenEndpointHandlers()), 1, "Multiple handlers should be registered")
	})

	t.Run("factory with nil storage interface", func(t *testing.T) {
		// Test with storage that doesn't implement RFC8693Storage
		basicStore := &BasicStorage{}

		provider := Compose(
			config,
			basicStore,
			strategy,
			RFC8693TokenExchangeFactory,
		)

		require.NotNil(t, provider)

		// The handler should still be created, but with the storage passed
		var rfc8693Handler *rfc8693.Handler
		for _, handler := range provider.TokenEndpointHandlers() {
			if h, ok := handler.(*rfc8693.Handler); ok {
				rfc8693Handler = h
				break
			}
		}

		require.NotNil(t, rfc8693Handler, "RFC 8693 handler should be created even with non-compliant storage")
		// The storage will be set to the passed storage (even if it doesn't implement the interface)
		assert.Equal(t, basicStore, rfc8693Handler.Storage)
	})
}

// BasicStorage is a minimal storage implementation that doesn't implement RFC8693Storage
type BasicStorage struct {
	*storage.MemoryStore
}

func (s *BasicStorage) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	return nil, fosite.ErrNotFound
}
