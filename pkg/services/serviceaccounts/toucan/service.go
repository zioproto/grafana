package toucan

import (
	"context"

	"github.com/grafana/grafana/pkg/services/apikey"
)

type Checker interface {
	CheckTokens(ctx context.Context) error
}

type TokenRetriever interface {
	GetActiveTokens(ctx context.Context) []apikey.APIKey
}

// Toucan Service is grafana's service for checking leaked keys.
type Service struct {
	store  TokenRetriever
	client *client
}

func NewService(store TokenRetriever) *Service {
	return &Service{
		store:  store,
		client: newClient(),
	}
}

// CheckTokens checks for leaked tokens.
func (s *Service) CheckTokens(ctx context.Context) error {
	// Retrieve all tokens from the database.
	s.store.GetActiveTokens(ctx)

	// Check if any leaked tokens exist.

	// Revoke leaked tokens.

	return nil
}
