package toucan

import (
	"context"

	"github.com/grafana/grafana/pkg/services/serviceaccounts"
)

type Checker interface {
	CheckTokens(ctx context.Context) error
}

// Toucan Service is grafana's service for checking leaked keys.
type Service struct {
	store  serviceaccounts.Store
	client *client
}

func NewService(store serviceaccounts.Store) *Service {
	return &Service{
		store:  store,
		client: newClient(),
	}
}

// CheckTokens checks for leaked tokens.
func (s *Service) CheckTokens(ctx context.Context) error {
	return nil
}
