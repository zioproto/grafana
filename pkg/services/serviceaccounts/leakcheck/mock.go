package leakcheck

import (
	"context"

	"github.com/grafana/grafana/pkg/services/apikey"
	"github.com/grafana/grafana/pkg/services/serviceaccounts"
)

type MockTokenRetriever struct{}

func (m *MockTokenRetriever) ListTokens(ctx context.Context, query *serviceaccounts.GetSATokensQuery) ([]apikey.APIKey, error) {
	return []apikey.APIKey{}, nil
}

func (m *MockTokenRetriever) DeleteServiceAccountToken(ctx context.Context, orgID, serviceAccountID, tokenID int64) error {
	return nil
}
