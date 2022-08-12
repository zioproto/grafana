package toucan

import (
	"context"

	"github.com/grafana/grafana/pkg/services/apikey"
)

type MockTokenRetriever struct{}

func (m *MockTokenRetriever) GetActiveTokens(ctx context.Context) []apikey.APIKey {
	return []apikey.APIKey{}
}
