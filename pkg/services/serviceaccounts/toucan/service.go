package toucan

import (
	"context"
	"fmt"
	"time"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/apikey"
	"github.com/grafana/grafana/pkg/services/serviceaccounts"
	"github.com/grafana/grafana/pkg/setting"
)

const defaultURL = "https://toucan.grafana.com"

type Checker interface {
	CheckTokens(ctx context.Context) error
}

type SATokenRetriever interface {
	ListTokens(ctx context.Context, query *serviceaccounts.GetSATokensQuery) ([]apikey.APIKey, error)
	RevokeServiceAccountToken(ctx context.Context, orgID, serviceAccountID, tokenID int64) error
}

// Toucan Service is grafana's service for checking leaked keys.
type Service struct {
	store     SATokenRetriever
	client    *client
	logger    log.Logger
	oncallURL string
}

func NewService(store SATokenRetriever, cfg *setting.Cfg) *Service {
	toucanBaseURL := cfg.SectionWithEnvOverrides("toucan").Key("base_url").MustString(defaultURL)
	oncallURL := cfg.SectionWithEnvOverrides("toucan").Key("oncall_url").MustString("")

	return &Service{
		store:     store,
		client:    newClient(toucanBaseURL, cfg.BuildVersion),
		logger:    log.New("toucan"),
		oncallURL: oncallURL,
	}
}

func (s *Service) RetrieveActiveTokens(ctx context.Context) ([]apikey.APIKey, error) {
	saTokens, err := s.store.ListTokens(ctx, &serviceaccounts.GetSATokensQuery{
		OrgID:            nil,
		ServiceAccountID: nil,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve service account tokens: %w", err)
	}

	return saTokens, nil
}

// hasExpired returns true if the token has expired.
// Duplicate to SA API. Remerge.
func hasExpired(expiration *int64) bool {
	if expiration == nil {
		return false
	}

	v := time.Unix(*expiration, 0)

	return (v).Before(time.Now())
}

// CheckTokens checks for leaked tokens.
func (s *Service) CheckTokens(ctx context.Context) error {
	// Retrieve all active tokens from the database.
	tokens, err := s.RetrieveActiveTokens(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve tokens for checking: %w", err)
	}

	hashes := make([]string, 0, len(tokens))
	hashMap := make(map[string]apikey.APIKey)

	for _, token := range tokens {
		if hasExpired(token.Expires) || (token.IsRevoked != nil && *token.IsRevoked) {
			continue
		}

		hashes = append(hashes, token.Key)
		hashMap[token.Key] = token
	}

	if len(hashes) == 0 {
		s.logger.Debug("no active tokens to check")

		return nil
	}

	// Check if any leaked tokens exist.
	toucanTokens, err := s.client.checkTokens(ctx, hashes)
	if err != nil {
		return fmt.Errorf("failed to check tokens: %w", err)
	}

	// Revoke leaked tokens.
	// Could be done in bulk but we don't expect more than 1 or 2 tokens to be leaked per check.
	for _, toucanToken := range toucanTokens {
		toucanToken := toucanToken
		leakedToken := hashMap[toucanToken.Hash]

		if err := s.store.RevokeServiceAccountToken(
			ctx, leakedToken.OrgId, *leakedToken.ServiceAccountId, leakedToken.Id); err != nil {
			s.logger.Error("failed to delete leaked token. Revoke manually.",
				"error", err,
				"url", toucanToken.URL,
				"reported_at", toucanToken.ReportedAt,
				"token_id", leakedToken.Id,
				"token", leakedToken.Name,
				"org", leakedToken.OrgId,
				"serviceAccount", *leakedToken.ServiceAccountId)
		}

		if s.oncallURL != "" {
			if err := s.client.webhookCall(ctx, &toucanToken, leakedToken.Name, s.oncallURL); err != nil {
				s.logger.Warn("failed to call token leak webhook", "error", err)
			}
		}

		s.logger.Info("revoked leaked token",
			"url", toucanToken.URL,
			"reported_at", toucanToken.ReportedAt,
			"token_id", leakedToken.Id,
			"token", leakedToken.Name,
			"org", leakedToken.OrgId,
			"serviceAccount", *leakedToken.ServiceAccountId)
	}

	return nil
}
