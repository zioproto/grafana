package leakcheck

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
)

const timeout = 4 * time.Second

// LeakCheck Client is grafana's client for checking leaked keys.
// Don't use this client directly,
// use the leakcheck Service which handles token collection and checking instead.
type client struct {
	httpClient *http.Client
	version    string
	baseURL    string
}

type leakcheckRequest struct {
	KeyHashes []string `json:"hashes"`
}

type LeakCheckToken struct {
	Type       string `json:"type"`
	URL        string `json:"url"`
	Hash       string `json:"hash"`
	ReportedAt string `json:"reported_at"`
}

var ErrInvalidStatusCode = errors.New("invalid status code")

func newClient(url, version string) *client {
	return &client{
		version: version,
		baseURL: url,
		httpClient: &http.Client{
			Timeout: timeout,
		}}
}

// checkTokens checks if any leaked tokens exist.
// Returns list of leaked tokens.
func (c *client) checkTokens(ctx context.Context, keyHashes []string) ([]LeakCheckToken, error) {
	// create request body
	values := leakcheckRequest{KeyHashes: keyHashes}

	jsonValue, err := json.Marshal(values)
	if err != nil {
		return nil, errors.Wrap(err, "failed to make http request")
	}

	// Build URL
	url := fmt.Sprintf("%s/tokens", c.baseURL)
	// Create request for leakcheck server
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		url, bytes.NewReader(jsonValue))
	if err != nil {
		return nil, errors.Wrap(err, "failed to make http request")
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "grafana-leakcheck-client/"+c.version)

	// make http POST request to check for leaked tokens.
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to do http request")
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w. status code: %s", ErrInvalidStatusCode, resp.Status)
	}

	// decode response body
	var tokens []LeakCheckToken
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		return nil, errors.Wrap(err, "failed to decode response body")
	}

	return tokens, nil
}

func (c *client) webhookCall(ctx context.Context, token *LeakCheckToken, tokenName string, webhookURL string) error {
	// create request body
	values := map[string]interface{}{
		"alert_uid":                uuid.NewString(),
		"title":                    "LeakCheck Alert: Grafana Token leaked",
		"image_url":                "https://images.pexels.com/photos/5119737/pexels-photo-5119737.jpeg?auto=compress&cs=tinysrgb&w=300", //nolint
		"state":                    "alerting",
		"link_to_upstream_details": token.URL,
		"message": "Token of type " +
			token.Type + " with name " +
			tokenName + " has been publicly exposed in " +
			token.URL + ". Grafana has revoked this token",
	}

	jsonValue, err := json.Marshal(values)
	if err != nil {
		return errors.Wrap(err, "failed to marshal webhook request")
	}

	// Build URL
	// Create request for leakcheck server
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		webhookURL, bytes.NewReader(jsonValue))
	if err != nil {
		return errors.Wrap(err, "failed to make http request")
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "grafana-leakcheck-client/"+c.version)

	// make http POST request to check for leaked tokens.
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "failed to webhook request")
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to signal webhook: %s", resp.Status)
	}

	return nil
}
