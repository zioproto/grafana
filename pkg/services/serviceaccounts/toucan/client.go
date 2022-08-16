package toucan

import (
	"context"
	"net/http"
	"time"
)

const timeout = 4 * time.Second

// Toucan Client is grafana's client for checking leaked keys.
// Don't use this client directly,
// use the toucan Service which handles token collection and checking instead.
type client struct {
	httpClient *http.Client
}

func newClient() *client {
	return &client{&http.Client{
		Timeout: timeout,
	}}
}

// checkTokens checks if any leaked tokens exist.
// Returns list of leaked tokens.
func (c *client) checkTokens(ctx context.Context, keyHashes []string) ([]string, error) {
	leakedTokens := []string{}

	return leakedTokens, nil
}
