package toucan

// Toucan Client is grafana's client for checking leaked keys.
// Don't use this client directly,
// use the toucan Service which handles token collection and checking instead.
type client struct{}

func newClient() *client {
	return &client{}
}

// checkTokens checks if any leaked tokens exist.
// Returns list of leaked tokens.
func (c *client) checkTokens(tokens []string) ([]string, error) {
	leakedTokens := []string{}

	return leakedTokens, nil
}
