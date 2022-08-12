package toucan

// Toucan Client is grafana's client for checking leaked keys.
// Don't use this client directly,
// use the toucan Service which handles token collection and checking instead.
type client struct{}

func newClient() *client {
	return &client{}
}
