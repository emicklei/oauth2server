package oauth2server

import "net/http"

// Flow holds all the state and configuration for the OAuth2 server.
type Flow struct {
	config FlowConfig
	store  FlowStateStore
}

// NewFlow creates a new Flow with initialized data stores.
func NewFlow(config FlowConfig, store FlowStateStore) *Flow {
	return &Flow{
		config: config,
		store:  store,
	}
}

type FlowConfig struct {
	// The resource protected by OAuth2.
	ResourceHandlerFunc http.HandlerFunc
	// For dynamic client registration.
	NewClientSecretFunc func(r *http.Request) string
	// For generating new authorization codes.
	NewAuthCodeFunc func(r *http.Request) string
	// For generating new access tokens.
	NewAccessTokenFunc func(r *http.Request) (string, error)

	LoginEndpoint             string
	AuthorizationBaseEndpoint string

	ResourcePath        string
	AuthorizePath       string
	AuthenticatedPath   string
	TokenPath           string
	RegisterPath        string
	AuthorizationScopes []string
}

type FlowStateStore interface {
	StoreAccessToken(code, token string) error
	LoadAccessToken(code string) (string, error)
	VerifyAccessToken(token string) (bool, error)
	RegisterClient(clientID, clientSecret string) error
	VerifyClient(clientID, clientSecret string) (bool, error)
	StoreAuthCode(code string, data AuthCodeData) error
	VerifyAuthCode(code string) (AuthCodeData, bool, error)
	DeleteAuthCode(code string) error
}
