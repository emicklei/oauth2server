package oauth2server

import (
	"errors"
	"log/slog"
	"net/http"
)

// Flow holds all the state and configuration for the OAuth2 server.
type Flow struct {
	config FlowConfig
	store  FlowStateStore
}

// NewFlow creates a new Flow with initialized data stores.
func NewFlow(config FlowConfig, store FlowStateStore) *Flow {
	if err := config.Validate(); err != nil {
		for _, e := range err {
			slog.Error("missing flow configuration field", "err", e)
		}
		panic("invalid flow config")
	}
	return &Flow{
		config: config,
		store:  store,
	}
}

type FlowConfig struct {
	AccessTokenHeaderName string
	// The resource protected by OAuth2.
	ResourceHandlerFunc http.HandlerFunc
	// For dynamic client registration.
	NewClientSecretFunc func(r *http.Request) string
	// For generating new authorization codes.
	NewAuthCodeFunc func(r *http.Request) string
	// For generating new access tokens.
	NewAccessTokenFunc func(r *http.Request) (string, error)
	// For generating new refresh tokens.
	NewRefreshTokenFunc func(r *http.Request) (string, error)

	LoginEndpoint             string
	AuthorizationBaseEndpoint string

	ResourcePath        string
	AuthorizePath       string
	AuthenticatedPath   string
	TokenPath           string
	RegisterPath        string
	AuthorizationScopes []string
}

func (c *FlowConfig) Validate() (list []error) {
	if c.ResourceHandlerFunc == nil {
		list = append(list, errors.New("ResourceHandlerFunc must be provided"))
	}
	if c.NewClientSecretFunc == nil {
		list = append(list, errors.New("NewClientSecretFunc must be provided"))
	}
	if c.NewAuthCodeFunc == nil {
		list = append(list, errors.New("NewAuthCodeFunc must be provided"))
	}
	if c.NewAccessTokenFunc == nil {
		list = append(list, errors.New("NewAccessTokenFunc must be provided"))
	}
	if c.NewRefreshTokenFunc == nil {
		list = append(list, errors.New("NewRefreshTokenFunc must be provided"))
	}
	if c.LoginEndpoint == "" {
		list = append(list, errors.New("LoginEndpoint must be provided"))
	}
	if c.AuthorizationBaseEndpoint == "" {
		list = append(list, errors.New("AuthorizationBaseEndpoint must be provided"))
	}
	if c.ResourcePath == "" {
		list = append(list, errors.New("ResourcePath must be provided"))
	}
	if c.AuthorizePath == "" {
		list = append(list, errors.New("AuthorizePath must be provided"))
	}
	if c.AuthenticatedPath == "" {
		list = append(list, errors.New("AuthenticatedPath must be provided"))
	}
	if c.TokenPath == "" {
		list = append(list, errors.New("TokenPath must be provided"))
	}
	if c.RegisterPath == "" {
		list = append(list, errors.New("RegisterPath must be provided"))
	}
	if c.AccessTokenHeaderName == "" {
		list = append(list, errors.New("AccessTokenHeaderName must be provided"))
	}
	if len(c.AuthorizationScopes) == 0 {
		list = append(list, errors.New("at least one AuthorizationScope must be provided"))
	}
	if len(list) > 0 {
		return list
	}
	return nil
}

type FlowStateStore interface {
	StoreAccessToken(code, token string) error
	LoadAccessToken(code string) (string, error)
	VerifyAccessToken(token string) (bool, error)
	RegisterClient(client Client) error
	GetClient(clientID string) (*Client, error)
	VerifyClient(clientID, clientSecret string) (bool, error)
	StoreAuthCode(code string, data AuthCodeData) error
	VerifyAuthCode(code string) (AuthCodeData, bool, error)
	DeleteAuthCode(code string) error
	StoreRefreshToken(token string, data RefreshTokenData) error
	GetRefreshToken(token string) (*RefreshTokenData, error)
	DeleteRefreshToken(token string) error
}

func (f *Flow) RegisterHandlers(mux *http.ServeMux) {
	mux.HandleFunc(OauthServerMetadataPath, f.OauthServerMetadata)
	mux.HandleFunc(f.config.AuthorizePath, f.AuthorizeHandler)
	mux.HandleFunc(f.config.AuthenticatedPath, f.AuthenticatedHandler)
	mux.HandleFunc(f.config.TokenPath, f.TokenHandler)
	mux.HandleFunc(f.config.ResourcePath, f.ProtectedHandler)
	mux.HandleFunc(f.config.RegisterPath, f.RegisterHandler)
}
