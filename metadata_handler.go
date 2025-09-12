package oauth2server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
)

const OauthServerMetadataPath = "/.well-known/oauth-authorization-server"

func (f *Flow) OauthServerMetadata(w http.ResponseWriter, r *http.Request) {
	slog.Debug("handling oauth server metadata", "url", r.URL.String())

	host := f.config.AuthorizationBaseEndpoint
	aPath, _ := url.JoinPath(host, f.config.AuthorizePath)
	tPath, _ := url.JoinPath(host, f.config.TokenPath)
	rPath, _ := url.JoinPath(host, f.config.RegisterPath)
	metadata := OauthServerMetadata{
		Issuer:                host,
		AuthorizationEndpoint: aPath,
		TokenEndpoint:         tPath,
		RegistrationEndpoint:  rPath,
		ScopesSupported:       f.config.AuthorizationScopes,

		// these are fixed for this implementation
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post"},
		CodeChallengeMethodsSupported:     []string{"S256"},

		// JwksURI:"http://localhost:8080/.well-known/jwks.json", // Example, not implemented
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metadata)

	slog.Debug("served OAuth2 server metadata", "host", host, "metadata", metadata)
}
