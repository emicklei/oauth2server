package oauth2server

import (
	"encoding/json"
	"net/http"
	"path"
)

const OauthServerMetadataPath = "/.well-known/oauth-authorization-server"

func (f *Flow) OauthServerMetadata(w http.ResponseWriter, r *http.Request) {
	host := f.config.AuthorizationBaseEndpoint
	metadata := OauthServerMetadata{
		Issuer:                host,
		AuthorizationEndpoint: path.Join(host, f.config.AuthorizePath),
		TokenEndpoint:         path.Join(host, f.config.TokenPath),
		RegistrationEndpoint:  path.Join(host, f.config.RegisterPath),
		ScopesSupported:       f.config.AuthorizationScopes,

		// these are fixed for this implementation
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post"},
		CodeChallengeMethodsSupported:     []string{"S256", "plain"},

		// JwksURI:"http://localhost:8080/.well-known/jwks.json", // Example, not implemented
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metadata)
}
