package oauth2server

import (
	"encoding/json"
	"net/http"
)

const OauthServerMetadataPath = "/.well-known/oauth-authorization-server"

func (f *Flow) OauthServerMetadata(w http.ResponseWriter, r *http.Request) {
	metadata := OauthServerMetadata{
		Issuer:                "http://localhost:8080",
		AuthorizationEndpoint: "http://localhost:8080/oauth2/authorize",
		TokenEndpoint:         "http://localhost:8080/oauth2/token",
		// JwksURI:                           "http://localhost:8080/.well-known/jwks.json", // Example, not implemented
		RegistrationEndpoint:              "http://localhost:8080/oauth2/register",
		ScopesSupported:                   []string{"all", "openid", "profile", "email"},
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post"},
		CodeChallengeMethodsSupported:     []string{"S256", "plain"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metadata)
}
