package oauth2server

import (
	"encoding/json"
	"net/http"
)

// OauthServerMetadata is the structure for the metadata document
type OauthServerMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
}

func (f *Flow) OauthServerMetadata(w http.ResponseWriter, r *http.Request) {
	metadata := OauthServerMetadata{
		Issuer:                            "http://localhost:8080",
		AuthorizationEndpoint:             "http://localhost:8080/oauth2/authorize",
		TokenEndpoint:                     "http://localhost:8080/oauth2/token",
		JwksURI:                           "http://localhost:8080/.well-known/jwks.json", // Example, not implemented
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
