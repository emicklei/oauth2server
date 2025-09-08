package oauth2server

import "context"

// AuthCodeData stores information about an authorization code
// See https://www.rfc-editor.org/rfc/rfc7636#section-4.2
type AuthCodeData struct {
	CodeChallenge       string
	CodeChallengeMethod string
}

// TokenResponse is the JSON response for a successful token request
// See https://www.rfc-editor.org/rfc/rfc6749#section-5.1
// See also oauth2.Token
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

// RegisterResponse is the JSON response for a successful client registration
// See https://www.rfc-editor.org/rfc/rfc7591#section-3.2
type RegisterResponse struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// OauthServerMetadata is the structure for the metadata document
// See https://www.rfc-editor.org/rfc/rfc8414#section-3
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

type AccessTokenData map[string]any

var accessTokenDataKey = struct{ AccessTokenData }{}

func ContextWithAccessTokenData(ctx context.Context, data AccessTokenData) context.Context {
	return context.WithValue(ctx, accessTokenDataKey, data)
}
func AccessTokenDataFromContext(ctx context.Context) AccessTokenData {
	v := ctx.Value(accessTokenDataKey)
	if v == nil {
		return nil
	}
	return v.(AccessTokenData)
}
