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
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type RefreshTokenData struct {
	AccessToken string
}

// Client holds information about a client
type Client struct {
	ID           string
	Secret       string
	RedirectURIs []string
}

// RegistrationRequest is the JSON request for dynamic client registration
// See https://www.rfc-editor.org/rfc/rfc7591#section-3.1
type RegistrationRequest struct {
	ClientName   string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
	GrantTypes   []string `json:"grant_types"`
}

// RegisterResponse is the JSON response for a successful client registration
// See https://www.rfc-editor.org/rfc/rfc7591#section-3.2
type RegisterResponse struct {
	ClientID string `json:"client_id"`
	// An OAuth client uses a client_secret to authenticate itself to the authorization server,
	// proving its identity so it can obtain an access token
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

var accessTokenDataKey = struct{ TokenResponse }{}

func ContextWithAccessToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, accessTokenDataKey, token)
}
func AccessTokenFromContext(ctx context.Context) string {
	v := ctx.Value(accessTokenDataKey)
	if v == nil {
		return ""
	}
	return v.(string)
}
