package oauth2server

// AuthCodeData stores information about an authorization code
type AuthCodeData struct {
	CodeChallenge       string
	CodeChallengeMethod string
}

// TokenResponse is the JSON response for a successful token request
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

// RegisterResponse is the JSON response for a successful client registration
type RegisterResponse struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}
