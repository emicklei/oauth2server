package oauth2server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
)

// TokenHandler handles requests for access tokens.
func (f *Flow) TokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	grantType := r.Form.Get("grant_type")
	if grantType == "authorization_code" {
		f.handleAuthorizationCodeGrant(w, r)
		return
	}
	if grantType == "refresh_token" {
		f.handleRefreshTokenGrant(w, r)
		return
	}
	http.Error(w, "unsupported grant_type", http.StatusBadRequest)
}

func (f *Flow) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	code := r.Form.Get("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}
	authData, ok, err := f.store.VerifyAuthCode(code)
	if err != nil {
		http.Error(w, "failed to verify auth code", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "invalid code", http.StatusBadRequest)
		return
	}
	// PKCE verification
	codeVerifier := r.Form.Get("code_verifier")
	if codeVerifier == "" {
		http.Error(w, "code_verifier required", http.StatusBadRequest)
		return
	}
	if authData.CodeChallengeMethod != "S256" {
		http.Error(w, "unsupported code_challenge_method", http.StatusBadRequest)
		return
	}
	s256 := sha256.Sum256([]byte(codeVerifier))
	challenge := base64.RawURLEncoding.EncodeToString(s256[:])
	if challenge != authData.CodeChallenge {
		http.Error(w, "invalid code_verifier", http.StatusBadRequest)
		return
	}
	if err := f.store.DeleteAuthCode(code); err != nil {
		slog.Error("failed to delete auth code", "err", err)
		http.Error(w, "failed to delete auth code", http.StatusInternalServerError)
		return
	}
	clientID := r.Form.Get("client_id")
	clientSecret := r.Form.Get("client_secret")
	ok, err = f.store.VerifyClient(clientID, clientSecret)
	if err != nil || !ok {
		http.Error(w, "invalid client credentials", http.StatusUnauthorized)
		return
	}
	accessToken, err := f.store.LoadAccessToken(code)
	if err != nil {
		http.Error(w, "failed to load access token", http.StatusInternalServerError)
		return
	}
	refreshToken, err := f.config.NewRefreshTokenFunc(r)
	if err != nil {
		http.Error(w, "failed to create refresh token", http.StatusInternalServerError)
		return
	}
	if err := f.store.StoreRefreshToken(refreshToken, RefreshTokenData{AccessToken: accessToken}); err != nil {
		http.Error(w, "failed to store refresh token", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	resp := TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "bearer",
		ExpiresIn:    3600,
		RefreshToken: refreshToken,
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("failed to write token response", "err", err)
	}
}

func (f *Flow) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	refreshToken := r.Form.Get("refresh_token")
	if refreshToken == "" {
		http.Error(w, "missing refresh_token", http.StatusBadRequest)
		return
	}
	_, err := f.store.GetRefreshToken(refreshToken)
	if err != nil {
		http.Error(w, "invalid refresh_token", http.StatusBadRequest)
		return
	}
	if err := f.store.DeleteRefreshToken(refreshToken); err != nil {
		slog.Error("failed to delete refresh token", "err", err)
		http.Error(w, "failed to delete refresh token", http.StatusInternalServerError)
		return
	}
	newAccessToken, err := f.config.NewAccessTokenFunc(r)
	if err != nil {
		http.Error(w, "failed to create access token", http.StatusInternalServerError)
		return
	}
	newRefreshToken, err := f.config.NewRefreshTokenFunc(r)
	if err != nil {
		http.Error(w, "failed to create refresh token", http.StatusInternalServerError)
		return
	}
	if err := f.store.StoreRefreshToken(newRefreshToken, RefreshTokenData{AccessToken: newAccessToken}); err != nil {
		http.Error(w, "failed to store refresh token", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	resp := TokenResponse{
		AccessToken:  newAccessToken,
		TokenType:    "bearer",
		ExpiresIn:    3600,
		RefreshToken: newRefreshToken,
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("failed to write token response", "err", err)
	}
}
