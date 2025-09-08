package oauth2server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
)

func (f *Flow) TokenHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	code := r.Form.Get("code")
	authData, ok, err := f.store.VerifyAuthCode(code)
	if err != nil {
		slog.Error("Error getting authorization code", "err", err)
		http.Error(w, "Error getting authorization code", http.StatusInternalServerError)
		return
	}
	if !ok {
		slog.Error("Invalid authorization code", "code", code)
		http.Error(w, "Invalid authorization code", http.StatusBadRequest)
		return
	}

	// PKCE verification
	if authData.CodeChallenge != "" {
		codeVerifier := r.Form.Get("code_verifier")
		if codeVerifier == "" {
			slog.Error("code_verifier required")
			http.Error(w, "code_verifier required", http.StatusBadRequest)
			return
		}
		switch authData.CodeChallengeMethod {
		case "S256":
			s256 := sha256.Sum256([]byte(codeVerifier))
			challenge := base64.RawURLEncoding.EncodeToString(s256[:])
			if challenge != authData.CodeChallenge {
				slog.Error("invalid code_verifier", "challenge", challenge, "expected", authData.CodeChallenge)
				http.Error(w, "invalid code_verifier", http.StatusBadRequest)
				return
			}
		case "plain":
			if codeVerifier != authData.CodeChallenge {
				slog.Error("invalid code_verifier", "verifier", codeVerifier, "expected", authData.CodeChallenge)
				http.Error(w, "invalid code_verifier", http.StatusBadRequest)
				return
			}
		default:
			slog.Error("unsupported code_challenge_method", "method", authData.CodeChallengeMethod)
			http.Error(w, "unsupported code_challenge_method", http.StatusBadRequest)
			return
		}
	}

	if err := f.store.DeleteAuthCode(code); err != nil {
		slog.Error("failed to delete auth code", "err", err)
		http.Error(w, "failed to delete auth code", http.StatusInternalServerError)
		return
	}
	// TODO: Validate the client ID and client secret.
	accessToken, _, _ := f.store.LoadAccessToken(code)
	w.Header().Set("Content-Type", "application/json")
	resp := TokenResponse{
		AccessToken: accessToken["token"].(string), // TODO
		TokenType:   "bearer",
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("failed to write token response", "err", err)
		// http status is already sent
	}
}
