package oauth2server

import (
	"log/slog"
	"net/http"
	"strings"
)

func (f *Flow) ProtectedHandler(w http.ResponseWriter, r *http.Request) {
	h := f.config.ResourceHandlerFunc
	if h == nil {
		slog.Warn("No resource handler configured")
		return
	}
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		slog.Error("Unauthorized: missing Authorization header")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	// The header should be in the format "Bearer <token>"
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		slog.Error("Invalid authorization header", "header", authHeader)
		http.Error(w, "Invalid authorization header", http.StatusBadRequest)
		return
	}
	accessToken := parts[1]
	data, ok, err := f.store.VerifyAccessToken(accessToken)
	if err != nil {
		slog.Error("Error verifying access token", "err", err)
		http.Error(w, "Error verifying access token", http.StatusInternalServerError)
		return
	}
	if !ok {
		slog.Error("Invalid access token", "token", accessToken)
		http.Error(w, "Invalid access token", http.StatusUnauthorized)
		return
	}
	r = r.WithContext(ContextWithAccessTokenData(r.Context(), data))
	h(w, r)
}
