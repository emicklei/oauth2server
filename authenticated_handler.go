package oauth2server

import (
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/url"
)

// AuthenticatedHandler is called from the Identity Provider after authenticating the user.
func (f *Flow) AuthenticatedHandler(w http.ResponseWriter, r *http.Request) {
	slog.Debug("handling authenticated", "url", r.URL.String())

	// base64 decode the client_query as it is encoded by the AuthorizeHandler
	base64QueryEncoded := r.URL.Query().Get("client_query")
	decodedClientQuery, err := base64.StdEncoding.DecodeString(base64QueryEncoded)
	if err != nil {
		http.Error(w, "failed to decode client_query", http.StatusBadRequest)
		return
	}

	vals, err := url.ParseQuery(string(decodedClientQuery))
	if err != nil {
		http.Error(w, "failed to parse client_query", http.StatusBadRequest)
		return
	}
	slog.Debug("parsed client_query", "vals", vals)
	clientID := vals.Get("client_id")
	redirectUri := vals.Get("redirect_uri")
	if redirectUri == "" {
		slog.Warn("missing redirect_uri", "vals", vals)
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}
	// code and state to the redirect_url

	redirectURL, err := url.Parse(redirectUri)
	if err != nil {
		http.Error(w, "failed to parse redirect_uri", http.StatusBadRequest)
		return
	}

	accessToken, err := f.config.NewAccessTokenFunc(r)
	if err != nil {
		slog.Error("failed to extract access token from request", "err", err)
		http.Error(w, "failed to extract access token from request", http.StatusBadRequest)
		return
	}

	code, err := f.config.NewAuthCodeFunc(r)
	if err != nil {
		slog.Error("failed to create auth code", "err", err)
		http.Error(w, "failed to create auth code", http.StatusInternalServerError)
		return
	}
	codeChallenge := vals.Get("code_challenge")
	if codeChallenge == "" {
		http.Error(w, "missing code_challenge", http.StatusBadRequest)
		return
	}
	codeChallengeMethod := vals.Get("code_challenge_method")
	if codeChallengeMethod != "S256" {
		http.Error(w, "code_challenge_method must be S256", http.StatusBadRequest)
		return
	}
	data := AuthCodeData{
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
	}
	if err := f.store.StoreAuthCode(r.Context(), clientID, code, data); err != nil {
		slog.Error("failed to store auth data", "err", err)
		http.Error(w, "failed to store auth data", http.StatusInternalServerError)
		return
	}

	if err := f.store.StoreAccessToken(r.Context(), clientID, code, accessToken); err != nil {
		slog.Error("failed to store access token", "err", err)
		http.Error(w, "failed to store access token", http.StatusInternalServerError)
		return
	}

	// TODO  only valid for response_type=code
	redirectVals := url.Values{}
	redirectVals.Set("code", code)
	redirectVals.Set("state", vals.Get("state"))
	redirectURL.RawQuery = redirectVals.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)

	slog.Debug("redirected to client", "redirect_uri", redirectURL.String())
}
