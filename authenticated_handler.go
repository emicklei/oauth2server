package oauth2server

import (
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/url"
)

func (f *Flow) AuthenticatedHandler(w http.ResponseWriter, r *http.Request) {
	vals := r.URL.Query()
	slog.Debug("HandleAuthenticated", "query", vals)

	base64QueryEncoded := vals.Get("client_query")
	decodedUri, err := base64.StdEncoding.DecodeString(base64QueryEncoded)
	if err != nil {
		http.Error(w, "failed to decode client_query", http.StatusBadRequest)
		return
	}
	slog.Debug("HandleAuthenticated:decoded client_query", "decoded", string(decodedUri))
	vals, err = url.ParseQuery(string(decodedUri))
	if err != nil {
		http.Error(w, "failed to parse client_query", http.StatusBadRequest)
		return
	}
	slog.Debug("HandleAuthenticated:parsed client_query", "vals", vals)
	redirectUri := vals.Get("redirect_uri")
	if redirectUri == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}
	// code and state to the redirect_url

	redirectURL, err := url.Parse(redirectUri)
	if err != nil {
		http.Error(w, "failed to parse redirect_uri", http.StatusBadRequest)
		return
	}

	accessToken, err := f.config.AccessTokenFromRequestFunc(r)
	if err != nil {
		slog.Error("failed to extract access token from request", "err", err)
		http.Error(w, "failed to extract access token from request", http.StatusBadRequest)
		return
	}

	code := f.config.NewAuthCodeFunc()
	f.store.StoreAccessToken(code, accessToken)

	// TODO  only valid for response_type=code
	redirectVals := url.Values{}
	redirectVals.Set("code", code)
	redirectVals.Set("state", vals.Get("state"))
	redirectURL.RawQuery = redirectVals.Encode()

	slog.Info("HandleAuthenticated:redirecting to client", "redirect_uri", redirectURL.String())
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}
