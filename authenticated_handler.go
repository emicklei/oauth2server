package oauth2server

import (
	"log/slog"
	"net/http"
	"net/url"
)

// AuthenticatedHandler is called from the Identity Provider after authenticating the user.
func (f *Flow) AuthenticatedHandler(w http.ResponseWriter, r *http.Request) {
	slog.Debug("handling authenticated", "url", r.URL.String())

	vals := r.URL.Query()
	slog.Debug("AuthenticatedHandler", "query", vals)

	clientQuery := vals.Get("client_query")
	vals, err := url.ParseQuery(clientQuery)
	if err != nil {
		http.Error(w, "failed to parse client_query", http.StatusBadRequest)
		return
	}
	slog.Debug("parsed client_query", "vals", vals)
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

	accessToken, err := f.config.NewAccessTokenFunc(r)
	if err != nil {
		slog.Error("failed to extract access token from request", "err", err)
		http.Error(w, "failed to extract access token from request", http.StatusBadRequest)
		return
	}

	code := f.config.NewAuthCodeFunc(r)
	f.store.StoreAccessToken(code, accessToken)

	// TODO  only valid for response_type=code
	redirectVals := url.Values{}
	redirectVals.Set("code", code)
	redirectVals.Set("state", vals.Get("state"))
	redirectURL.RawQuery = redirectVals.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)

	slog.Debug("redirecting to client", "redirect_uri", redirectURL.String())
}
