package oauth2server

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
)

func (f *Flow) AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	slog.Debug("handling authorize", "url", r.URL.String())

	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		http.Error(w, "client_id is required", http.StatusBadRequest)
		return
	}
	client, err := f.store.GetClient(clientID)
	if err != nil {
		slog.Warn("failed to get client", "client_id", clientID, "error", err)
		http.Error(w, "invalid client_id (clear DCR cache if applicable)", http.StatusBadRequest)
		return
	}
	redirectURI := r.URL.Query().Get("redirect_uri")
	if redirectURI == "" {
		http.Error(w, "redirect_uri is required", http.StatusBadRequest)
		return
	}
	var found bool
	for _, ruri := range client.RedirectURIs {
		if ruri == redirectURI {
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}

	newURL, err := url.Parse(f.config.LoginEndpoint)
	if err != nil {
		http.Error(w, "failed to parse login url", http.StatusInternalServerError)
		return
	}
	encodedQuery := r.URL.Query().Encode()
	urlEncoded := url.QueryEscape(encodedQuery)
	redirect_uri := fmt.Sprintf(f.config.AuthorizationBaseEndpoint+f.config.AuthenticatedPath+"?client_query=%s", urlEncoded)

	newValues := url.Values{}
	newValues.Set("redirect_uri", redirect_uri)
	newURL.RawQuery = newValues.Encode()

	http.Redirect(w, r, newURL.String(), http.StatusFound)
}
