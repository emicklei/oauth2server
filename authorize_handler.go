package oauth2server

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
)

func (f *Flow) AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	slog.Debug("handling authorize", "url", r.URL.String())

	// TODO. validate the client_id, redirect_uri, etc.
	// and prompt the user for consent.
	// For this example, we'll just redirect.

	newURL, err := url.Parse(f.config.LoginEndpoint)
	if err != nil {
		http.Error(w, "failed to parse login url", http.StatusInternalServerError)
		return
	}
	redirect_uri := fmt.Sprintf(f.config.AuthorizationBaseEndpoint+f.config.AuthenticatedPath+"?client_query=%s", newURL.Query().Encode())

	newValues := url.Values{}
	newValues.Set("redirect_uri", redirect_uri)
	newURL.RawQuery = newValues.Encode()

	http.Redirect(w, r, newURL.String(), http.StatusFound)
}
