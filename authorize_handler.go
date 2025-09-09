package oauth2server

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"path"
)

func (f *Flow) AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	// TODO. validate the client_id, redirect_uri, etc.
	// and prompt the user for consent.
	// For this example, we'll just redirect.

	newURL, err := url.Parse(f.config.LoginEndpoint)
	if err != nil {
		http.Error(w, "failed to parse auth url", http.StatusInternalServerError)
		return
	}
	// base64 encocde the original query string is not really necessary but makes it
	// easier to see where the query string starts and ends.
	// Also avoids issues with & and ? characters in the original query.
	// The authenticated handler will decode and parse it again.
	base64QueryEncoded := base64.StdEncoding.EncodeToString([]byte(r.URL.Query().Encode()))
	redirect_uri := fmt.Sprintf(path.Join(f.config.AuthorizationBaseEndpoint, f.config.AuthenticatedPath, "?client_query=%s"), base64QueryEncoded)

	newVales := url.Values{}
	newVales.Set("redirect_uri", redirect_uri)
	newURL.RawQuery = newVales.Encode()

	http.Redirect(w, r, newURL.String(), http.StatusFound)

	slog.Debug("Redirecting to auth url", "url", newURL.String(), "redirect_uri", redirect_uri)
}
