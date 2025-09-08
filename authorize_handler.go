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
	// In a real implementation, you would validate the client_id, redirect_uri, etc.
	// and prompt the user for consent.
	// For this example, we'll just redirect.

	newURL, err := url.Parse(f.config.LoginEndpoint)
	if err != nil {
		http.Error(w, "failed to parse auth url", http.StatusInternalServerError)
		return
	}
	// pass on new redirect_uri to come back to beacon
	// redirect_uri=https://mcp.requirehub.app/authenticed?<query or this request>

	// the base64 may not have been needed

	base64QueryEncoded := base64.StdEncoding.EncodeToString([]byte(r.URL.Query().Encode()))
	redirect_uri := fmt.Sprintf(path.Join(f.config.AuthorizationBaseEndpoint, f.config.AuthenticatedPath, "?client_query=%s"), base64QueryEncoded)

	newVales := url.Values{}
	newVales.Set("redirect_uri", redirect_uri)
	newURL.RawQuery = newVales.Encode()

	slog.Debug("HandleAuthorize:redirecting to auth url", "url", newURL.String(), "redirect_uri", redirect_uri)
	http.Redirect(w, r, newURL.String(), http.StatusFound)
}
