package oauth2server

import (
	"log/slog"
	"net/http"
	"net/url"
)

func (f *Flow) AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	slog.Debug("handling authorize", "url", r.URL.String())

	// TODO. validate the client_id, redirect_uri, etc.
	// and prompt the user for consent.
	// For this example, we'll just redirect.

	//newURL, err := url.Parse(f.config.LoginEndpoint)
	//if err != nil {
	//	http.Error(w, "failed to parse auth url", http.StatusInternalServerError)
	//	return
	//}
	authCode := f.config.NewAuthCodeFunc(r)
	redirectURI := r.URL.Query().Get("redirect_uri")
	if redirectURI == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}
	// TODO: store the auth code
	ru, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	q := ru.Query()
	q.Set("code", authCode)
	ru.RawQuery = q.Encode()

	if err := f.store.StoreAuthCode(authCode, AuthCodeData{}); err != nil {
		http.Error(w, "failed to store auth code", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, ru.String(), http.StatusFound)
}
