package oauth2server

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

func (f *Flow) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		slog.Error("Method not allowed", "method", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.ParseForm()
	// TODO Validate the registration request

	clientID, clientSecret := f.config.NewClientCredentialsFunc()
	if err := f.store.RegisterClient(clientID, clientSecret); err != nil {
		slog.Error("failed to register client", "err", err)
		http.Error(w, "failed to register client", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	resp := RegisterResponse{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("failed to write register response", "err", err)
		// http status is already sent
	}
}
