package oauth2server

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

func (f *Flow) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	slog.Debug("handling register", "url", r.URL.String())

	if r.Method != http.MethodPost {
		slog.Error("Method not allowed", "method", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req RegistrationRequest

	// if payload is sent as JSON, parse it
	if r.Header.Get("Content-Type") == "application/json" {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			slog.Warn("failed to JSON decode registration request", "err", err)
			http.Error(w, "invalid registration request", http.StatusBadRequest)
			return
		}
	}
	// if payload is sent as form data, parse it
	if r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
		if err := r.ParseForm(); err == nil {
			req.ClientName = r.Form.Get("client_name")
			req.RedirectURIs = r.Form["redirect_uris"]
			req.GrantTypes = r.Form["grant_types"]
		} else {
			slog.Warn("failed to parse form data", "err", err)
			http.Error(w, "invalid registration request", http.StatusBadRequest)
			return
		}
	}

	// basic validation
	if req.ClientName == "" || len(req.RedirectURIs) == 0 {
		slog.Debug("client_name and redirect_uris are required", "client_name", req.ClientName, "redirect_uris", req.RedirectURIs)
		http.Error(w, "client_name and redirect_uris are required", http.StatusBadRequest)
		return
	}

	client := Client{
		ID:           randSeq(32),
		Secret:       f.config.NewClientSecretFunc(r),
		RedirectURIs: req.RedirectURIs,
	}
	if err := f.store.RegisterClient(client); err != nil {
		slog.Error("failed to register client", "err", err)
		http.Error(w, "failed to register client", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	resp := RegisterResponse{
		ClientID:     client.ID,
		ClientSecret: client.Secret,
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("failed to write register response", "err", err)
		// http status is already sent
	}
	slog.Debug("registered new client", "client_id", client.ID, "client_name", req.ClientName, "redirect_uris", req.RedirectURIs)
}
