package oauth2server

import (
	"fmt"
	"log/slog"
	"net/http"
)

func (f *Flow) AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	// In a real application, you would redirect to a login and consent page.
	// Here we will show a login page.
	if r.Method == http.MethodPost {
		// "Log in" the user
		r.ParseForm()
		if r.Form.Get("username") == "user" && r.Form.Get("password") == "pass" {
			code := f.config.NewAuthCodeFunc()
			if err := f.store.StoreAuthCode(code, AuthCodeData{
				CodeChallenge:       r.URL.Query().Get("code_challenge"),
				CodeChallengeMethod: r.URL.Query().Get("code_challenge_method"),
			}); err != nil {
				slog.Error("failed to store auth code", "err", err)
				http.Error(w, "failed to store auth code", http.StatusInternalServerError)
				return
			}
			redirectURL := r.URL.Query().Get("redirect_uri")
			state := r.URL.Query().Get("state")
			http.Redirect(w, r, fmt.Sprintf("%s?code=%s&state=%s", redirectURL, code, state), http.StatusFound)
			return
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `
		<h1>Login</h1>
		<form method="post">
			<label for="username">Username:</label>
			<input type="text" id="username" name="username"><br><br>
			<label for="password">Password:</label>
			<input type="password" id="password" name="password"><br><br>
			<input type="submit" value="Login">
		</form>
	`)
}
