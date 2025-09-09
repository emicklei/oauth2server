package oauth2server

import (
	"fmt"
	"log/slog"
)

var _ FlowStateStore = (*InMemoryFlowStore)(nil)

type InMemoryFlowStore struct {
	clients      map[string]string
	authCodes    map[string]AuthCodeData
	accessTokens map[string]string
}

func NewInMemoryFlowStore() *InMemoryFlowStore {
	return &InMemoryFlowStore{
		clients: map[string]string{
			"YOUR_CLIENT_ID": "YOUR_CLIENT_SECRET",
		},
		authCodes:    make(map[string]AuthCodeData),
		accessTokens: make(map[string]string),
	}
}

func (s *InMemoryFlowStore) RegisterClient(clientID, clientSecret string) error {
	s.clients[clientID] = clientSecret
	return nil
}

func (s *InMemoryFlowStore) VerifyClient(clientID, clientSecret string) (bool, error) {
	secret, ok := s.clients[clientID]
	if !ok {
		return false, nil
	}
	return secret == clientSecret, nil
}

func (s *InMemoryFlowStore) StoreAuthCode(code string, data AuthCodeData) error {
	s.authCodes[code] = data
	return nil
}

func (s *InMemoryFlowStore) VerifyAuthCode(code string) (AuthCodeData, bool, error) {
	data, ok := s.authCodes[code]
	return data, ok, nil
}

func (s *InMemoryFlowStore) DeleteAuthCode(code string) error {
	delete(s.authCodes, code)
	return nil
}

func (s *InMemoryFlowStore) StoreAccessToken(code, token string) error {
	slog.Debug("store access token", "code", code, "token", token)
	s.accessTokens[code] = token
	return nil
}

func (s *InMemoryFlowStore) LoadAccessToken(code string) (string, error) {
	token, ok := s.accessTokens[code]
	if !ok {
		return "", fmt.Errorf("access token not found, code:%s", code)
	}
	return token, nil
}

func (s *InMemoryFlowStore) VerifyAccessToken(token string) (bool, error) {
	return true, nil
}

func (s *InMemoryFlowStore) NewAccessToken() (string, error) {
	return fmt.Sprintf("access-token-%d", len(s.accessTokens)+1), nil
}
