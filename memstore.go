package oauth2server

import (
	"fmt"
	"log/slog"
)

var _ FlowStateStore = (*InMemoryFlowStore)(nil)

type InMemoryFlowStore struct {
	clients       map[string]Client
	authCodes     map[string]AuthCodeData
	accessTokens  map[string]string
	refreshTokens map[string]RefreshTokenData
}

func NewInMemoryFlowStore() *InMemoryFlowStore {
	return &InMemoryFlowStore{
		clients: map[string]Client{
			"YOUR_CLIENT_ID": {ID: "YOUR_CLIENT_ID", Secret: "YOUR_CLIENT_SECRET", RedirectURIs: []string{"http://localhost:8080/callback"}},
		},
		authCodes:     make(map[string]AuthCodeData),
		accessTokens:  make(map[string]string),
		refreshTokens: make(map[string]RefreshTokenData),
	}
}

func (s *InMemoryFlowStore) RegisterClient(client Client) error {
	s.clients[client.ID] = client
	return nil
}

func (s *InMemoryFlowStore) GetClient(clientID string) (*Client, error) {
	client, ok := s.clients[clientID]
	if !ok {
		return nil, fmt.Errorf("client not found")
	}
	return &client, nil
}

func (s *InMemoryFlowStore) VerifyClient(clientID, clientSecret string) (bool, error) {
	client, ok := s.clients[clientID]
	if !ok {
		return false, nil
	}
	return client.Secret == clientSecret, nil
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

func (s *InMemoryFlowStore) StoreRefreshToken(token string, data RefreshTokenData) error {
	s.refreshTokens[token] = data
	return nil
}

func (s *InMemoryFlowStore) GetRefreshToken(token string) (*RefreshTokenData, error) {
	data, ok := s.refreshTokens[token]
	if !ok {
		return nil, fmt.Errorf("refresh token not found")
	}
	return &data, nil
}

func (s *InMemoryFlowStore) DeleteRefreshToken(token string) error {
	delete(s.refreshTokens, token)
	return nil
}
