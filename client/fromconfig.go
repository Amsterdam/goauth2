package client

import "errors"

type OAuth20ClientConfig struct {
	Redirects []string `toml:"redirects"`
	Secret    string   `toml:"secret"`
}

type OAuth20ClientMapFromConfig map[string]OAuth20ClientConfig

func (m OAuth20ClientMapFromConfig) Get(id string) (*OAuth20ClientData, error) {
	if data, ok := m[id]; ok {
		return &OAuth20ClientData{id, data.Redirects, data.Secret}, nil
	}
	return nil, errors.New("Client ID not found")
}