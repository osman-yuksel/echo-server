package auth

import (
	"echo-server/internal/database"
	"net/url"
)

type ProviderData struct {
	Id     string `json:"id"`
	Name   string `json:"name"`
	Issuer string `json:"issuer"`
	Type   string `json:"type"`
	Image  string `json:"image"`
}

type Provider interface {
	GetId() string
	GetPublicData() ProviderData
	GetRedirectURL() string
	HandleCallback(url *url.URL) (database.Account, database.User, error)
}

type Providers map[string]Provider
