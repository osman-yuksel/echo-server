package auth

import (
	"echo-server/internal/models"
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
	GetRedirectURI(baseUrl string) string
	HandleCallback(url *url.URL) (models.Profile, error)
}

type Providers map[string]Provider
