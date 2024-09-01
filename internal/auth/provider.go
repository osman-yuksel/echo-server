package auth

import "net/http"

type ProviderData struct {
	Id     string `json:"id"`
	Name   string `json:"name"`
	Issuer string `json:"issuer"`
	Type   string `json:"type"`
	Image  string `json:"image"`
}

type Provider interface {
	GetId() string
	GetType() string
	GetPublicData() ProviderData
	GetRedirectURL(base string) string
	HandleCallback(request *http.Request) (Profile, TokenSet, error)
}

type Providers map[string]Provider
