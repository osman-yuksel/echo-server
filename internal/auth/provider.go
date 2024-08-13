package auth

import "net/url"

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
	HandleCallback(url *url.URL) (Account, error)
}

type Providers map[string]Provider

type Account struct {
	Id    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}
