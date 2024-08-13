package auth

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

type ServiceOptions struct {
	Providers Providers
}

type Service struct {
	providers *Providers
}

func New(providers ...Provider) Service {
	var providerMap = make(Providers)

	for _, p := range providers {
		providerMap[p.GetId()] = p
	}

	return Service{
		providers: &providerMap,
	}
}

func (s *Service) GetProviders(c echo.Context) error {
	providers := make([]interface{}, 0, len(*s.providers))

	for _, p := range *s.providers {
		data := p.GetPublicData()
		providers = append(providers, data)
	}

	resp := map[string]interface{}{
		"providers": providers,
	}

	return c.JSON(http.StatusOK, resp)
}

func (s *Service) Login(c echo.Context) error {
	providerId := c.Param("provider")
	provider, ok := (*s.providers)[providerId]
	if !ok {
		return c.JSON(http.StatusNotFound, map[string]string{
			"error": "provider not found",
		})
	}

	return c.Redirect(http.StatusTemporaryRedirect, provider.GetRedirectURL())
}

func (s *Service) Callback(c echo.Context) error {
	providerId := c.Param("provider")
	provider, ok := (*s.providers)[providerId]
	if !ok {
		return c.JSON(http.StatusNotFound, map[string]string{
			"error": "provider not found",
		})
	}

	account, err := provider.HandleCallback(c.Request().URL)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, account)
}
