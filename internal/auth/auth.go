package auth

import (
	"echo-server/internal/database"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
)

type Service struct {
	providers *Providers

	db *database.Service
}

type AuthServiceOptions struct {
	Providers []Provider

	Database *database.Service
}

func New(opts AuthServiceOptions) Service {
	var providerMap = make(Providers)

	for _, p := range opts.Providers {
		providerMap[p.GetId()] = p
	}

	return Service{
		providers: &providerMap,
		db:        opts.Database,
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

	callbackUrl := fmt.Sprintf("%s/auth/callback/%s", c.Request().Host, provider.GetId())
	return c.Redirect(http.StatusTemporaryRedirect, provider.GetRedirectURI(callbackUrl))
}

func (s *Service) Callback(c echo.Context) error {
	providerId := c.Param("provider")
	provider, ok := (*s.providers)[providerId]
	if !ok {
		return c.JSON(http.StatusNotFound, map[string]string{
			"error": "provider not found",
		})
	}

	profile, err := provider.HandleCallback(c.Request().URL)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	user, err := (*s.db).CreateUser(profile)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	session, err := (*s.db).CreateSession(user)

	if err != nil || session.Id == "" {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "session not created",
		})
	}

	c.Response().Header().Set("Set-Cookie", "session="+session.Id+"; Path=/; HttpOnly; Secure; SameSite=Strict")
	return c.JSON(http.StatusOK, user)
}
