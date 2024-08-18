package auth

import (
	"echo-server/internal/database"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
)

type Service struct {
	providers *Providers
	db        *database.Service
}

func New(db *database.Service, providers ...Provider) Service {
	var providerMap = make(Providers)

	for _, p := range providers {
		providerMap[p.GetId()] = p
	}

	return Service{
		providers: &providerMap,
		db:        db,
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

	account, user, err := provider.HandleCallback(c.Request().URL)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	user, err = (*s.db).CreateUser(account, user)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	// five minutes
	exp := time.Now().Add(5 * time.Minute)
	session, err := (*s.db).CreateSession(user.Id, exp, "sessionToken")

	if err != nil || session.Id == "" {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "session not created",
		})
	}

	c.Response().Header().Set("Set-Cookie", "session="+session.Id+"; Path=/; HttpOnly; Secure; SameSite=Strict")
	return c.JSON(http.StatusOK, account)
}
