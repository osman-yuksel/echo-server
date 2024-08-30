package auth

import (
	"fmt"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
)

type Service struct {
	providers *Providers
	adapter   *Adapter
}

type AuthServiceOptions struct {
	Providers []Provider
	Adapter   Adapter
}

func New(opts AuthServiceOptions) Service {
	var providerMap = make(Providers)

	for _, p := range opts.Providers {
		providerMap[p.GetId()] = p
	}

	return Service{
		providers: &providerMap,
		adapter:   &opts.Adapter,
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

	callbackUrl := fmt.Sprintf("http://%s/auth/callback/%s", c.Request().Host, provider.GetId())
	return c.Redirect(http.StatusTemporaryRedirect, provider.GetRedirectURL(callbackUrl))
}

func (s *Service) Callback(c echo.Context) error {
	providerId := c.Param("provider")
	provider, ok := (*s.providers)[providerId]

	fail := func(err error) error {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	if !ok {
		return fail(fmt.Errorf("provider not found"))
	}

	profile, tokenSet, err := provider.HandleCallback(c.Request().URL)
	if err != nil {
		return fail(err)
	}

	user := User{
		Name:  profile.Name,
		Email: profile.Email,
		Image: profile.Picture,
	}

	account := Account{
		Type:              provider.GetType(),
		Provider:          provider.GetId(),
		ProviderAccountId: profile.Id,
		RefreshToken:      &tokenSet.RefreshToken,
		AccessToken:       tokenSet.AccessToken,
		ExpiresAt:         int64(tokenSet.ExpiresAt),
		IdToken:           tokenSet.IdToken,
		Scope:             tokenSet.Scope,
		TokenType:         tokenSet.TokenType,
	}

	u, err := (*s.adapter).CreateUser(user, account)
	if err != nil {
		return fail(err)
	}

	session, err := (*s.adapter).CreateSession(u)
	if err != nil || session.SessionToken == "" {
		return fail(err)
	}
	fmt.Println(session)

	c.Response().Header().Set("Set-Cookie", "session="+session.SessionToken+"; Path=/; HttpOnly; Secure; SameSite=Strict"+"; Expires="+session.Expires.Format(time.RFC1123))
	return c.JSON(http.StatusOK, u)
}

func (s *Service) Session(c echo.Context) error {
	cookies := c.Request().Cookies()
	var sessionToken string
	for _, cookie := range cookies {
		if cookie.Name == "session" {
			sessionToken = cookie.Value
		}
	}
	fmt.Println(sessionToken, cookies)
	user, err := (*s.adapter).GetUserBySessionToken(sessionToken)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "invalid session",
		})
	}

	return c.JSON(http.StatusOK, user)
}
