package server

import (
	"echo-server/internal/auth"
	"echo-server/internal/auth/adapters"
	"echo-server/internal/auth/providers"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

var authService = auth.New(auth.AuthServiceOptions{
	Providers: []auth.Provider{
		providers.Google(),
	},
	Adapter: adapters.SQLite("auth.db"),
})

func (s *Server) RegisterRoutes() http.Handler {
	e := echo.New()
	e.Use(middleware.Logger())
	// e.Use(middleware.Recover())

	e.GET("/", s.HelloWorldHandler)
	e.GET("/health", s.healthHandler)

	authGroup := e.Group("/auth")
	authGroup.GET("/providers", authService.Providers)
	authGroup.GET("/login/:provider", authService.Login)
	authGroup.GET("/callback/:provider", authService.Callback)
	authGroup.GET("/session", authService.Session)

	return e
}

func (s *Server) HelloWorldHandler(c echo.Context) error {
	resp := map[string]string{
		"message": "Hello World",
	}

	return c.JSON(http.StatusOK, resp)
}

func (s *Server) healthHandler(c echo.Context) error {
	return c.JSON(http.StatusOK, s.db.Health())
}
