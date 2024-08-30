package auth

import (
	"time"
)

type Adapter interface {
	GetUserById(id string) (User, error)
	GetUserByEmail(email string) (User, error)
	GetUserBySessionToken(token string) (User, error)
	CreateUser(user User, account Account) (User, error)
	CreateSession(user User) (Session, error)
}

type Account struct {
	Id                string  `json:"id"`
	UserId            string  `json:"userId" db:"user_id"`
	Type              string  `json:"type"`
	Provider          string  `json:"provider"`
	ProviderAccountId string  `json:"providerAccountId" db:"provider_account_id"`
	RefreshToken      *string `json:"refreshToken" db:"refresh_token"`
	AccessToken       string  `json:"accessToken" db:"access_token"`
	ExpiresAt         int64   `json:"expiresAt" db:"expires_at"`
	IdToken           string  `json:"idToken" db:"id_token"`
	Scope             string  `json:"scope"`
	TokenType         string  `json:"tokenType" db:"token_type"`
	SessionState      *string `json:"sessionState" db:"session_state"`
}

type User struct {
	Id            string  `json:"id"`
	Name          string  `json:"name"`
	Email         string  `json:"email"`
	EmailVerified *string `json:"emailVerified" db:"email_verified"`
	Image         string  `json:"image"`
}

type Session struct {
	SessionToken string    `json:"sessionToken" db:"session_token"`
	UserId       string    `json:"userId" db:"user_id"`
	Expires      time.Time `json:"expires"`
}
