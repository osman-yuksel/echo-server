package adapters

import (
	"echo-server/internal/auth"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type Memory struct{}

var users = []auth.User{}
var accounts = []auth.Account{}
var sessions = []auth.Session{}

func (a Memory) New() auth.Adapter {
	return Memory{}
}

func (s Memory) GetUserById(id string) (auth.User, error) {
	for _, u := range users {
		if u.Id == id {
			return u, nil
		}
	}

	return auth.User{}, fmt.Errorf("user not found")
}

func (s Memory) GetUserByEmail(email string) (auth.User, error) {
	for _, u := range users {
		if u.Email == email {
			return u, nil
		}
	}

	return auth.User{}, fmt.Errorf("user not found")
}

func (s Memory) GetUserBySessionToken(token string) (auth.User, error) {
	for _, s := range sessions {
		if s.SessionToken == token {
			for _, u := range users {
				if u.Id == s.UserId {
					return u, nil
				}
			}
			break
		}
	}

	return auth.User{}, fmt.Errorf("user not found")
}

func (s Memory) CreateUser(u auth.User, a auth.Account) (auth.User, error) {
	for _, acc := range accounts {
		if acc.ProviderAccountId == a.ProviderAccountId {
			for _, user := range users {
				if user.Id == acc.UserId {
					return user, nil
				} else {
					return auth.User{}, fmt.Errorf("user not found")
				}
			}
			break
		}
	}

	userId := uuid.New()
	newUser := auth.User{
		Id:            userId.String(),
		Name:          u.Name,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Image:         u.Image,
	}
	users = append(users, newUser)

	accountId := uuid.New()
	accounts = append(accounts, auth.Account{
		Id:                accountId.String(),
		UserId:            userId.String(),
		Type:              a.Type,
		Provider:          a.Provider,
		ProviderAccountId: a.ProviderAccountId,
		RefreshToken:      a.RefreshToken,
		AccessToken:       a.AccessToken,
		ExpiresAt:         a.ExpiresAt,
		IdToken:           a.IdToken,
		Scope:             a.Scope,
		TokenType:         a.TokenType,
		SessionState:      a.SessionState,
	})

	return newUser, nil
}

func (s Memory) CreateSession(user auth.User) (auth.Session, error) {
	sessionToken := uuid.New()
	newSession := auth.Session{
		SessionToken: sessionToken.String(),
		UserId:       user.Id,
		Expires:      time.Now().Add(5 * time.Minute),
	}
	sessions = append(sessions, newSession)
	fmt.Println(sessions)

	return newSession, nil
}
