package adapters

import (
	"echo-server/internal/auth"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type Memory_internal struct{}

var users = []auth.User{}
var accounts = []auth.Account{}
var sessions = []auth.Session{}

func Memory() Memory_internal {
	return Memory_internal{}
}

func (a Memory_internal) GetUserById(id string) (auth.User, error) {
	for _, u := range users {
		if u.Id == id {
			return u, nil
		}
	}

	return auth.User{}, fmt.Errorf("user not found")
}

func (a Memory_internal) GetUserByEmail(email string) (auth.User, error) {
	for _, u := range users {
		if u.Email == email {
			return u, nil
		}
	}

	return auth.User{}, fmt.Errorf("user not found")
}

func (a Memory_internal) GetUserBySessionToken(token string) (auth.User, error) {
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

func (a Memory_internal) CreateUser(u auth.User, acc auth.Account) (auth.User, error) {
	for _, account := range accounts {
		if account.ProviderAccountId == acc.ProviderAccountId {
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
		Type:              acc.Type,
		Provider:          acc.Provider,
		ProviderAccountId: acc.ProviderAccountId,
		RefreshToken:      acc.RefreshToken,
		AccessToken:       acc.AccessToken,
		ExpiresAt:         acc.ExpiresAt,
		IdToken:           acc.IdToken,
		Scope:             acc.Scope,
		TokenType:         acc.TokenType,
	})

	return newUser, nil
}

func (a Memory_internal) CreateSession(user auth.User) (auth.Session, error) {
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
