package adapters

import (
	"echo-server/internal/database"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

type Postgres struct {
	db *sqlx.DB
}

var users = []User{}
var accounts = []Account{}
var sessions = []Session{}

func (a Postgres) New() Adapter {
	db := database.New().GetDB()
	return Postgres{db: db}
}

func (s Postgres) GetUserById(id string) (User, error) {
	for _, u := range users {
		if u.Id == id {
			return u, nil
		}
	}

	return User{}, fmt.Errorf("user not found")
}

func (s Postgres) GetUserByEmail(email string) (User, error) {
	for _, u := range users {
		if u.Email == email {
			return u, nil
		}
	}

	return User{}, fmt.Errorf("user not found")
}

func (s Postgres) GetUserBySessionToken(token string) (User, error) {
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

	return User{}, fmt.Errorf("user not found")
}

func (s Postgres) CreateUser(u User, a Account) (User, error) {
	for _, acc := range accounts {
		if acc.ProviderAccountId == a.ProviderAccountId {
			for _, user := range users {
				if user.Id == acc.UserId {
					return user, nil
				} else {
					return User{}, fmt.Errorf("user not found")
				}
			}
			break
		}
	}

	userId := uuid.New()
	newUser := User{
		Id:            userId.String(),
		Name:          u.Name,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Image:         u.Image,
	}
	users = append(users, newUser)

	accountId := uuid.New()
	accounts = append(accounts, Account{
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

func (s Postgres) CreateSession(user User) (Session, error) {
	sessionToken := uuid.New()
	newSession := Session{
		SessionToken: sessionToken.String(),
		UserId:       user.Id,
		Expires:      time.Now().Add(5 * time.Minute),
	}
	sessions = append(sessions, newSession)
	fmt.Println(sessions)

	return newSession, nil
}
