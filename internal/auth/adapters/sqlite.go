package adapters

import (
	"database/sql"
	"echo-server/internal/auth"
	"fmt"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
)

type SQLite_internal struct {
	db *sql.DB
}

func SQLite(dbPath string) SQLite_internal {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		panic(err)
	}

	// Create necessary tables if they don't exist
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			name TEXT,
			email TEXT,
			email_verified INTEGER,
			image TEXT
		);
		CREATE TABLE IF NOT EXISTS accounts (
			id TEXT PRIMARY KEY,
			user_id TEXT,
			type TEXT,
			provider TEXT,
			provider_account_id TEXT,
			refresh_token TEXT,
			access_token TEXT,
			expires_at INTEGER,
			id_token TEXT,
			scope TEXT,
			token_type TEXT
		);
		CREATE TABLE IF NOT EXISTS sessions (
			session_token TEXT PRIMARY KEY,
			user_id TEXT,
			expires INTEGER
		);
	`)
	if err != nil {
		panic(err)
	}

	return SQLite_internal{db: db}
}

func (a SQLite_internal) GetUserById(id string) (auth.User, error) {
	var user auth.User
	err := a.db.QueryRow("SELECT id, name, email, email_verified, image FROM users WHERE id = ?", id).Scan(
		&user.Id, &user.Name, &user.Email, &user.EmailVerified, &user.Image,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return auth.User{}, fmt.Errorf("user not found")
		}
		return auth.User{}, err
	}
	return user, nil
}

func (a SQLite_internal) GetUserByEmail(email string) (auth.User, error) {
	var user auth.User
	err := a.db.QueryRow("SELECT id, name, email, email_verified, image FROM users WHERE email = ?", email).Scan(
		&user.Id, &user.Name, &user.Email, &user.EmailVerified, &user.Image,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return auth.User{}, fmt.Errorf("user not found")
		}
		return auth.User{}, err
	}
	return user, nil
}

func (a SQLite_internal) GetUserBySessionToken(token string) (auth.User, error) {
	var userId string
	err := a.db.QueryRow("SELECT user_id FROM sessions WHERE session_token = ?", token).Scan(&userId)
	if err != nil {
		if err == sql.ErrNoRows {
			return auth.User{}, fmt.Errorf("session not found")
		}
		return auth.User{}, err
	}

	return a.GetUserById(userId)
}

func (a SQLite_internal) CreateUser(u auth.User, acc auth.Account) (auth.User, error) {
	// Check if account already exists
	var existingUserId string
	err := a.db.QueryRow("SELECT user_id FROM accounts WHERE provider_account_id = ? AND provider = ?", acc.ProviderAccountId, acc.Provider).Scan(&existingUserId)
	if err == nil {
		return a.GetUserById(existingUserId)
	} else if err != sql.ErrNoRows {
		return auth.User{}, err
	}

	userId := uuid.New().String()
	_, err = a.db.Exec("INSERT INTO users (id, name, email, email_verified, image) VALUES (?, ?, ?, ?, ?)",
		userId, u.Name, u.Email, u.EmailVerified, u.Image)
	if err != nil {
		return auth.User{}, err
	}

	accountId := uuid.New().String()
	_, err = a.db.Exec(`INSERT INTO accounts 
		(id, user_id, type, provider, provider_account_id, refresh_token, access_token, expires_at, id_token, scope, token_type) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		accountId, userId, acc.Type, acc.Provider, acc.ProviderAccountId, acc.RefreshToken, acc.AccessToken, acc.ExpiresAt, acc.IdToken, acc.Scope, acc.TokenType)
	if err != nil {
		return auth.User{}, err
	}

	newUser := auth.User{
		Id:            userId,
		Name:          u.Name,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Image:         u.Image,
	}

	return newUser, nil
}

func (a SQLite_internal) CreateSession(user auth.User) (auth.Session, error) {
	sessionToken := uuid.New().String()
	expiresAt := time.Now().Add(5 * time.Minute).Unix()

	_, err := a.db.Exec("INSERT INTO sessions (session_token, user_id, expires) VALUES (?, ?, ?)",
		sessionToken, user.Id, expiresAt)
	if err != nil {
		return auth.Session{}, err
	}

	newSession := auth.Session{
		SessionToken: sessionToken,
		UserId:       user.Id,
		Expires:      time.Unix(expiresAt, 0),
	}

	return newSession, nil
}
