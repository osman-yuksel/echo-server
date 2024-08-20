package database

import (
	"context"
	"echo-server/internal/models"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/joho/godotenv/autoload"
	_ "github.com/lib/pq"
)

// Service represents a service that interacts with a database.
type Service interface {
	// Health returns a map of health status information.
	// The keys and values in the map are service-specific.
	Health() map[string]string

	// Close terminates the database connection.
	// It returns an error if the connection cannot be closed.
	Close() error

	// CreateTables creates the necessary tables in the database.
	CreateTables() error

	// CreateUser creates a new user and account in the database.
	CreateUser(profile models.Profile) (models.User, error)

	// CreateSession creates a new session for a user.
	CreateSession(user models.User) (models.Session, error)
}

type service struct {
	db *sqlx.DB
}

var (
	database   = os.Getenv("DB_DATABASE")
	password   = os.Getenv("DB_PASSWORD")
	username   = os.Getenv("DB_USERNAME")
	port       = os.Getenv("DB_PORT")
	host       = os.Getenv("DB_HOST")
	schema     = os.Getenv("DB_SCHEMA")
	dbInstance *service
)

func New() Service {
	// Reuse Connection
	if dbInstance != nil {
		return dbInstance
	}
	connStr := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable&search_path=%s", username, password, host, port, database, schema)
	db, err := sqlx.Connect("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	dbInstance = &service{
		db: db,
	}
	err = dbInstance.CreateTables()
	if err != nil {
		log.Fatal(err)
	}

	return dbInstance
}

// Health checks the health of the database connection by pinging the database.
// It returns a map with keys indicating various health statistics.
func (s *service) Health() map[string]string {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	stats := make(map[string]string)

	// Ping the database
	err := s.db.PingContext(ctx)
	if err != nil {
		stats["status"] = "down"
		stats["error"] = fmt.Sprintf("db down: %v", err)
		log.Fatalf(fmt.Sprintf("db down: %v", err)) // Log the error and terminate the program
		return stats
	}

	// Database is up, add more statistics
	stats["status"] = "up"
	stats["message"] = "It's healthy"

	// Get database stats (like open connections, in use, idle, etc.)
	dbStats := s.db.Stats()
	stats["open_connections"] = strconv.Itoa(dbStats.OpenConnections)
	stats["in_use"] = strconv.Itoa(dbStats.InUse)
	stats["idle"] = strconv.Itoa(dbStats.Idle)
	stats["wait_count"] = strconv.FormatInt(dbStats.WaitCount, 10)
	stats["wait_duration"] = dbStats.WaitDuration.String()
	stats["max_idle_closed"] = strconv.FormatInt(dbStats.MaxIdleClosed, 10)
	stats["max_lifetime_closed"] = strconv.FormatInt(dbStats.MaxLifetimeClosed, 10)

	// Evaluate stats to provide a health message
	if dbStats.OpenConnections > 40 { // Assuming 50 is the max for this example
		stats["message"] = "The database is experiencing heavy load."
	}

	if dbStats.WaitCount > 1000 {
		stats["message"] = "The database has a high number of wait events, indicating potential bottlenecks."
	}

	if dbStats.MaxIdleClosed > int64(dbStats.OpenConnections)/2 {
		stats["message"] = "Many idle connections are being closed, consider revising the connection pool settings."
	}

	if dbStats.MaxLifetimeClosed > int64(dbStats.OpenConnections)/2 {
		stats["message"] = "Many connections are being closed due to max lifetime, consider increasing max lifetime or revising the connection usage pattern."
	}

	return stats
}

// Close closes the database connection.
// It logs a message indicating the disconnection from the specific database.
// If the connection is successfully closed, it returns nil.
// If an error occurs while closing the connection, it returns the error.
func (s *service) Close() error {
	log.Printf("Disconnected from database: %s", database)
	return s.db.Close()
}

var authSchema = `
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS users (
	id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
	name VARCHAR(255) NOT NULL,
	email VARCHAR(255) NOT NULL,
	email_verified BOOLEAN NOT NULL,
	image TEXT
);

CREATE TABLE IF NOT EXISTS accounts (
	id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
	user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	type VARCHAR(255) NOT NULL,
	provider VARCHAR(255) NOT NULL,
	provider_account_id VARCHAR(255) NOT NULL,
	refresh_token TEXT,
	access_token TEXT,
	expires_at BIGINT,
	id_token TEXT,
	scope TEXT,
	token_type TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
	id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
	user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	expires TIMESTAMP NOT NULL,
	session_token TEXT NOT NULL
);`

func (s *service) CreateTables() error {
	_, err := s.db.Exec(authSchema)
	return err
}

func (s *service) CreateUser(profile models.Profile) (models.User, error) {
	userId := uuid.New()
	log.Printf("Generated UUID: %s", userId.String())

	tx, err := s.db.Beginx()
	if err != nil {
		log.Printf("Error starting transaction: %v", err)
		return models.User{}, err
	}

	_, err = tx.Exec("INSERT INTO users (id, name, email, email_verified, image) VALUES ($1, $2, $3, $4, $5)", profile.Id, profile.Name, profile.Email, profile.EmailVerified, profile.Picture)
	if err != nil {
		log.Printf("Error inserting into users: %v", err)
		tx.Rollback()
		return models.User{}, err
	}

	// _, err = tx.Exec("INSERT INTO accounts (user_id, type, provider, provider_account_id, refresh_token, access_token, expires_at, id_token, scope, token_type) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)", userId.String(), profile.Type, profile.Provider, profile.ProviderAccountId, profile.RefreshToken, profile.AccessToken, profile.ExpiresAt, idToken.IdToken, profile.Scope, profile.TokenType)
	// if err != nil {
	// 	log.Printf("Error inserting into accounts: %v", err)
	// 	tx.Rollback()
	// 	return User{}, err
	// }

	err = tx.Commit()
	if err != nil {
		log.Printf("Error committing transaction: %v", err)
		return models.User{}, err
	}

	log.Println("User created successfully")
	var u models.User
	err = s.db.Get(&u, "SELECT * FROM users WHERE id = $1", userId.String())

	if err != nil {
		log.Printf("Error getting user: %v", err)
		return models.User{}, err
	}

	return u, nil
}

func (s *service) CreateSession(user models.User) (models.Session, error) {

	expires := time.Now().Add(5 * time.Minute)
	rows, err := s.db.NamedQuery("INSERT INTO sessions (user_id, expires, session_token) VALUES (:user_id, :expires, :session_token) RETURNING id", map[string]interface{}{
		"user_id":       user.Id,
		"expires":       expires.Unix(),
		"session_token": "sessionToken",
	})

	if err != nil {
		log.Printf("Error inserting into sessions: %v", err)
		return models.Session{}, err
	}

	var sessionId string
	if rows.Next() {
		rows.Scan(&sessionId)
	}

	log.Println("Session created successfully")
	return models.Session{
		Id:           sessionId,
		UserId:       user.Id,
		Expires:      expires,
		SessionToken: "sessionToken",
	}, nil
}
