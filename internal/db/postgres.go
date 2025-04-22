package db

import (
	"database/sql"
	"time"
)

func NewPostgresDB(pgDatabaseURL string) (*sql.DB, error) {
	db, err := sql.Open("postgres", pgDatabaseURL)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(time.Hour)

	if err = db.Ping(); err != nil {
		return nil, err
	}

	query := `
	CREATE TABLE IF NOT EXISTS refresh_tokens (
		id UUID PRIMARY KEY,
		user_id UUID NOT NULL,
		access_id UUID NOT NULL,
		token_hash TEXT NOT NULL,
		client_ip VARCHAR(45) NOT NULL,
		issued_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
		revoked BOOLEAN DEFAULT FALSE
	);
	`
	if _, err := db.Exec(query); err != nil {
		return nil, err
	}

	return db, nil
}
