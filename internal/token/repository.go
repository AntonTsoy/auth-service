package token

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type TokenRepository struct {
	db *sql.DB
}

func NewTokenRepository(db *sql.DB) *TokenRepository {
	return &TokenRepository{db: db}
}

func (r *TokenRepository) SaveToken(userID, accessID uuid.UUID, hash string, clientIP string) error {
	_, err := r.db.Exec(`
		INSERT INTO refresh_tokens (id, user_id, access_id, token_hash, client_ip, issued_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		uuid.New(), userID, accessID, hash, clientIP, time.Now(),
	)
	return err
}

func (r *TokenRepository) FindToken(token string) (*RefreshToken, error) {
	var rt RefreshToken

	query := "SELECT id, user_id, access_id, token_hash, client_ip, issued_at, revoked FROM refresh_tokens WHERE revoked = false"
	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		err := rows.Scan(&rt.ID, &rt.UserID, &rt.AccessID, &rt.TokenHash, &rt.ClientIP, &rt.IssuedAt, &rt.Revoked)
		if err != nil {
			return nil, err
		}
		if bcrypt.CompareHashAndPassword([]byte(rt.TokenHash), []byte(token)) == nil {
			return &rt, nil
		}
	}

	return nil, fmt.Errorf("invalid or revoked refresh token")
}

func (r *TokenRepository) RevokeRefreshToken(id uuid.UUID) error {
	_, err := r.db.Exec(`UPDATE refresh_tokens SET revoked = true WHERE id = $1`, id)
	return err
}
