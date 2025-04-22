package token

import (
	"time"

	"github.com/google/uuid"
)

type RefreshToken struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	AccessID  uuid.UUID
	TokenHash string
	ClientIP  string
	IssuedAt  time.Time
	Revoked   bool
}
