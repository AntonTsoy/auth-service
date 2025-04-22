package token

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func GenerateAccessToken(userID uuid.UUID, accessID uuid.UUID, jwtSecret, clientIP string, ttl time.Duration) (string, error) {
	claims := jwt.MapClaims{
		"user_id":   userID.String(),
		"access_id": accessID.String(),
		"client_ip": clientIP,
		"exp":       time.Now().Add(ttl).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString([]byte(jwtSecret))
}

func GenerateRefreshToken() (string, error) {
	rawToken := make([]byte, 32)
	if _, err := rand.Read(rawToken); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(rawToken), nil
}

func HashRefreshToken(refreshToken string) (string, error) {
	hashedToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedToken), nil
}
