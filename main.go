package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

func initDB() (*sql.DB, error) {
	connStr := "host=db port=5432 user=service password=password1234 dbname=auth sslmode=disable"

	db, err := sql.Open("postgres", connStr)
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

type RefreshToken struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	AccessID  uuid.UUID
	TokenHash string
	ClientIP  string
	IssuedAt  time.Time
	Revoked   bool
}

func sendEmailWarning(newIPAddress string) {
	time.Sleep(5 * time.Second)
	fmt.Printf("Email notification! Warning: IP address changed to %s.\n", newIPAddress)
}

func generateAccessToken(userID uuid.UUID, accessID uuid.UUID, clientIP string, ttl time.Duration) (string, error) {
	claims := jwt.MapClaims{
		"user_id":   userID.String(),
		"access_id": accessID.String(),
		"client_ip": clientIP,
		"exp":       time.Now().Add(ttl).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString([]byte(os.Getenv("JWT_SECRET")))
}

func generateRefreshToken() (string, error) {
	rawToken := make([]byte, 32)
	if _, err := rand.Read(rawToken); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(rawToken), nil
}

func hashRefreshToken(refreshToken string) (string, error) {
	hashedToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedToken), nil
}

func validateRefreshToken(storedHash, refreshToken string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(refreshToken))
	return err == nil
}

type AuthHandler struct {
	tokenRepo *TokenRepository
}

func NewAuthHandler(tokenRepo *TokenRepository) *AuthHandler {
	return &AuthHandler{tokenRepo: tokenRepo}
}

func (h *AuthHandler) GetUserTokens(c *gin.Context) {
	userIDStr := c.Query("user_id")
	userGUID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user identificator"})
		return
	}

	accessID := uuid.New()
	clientIP := c.ClientIP()
	accessTokenTTL, _ := strconv.Atoi(os.Getenv("ACCESS_TOKEN_MINUTES_TTL"))
	accessToken, err := generateAccessToken(
		userGUID, accessID, clientIP, time.Duration(accessTokenTTL)*time.Minute,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate access token"})
		fmt.Println(accessTokenTTL)
		fmt.Println(err)
		return
	}
	refreshToken, err := generateRefreshToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate refresh token"})
		return
	}
	refreshHash, err := hashRefreshToken(refreshToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cannot save refresh token"})
		return
	}

	err = h.tokenRepo.SaveToken(userGUID, accessID, refreshHash, clientIP)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cannot save refresh token"})
		return
	}

	refreshTokenTTL, _ := strconv.Atoi(os.Getenv("REFRESH_TOKEN_MINUTES_TTL"))
	c.SetCookie("refresh_token", refreshToken, refreshTokenTTL*60, "/", "", false, true)
	c.SetCookie("access_token", accessToken, accessTokenTTL*60, "/", "", false, true)

	c.JSON(http.StatusOK, gin.H{
		"message": "Tokens issued successfully",
	})
}

func main() {
	if err := godotenv.Load(); err != nil {
		panic(err)
	}

	db, err := initDB()
	if err != nil {
		panic(err)
	}
	defer db.Close()

	tokenRepo := NewTokenRepository(db)
	authHandler := NewAuthHandler(tokenRepo)

	router := gin.Default()
	router.GET("/tokens", authHandler.GetUserTokens)
	router.Run()
}
