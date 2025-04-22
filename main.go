package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

// TODO: НЕ ЗАБУДЬ ВЫНЕСТИ В КОНФИГ!!!
var (
	JWTSecret                 = []byte("c9029183bc75a4ad92bf44e5e7cd03adf071615708ffef5904615e6a82b2826e15c06ed084cbbdf6833663ed7f3c68f7854948a39d850612c3d9c25061c8bfb9a918134d8f30109fe68c9104a89eefcf76582e91ff9dd6fc75458f944aab91ae81c0667e953702b768fae1b4036059729dae906343e0d7ecba173d942cd55552aeeaa34c566e1716a7c7c9338fbde787e8de0fb74755a5e3507cb9ad703864351e1ccb0bd5a183a1d23990f94d2411586315a72d444ce86920916d4136a70318164ef3c557f7037f517b30f3a7e9ec9885814edc380acc25382752af1b3f5234e973e03c61ae26d39d2bd72c486bcdde3fe647cc58fbc81e1f610b3b6286e94e")
	access_token_minutes_ttl  = 5
	refresh_token_minutes_ttl = 20
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

	return db, nil
}

type TokenRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *TokenRepository {
	return &TokenRepository{db: db}
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
	return token.SignedString(JWTSecret)
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

func getUserTokens(c *gin.Context) {
	userIDStr := c.Query("user_id")
	userGUID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user identificator"})
		return
	}

	accessToken, err := generateAccessToken(
		userGUID, uuid.New(), c.ClientIP(), time.Duration(access_token_minutes_ttl)*time.Minute,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate access token"})
		return
	}
	refreshToken, err := generateRefreshToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate refresh token"})
		return
	}

	c.SetCookie("access_token", accessToken, access_token_minutes_ttl*60, "/", "", false, true)
	c.SetCookie("refresh_token", refreshToken, refresh_token_minutes_ttl*60, "/", "", false, true)

	c.JSON(http.StatusOK, gin.H{
		"message": "Tokens issued successfully",
	})
}

func main() {
	db, err := initDB()
	if err != nil {
		panic(err)
	}
	defer db.Close()

	router := gin.Default()
	router.GET("/tokens", getUserTokens)
	router.Run()
}
