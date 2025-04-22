package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var JWTSecret []byte = []byte("Надо это вынести в конфиг")

func sendEmailWarning(newIPAddress string) {
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

	accessToken, err := generateAccessToken(userGUID, uuid.New(), c.ClientIP(), 5*time.Minute)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate access token"})
		return
	}
	refreshToken, err := generateRefreshToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate refresh token"})
		return
	}

	c.SetCookie("access_token", accessToken, 5*60, "/", "", true, true)
	c.SetCookie("refresh_token", refreshToken, 20*60, "/", "", true, true)

	c.JSON(http.StatusOK, gin.H{
		"message": "Tokens issued successfully",
	})
}

func main() {
	router := gin.Default()
	router.GET("/tokens", getUserTokens)
	router.Run()
}
