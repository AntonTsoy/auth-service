package auth

import (
	"net/http"
	"time"

	"github.com/AntonTsoy/auth-service/internal/email"
	"github.com/AntonTsoy/auth-service/internal/token"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

type AuthHandler struct {
	tokenRepo  *token.TokenRepository
	accessTTL  int
	refreshTTL int
	jwtSecret  string
}

func NewAuthHandler(tokenRepo *token.TokenRepository, accessTTL, refreshTTL int, jwtSecret string) *AuthHandler {
	return &AuthHandler{tokenRepo, accessTTL, refreshTTL, jwtSecret}
}

func (h *AuthHandler) GetUserTokens(c *gin.Context) {
	userIDStr := c.Query("user_id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user identificator"})
		return
	}

	accessID := uuid.New()
	clientIP := c.ClientIP()
	if h.createTokensPair(userID, accessID, clientIP, c) != nil {
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Tokens issued successfully",
	})
}

func (h *AuthHandler) RefreshToken(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh_token missing"})
		return
	}

	clientIP := c.ClientIP()

	tokenData, err := h.tokenRepo.FindToken(refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	if tokenData.IssuedAt.Add(time.Duration(h.refreshTTL) * time.Minute).Before(time.Now()) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "expired refresh token"})
		return
	}
	if tokenData.ClientIP != clientIP {
		go email.SendEmailWarning(clientIP)
	}

	if h.createTokensPair(tokenData.UserID, tokenData.AccessID, clientIP, c) != nil {
		return
	}

	h.tokenRepo.RevokeRefreshToken(tokenData.ID)

	c.JSON(http.StatusOK, gin.H{
		"message": "Tokens refreshed successfully",
	})
}

func (h *AuthHandler) createTokensPair(userID, accessID uuid.UUID, clientIP string, c *gin.Context) (err error) {
	accessToken, err := token.GenerateAccessToken(
		userID, accessID, h.jwtSecret, clientIP, time.Duration(h.accessTTL)*time.Minute,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate access token"})
		return
	}
	refreshToken, err := token.GenerateRefreshToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate refresh token"})
		return
	}
	refreshHash, err := token.HashRefreshToken(refreshToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cannot save refresh token"})
		return
	}

	err = h.tokenRepo.SaveToken(userID, accessID, refreshHash, clientIP)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cannot save refresh token"})
		return
	}

	c.SetCookie("refresh_token", refreshToken, h.refreshTTL*60, "/", "", false, true)
	c.SetCookie("access_token", accessToken, h.accessTTL*60, "/", "", false, true)
	return
}
