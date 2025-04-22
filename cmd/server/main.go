package main

import (
	"github.com/AntonTsoy/auth-service/internal/auth"
	"github.com/AntonTsoy/auth-service/internal/db"
	"github.com/AntonTsoy/auth-service/internal/token"
	"github.com/AntonTsoy/auth-service/pkg/config"

	"github.com/gin-gonic/gin"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		panic(err)
	}

	db, err := db.NewPostgresDB(cfg.DatabaseURL)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	tokenRepo := token.NewTokenRepository(db)
	authHandler := auth.NewAuthHandler(tokenRepo, cfg.AccessTokenTTLMinutes, cfg.RefreshTokenTTLMinutes, cfg.JWTSecret)

	router := gin.Default()
	router.GET("/auth/tokens", authHandler.GetUserTokens)
	router.GET("/auth/refresh", authHandler.RefreshToken)
	router.Run(cfg.ListenAddr)
}
