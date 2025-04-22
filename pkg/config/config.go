package config

import (
	"fmt"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	ListenAddr             string
	DatabaseURL            string
	JWTSecret              string
	AccessTokenTTLMinutes  int
	RefreshTokenTTLMinutes int
}

func Load() (*Config, error) {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("No .env file found, falling back to OS environment")
		return nil, err
	}

	accessTTL := getInt("ACCESS_TOKEN_MINUTES_TTL")
	refreshTTL := getInt("REFRESH_TOKEN_MINUTES_TTL")

	return &Config{
		ListenAddr:             getString("LISTEN_ADDR"),
		DatabaseURL:            getString("DATABASE_URL"),
		JWTSecret:              getString("JWT_SECRET"),
		AccessTokenTTLMinutes:  accessTTL,
		RefreshTokenTTLMinutes: refreshTTL,
	}, nil
}

func getString(key string) (value string) {
	value = os.Getenv(key)
	if value == "" {
		fmt.Printf("missing required environment variable: %s\n", key)
	}
	return value
}

func getInt(key string) (value int) {
	valueStr := getString(key)
	value, err := strconv.Atoi(valueStr)
	if err != nil {
		fmt.Printf("Invalid int for %s: %s\n", key, valueStr)
	}
	return value
}
