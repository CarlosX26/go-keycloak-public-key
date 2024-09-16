package main

import (
	"crypto/rsa"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

// Função para carregar a chave pública
func loadPublicKey() (*rsa.PublicKey, error) {
	publicKeyData, err := os.ReadFile("public_key.pem")
	if err != nil {
		return nil, fmt.Errorf("erro ao carregar a chave pública: %v", err)
	}

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyData)
	if err != nil {
		return nil, fmt.Errorf("erro ao parsear a chave pública: %v", err)
	}
	return publicKey, nil
}

// Middleware para validar o token JWT
func authMiddleware(publicKey *rsa.PublicKey) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Header de autorização ausente"})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("método de assinatura inesperado: %v", token.Header["alg"])
			}
			return publicKey, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token inválido"})
			c.Abort()
			return
		}

		c.Next() // Continue se o token for válido
	}
}

func main() {
	publicKey, err := loadPublicKey()
	if err != nil {
		panic(fmt.Errorf("falha ao carregar a chave pública: %v", err))
	}

	r := gin.Default()

	// Rota pública
	r.GET("/public", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Rota pública, sem autenticação."})
	})

	// Rota privada que requer validação do JWT
	r.GET("/private", authMiddleware(publicKey), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Bem-vindo à rota privada, token válido!"})
	})

	r.Run(":8081")
}
