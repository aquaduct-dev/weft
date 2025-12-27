package server

import (
	"context"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

// contextKey is a custom type for context keys to avoid collisions.
type contextKey string

// jwtTokenKey is the context key used to store the validated JWT token.
const jwtTokenKey contextKey = "jwtToken"

// requireJWT is middleware that validates JWT authentication on requests.
// It extracts the Bearer token from the Authorization header, validates it,
// and stores the token in the request context for downstream handlers.
func (s *Server) requireJWT(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid Authorization header", http.StatusUnauthorized)
			return
		}

		tokenString := parts[1]
		token, err := s.ValidateJWT(tokenString)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), jwtTokenKey, token)
		next(w, r.WithContext(ctx))
	}
}

// getJWTFromContext retrieves the validated JWT token from the request context.
// Returns nil if no token is present.
func getJWTFromContext(ctx context.Context) *jwt.Token {
	token, _ := ctx.Value(jwtTokenKey).(*jwt.Token)
	return token
}

// getJWTSubject extracts the "sub" claim from a JWT token in the request context.
// Returns empty string if the token or claim is not present.
func getJWTSubject(ctx context.Context) string {
	token := getJWTFromContext(ctx)
	if token == nil {
		return ""
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return ""
	}
	sub, _ := claims["sub"].(string)
	return sub
}

// getJWTSubjectFromRequest extracts the "sub" claim from the JWT token.
// It assumes the request has passed through requireJWT middleware.
func (s *Server) getJWTSubjectFromRequest(r *http.Request) string {
	return getJWTSubject(r.Context())
}
