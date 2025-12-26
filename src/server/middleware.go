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

		// Store the validated token in the request context
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
// It first checks the request context (set by middleware), then falls back
// to parsing the Authorization header directly (for direct handler calls in tests).
func (s *Server) getJWTSubjectFromRequest(r *http.Request) string {
	// Try context first (set by middleware)
	if sub := getJWTSubject(r.Context()); sub != "" {
		return sub
	}

	// Fallback: parse directly from Authorization header (for tests that call handlers directly)
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ""
	}
	token, err := s.ValidateJWT(parts[1])
	if err != nil {
		return ""
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return ""
	}
	sub, _ := claims["sub"].(string)
	return sub
}
