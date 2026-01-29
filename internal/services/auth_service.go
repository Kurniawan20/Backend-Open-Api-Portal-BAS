package services

import (
	"errors"
	"time"

	"github.com/bankaceh/bas-portal-api/internal/config"
	"github.com/bankaceh/bas-portal-api/internal/models"
	"github.com/bankaceh/bas-portal-api/internal/repository"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrEmailExists        = errors.New("email already registered")
	ErrUserNotFound       = errors.New("user not found")
)

// AuthService handles authentication logic
type AuthService struct {
	userRepo *repository.UserRepository
	cfg      *config.Config
}

// NewAuthService creates a new AuthService
func NewAuthService(userRepo *repository.UserRepository, cfg *config.Config) *AuthService {
	return &AuthService{
		userRepo: userRepo,
		cfg:      cfg,
	}
}

// RegisterInput represents registration request data
type RegisterInput struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
	FullName string `json:"fullName" validate:"required,min=2"`
}

// LoginInput represents login request data
type LoginInput struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// AuthResponse contains tokens and user data
type AuthResponse struct {
	AccessToken  string              `json:"accessToken"`
	RefreshToken string              `json:"refreshToken"`
	ExpiresIn    int                 `json:"expiresIn"`
	User         models.UserResponse `json:"user"`
}

// Register creates a new user account
func (s *AuthService) Register(input RegisterInput) (*AuthResponse, error) {
	// Check if email exists
	if s.userRepo.EmailExists(input.Email) {
		return nil, ErrEmailExists
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// Create user
	user := &models.User{
		Email:        input.Email,
		PasswordHash: string(hashedPassword),
		FullName:     input.FullName,
		Provider:     "local",
	}

	if err := s.userRepo.Create(user); err != nil {
		return nil, err
	}

	// Generate tokens
	return s.generateAuthResponse(user)
}

// Login authenticates a user
func (s *AuthService) Login(input LoginInput) (*AuthResponse, error) {
	user, err := s.userRepo.FindByEmail(input.Email)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.Password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	return s.generateAuthResponse(user)
}

// GoogleAuth handles Google OAuth authentication
func (s *AuthService) GoogleAuth(email, fullName, providerID string) (*AuthResponse, error) {
	// Try to find existing user
	user, err := s.userRepo.FindByProvider("google", providerID)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	if user == nil {
		// Check if email exists with different provider
		existingUser, err := s.userRepo.FindByEmail(email)
		if err == nil {
			// Link Google to existing account
			existingUser.Provider = "google"
			existingUser.ProviderID = providerID
			if err := s.userRepo.Update(existingUser); err != nil {
				return nil, err
			}
			user = existingUser
		} else if errors.Is(err, gorm.ErrRecordNotFound) {
			// Create new user
			user = &models.User{
				Email:      email,
				FullName:   fullName,
				Provider:   "google",
				ProviderID: providerID,
				IsVerified: true, // Google accounts are pre-verified
			}
			if err := s.userRepo.Create(user); err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	return s.generateAuthResponse(user)
}

// RefreshToken generates a new access token from a refresh token
func (s *AuthService) RefreshToken(refreshToken string) (*AuthResponse, error) {
	// Parse and validate refresh token
	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.cfg.JWTSecret), nil
	})
	if err != nil || !token.Valid {
		return nil, errors.New("invalid refresh token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	// Check token type
	tokenType, ok := claims["type"].(string)
	if !ok || tokenType != "refresh" {
		return nil, errors.New("invalid token type")
	}

	// Get user ID
	userIDStr, ok := claims["sub"].(string)
	if !ok {
		return nil, errors.New("invalid user ID in token")
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, errors.New("invalid user ID format")
	}

	// Find user
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return nil, ErrUserNotFound
	}

	return s.generateAuthResponse(user)
}

// generateAuthResponse creates access and refresh tokens
func (s *AuthService) generateAuthResponse(user *models.User) (*AuthResponse, error) {
	expiryHours := s.cfg.JWTExpiryHours
	accessExpiry := time.Now().Add(time.Duration(expiryHours) * time.Hour)
	refreshExpiry := time.Now().Add(time.Duration(expiryHours*7) * time.Hour) // 7x access token lifetime

	// Access token
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   user.ID.String(),
		"email": user.Email,
		"type":  "access",
		"exp":   accessExpiry.Unix(),
		"iat":   time.Now().Unix(),
	})

	accessTokenString, err := accessToken.SignedString([]byte(s.cfg.JWTSecret))
	if err != nil {
		return nil, err
	}

	// Refresh token
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  user.ID.String(),
		"type": "refresh",
		"exp":  refreshExpiry.Unix(),
		"iat":  time.Now().Unix(),
	})

	refreshTokenString, err := refreshToken.SignedString([]byte(s.cfg.JWTSecret))
	if err != nil {
		return nil, err
	}

	return &AuthResponse{
		AccessToken:  accessTokenString,
		RefreshToken: refreshTokenString,
		ExpiresIn:    expiryHours * 3600,
		User:         user.ToResponse(),
	}, nil
}
