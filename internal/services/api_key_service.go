package services

import (
	"errors"

	"github.com/bankaceh/bas-portal-api/internal/models"
	"github.com/bankaceh/bas-portal-api/internal/repository"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const MaxAPIKeysPerUser = 10

var (
	ErrMaxKeysReached = errors.New("maximum number of API keys reached")
	ErrKeyNotFound    = errors.New("API key not found")
)

// APIKeyService handles API key business logic
type APIKeyService struct {
	keyRepo *repository.APIKeyRepository
}

// NewAPIKeyService creates a new APIKeyService
func NewAPIKeyService(keyRepo *repository.APIKeyRepository) *APIKeyService {
	return &APIKeyService{keyRepo: keyRepo}
}

// CreateKeyInput represents new API key request data
type CreateKeyInput struct {
	Name        string `json:"name" validate:"required,min=1,max=100"`
	Environment string `json:"environment" validate:"required,oneof=sandbox production"`
}

// ListKeys retrieves all API keys for a user
func (s *APIKeyService) ListKeys(userID uuid.UUID) ([]models.APIKeyResponse, error) {
	keys, err := s.keyRepo.FindByUserID(userID)
	if err != nil {
		return nil, err
	}

	response := make([]models.APIKeyResponse, len(keys))
	for i, key := range keys {
		response[i] = key.ToResponse()
	}

	return response, nil
}

// CreateKey generates a new API key for a user
func (s *APIKeyService) CreateKey(userID uuid.UUID, input CreateKeyInput) (*models.APIKeyCreateResponse, error) {
	// Check key limit
	count, err := s.keyRepo.CountByUserID(userID)
	if err != nil {
		return nil, err
	}
	if count >= MaxAPIKeysPerUser {
		return nil, ErrMaxKeysReached
	}

	// Generate key
	fullKey, prefix, err := models.GenerateAPIKey()
	if err != nil {
		return nil, err
	}

	// Hash the key for storage
	keyHash, err := bcrypt.GenerateFromPassword([]byte(fullKey), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// Create API key record
	apiKey := &models.APIKey{
		UserID:      userID,
		Name:        input.Name,
		KeyPrefix:   prefix,
		KeyHash:     string(keyHash),
		Environment: input.Environment,
		IsActive:    true,
	}

	if err := s.keyRepo.Create(apiKey); err != nil {
		return nil, err
	}

	return &models.APIKeyCreateResponse{
		APIKeyResponse: apiKey.ToResponse(),
		Key:            fullKey,
	}, nil
}

// RevokeKey deactivates an API key
func (s *APIKeyService) RevokeKey(keyID, userID uuid.UUID) error {
	// Verify key exists and belongs to user
	key, err := s.keyRepo.FindByID(keyID)
	if err != nil {
		return ErrKeyNotFound
	}

	if key.UserID != userID {
		return ErrKeyNotFound
	}

	return s.keyRepo.Revoke(keyID, userID)
}

// ValidateKey checks if an API key is valid and returns the associated user
func (s *APIKeyService) ValidateKey(key string) (*models.User, error) {
	// Find all active keys and check against hash
	// Note: In production, you'd want a more efficient lookup
	// This is simplified for demonstration

	// For now, we'll just return an error
	// Real implementation would hash the key and look it up
	return nil, errors.New("key validation not implemented")
}
