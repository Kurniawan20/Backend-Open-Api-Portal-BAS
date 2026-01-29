package models

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// APIKey represents a developer API key
type APIKey struct {
	ID          uuid.UUID      `gorm:"type:uuid;primaryKey" json:"id"`
	UserID      uuid.UUID      `gorm:"type:uuid;not null;index" json:"userId"`
	Name        string         `gorm:"not null" json:"name"`
	KeyPrefix   string         `gorm:"not null" json:"keyPrefix"`       // First 8 chars for display
	KeyHash     string         `gorm:"not null" json:"-"`               // Hashed full key
	Environment string         `gorm:"default:'sandbox'" json:"environment"` // sandbox, production
	IsActive    bool           `gorm:"default:true" json:"isActive"`
	LastUsedAt  *time.Time     `json:"lastUsedAt"`
	ExpiresAt   *time.Time     `json:"expiresAt"`
	CreatedAt   time.Time      `json:"createdAt"`
	UpdatedAt   time.Time      `json:"updatedAt"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`

	// Relations
	User User `gorm:"foreignKey:UserID" json:"-"`
}

// BeforeCreate generates a UUID before creating a new API key
func (k *APIKey) BeforeCreate(tx *gorm.DB) error {
	if k.ID == uuid.Nil {
		k.ID = uuid.New()
	}
	return nil
}

// GenerateAPIKey creates a new random API key
func GenerateAPIKey() (string, string, error) {
	// Generate 32 random bytes (256 bits)
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", "", err
	}

	fullKey := "bas_" + hex.EncodeToString(bytes)
	prefix := fullKey[:12] // "bas_" + first 8 hex chars

	return fullKey, prefix, nil
}

// APIKeyResponse is the response struct for listing keys
type APIKeyResponse struct {
	ID          uuid.UUID  `json:"id"`
	Name        string     `json:"name"`
	KeyPrefix   string     `json:"keyPrefix"`
	Environment string     `json:"environment"`
	IsActive    bool       `json:"isActive"`
	LastUsedAt  *time.Time `json:"lastUsedAt"`
	ExpiresAt   *time.Time `json:"expiresAt"`
	CreatedAt   time.Time  `json:"createdAt"`
}

// ToResponse converts APIKey to APIKeyResponse
func (k *APIKey) ToResponse() APIKeyResponse {
	return APIKeyResponse{
		ID:          k.ID,
		Name:        k.Name,
		KeyPrefix:   k.KeyPrefix,
		Environment: k.Environment,
		IsActive:    k.IsActive,
		LastUsedAt:  k.LastUsedAt,
		ExpiresAt:   k.ExpiresAt,
		CreatedAt:   k.CreatedAt,
	}
}

// APIKeyCreateResponse includes the full key (only shown once)
type APIKeyCreateResponse struct {
	APIKeyResponse
	Key string `json:"key"` // Full key, only returned on creation
}
