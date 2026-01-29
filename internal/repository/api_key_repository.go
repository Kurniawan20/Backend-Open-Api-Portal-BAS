package repository

import (
	"github.com/bankaceh/bas-portal-api/internal/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// APIKeyRepository handles database operations for API keys
type APIKeyRepository struct {
	db *gorm.DB
}

// NewAPIKeyRepository creates a new APIKeyRepository
func NewAPIKeyRepository(db *gorm.DB) *APIKeyRepository {
	return &APIKeyRepository{db: db}
}

// Create inserts a new API key into the database
func (r *APIKeyRepository) Create(apiKey *models.APIKey) error {
	return r.db.Create(apiKey).Error
}

// FindByID finds an API key by its UUID
func (r *APIKeyRepository) FindByID(id uuid.UUID) (*models.APIKey, error) {
	var key models.APIKey
	err := r.db.Where("id = ?", id).First(&key).Error
	if err != nil {
		return nil, err
	}
	return &key, nil
}

// FindByUserID finds all API keys for a user
func (r *APIKeyRepository) FindByUserID(userID uuid.UUID) ([]models.APIKey, error) {
	var keys []models.APIKey
	err := r.db.Where("user_id = ? AND is_active = ?", userID, true).
		Order("created_at DESC").
		Find(&keys).Error
	if err != nil {
		return nil, err
	}
	return keys, nil
}

// FindByKeyHash finds an API key by its hash (for validation)
func (r *APIKeyRepository) FindByKeyHash(keyHash string) (*models.APIKey, error) {
	var key models.APIKey
	err := r.db.Where("key_hash = ? AND is_active = ?", keyHash, true).
		Preload("User").
		First(&key).Error
	if err != nil {
		return nil, err
	}
	return &key, nil
}

// Update updates an existing API key
func (r *APIKeyRepository) Update(apiKey *models.APIKey) error {
	return r.db.Save(apiKey).Error
}

// Revoke deactivates an API key
func (r *APIKeyRepository) Revoke(id, userID uuid.UUID) error {
	return r.db.Model(&models.APIKey{}).
		Where("id = ? AND user_id = ?", id, userID).
		Update("is_active", false).Error
}

// CountByUserID counts active API keys for a user
func (r *APIKeyRepository) CountByUserID(userID uuid.UUID) (int64, error) {
	var count int64
	err := r.db.Model(&models.APIKey{}).
		Where("user_id = ? AND is_active = ?", userID, true).
		Count(&count).Error
	return count, err
}
