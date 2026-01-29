package repository

import (
	"github.com/bankaceh/bas-portal-api/internal/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// PartnerCredentialRepository handles database operations for partner credentials
type PartnerCredentialRepository struct {
	db *gorm.DB
}

// NewPartnerCredentialRepository creates a new PartnerCredentialRepository
func NewPartnerCredentialRepository(db *gorm.DB) *PartnerCredentialRepository {
	return &PartnerCredentialRepository{db: db}
}

// Create inserts a new partner credential into the database
func (r *PartnerCredentialRepository) Create(credential *models.PartnerCredential) error {
	return r.db.Create(credential).Error
}

// FindByID finds a partner credential by its UUID
func (r *PartnerCredentialRepository) FindByID(id uuid.UUID) (*models.PartnerCredential, error) {
	var credential models.PartnerCredential
	err := r.db.Where("id = ? AND is_active = ?", id, true).First(&credential).Error
	if err != nil {
		return nil, err
	}
	return &credential, nil
}

// FindByIDAndUserID finds a partner credential by ID and user ID
func (r *PartnerCredentialRepository) FindByIDAndUserID(id, userID uuid.UUID) (*models.PartnerCredential, error) {
	var credential models.PartnerCredential
	err := r.db.Where("id = ? AND user_id = ?", id, userID).First(&credential).Error
	if err != nil {
		return nil, err
	}
	return &credential, nil
}

// FindByUserID finds all partner credentials for a user
func (r *PartnerCredentialRepository) FindByUserID(userID uuid.UUID) ([]models.PartnerCredential, error) {
	var credentials []models.PartnerCredential
	err := r.db.Where("user_id = ? AND is_active = ?", userID, true).
		Order("created_at DESC").
		Find(&credentials).Error
	if err != nil {
		return nil, err
	}
	return credentials, nil
}

// FindByClientID finds a partner credential by client ID (for API authentication)
func (r *PartnerCredentialRepository) FindByClientID(clientID string) (*models.PartnerCredential, error) {
	var credential models.PartnerCredential
	err := r.db.Where("client_id = ? AND is_active = ?", clientID, true).
		Preload("User").
		First(&credential).Error
	if err != nil {
		return nil, err
	}
	return &credential, nil
}

// Update updates an existing partner credential
func (r *PartnerCredentialRepository) Update(credential *models.PartnerCredential) error {
	return r.db.Save(credential).Error
}

// UpdatePublicKey updates only the public key fields
func (r *PartnerCredentialRepository) UpdatePublicKey(id, userID uuid.UUID, publicKey, fingerprint string) error {
	return r.db.Model(&models.PartnerCredential{}).
		Where("id = ? AND user_id = ?", id, userID).
		Updates(map[string]interface{}{
			"public_key":             publicKey,
			"public_key_fingerprint": fingerprint,
			"public_key_added_at":    gorm.Expr("NOW()"),
		}).Error
}

// Delete soft deletes a partner credential
func (r *PartnerCredentialRepository) Delete(id, userID uuid.UUID) error {
	return r.db.Where("id = ? AND user_id = ?", id, userID).
		Delete(&models.PartnerCredential{}).Error
}

// Deactivate sets a partner credential as inactive
func (r *PartnerCredentialRepository) Deactivate(id, userID uuid.UUID) error {
	return r.db.Model(&models.PartnerCredential{}).
		Where("id = ? AND user_id = ?", id, userID).
		Update("is_active", false).Error
}

// UpdateLastUsed updates the last used timestamp
func (r *PartnerCredentialRepository) UpdateLastUsed(id uuid.UUID) error {
	return r.db.Model(&models.PartnerCredential{}).
		Where("id = ?", id).
		Update("last_used_at", gorm.Expr("NOW()")).Error
}

// CountByUserID counts active partner credentials for a user
func (r *PartnerCredentialRepository) CountByUserID(userID uuid.UUID) (int64, error) {
	var count int64
	err := r.db.Model(&models.PartnerCredential{}).
		Where("user_id = ? AND is_active = ?", userID, true).
		Count(&count).Error
	return count, err
}

// ExistsByClientID checks if a client ID already exists
func (r *PartnerCredentialRepository) ExistsByClientID(clientID string) (bool, error) {
	var count int64
	err := r.db.Model(&models.PartnerCredential{}).
		Where("client_id = ?", clientID).
		Count(&count).Error
	return count > 0, err
}
