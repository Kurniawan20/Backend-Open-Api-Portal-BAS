package services

import (
	"errors"
	"time"

	"github.com/bankaceh/bas-portal-api/internal/models"
	"github.com/bankaceh/bas-portal-api/internal/repository"
	"github.com/google/uuid"
)

var (
	ErrCredentialNotFound     = errors.New("partner credential not found")
	ErrMaxCredentialsReached  = errors.New("maximum number of credentials reached")
	ErrInvalidPublicKey       = errors.New("invalid public key format")
	ErrClientIDExists         = errors.New("client ID already exists")
)

// PartnerCredentialService handles business logic for partner credentials
type PartnerCredentialService struct {
	repo *repository.PartnerCredentialRepository
}

// NewPartnerCredentialService creates a new PartnerCredentialService
func NewPartnerCredentialService(repo *repository.PartnerCredentialRepository) *PartnerCredentialService {
	return &PartnerCredentialService{repo: repo}
}

// CreateCredentialInput represents the input for creating a partner credential
type CreateCredentialInput struct {
	PartnerName string   `json:"partnerName"`
	Environment string   `json:"environment"`
	CallbackURL string   `json:"callbackUrl"`
	IPWhitelist []string `json:"ipWhitelist"`
	PublicKey   string   `json:"publicKey"`
}

// CreateCredential creates a new partner credential with auto-generated client ID and secret
func (s *PartnerCredentialService) CreateCredential(userID uuid.UUID, input CreateCredentialInput) (*models.PartnerCredentialCreateResponse, error) {
	// Check max credentials limit (5 per user)
	count, err := s.repo.CountByUserID(userID)
	if err != nil {
		return nil, err
	}
	if count >= 5 {
		return nil, ErrMaxCredentialsReached
	}

	// Generate client credentials
	clientID, clientSecret, secretPrefix, err := models.GenerateClientCredentials()
	if err != nil {
		return nil, err
	}

	// Generate channel ID
	channelID, err := models.GenerateChannelID()
	if err != nil {
		return nil, err
	}

	// Validate public key if provided
	var fingerprint string
	var publicKeyAddedAt *time.Time
	if input.PublicKey != "" {
		fingerprint, err = models.ValidatePublicKey(input.PublicKey)
		if err != nil {
			return nil, ErrInvalidPublicKey
		}
		now := time.Now()
		publicKeyAddedAt = &now
	}

	// Set default environment
	if input.Environment == "" {
		input.Environment = "sandbox"
	}

	// Create credential
	credential := &models.PartnerCredential{
		UserID:               userID,
		ClientID:             clientID,
		ClientSecret:         clientSecret, // TODO: Encrypt before storing
		ClientSecretPrefix:   secretPrefix,
		PublicKey:            input.PublicKey,
		PublicKeyFingerprint: fingerprint,
		PublicKeyAddedAt:     publicKeyAddedAt,
		PartnerName:          input.PartnerName,
		ChannelID:            channelID,
		Environment:          input.Environment,
		CallbackURL:          input.CallbackURL,
		IPWhitelist:          input.IPWhitelist,
		IsActive:             true,
	}

	if err := s.repo.Create(credential); err != nil {
		return nil, err
	}

	// Return response with full secret (only shown once)
	response := &models.PartnerCredentialCreateResponse{
		PartnerCredentialResponse: credential.ToResponse(),
		ClientSecret:              clientSecret,
	}

	return response, nil
}

// ListCredentials returns all credentials for a user
func (s *PartnerCredentialService) ListCredentials(userID uuid.UUID) ([]models.PartnerCredentialResponse, error) {
	credentials, err := s.repo.FindByUserID(userID)
	if err != nil {
		return nil, err
	}

	responses := make([]models.PartnerCredentialResponse, len(credentials))
	for i, cred := range credentials {
		responses[i] = cred.ToResponse()
	}

	return responses, nil
}

// GetCredential returns a single credential with details
func (s *PartnerCredentialService) GetCredential(id, userID uuid.UUID) (*models.PartnerCredentialDetailResponse, error) {
	credential, err := s.repo.FindByIDAndUserID(id, userID)
	if err != nil {
		return nil, ErrCredentialNotFound
	}

	response := credential.ToDetailResponse()
	return &response, nil
}

// UpdateCredentialInput represents the input for updating a partner credential
type UpdateCredentialInput struct {
	PartnerName string   `json:"partnerName"`
	Environment string   `json:"environment"`
	CallbackURL string   `json:"callbackUrl"`
	IPWhitelist []string `json:"ipWhitelist"`
}

// UpdateCredential updates an existing credential
func (s *PartnerCredentialService) UpdateCredential(id, userID uuid.UUID, input UpdateCredentialInput) (*models.PartnerCredentialResponse, error) {
	credential, err := s.repo.FindByIDAndUserID(id, userID)
	if err != nil {
		return nil, ErrCredentialNotFound
	}

	// Update fields
	if input.PartnerName != "" {
		credential.PartnerName = input.PartnerName
	}
	if input.Environment != "" {
		credential.Environment = input.Environment
	}
	credential.CallbackURL = input.CallbackURL
	credential.IPWhitelist = input.IPWhitelist

	if err := s.repo.Update(credential); err != nil {
		return nil, err
	}

	response := credential.ToResponse()
	return &response, nil
}

// UpdatePublicKeyInput represents the input for updating a public key
type UpdatePublicKeyInput struct {
	PublicKey string `json:"publicKey"`
}

// UpdatePublicKey updates the public key for a credential
func (s *PartnerCredentialService) UpdatePublicKey(id, userID uuid.UUID, input UpdatePublicKeyInput) (*models.PartnerCredentialResponse, error) {
	// Verify credential exists and belongs to user
	credential, err := s.repo.FindByIDAndUserID(id, userID)
	if err != nil {
		return nil, ErrCredentialNotFound
	}

	// Validate public key
	fingerprint, err := models.ValidatePublicKey(input.PublicKey)
	if err != nil {
		return nil, ErrInvalidPublicKey
	}

	// Update public key
	if err := s.repo.UpdatePublicKey(id, userID, input.PublicKey, fingerprint); err != nil {
		return nil, err
	}

	// Refresh credential
	credential, _ = s.repo.FindByIDAndUserID(id, userID)
	response := credential.ToResponse()
	return &response, nil
}

// DeleteCredential soft deletes a credential
func (s *PartnerCredentialService) DeleteCredential(id, userID uuid.UUID) error {
	// Verify credential exists and belongs to user
	_, err := s.repo.FindByIDAndUserID(id, userID)
	if err != nil {
		return ErrCredentialNotFound
	}

	return s.repo.Delete(id, userID)
}

// RegenerateSecret generates a new client secret for a credential
func (s *PartnerCredentialService) RegenerateSecret(id, userID uuid.UUID) (*models.PartnerCredentialCreateResponse, error) {
	credential, err := s.repo.FindByIDAndUserID(id, userID)
	if err != nil {
		return nil, ErrCredentialNotFound
	}

	// Generate new secret
	_, clientSecret, secretPrefix, err := models.GenerateClientCredentials()
	if err != nil {
		return nil, err
	}

	// Update credential with new secret
	credential.ClientSecret = clientSecret // TODO: Encrypt before storing
	credential.ClientSecretPrefix = secretPrefix

	if err := s.repo.Update(credential); err != nil {
		return nil, err
	}

	// Return response with full new secret
	response := &models.PartnerCredentialCreateResponse{
		PartnerCredentialResponse: credential.ToResponse(),
		ClientSecret:              clientSecret,
	}

	return response, nil
}

// ValidateCredential validates client ID and secret for API authentication
func (s *PartnerCredentialService) ValidateCredential(clientID, clientSecret string) (*models.PartnerCredential, error) {
	credential, err := s.repo.FindByClientID(clientID)
	if err != nil {
		return nil, ErrCredentialNotFound
	}

	// Compare secret (TODO: Use constant-time comparison and encrypted storage)
	if credential.ClientSecret != clientSecret {
		return nil, ErrCredentialNotFound
	}

	// Update last used timestamp
	_ = s.repo.UpdateLastUsed(credential.ID)

	return credential, nil
}
