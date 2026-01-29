package models

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql/driver"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// StringArray is a custom type for storing string arrays in PostgreSQL as JSON
type StringArray []string

// Value implements the driver.Valuer interface for database storage
func (s StringArray) Value() (driver.Value, error) {
	if s == nil {
		return nil, nil
	}
	return json.Marshal(s)
}

// Scan implements the sql.Scanner interface for database retrieval
func (s *StringArray) Scan(value interface{}) error {
	if value == nil {
		*s = nil
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}
	return json.Unmarshal(bytes, s)
}

// PartnerCredential represents SNAP API credentials for a partner
type PartnerCredential struct {
	ID                   uuid.UUID      `gorm:"type:uuid;primaryKey" json:"id"`
	UserID               uuid.UUID      `gorm:"type:uuid;not null;index" json:"userId"`

	// SNAP Authentication
	ClientID             string         `gorm:"uniqueIndex;not null;size:64" json:"clientId"`
	ClientSecret         string         `gorm:"not null" json:"-"` // Encrypted, never exposed
	ClientSecretPrefix   string         `gorm:"size:12" json:"clientSecretPrefix"` // First 8 chars for display

	// RSA Public Key Configuration
	PublicKey            string         `gorm:"type:text" json:"-"` // PEM format, not exposed in list
	PublicKeyFingerprint string         `gorm:"size:64;index" json:"publicKeyFingerprint"` // SHA256 fingerprint
	PublicKeyAddedAt     *time.Time     `json:"publicKeyAddedAt"`

	// Partner Configuration
	PartnerName          string         `gorm:"not null;size:255" json:"partnerName"`
	ChannelID            string         `gorm:"size:64" json:"channelId"`
	Environment          string         `gorm:"default:'sandbox';size:20" json:"environment"` // sandbox, production

	// Security Settings
	CallbackURL          string         `gorm:"size:500" json:"callbackUrl"`
	IPWhitelist          StringArray    `gorm:"type:jsonb" json:"ipWhitelist"`

	// Status
	IsActive             bool           `gorm:"default:true" json:"isActive"`
	ExpiresAt            *time.Time     `json:"expiresAt"`
	LastUsedAt           *time.Time     `json:"lastUsedAt"`

	// Timestamps
	CreatedAt            time.Time      `json:"createdAt"`
	UpdatedAt            time.Time      `json:"updatedAt"`
	DeletedAt            gorm.DeletedAt `gorm:"index" json:"-"`

	// Relations
	User                 User           `gorm:"foreignKey:UserID" json:"-"`
}

// BeforeCreate generates UUID and credentials before creating
func (p *PartnerCredential) BeforeCreate(tx *gorm.DB) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	return nil
}

// GenerateClientCredentials creates a new client ID and secret
func GenerateClientCredentials() (clientID, clientSecret, secretPrefix string, err error) {
	// Generate Client ID (16 bytes = 32 hex chars)
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return "", "", "", err
	}
	clientID = "BAS" + hex.EncodeToString(idBytes)[:29] // BAS + 29 chars = 32 total

	// Generate Client Secret (32 bytes = 64 hex chars)
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return "", "", "", err
	}
	clientSecret = hex.EncodeToString(secretBytes)
	secretPrefix = clientSecret[:8] + "..."

	return clientID, clientSecret, secretPrefix, nil
}

// GenerateChannelID creates a new channel ID
func GenerateChannelID() (string, error) {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return "CH" + hex.EncodeToString(bytes), nil
}

// ValidatePublicKey validates a PEM-encoded RSA public key and returns its fingerprint
func ValidatePublicKey(pemKey string) (fingerprint string, err error) {
	if pemKey == "" {
		return "", nil // Empty is allowed
	}

	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return "", errors.New("invalid PEM format: no valid PEM block found")
	}

	if block.Type != "PUBLIC KEY" && block.Type != "RSA PUBLIC KEY" {
		return "", errors.New("invalid PEM format: expected PUBLIC KEY or RSA PUBLIC KEY")
	}

	// Try to parse as PKIX public key
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		// Try parsing as PKCS1 public key
		_, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return "", errors.New("invalid public key: unable to parse")
		}
	}

	// If we got here with PKIX, verify it's valid
	if pubKey != nil {
		// Key is valid
	}

	// Calculate SHA256 fingerprint
	hash := sha256.Sum256(block.Bytes)
	fingerprint = hex.EncodeToString(hash[:])

	return fingerprint, nil
}

// FormatFingerprint formats a fingerprint for display (e.g., "94:32:f2:a1:...")
func FormatFingerprint(fingerprint string) string {
	if len(fingerprint) < 16 {
		return fingerprint
	}
	formatted := ""
	for i := 0; i < 16; i += 2 {
		if i > 0 {
			formatted += ":"
		}
		formatted += fingerprint[i : i+2]
	}
	return formatted + "..."
}

// PartnerCredentialResponse is the response struct for listing credentials
type PartnerCredentialResponse struct {
	ID                   uuid.UUID  `json:"id"`
	ClientID             string     `json:"clientId"`
	ClientSecretPrefix   string     `json:"clientSecretPrefix"`
	PublicKeyFingerprint string     `json:"publicKeyFingerprint,omitempty"`
	PublicKeyAddedAt     *time.Time `json:"publicKeyAddedAt,omitempty"`
	PartnerName          string     `json:"partnerName"`
	ChannelID            string     `json:"channelId"`
	Environment          string     `json:"environment"`
	CallbackURL          string     `json:"callbackUrl,omitempty"`
	IPWhitelist          []string   `json:"ipWhitelist,omitempty"`
	IsActive             bool       `json:"isActive"`
	ExpiresAt            *time.Time `json:"expiresAt,omitempty"`
	LastUsedAt           *time.Time `json:"lastUsedAt,omitempty"`
	CreatedAt            time.Time  `json:"createdAt"`
}

// ToResponse converts PartnerCredential to PartnerCredentialResponse
func (p *PartnerCredential) ToResponse() PartnerCredentialResponse {
	return PartnerCredentialResponse{
		ID:                   p.ID,
		ClientID:             p.ClientID,
		ClientSecretPrefix:   p.ClientSecretPrefix,
		PublicKeyFingerprint: FormatFingerprint(p.PublicKeyFingerprint),
		PublicKeyAddedAt:     p.PublicKeyAddedAt,
		PartnerName:          p.PartnerName,
		ChannelID:            p.ChannelID,
		Environment:          p.Environment,
		CallbackURL:          p.CallbackURL,
		IPWhitelist:          p.IPWhitelist,
		IsActive:             p.IsActive,
		ExpiresAt:            p.ExpiresAt,
		LastUsedAt:           p.LastUsedAt,
		CreatedAt:            p.CreatedAt,
	}
}

// PartnerCredentialCreateResponse includes the full secret (only shown once)
type PartnerCredentialCreateResponse struct {
	PartnerCredentialResponse
	ClientSecret string `json:"clientSecret"` // Full secret, only returned on creation
}

// PartnerCredentialDetailResponse includes public key for detail view
type PartnerCredentialDetailResponse struct {
	PartnerCredentialResponse
	PublicKey string `json:"publicKey,omitempty"` // Full PEM key
}

// ToDetailResponse converts PartnerCredential to PartnerCredentialDetailResponse
func (p *PartnerCredential) ToDetailResponse() PartnerCredentialDetailResponse {
	// Mask public key for security (show first and last lines only)
	maskedKey := ""
	if p.PublicKey != "" {
		maskedKey = maskPublicKey(p.PublicKey)
	}
	
	return PartnerCredentialDetailResponse{
		PartnerCredentialResponse: p.ToResponse(),
		PublicKey:                 maskedKey,
	}
}

func maskPublicKey(key string) string {
	if len(key) < 100 {
		return key
	}
	// Show header and footer only
	encoded := base64.StdEncoding.EncodeToString([]byte(key))
	if len(encoded) > 40 {
		return encoded[:20] + "..." + encoded[len(encoded)-20:]
	}
	return encoded
}
