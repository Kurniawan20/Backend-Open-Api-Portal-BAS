package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// User represents a developer account
type User struct {
	ID           uuid.UUID      `gorm:"type:uuid;primaryKey" json:"id"`
	Email        string         `gorm:"uniqueIndex;not null" json:"email"`
	PasswordHash string         `gorm:"" json:"-"`
	FullName     string         `gorm:"not null" json:"fullName"`
	JobTitle     string         `gorm:"" json:"jobTitle"`
	Company      string         `gorm:"" json:"company"`
	Provider     string         `gorm:"default:'local'" json:"provider"` // local, google
	ProviderID   string         `gorm:"" json:"-"`
	IsVerified   bool           `gorm:"default:false" json:"isVerified"`
	CreatedAt    time.Time      `json:"createdAt"`
	UpdatedAt    time.Time      `json:"updatedAt"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`

	// Relations
	APIKeys []APIKey `gorm:"foreignKey:UserID" json:"-"`
}

// BeforeCreate generates a UUID before creating a new user
func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	return nil
}

// UserResponse is the safe response struct without sensitive data
type UserResponse struct {
	ID         uuid.UUID `json:"id"`
	Email      string    `json:"email"`
	FullName   string    `json:"fullName"`
	JobTitle   string    `json:"jobTitle"`
	Company    string    `json:"company"`
	Provider   string    `json:"provider"`
	IsVerified bool      `json:"isVerified"`
	CreatedAt  time.Time `json:"createdAt"`
}

// ToResponse converts User to UserResponse
func (u *User) ToResponse() UserResponse {
	return UserResponse{
		ID:         u.ID,
		Email:      u.Email,
		FullName:   u.FullName,
		JobTitle:   u.JobTitle,
		Company:    u.Company,
		Provider:   u.Provider,
		IsVerified: u.IsVerified,
		CreatedAt:  u.CreatedAt,
	}
}
