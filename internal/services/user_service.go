package services

import (
	"github.com/bankaceh/bas-portal-api/internal/models"
	"github.com/bankaceh/bas-portal-api/internal/repository"
	"github.com/google/uuid"
)

// UserService handles user-related business logic
type UserService struct {
	userRepo *repository.UserRepository
}

// NewUserService creates a new UserService
func NewUserService(userRepo *repository.UserRepository) *UserService {
	return &UserService{userRepo: userRepo}
}

// UpdateProfileInput represents profile update data
type UpdateProfileInput struct {
	FullName       string `json:"fullName"`
	FirstName      string `json:"firstName"`
	LastName       string `json:"lastName"`
	JobTitle       string `json:"jobTitle"`
	Company        string `json:"company"`
	ProfilePicture string `json:"profilePicture"`
}

// GetProfile retrieves a user's profile
func (s *UserService) GetProfile(userID uuid.UUID) (*models.UserResponse, error) {
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return nil, err
	}

	response := user.ToResponse()
	return &response, nil
}

// UpdateProfile updates a user's profile
func (s *UserService) UpdateProfile(userID uuid.UUID, input UpdateProfileInput) (*models.UserResponse, error) {
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return nil, err
	}

	if input.FullName != "" {
		user.FullName = input.FullName
	}
	if input.FirstName != "" {
		user.FirstName = input.FirstName
	}
	if input.LastName != "" {
		user.LastName = input.LastName
	}
	if input.JobTitle != "" {
		user.JobTitle = input.JobTitle
	}
	if input.Company != "" {
		user.Company = input.Company
	}
	if input.ProfilePicture != "" {
		user.ProfilePicture = input.ProfilePicture
	}

	if err := s.userRepo.Update(user); err != nil {
		return nil, err
	}

	response := user.ToResponse()
	return &response, nil
}
