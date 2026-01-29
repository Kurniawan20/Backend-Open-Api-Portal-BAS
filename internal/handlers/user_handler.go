package handlers

import (
	"github.com/bankaceh/bas-portal-api/internal/middleware"
	"github.com/bankaceh/bas-portal-api/internal/services"
	"github.com/gofiber/fiber/v2"
)

// UserHandler handles user-related endpoints
type UserHandler struct {
	userService *services.UserService
}

// NewUserHandler creates a new UserHandler
func NewUserHandler(userService *services.UserService) *UserHandler {
	return &UserHandler{userService: userService}
}

// GetProfile godoc
// @Summary Get current user profile
// @Description Get the authenticated user's profile
// @Tags Users
// @Security BearerAuth
// @Produce json
// @Success 200 {object} models.UserResponse
// @Failure 401 {object} ErrorResponse
// @Router /users/me [get]
func (h *UserHandler) GetProfile(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)

	profile, err := h.userService.GetProfile(userID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
			Error:   "Not Found",
			Message: "User not found",
		})
	}

	return c.JSON(profile)
}

// UpdateProfile godoc
// @Summary Update user profile
// @Description Update the authenticated user's profile
// @Tags Users
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param input body services.UpdateProfileInput true "Profile data"
// @Success 200 {object} models.UserResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Router /users/me [put]
func (h *UserHandler) UpdateProfile(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)

	var input services.UpdateProfileInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "Bad Request",
			Message: "Invalid request body",
		})
	}

	if input.FullName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "Bad Request",
			Message: "Full name is required",
		})
	}

	profile, err := h.userService.UpdateProfile(userID, input)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error:   "Internal Server Error",
			Message: "Failed to update profile",
		})
	}

	return c.JSON(profile)
}
