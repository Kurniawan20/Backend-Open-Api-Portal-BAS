package handlers

import (
	"errors"

	"github.com/bankaceh/bas-portal-api/internal/services"
	"github.com/gofiber/fiber/v2"
)

// AuthHandler handles authentication endpoints
type AuthHandler struct {
	authService *services.AuthService
}

// NewAuthHandler creates a new AuthHandler
func NewAuthHandler(authService *services.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

// Register godoc
// @Summary Register a new user
// @Description Create a new developer account
// @Tags Authentication
// @Accept json
// @Produce json
// @Param input body services.RegisterInput true "Registration data"
// @Success 201 {object} services.AuthResponse
// @Failure 400 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Router /auth/register [post]
func (h *AuthHandler) Register(c *fiber.Ctx) error {
	var input services.RegisterInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "Bad Request",
			Message: "Invalid request body",
		})
	}

	// Validate input
	if input.Email == "" || input.Password == "" || input.FullName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "Bad Request",
			Message: "Email, password, and full name are required",
		})
	}

	if len(input.Password) < 8 {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "Bad Request",
			Message: "Password must be at least 8 characters",
		})
	}

	response, err := h.authService.Register(input)
	if err != nil {
		if errors.Is(err, services.ErrEmailExists) {
			return c.Status(fiber.StatusConflict).JSON(ErrorResponse{
				Error:   "Conflict",
				Message: "Email already registered",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error:   "Internal Server Error",
			Message: "Failed to register user",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(response)
}

// Login godoc
// @Summary Login user
// @Description Authenticate with email and password
// @Tags Authentication
// @Accept json
// @Produce json
// @Param input body services.LoginInput true "Login credentials"
// @Success 200 {object} services.AuthResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Router /auth/login [post]
func (h *AuthHandler) Login(c *fiber.Ctx) error {
	var input services.LoginInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "Bad Request",
			Message: "Invalid request body",
		})
	}

	if input.Email == "" || input.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "Bad Request",
			Message: "Email and password are required",
		})
	}

	response, err := h.authService.Login(input)
	if err != nil {
		if errors.Is(err, services.ErrInvalidCredentials) {
			return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
				Error:   "Unauthorized",
				Message: "Invalid email or password",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error:   "Internal Server Error",
			Message: "Failed to login",
		})
	}

	return c.JSON(response)
}

// GoogleLogin godoc
// @Summary Initiate Google OAuth login
// @Description Redirects to Google OAuth consent screen
// @Tags Authentication
// @Produce json
// @Success 302 {string} string "Redirect to Google"
// @Router /auth/google [get]
func (h *AuthHandler) GoogleLogin(c *fiber.Ctx) error {
	// TODO: Implement Google OAuth redirect
	// For now, return a placeholder
	return c.JSON(fiber.Map{
		"message": "Google OAuth not yet implemented",
		"hint":    "Configure GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in .env",
	})
}

// GoogleCallback godoc
// @Summary Handle Google OAuth callback
// @Description Processes Google OAuth callback and returns tokens
// @Tags Authentication
// @Produce json
// @Param code query string true "OAuth authorization code"
// @Success 200 {object} services.AuthResponse
// @Failure 400 {object} ErrorResponse
// @Router /auth/google/callback [get]
func (h *AuthHandler) GoogleCallback(c *fiber.Ctx) error {
	// TODO: Implement Google OAuth callback handling
	code := c.Query("code")
	if code == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "Bad Request",
			Message: "Missing authorization code",
		})
	}

	return c.JSON(fiber.Map{
		"message": "Google OAuth callback not yet implemented",
	})
}

// RefreshToken godoc
// @Summary Refresh access token
// @Description Get a new access token using a refresh token
// @Tags Authentication
// @Accept json
// @Produce json
// @Param input body RefreshTokenInput true "Refresh token"
// @Success 200 {object} services.AuthResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Router /auth/refresh [post]
func (h *AuthHandler) RefreshToken(c *fiber.Ctx) error {
	var input RefreshTokenInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "Bad Request",
			Message: "Invalid request body",
		})
	}

	if input.RefreshToken == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "Bad Request",
			Message: "Refresh token is required",
		})
	}

	response, err := h.authService.RefreshToken(input.RefreshToken)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error:   "Unauthorized",
			Message: "Invalid refresh token",
		})
	}

	return c.JSON(response)
}

// RefreshTokenInput represents refresh token request
type RefreshTokenInput struct {
	RefreshToken string `json:"refreshToken"`
}
