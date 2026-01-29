package handlers

import (
	"errors"

	"github.com/bankaceh/bas-portal-api/internal/middleware"
	"github.com/bankaceh/bas-portal-api/internal/services"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// APIKeyHandler handles API key endpoints
type APIKeyHandler struct {
	apiKeyService *services.APIKeyService
}

// NewAPIKeyHandler creates a new APIKeyHandler
func NewAPIKeyHandler(apiKeyService *services.APIKeyService) *APIKeyHandler {
	return &APIKeyHandler{apiKeyService: apiKeyService}
}

// ListKeys godoc
// @Summary List API keys
// @Description Get all API keys for the authenticated user
// @Tags API Keys
// @Security BearerAuth
// @Produce json
// @Success 200 {array} models.APIKeyResponse
// @Failure 401 {object} ErrorResponse
// @Router /api-keys [get]
func (h *APIKeyHandler) ListKeys(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)

	keys, err := h.apiKeyService.ListKeys(userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error:   "Internal Server Error",
			Message: "Failed to retrieve API keys",
		})
	}

	return c.JSON(keys)
}

// CreateKey godoc
// @Summary Create API key
// @Description Generate a new API key
// @Tags API Keys
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param input body services.CreateKeyInput true "API key data"
// @Success 201 {object} models.APIKeyCreateResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Router /api-keys [post]
func (h *APIKeyHandler) CreateKey(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)

	var input services.CreateKeyInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "Bad Request",
			Message: "Invalid request body",
		})
	}

	if input.Name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "Bad Request",
			Message: "Key name is required",
		})
	}

	if input.Environment == "" {
		input.Environment = "sandbox"
	}

	if input.Environment != "sandbox" && input.Environment != "production" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "Bad Request",
			Message: "Environment must be 'sandbox' or 'production'",
		})
	}

	response, err := h.apiKeyService.CreateKey(userID, input)
	if err != nil {
		if errors.Is(err, services.ErrMaxKeysReached) {
			return c.Status(fiber.StatusConflict).JSON(ErrorResponse{
				Error:   "Conflict",
				Message: "Maximum number of API keys reached (10)",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error:   "Internal Server Error",
			Message: "Failed to create API key",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(response)
}

// RevokeKey godoc
// @Summary Revoke API key
// @Description Deactivate an existing API key
// @Tags API Keys
// @Security BearerAuth
// @Param id path string true "API Key ID"
// @Success 204 "No Content"
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api-keys/{id} [delete]
func (h *APIKeyHandler) RevokeKey(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)

	keyIDStr := c.Params("id")
	keyID, err := uuid.Parse(keyIDStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "Bad Request",
			Message: "Invalid API key ID",
		})
	}

	if err := h.apiKeyService.RevokeKey(keyID, userID); err != nil {
		if errors.Is(err, services.ErrKeyNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
				Error:   "Not Found",
				Message: "API key not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error:   "Internal Server Error",
			Message: "Failed to revoke API key",
		})
	}

	return c.SendStatus(fiber.StatusNoContent)
}
