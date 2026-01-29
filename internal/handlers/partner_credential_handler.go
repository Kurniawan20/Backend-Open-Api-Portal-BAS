package handlers

import (
	"errors"

	"github.com/bankaceh/bas-portal-api/internal/middleware"
	"github.com/bankaceh/bas-portal-api/internal/services"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// PartnerCredentialHandler handles partner credential endpoints
type PartnerCredentialHandler struct {
	service *services.PartnerCredentialService
}

// NewPartnerCredentialHandler creates a new PartnerCredentialHandler
func NewPartnerCredentialHandler(service *services.PartnerCredentialService) *PartnerCredentialHandler {
	return &PartnerCredentialHandler{service: service}
}

// ListCredentials godoc
// @Summary List partner credentials
// @Description Get all SNAP partner credentials for the authenticated user
// @Tags Partner Credentials
// @Security BearerAuth
// @Produce json
// @Success 200 {array} models.PartnerCredentialResponse
// @Failure 401 {object} ErrorResponse
// @Router /partner-credentials [get]
func (h *PartnerCredentialHandler) ListCredentials(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)

	credentials, err := h.service.ListCredentials(userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error:   "Internal Server Error",
			Message: "Failed to retrieve partner credentials",
		})
	}

	return c.JSON(credentials)
}

// GetCredential godoc
// @Summary Get partner credential details
// @Description Get a single SNAP partner credential with full details
// @Tags Partner Credentials
// @Security BearerAuth
// @Produce json
// @Param id path string true "Credential ID"
// @Success 200 {object} models.PartnerCredentialDetailResponse
// @Failure 401 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /partner-credentials/{id} [get]
func (h *PartnerCredentialHandler) GetCredential(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)

	idStr := c.Params("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "Bad Request",
			Message: "Invalid credential ID",
		})
	}

	credential, err := h.service.GetCredential(id, userID)
	if err != nil {
		if errors.Is(err, services.ErrCredentialNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
				Error:   "Not Found",
				Message: "Partner credential not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error:   "Internal Server Error",
			Message: "Failed to retrieve partner credential",
		})
	}

	return c.JSON(credential)
}

// CreateCredential godoc
// @Summary Create partner credential
// @Description Create a new SNAP partner credential with auto-generated Client ID and Secret
// @Tags Partner Credentials
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param input body services.CreateCredentialInput true "Credential data"
// @Success 201 {object} models.PartnerCredentialCreateResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Router /partner-credentials [post]
func (h *PartnerCredentialHandler) CreateCredential(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)

	var input services.CreateCredentialInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "Bad Request",
			Message: "Invalid request body",
		})
	}

	if input.PartnerName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "Bad Request",
			Message: "Partner name is required",
		})
	}

	if input.Environment != "" && input.Environment != "sandbox" && input.Environment != "production" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "Bad Request",
			Message: "Environment must be 'sandbox' or 'production'",
		})
	}

	response, err := h.service.CreateCredential(userID, input)
	if err != nil {
		if errors.Is(err, services.ErrMaxCredentialsReached) {
			return c.Status(fiber.StatusConflict).JSON(ErrorResponse{
				Error:   "Conflict",
				Message: "Maximum number of partner credentials reached (5)",
			})
		}
		if errors.Is(err, services.ErrInvalidPublicKey) {
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Error:   "Bad Request",
				Message: "Invalid public key format. Please provide a valid PEM-encoded RSA public key",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error:   "Internal Server Error",
			Message: "Failed to create partner credential",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(response)
}

// UpdateCredential godoc
// @Summary Update partner credential
// @Description Update an existing SNAP partner credential
// @Tags Partner Credentials
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param id path string true "Credential ID"
// @Param input body services.UpdateCredentialInput true "Credential data"
// @Success 200 {object} models.PartnerCredentialResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /partner-credentials/{id} [put]
func (h *PartnerCredentialHandler) UpdateCredential(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)

	idStr := c.Params("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "Bad Request",
			Message: "Invalid credential ID",
		})
	}

	var input services.UpdateCredentialInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "Bad Request",
			Message: "Invalid request body",
		})
	}

	if input.Environment != "" && input.Environment != "sandbox" && input.Environment != "production" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "Bad Request",
			Message: "Environment must be 'sandbox' or 'production'",
		})
	}

	response, err := h.service.UpdateCredential(id, userID, input)
	if err != nil {
		if errors.Is(err, services.ErrCredentialNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
				Error:   "Not Found",
				Message: "Partner credential not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error:   "Internal Server Error",
			Message: "Failed to update partner credential",
		})
	}

	return c.JSON(response)
}

// UpdatePublicKey godoc
// @Summary Update public key
// @Description Update the RSA public key for a SNAP partner credential
// @Tags Partner Credentials
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param id path string true "Credential ID"
// @Param input body services.UpdatePublicKeyInput true "Public key data"
// @Success 200 {object} models.PartnerCredentialResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /partner-credentials/{id}/public-key [put]
func (h *PartnerCredentialHandler) UpdatePublicKey(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)

	idStr := c.Params("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "Bad Request",
			Message: "Invalid credential ID",
		})
	}

	var input services.UpdatePublicKeyInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "Bad Request",
			Message: "Invalid request body",
		})
	}

	if input.PublicKey == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "Bad Request",
			Message: "Public key is required",
		})
	}

	response, err := h.service.UpdatePublicKey(id, userID, input)
	if err != nil {
		if errors.Is(err, services.ErrCredentialNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
				Error:   "Not Found",
				Message: "Partner credential not found",
			})
		}
		if errors.Is(err, services.ErrInvalidPublicKey) {
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Error:   "Bad Request",
				Message: "Invalid public key format. Please provide a valid PEM-encoded RSA public key",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error:   "Internal Server Error",
			Message: "Failed to update public key",
		})
	}

	return c.JSON(response)
}

// RegenerateSecret godoc
// @Summary Regenerate client secret
// @Description Generate a new client secret for a SNAP partner credential
// @Tags Partner Credentials
// @Security BearerAuth
// @Produce json
// @Param id path string true "Credential ID"
// @Success 200 {object} models.PartnerCredentialCreateResponse
// @Failure 401 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /partner-credentials/{id}/regenerate-secret [post]
func (h *PartnerCredentialHandler) RegenerateSecret(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)

	idStr := c.Params("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "Bad Request",
			Message: "Invalid credential ID",
		})
	}

	response, err := h.service.RegenerateSecret(id, userID)
	if err != nil {
		if errors.Is(err, services.ErrCredentialNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
				Error:   "Not Found",
				Message: "Partner credential not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error:   "Internal Server Error",
			Message: "Failed to regenerate client secret",
		})
	}

	return c.JSON(response)
}

// DeleteCredential godoc
// @Summary Delete partner credential
// @Description Delete a SNAP partner credential
// @Tags Partner Credentials
// @Security BearerAuth
// @Param id path string true "Credential ID"
// @Success 204 "No Content"
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /partner-credentials/{id} [delete]
func (h *PartnerCredentialHandler) DeleteCredential(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)

	idStr := c.Params("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "Bad Request",
			Message: "Invalid credential ID",
		})
	}

	if err := h.service.DeleteCredential(id, userID); err != nil {
		if errors.Is(err, services.ErrCredentialNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
				Error:   "Not Found",
				Message: "Partner credential not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error:   "Internal Server Error",
			Message: "Failed to delete partner credential",
		})
	}

	return c.SendStatus(fiber.StatusNoContent)
}
