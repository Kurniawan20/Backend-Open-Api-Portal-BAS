package main

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/joho/godotenv"

	"github.com/bankaceh/bas-portal-api/internal/config"
	"github.com/bankaceh/bas-portal-api/internal/database"
	"github.com/bankaceh/bas-portal-api/internal/handlers"
	"github.com/bankaceh/bas-portal-api/internal/middleware"
	"github.com/bankaceh/bas-portal-api/internal/repository"
	"github.com/bankaceh/bas-portal-api/internal/services"
)

// @title BAS Portal API
// @version 1.0
// @description API for BAS Developer Portal - Authentication, User Management, and API Key Management
// @termsOfService http://swagger.io/terms/

// @contact.name BAS API Support
// @contact.url https://bankaceh.co.id/support
// @contact.email support@bankaceh.co.id

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host localhost:3000
// @BasePath /api/v1

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Enter your bearer token in the format: Bearer {token}

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	// Load configuration
	cfg := config.Load()

	// Initialize database
	db, err := database.Connect(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Run migrations
	if err := database.Migrate(db); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	// Initialize repositories
	userRepo := repository.NewUserRepository(db)
	apiKeyRepo := repository.NewAPIKeyRepository(db)
	partnerCredRepo := repository.NewPartnerCredentialRepository(db)

	// Initialize services
	authService := services.NewAuthService(userRepo, cfg)
	userService := services.NewUserService(userRepo)
	apiKeyService := services.NewAPIKeyService(apiKeyRepo)
	partnerCredService := services.NewPartnerCredentialService(partnerCredRepo)

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(authService)
	userHandler := handlers.NewUserHandler(userService)
	apiKeyHandler := handlers.NewAPIKeyHandler(apiKeyService)
	partnerCredHandler := handlers.NewPartnerCredentialHandler(partnerCredService)

	// Create Fiber app
	app := fiber.New(fiber.Config{
		AppName:      "BAS Portal API v1.0",
		ErrorHandler: handlers.ErrorHandler,
	})

	// Middleware
	app.Use(recover.New())
	app.Use(logger.New())
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://localhost:5173, http://localhost:3001, http://127.0.0.1:5173, http://127.0.0.1:4173",
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization",
		AllowMethods:     "GET, POST, PUT, DELETE, OPTIONS",
		AllowCredentials: true,
	}))

	// Health check
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":  "healthy",
			"service": "bas-portal-api",
		})
	})

	// API v1 routes
	api := app.Group("/api/v1")

	// Auth routes (public)
	auth := api.Group("/auth")
	auth.Post("/register", authHandler.Register)
	auth.Post("/login", authHandler.Login)
	auth.Get("/google", authHandler.GoogleLogin)
	auth.Get("/google/callback", authHandler.GoogleCallback)
	auth.Post("/refresh", authHandler.RefreshToken)

	// Protected routes
	protected := api.Group("", middleware.JWTAuth(cfg.JWTSecret))

	// User routes
	users := protected.Group("/users")
	users.Get("/me", userHandler.GetProfile)
	users.Put("/me", userHandler.UpdateProfile)

	// API Key routes
	apiKeys := protected.Group("/api-keys")
	apiKeys.Get("/", apiKeyHandler.ListKeys)
	apiKeys.Post("/", apiKeyHandler.CreateKey)
	apiKeys.Delete("/:id", apiKeyHandler.RevokeKey)

	// Partner Credential routes (SNAP API)
	partnerCreds := protected.Group("/partner-credentials")
	partnerCreds.Get("/", partnerCredHandler.ListCredentials)
	partnerCreds.Get("/:id", partnerCredHandler.GetCredential)
	partnerCreds.Post("/", partnerCredHandler.CreateCredential)
	partnerCreds.Put("/:id", partnerCredHandler.UpdateCredential)
	partnerCreds.Put("/:id/public-key", partnerCredHandler.UpdatePublicKey)
	partnerCreds.Post("/:id/regenerate-secret", partnerCredHandler.RegenerateSecret)
	partnerCreds.Delete("/:id", partnerCredHandler.DeleteCredential)

	// Start server
	port := cfg.Port
	if port == "" {
		port = "3000"
	}

	log.Printf("🚀 BAS Portal API starting on port %s", port)
	if err := app.Listen(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
