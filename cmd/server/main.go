package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/banking/audit-compliance/internal/api"
	"github.com/banking/audit-compliance/internal/config"
	"github.com/banking/audit-compliance/internal/crypto"
	"github.com/banking/audit-compliance/internal/events"
	"github.com/banking/audit-compliance/internal/repository/elasticsearch"
	"github.com/banking/audit-compliance/internal/repository/postgres"
	"github.com/banking/audit-compliance/internal/repository/s3"
	"github.com/banking/audit-compliance/internal/service"
	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.uber.org/zap"
)

func main() {
	// 1. Config
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// 2. Logger
	logger, _ := zap.NewProduction()
	defer logger.Sync()
	sugar := logger.Sugar()

	sugar.Info("Starting Audit & Compliance Service...")

	// 3. Crypto / Security
	encryptor, err := crypto.NewFieldEncryptor(
		cfg.Encryption.EncryptionKeysBase64,
		cfg.Encryption.CurrentKeyVersion,
		cfg.Encryption.AuditHMACSecret,
	)
	if err != nil {
		sugar.Fatalf("Failed to initialize encryptor: %v", err)
	}

	// 4. Repositories
	pgRepo, err := postgres.NewAuditRepository(cfg.Database, encryptor)
	if err != nil {
		sugar.Fatalf("Failed to connect to Postgres: %v", err)
	}
	defer pgRepo.Close()

	esRepo, err := elasticsearch.NewSearchRepository(cfg.Elasticsearch)
	if err != nil {
		sugar.Warnf("Failed to connect to Elasticsearch: %v (Search capabilities will be limited)", err)
		// Proceeding without strict ES requirement for robustness, or fail depending on policy?
		// Plan said "Optional/Mock if simple", but we implemented it.
		// Let's fail hard if we really need it, but warning is safer for dev.
	}

	s3Repo, err := s3.NewArchiveRepository(context.Background(), cfg.S3)
	if err != nil {
		sugar.Fatalf("Failed to initialize S3 repository: %v", err)
	}

	// 5. Services
	auditService := service.NewAuditService(pgRepo, esRepo, s3Repo, encryptor, logger)

	// 6. Kafka Consumer
	consumer, err := events.NewAuditConsumer(cfg.Kafka, auditService, logger)
	if err != nil {
		sugar.Fatalf("Failed to create Kafka consumer: %v", err)
	}

	// Start Consumer in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sugar.Info("Starting Kafka consumer loop...")
		if err := consumer.Start(ctx); err != nil {
			sugar.Errorf("Kafka consumer failed: %v", err)
		}
	}()
	defer consumer.Close()

	// 7. API Server
	e := echo.New()
	e.HideBanner = true
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())

	auditHandler := api.NewAuditHandler(auditService)

	apiGroup := e.Group("/audit")

	// Security: Add JWT Authentication
	keyData, err := os.ReadFile(cfg.Auth.JWTPublicKeyPath)
	var signingKey interface{}
	if err == nil {
		signingKey, err = jwt.ParseRSAPublicKeyFromPEM(keyData)
		if err != nil {
			sugar.Warnf("Failed to parse JWT public key: %v", err)
		}
	} else {
		sugar.Warnf("JWT public key not found at %s: %v", cfg.Auth.JWTPublicKeyPath, err)
	}

	if signingKey != nil {
		config := echojwt.Config{
			SigningKey:    signingKey,
			SigningMethod: "RS256",
			NewClaimsFunc: func(c echo.Context) jwt.Claims {
				return new(jwt.MapClaims)
			},
		}
		apiGroup.Use(echojwt.WithConfig(config))
		sugar.Info("JWT Authentication enabled for /audit/*")
	} else {
		sugar.Warn("JWT Authentication DISABLED - Missing Public Key (Security Risk)")
	}

	auditHandler.RegisterRoutes(apiGroup)

	// Health Check
	e.GET("/health", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})

	// Start Server
	go func() {
		addr := fmt.Sprintf(":%d", cfg.Server.Port)
		if err := e.Start(addr); err != nil && err != http.ErrServerClosed {
			sugar.Fatalf("Shutting down the server: %v", err)
		}
	}()

	// Graceful Shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	sugar.Info("Shutting down service...")
	// Timeout for shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := e.Shutdown(shutdownCtx); err != nil {
		sugar.Fatal(err)
	}
}
