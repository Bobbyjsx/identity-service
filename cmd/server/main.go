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

	"identity-service/internal/config"
	"identity-service/internal/database"
	"identity-service/internal/handlers"
	"identity-service/internal/services"
)

func main() {
	cfg := config.Load()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dbClient, err := database.NewFirestoreClient(ctx, cfg)
	if err != nil {
		log.Fatalf("Failed to initialize Firestore client: %v", err)
	}
	defer dbClient.Close()

	keyManager := services.NewKeyManager(cfg)
	if err := keyManager.Initialize(ctx, dbClient); err != nil {
		log.Fatalf("Failed to initialize KeyManager: %v", err)
	}

	appService := services.NewApplicationService(dbClient)
	authService := services.NewAuthService(cfg, dbClient, appService, keyManager)
	notifService := services.NewLoggingNotificationService()
	oauthService := services.NewOAuthService(cfg, dbClient, appService, authService, keyManager, notifService)
	rbacService := services.NewRBACService(dbClient)

	server := handlers.NewServer(cfg, appService, authService, oauthService, rbacService, keyManager)
	router := server.Routes()

	addr := fmt.Sprintf("0.0.0.0:%s", cfg.Port)
	httpServer := &http.Server{
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("Starting Identity Service (Go) on %s", addr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exiting")
}
