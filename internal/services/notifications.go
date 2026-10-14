package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"cloud.google.com/go/pubsub"
	"github.com/google/uuid"
	"google.golang.org/api/option"

	"identity-service/internal/config"
)

type NotificationService interface {
	SendPasswordResetEmail(ctx context.Context, to, resetURL, appName, appID string, firstName *string) error
	SendWelcomeEmail(ctx context.Context, to, appName, appID string, firstName *string) error
	SendVerificationEmail(ctx context.Context, to, otp, appName, appID string, firstName *string) error
}

type LoggingNotificationService struct{}

func NewLoggingNotificationService() *LoggingNotificationService {
	return &LoggingNotificationService{}
}

func (s *LoggingNotificationService) SendPasswordResetEmail(ctx context.Context, to, resetURL, appName, appID string, firstName *string) error {
	log.Printf("[NotificationService][dev] to=%s subject=%s: reset your password\nReset your password by visiting: %s\n", to, appName, resetURL)
	return nil
}

func (s *LoggingNotificationService) SendWelcomeEmail(ctx context.Context, to, appName, appID string, firstName *string) error {
	log.Printf("[NotificationService][dev] to=%s subject=Welcome to %s\nWelcome!\n", to, appName)
	return nil
}

func (s *LoggingNotificationService) SendVerificationEmail(ctx context.Context, to, otp, appName, appID string, firstName *string) error {
	log.Printf("[NotificationService][dev] to=%s subject=%s: verify your email\nYour email verification code is: %s\n", to, appName, otp)
	return nil
}

type PubSubNotificationService struct {
	client    *pubsub.Client
	topic     *pubsub.Topic
	projectID string
	topicID   string
}

func NewPubSubNotificationService(ctx context.Context, cfg *config.Config) (*PubSubNotificationService, error) {
	projectID := cfg.GCPProjectID
	if projectID == "" {
		projectID = "project-atlas-501612"
	}
	topicID := cfg.PubSubTopicID
	if topicID == "" {
		topicID = "platform-events"
	}

	var opts []option.ClientOption
	if cfg.FirebaseCredentialsJSON != "" {
		opts = append(opts, option.WithCredentialsJSON([]byte(cfg.FirebaseCredentialsJSON)))
	} else if cfg.GoogleApplicationCredentials != "" {
		if _, err := os.Stat(cfg.GoogleApplicationCredentials); err == nil {
			opts = append(opts, option.WithCredentialsFile(cfg.GoogleApplicationCredentials))
		}
	}

	client, err := pubsub.NewClient(ctx, projectID, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create pubsub client: %w", err)
	}

	topic := client.Topic(topicID)
	return &PubSubNotificationService{
		client:    client,
		topic:     topic,
		projectID: projectID,
		topicID:   topicID,
	}, nil
}

func (s *PubSubNotificationService) Close() error {
	if s.topic != nil {
		s.topic.Stop()
	}
	if s.client != nil {
		return s.client.Close()
	}
	return nil
}

func (s *PubSubNotificationService) publishEvent(ctx context.Context, eventType, appID string, data map[string]interface{}, subject *string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	eventID := fmt.Sprintf("evt-%s", strings.ReplaceAll(uuid.New().String(), "-", ""))

	source := appID
	if source == "" {
		source = "identity-service"
	}

	event := map[string]interface{}{
		"id":        eventID,
		"type":      eventType,
		"version":   1,
		"source":    source,
		"timestamp": now,
		"data":      data,
	}
	if subject != nil && *subject != "" {
		event["subject"] = *subject
	}

	payload, err := json.Marshal(event)
	if err != nil {
		log.Printf("[PubSubNotificationService] Error marshaling event: %v", err)
		return err
	}

	result := s.topic.Publish(ctx, &pubsub.Message{
		Data: payload,
	})

	pubCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	msgID, err := result.Get(pubCtx)
	if err != nil {
		log.Printf("[PubSubNotificationService] Failed to publish %s event to Pub/Sub: %v", eventType, err)
		return nil // Non-blocking
	}

	log.Printf("[PubSubNotificationService] Published %s event to Pub/Sub with message ID: %s", eventType, msgID)
	return nil
}

func (s *PubSubNotificationService) SendPasswordResetEmail(ctx context.Context, to, resetURL, appName, appID string, firstName *string) error {
	data := map[string]interface{}{
		"email":              to,
		"reset_url":          resetURL,
		"app_name":           appName,
		"expiration_minutes": 30,
	}
	if firstName != nil && *firstName != "" {
		data["first_name"] = *firstName
	}
	return s.publishEvent(ctx, "user.password_reset_requested", appID, data, nil)
}

func (s *PubSubNotificationService) SendVerificationEmail(ctx context.Context, to, otp, appName, appID string, firstName *string) error {
	data := map[string]interface{}{
		"email":              to,
		"otp":                otp,
		"app_name":           appName,
		"expiration_minutes": 30,
	}
	if firstName != nil && *firstName != "" {
		data["first_name"] = *firstName
	}
	return s.publishEvent(ctx, "user.email_verification_requested", appID, data, nil)
}

func (s *PubSubNotificationService) SendWelcomeEmail(ctx context.Context, to, appName, appID string, firstName *string) error {
	data := map[string]interface{}{
		"email":    to,
		"title":    fmt.Sprintf("Welcome to %s", appName),
		"body":     fmt.Sprintf("Welcome to %s! Your email has been successfully verified.", appName),
		"app_name": appName,
	}
	if firstName != nil && *firstName != "" {
		data["first_name"] = *firstName
	}
	subj := fmt.Sprintf("Welcome to %s!", appName)
	return s.publishEvent(ctx, "general.notification", appID, data, &subj)
}
