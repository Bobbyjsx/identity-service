package services

import (
	"context"
	"log"
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
