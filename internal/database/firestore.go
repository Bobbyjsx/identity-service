package database

import (
	"context"
	"os"

	"cloud.google.com/go/firestore"
	"google.golang.org/api/option"
	"identity-service/internal/config"
)

func NewFirestoreClient(ctx context.Context, cfg *config.Config) (*firestore.Client, error) {
	projectID := cfg.GoogleCloudProject
	if projectID == "" {
		projectID = "test-project"
	}

	databaseID := cfg.FirestoreDatabase
	if databaseID == "" {
		databaseID = "(default)"
	}

	var opts []option.ClientOption

	emulatorHost := cfg.FirestoreEmulatorHost
	if emulatorHost == "" {
		emulatorHost = os.Getenv("FIRESTORE_EMULATOR_HOST")
	}

	if emulatorHost != "" {
		// When using emulator, skip auth credentials
		opts = append(opts, option.WithoutAuthentication())
	} else if cfg.FirebaseCredentialsJSON != "" {
		opts = append(opts, option.WithCredentialsJSON([]byte(cfg.FirebaseCredentialsJSON)))
	} else if cfg.GoogleApplicationCredentials != "" {
		if _, err := os.Stat(cfg.GoogleApplicationCredentials); err == nil {
			opts = append(opts, option.WithCredentialsFile(cfg.GoogleApplicationCredentials))
		}
	}

	return firestore.NewClientWithDatabase(ctx, projectID, databaseID, opts...)
}
