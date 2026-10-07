package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"google.golang.org/api/iterator"
	"identity-service/internal/config"
	"identity-service/internal/database"
)

func main() {
	_ = os.Unsetenv("FIRESTORE_EMULATOR_HOST")
	os.Setenv("ENVIRONMENT", "production")

	cfg := config.Load()
	ctx := context.Background()

	client, err := database.NewFirestoreClient(ctx, cfg)
	if err != nil {
		log.Fatalf("Failed to initialize Firestore: %v", err)
	}
	defer client.Close()

	collections := []string{"applications", "application_credentials", "users", "refresh_tokens", "roles", "permissions", "auth_sessions", "authorization_codes", "password_reset_tokens", "email_verification_tokens"}
	for _, collName := range collections {
		fmt.Printf("Deleting collection: %s\n", collName)
		coll := client.Collection(collName)
		iter := coll.Limit(500).Documents(ctx)
		for {
			doc, err := iter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				log.Printf("Error iterating %s: %v", collName, err)
				break
			}
			fmt.Printf("Deleting doc %s\n", doc.Ref.ID)
			_, _ = doc.Ref.Delete(ctx)
		}
	}
	fmt.Println("Done dropping documents.")
}
