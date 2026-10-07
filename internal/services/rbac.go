package services

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/google/uuid"
	"google.golang.org/api/iterator"

	"identity-service/internal/core"
	"identity-service/internal/models"
)

type RBACService struct {
	db *firestore.Client
}

func NewRBACService(db *firestore.Client) *RBACService {
	return &RBACService{db: db}
}

type PermissionCreateRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type RoleCreateRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

func (s *RBACService) CreatePermission(ctx context.Context, appID string, req PermissionCreateRequest) (*models.Permission, error) {
	iter := s.db.Collection("permissions").
		Where("app_id", "==", appID).
		Where("name", "==", req.Name).
		Limit(1).
		Documents(ctx)
	defer iter.Stop()

	if doc, err := iter.Next(); err == nil && doc != nil {
		return nil, core.NewHTTPError(http.StatusBadRequest, "Permission already exists")
	}

	permID := strings.ReplaceAll(uuid.New().String(), "-", "")
	now := time.Now().UTC().Format(time.RFC3339)

	perm := models.Permission{
		ID:          permID,
		AppID:       appID,
		Name:        req.Name,
		Description: req.Description,
		CreatedAt:   now,
	}

	if _, err := s.db.Collection("permissions").Doc(permID).Set(ctx, perm); err != nil {
		return nil, err
	}

	return &perm, nil
}

func (s *RBACService) GetPermissions(ctx context.Context, appID string) ([]models.Permission, error) {
	iter := s.db.Collection("permissions").Where("app_id", "==", appID).Documents(ctx)
	defer iter.Stop()

	var results []models.Permission
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		var p models.Permission
		if err := doc.DataTo(&p); err == nil {
			p.ID = doc.Ref.ID
			results = append(results, p)
		}
	}
	if results == nil {
		results = []models.Permission{}
	}
	return results, nil
}

func (s *RBACService) CreateRole(ctx context.Context, appID string, req RoleCreateRequest) (*models.Role, error) {
	iter := s.db.Collection("roles").
		Where("app_id", "==", appID).
		Where("name", "==", req.Name).
		Limit(1).
		Documents(ctx)
	defer iter.Stop()

	if doc, err := iter.Next(); err == nil && doc != nil {
		return nil, core.NewHTTPError(http.StatusBadRequest, "Role already exists")
	}

	if len(req.Permissions) > 0 {
		perms, err := s.GetPermissions(ctx, appID)
		if err != nil {
			return nil, err
		}
		permMap := make(map[string]bool)
		for _, p := range perms {
			permMap[p.Name] = true
		}
		for _, pName := range req.Permissions {
			if !permMap[pName] {
				return nil, core.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Permission %s does not exist", pName))
			}
		}
	}

	roleID := strings.ReplaceAll(uuid.New().String(), "-", "")
	now := time.Now().UTC().Format(time.RFC3339)

	permissions := req.Permissions
	if permissions == nil {
		permissions = []string{}
	}

	role := models.Role{
		ID:          roleID,
		AppID:       appID,
		Name:        req.Name,
		Description: req.Description,
		Permissions: permissions,
		CreatedAt:   now,
	}

	if _, err := s.db.Collection("roles").Doc(roleID).Set(ctx, role); err != nil {
		return nil, err
	}

	return &role, nil
}

func (s *RBACService) GetRoles(ctx context.Context, appID string) ([]models.Role, error) {
	iter := s.db.Collection("roles").Where("app_id", "==", appID).Documents(ctx)
	defer iter.Stop()

	var results []models.Role
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		var r models.Role
		if err := doc.DataTo(&r); err == nil {
			r.ID = doc.Ref.ID
			results = append(results, r)
		}
	}
	if results == nil {
		results = []models.Role{}
	}
	return results, nil
}
