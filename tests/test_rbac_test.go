package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRBACFlow(t *testing.T) {
	h := setup(t)

	// 1. Create an application
	appResp := h.Client.Post("/api/v1/admin/applications", map[string]interface{}{
		"name": "Test App",
	}, map[string]string{
		"X-Admin-Token": h.Config.AdminSecret,
	})
	require.Equal(t, 200, appResp.StatusCode)
	appData := appResp.JSONMap()
	clientID := appData["client_id"].(string)

	// 2. Create permissions
	perm1Resp := h.Client.Post("/api/v1/rbac/permissions", map[string]interface{}{
		"name":        "read:documents",
		"description": "Read documents",
	}, map[string]string{
		"X-Application-Id": clientID,
	})
	assert.Equal(t, 200, perm1Resp.StatusCode)

	perm2Resp := h.Client.Post("/api/v1/rbac/permissions", map[string]interface{}{
		"name":        "write:documents",
		"description": "Write documents",
	}, map[string]string{
		"X-Application-Id": clientID,
	})
	assert.Equal(t, 200, perm2Resp.StatusCode)

	// 3. Create a role with a valid permission
	roleResp := h.Client.Post("/api/v1/rbac/roles", map[string]interface{}{
		"name":        "document_reader",
		"permissions": []string{"read:documents"},
	}, map[string]string{
		"X-Application-Id": clientID,
	})
	assert.Equal(t, 200, roleResp.StatusCode)
	roleData := roleResp.JSONMap()
	permissions := roleData["permissions"].([]interface{})
	assert.Contains(t, permissions, "read:documents")

	// 4. Try to create a role with invalid permission
	roleInvalidResp := h.Client.Post("/api/v1/rbac/roles", map[string]interface{}{
		"name":        "document_writer",
		"permissions": []string{"delete:documents"},
	}, map[string]string{
		"X-Application-Id": clientID,
	})
	assert.Equal(t, 400, roleInvalidResp.StatusCode)
	invalidData := roleInvalidResp.JSONMap()
	assert.Contains(t, invalidData["detail"].(string), "delete:documents does not exist")

	// 5. List roles
	listRolesResp := h.Client.Get("/api/v1/rbac/roles", nil, map[string]string{
		"X-Application-Id": clientID,
	})
	assert.Equal(t, 200, listRolesResp.StatusCode)
	var roles []map[string]interface{}
	listRolesResp.JSON(&roles)
	assert.Len(t, roles, 1)
	assert.Equal(t, "document_reader", roles[0]["name"])
}
