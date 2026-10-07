package tests

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnauthorizedApplicationCreation(t *testing.T) {
	h := setup(t)

	resp := h.Client.Post("/api/v1/admin/applications", map[string]string{
		"name": "Test App",
	}, map[string]string{
		"X-Admin-Token": "wrong_token",
	})
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, "Invalid admin token", resp.JSONMap()["detail"])
}

func TestAuthorizedApplicationCreation(t *testing.T) {
	h := setup(t)

	resp := h.Client.Post("/api/v1/admin/applications", map[string]string{
		"name": "Test App",
	}, map[string]string{
		"X-Admin-Token": h.Config.AdminSecret,
	})
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	data := resp.JSONMap()
	assert.NotEmpty(t, data["client_id"])
	assert.NotEmpty(t, data["client_secret"])
}

func TestApplicationConfigDefaults(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", nil, "")

	resp := h.Client.Get(fmt.Sprintf("/api/v1/applications/%s/configuration", appData["client_id"]), nil, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	config := resp.JSONMap()

	assert.Equal(t, appData["name"], config["name"])
	assert.Equal(t, true, config["allow_signup"])
	assert.Equal(t, true, config["allow_password_login"])
	assert.Equal(t, false, config["require_email_verification"])
	assert.Equal(t, []interface{}{"openid", "profile", "email"}, config["allowed_scopes"])
	assert.Nil(t, config["client_type"])
	assert.Nil(t, config["client_secret"])
	assert.Nil(t, config["redirect_uris"])
	assert.Nil(t, config["logo_url"])
	assert.Nil(t, config["primary_color"])
	assert.Equal(t, []interface{}{"light", "dark"}, config["themes"])
	assert.Nil(t, config["theme"])
}

func TestApplicationConfigPersisted(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", map[string]interface{}{
		"branding": map[string]interface{}{
			"logo_url":        "https://cdn.example.com/logo.png",
			"primary_color":   "#112233",
			"secondary_color": "#445566",
		},
		"authentication": map[string]interface{}{
			"allow_signup":               false,
			"allow_password_login":       true,
			"require_email_verification": true,
		},
		"oauth": map[string]interface{}{
			"redirect_uris":  []string{RedirectURI, "http://localhost:3000/callback"},
			"allowed_scopes": []string{"openid", "email"},
			"allowed_grants": []string{"authorization_code"},
		},
	}, "")

	resp := h.Client.Get(fmt.Sprintf("/api/v1/applications/%s/configuration", appData["client_id"]), nil, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	config := resp.JSONMap()

	assert.Equal(t, "https://cdn.example.com/logo.png", config["logo_url"])
	assert.Equal(t, "#112233", config["primary_color"])
	assert.Equal(t, "#445566", config["secondary_color"])
	assert.Equal(t, false, config["allow_signup"])
	assert.Equal(t, true, config["require_email_verification"])
	assert.Equal(t, []interface{}{"openid", "email"}, config["allowed_scopes"])
}

func TestApplicationConfigValidationRejectsDangerousValues(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", nil, "")

	cases := []map[string]interface{}{
		{"branding": map[string]interface{}{"logo_url": "javascript:alert(1)"}},
		{"branding": map[string]interface{}{"primary_color": "red"}},
		{"oauth": map[string]interface{}{"redirect_uris": []string{"https://evil.example.com/*"}}},
		{"oauth": map[string]interface{}{"redirect_uris": []string{"javascript:alert(1)"}}},
		{"oauth": map[string]interface{}{"redirect_uris": []string{"data:text/html,<script>"}}},
		{"oauth": map[string]interface{}{"redirect_uris": []string{"file:///etc/passwd"}}},
		{"oauth": map[string]interface{}{"redirect_uris": []string{"https://example.com/cb#fragment"}}},
		{"oauth": map[string]interface{}{"redirect_uris": []string{"http://notlocalhost.example.com/cb"}}},
		{"oauth": map[string]interface{}{"allowed_scopes": []string{"admin:everything"}}},
		{"oauth": map[string]interface{}{"allowed_scopes": []string{"offline_access"}}},
		{"oauth": map[string]interface{}{"allowed_grants": []string{"password"}}},
		{"name": "<script>alert(1)</script>"},
		{"description": "ok <img src=x onerror=alert(1)>"},
		{"client_type": "trusted"},
	}

	for _, c := range cases {
		resp := h.Client.Patch(
			fmt.Sprintf("/api/v1/admin/applications/%s/configuration", appData["client_id"]),
			c,
			map[string]string{"X-Admin-Token": h.Config.AdminSecret},
		)
		assert.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode, "case %v should be rejected with 422: %s", c, resp.Text())
	}
}

func TestApplicationConfigAdminRequired(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", nil, "")

	for _, headers := range []map[string]string{nil, {"X-Admin-Token": "wrong_token"}} {
		resp := h.Client.Patch(
			fmt.Sprintf("/api/v1/admin/applications/%s/configuration", appData["client_id"]),
			map[string]interface{}{"branding": map[string]interface{}{"primary_color": "#000000"}},
			headers,
		)
		assert.Contains(t, []int{http.StatusForbidden, http.StatusUnprocessableEntity}, resp.StatusCode)

		configResp := h.Client.Get(fmt.Sprintf("/api/v1/applications/%s/configuration", appData["client_id"]), nil, nil)
		assert.Nil(t, configResp.JSONMap()["primary_color"])
	}
}

func TestApplicationConfigPartialUpdateMerges(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", nil, "")
	clientID := appData["client_id"].(string)

	resp1 := h.Client.Patch(
		fmt.Sprintf("/api/v1/admin/applications/%s/configuration", clientID),
		map[string]interface{}{"branding": map[string]interface{}{"primary_color": "#aabbcc"}},
		map[string]string{"X-Admin-Token": h.Config.AdminSecret},
	)
	require.Equal(t, http.StatusOK, resp1.StatusCode)

	resp2 := h.Client.Patch(
		fmt.Sprintf("/api/v1/admin/applications/%s/configuration", clientID),
		map[string]interface{}{"authentication": map[string]interface{}{"allow_signup": false}},
		map[string]string{"X-Admin-Token": h.Config.AdminSecret},
	)
	require.Equal(t, http.StatusOK, resp2.StatusCode)

	config := h.Client.Get(fmt.Sprintf("/api/v1/applications/%s/configuration", clientID), nil, nil).JSONMap()
	assert.Equal(t, "#aabbcc", config["primary_color"])
	assert.Equal(t, false, config["allow_signup"])
	assert.Equal(t, true, config["allow_password_login"])
}

func TestPublicConfigurationUnknownClient(t *testing.T) {
	h := setup(t)

	resp := h.Client.Get("/api/v1/applications/nonexistent/configuration", nil, nil)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Equal(t, "invalid_client", resp.JSONMap()["error"])
}

func TestApplicationThemeConfiguration(t *testing.T) {
	h := setup(t)

	appLight := createApplication(t, h, "", map[string]interface{}{
		"branding": map[string]interface{}{"themes": []string{"light"}},
	}, "")
	confLight := h.Client.Get(fmt.Sprintf("/api/v1/applications/%s/configuration", appLight["client_id"]), nil, nil).JSONMap()
	assert.Equal(t, []interface{}{"light"}, confLight["themes"])
	assert.Nil(t, confLight["theme"])

	appDark := createApplication(t, h, "", map[string]interface{}{
		"theme": []string{"dark"},
	}, "")
	confDark := h.Client.Get(fmt.Sprintf("/api/v1/applications/%s/configuration", appDark["client_id"]), nil, nil).JSONMap()
	assert.Equal(t, []interface{}{"dark"}, confDark["themes"])
	assert.Nil(t, confDark["theme"])

	updateResp := h.Client.Patch(
		fmt.Sprintf("/api/v1/admin/applications/%s/configuration", appLight["client_id"]),
		map[string]interface{}{"branding": map[string]interface{}{"themes": []string{"dark", "light"}}},
		map[string]string{"X-Admin-Token": h.Config.AdminSecret},
	)
	require.Equal(t, http.StatusOK, updateResp.StatusCode)
	confUpdated := h.Client.Get(fmt.Sprintf("/api/v1/applications/%s/configuration", appLight["client_id"]), nil, nil).JSONMap()
	assert.ElementsMatch(t, []interface{}{"light", "dark"}, confUpdated["themes"].([]interface{}))

	badResp := h.Client.Patch(
		fmt.Sprintf("/api/v1/admin/applications/%s/configuration", appLight["client_id"]),
		map[string]interface{}{"branding": map[string]interface{}{"themes": []string{"neon"}}},
		map[string]string{"X-Admin-Token": h.Config.AdminSecret},
	)
	assert.Equal(t, http.StatusUnprocessableEntity, badResp.StatusCode)
}
