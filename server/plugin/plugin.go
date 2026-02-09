package plugin

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/gorilla/mux"
	"github.com/mattermost/mattermost/server/public/model"
	mmPlugin "github.com/mattermost/mattermost/server/public/plugin"

	"github.com/dgwhited/mattermost-plugin-aws-jit-access/server/api"
	jithmac "github.com/dgwhited/mattermost-plugin-aws-jit-access/server/hmac"
)

// configuration holds the plugin settings from the Mattermost system console.
type configuration struct {
	BackendAPIURL         string `json:"BackendAPIURL" yaml:"BackendAPIURL"`
	SigningKeyID          string `json:"SigningKeyID" yaml:"SigningKeyID"`
	SigningKeySecret      string `json:"SigningKeySecret" yaml:"SigningKeySecret"`
	CallbackSigningSecret string `json:"CallbackSigningSecret" yaml:"CallbackSigningSecret"`
}

// isValid checks that the minimum required settings are present.
func (c *configuration) isValid() error {
	if c.BackendAPIURL == "" {
		return fmt.Errorf("BackendAPIURL must be configured")
	}
	return nil
}

// Plugin implements the Mattermost plugin interface.
type Plugin struct {
	mmPlugin.MattermostPlugin

	// configurationLock synchronises access to the configuration.
	configurationLock sync.RWMutex

	// config is the active plugin configuration.
	config *configuration

	// router is the HTTP router for handling API requests.
	router *mux.Router

	// signer signs outbound requests to the backend.
	signer *jithmac.Signer

	// validator validates inbound webhook callbacks from the backend.
	validator *jithmac.Validator

	// apiClient is the backend API client.
	apiClient *api.Client
}

// OnActivate is called when the plugin is activated.
func (p *Plugin) OnActivate() error {
	if err := p.OnConfigurationChange(); err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	p.router = p.initRouter()

	// Register the /jit slash command.
	if err := p.API.RegisterCommand(&model.Command{
		Trigger:          "jit",
		DisplayName:      "JIT Access",
		Description:      "Just-In-Time AWS access management",
		AutoComplete:     true,
		AutoCompleteDesc: "Manage JIT AWS access requests",
		AutoCompleteHint: "[request|bind|approvers|revoke|status|info|help]",
	}); err != nil {
		return fmt.Errorf("failed to register /jit command: %w", err)
	}

	return nil
}

// initRouter initialises the HTTP router with all plugin endpoints.
func (p *Plugin) initRouter() *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc("/webhook", p.handleWebhook).Methods(http.MethodPost)
	r.HandleFunc("/api/v1/request-dialog", p.handleSubmitDialogRequest).Methods(http.MethodPost)
	r.HandleFunc("/api/v1/action", p.handlePostAction).Methods(http.MethodPost)
	r.HandleFunc("/api/v1/deny-dialog", p.handleDenyDialogSubmit).Methods(http.MethodPost)
	return r
}

// OnDeactivate is called when the plugin is deactivated.
func (p *Plugin) OnDeactivate() error {
	return nil
}

// OnConfigurationChange reloads the plugin configuration from the Mattermost
// system console settings and reinitialises the HMAC signer, validator, and
// API client.
func (p *Plugin) OnConfigurationChange() error {
	var cfg configuration
	if err := p.API.LoadPluginConfiguration(&cfg); err != nil {
		return fmt.Errorf("failed to load plugin configuration: %w", err)
	}

	p.configurationLock.Lock()
	defer p.configurationLock.Unlock()

	p.config = &cfg

	// Initialise the HMAC signer for outbound requests.
	if cfg.SigningKeyID != "" && cfg.SigningKeySecret != "" {
		p.signer = jithmac.NewSigner(cfg.SigningKeyID, cfg.SigningKeySecret)
	} else {
		p.signer = nil
	}

	// Initialise the HMAC validator for inbound webhooks.
	if cfg.CallbackSigningSecret != "" {
		secrets := map[string]string{
			"backend": cfg.CallbackSigningSecret,
		}
		p.validator = jithmac.NewValidator(secrets)
	} else {
		p.validator = nil
		p.API.LogWarn("CallbackSigningSecret is empty — inbound webhooks will be rejected (fail-closed)")
	}

	// Initialise the backend API client.
	if cfg.BackendAPIURL != "" && p.signer != nil {
		p.apiClient = api.NewClient(cfg.BackendAPIURL, p.signer)
	} else if cfg.BackendAPIURL != "" {
		p.apiClient = api.NewClient(cfg.BackendAPIURL, nil)
	} else {
		p.apiClient = nil
	}

	return nil
}

// getConfiguration returns the current plugin configuration.
func (p *Plugin) getConfiguration() *configuration {
	p.configurationLock.RLock()
	defer p.configurationLock.RUnlock()

	if p.config == nil {
		return &configuration{}
	}

	// Return a copy to avoid races.
	cfg := *p.config
	return &cfg
}

// getAPIClient returns the current backend API client. It returns nil if the
// plugin is not fully configured.
func (p *Plugin) getAPIClient() *api.Client {
	p.configurationLock.RLock()
	defer p.configurationLock.RUnlock()
	return p.apiClient
}

// getValidator returns the current HMAC validator.
func (p *Plugin) getValidator() *jithmac.Validator {
	p.configurationLock.RLock()
	defer p.configurationLock.RUnlock()
	return p.validator
}

// isSystemAdmin checks whether the given user ID belongs to a system admin.
func (p *Plugin) isSystemAdmin(userID string) bool {
	user, appErr := p.API.GetUser(userID)
	if appErr != nil {
		return false
	}
	return user.IsSystemAdmin()
}
