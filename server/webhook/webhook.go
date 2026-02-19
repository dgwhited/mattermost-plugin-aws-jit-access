package webhook

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"

	"github.com/dgwhited/mattermost-plugin-aws-jit-access/server/api"
	jithmac "github.com/dgwhited/mattermost-plugin-aws-jit-access/server/hmac"
)

// Handler processes inbound webhook callbacks from the JIT backend.
type Handler struct {
	api       plugin.API
	validator *jithmac.Validator
}

// NewHandler creates a new webhook Handler.
func NewHandler(api plugin.API, validator *jithmac.Validator) *Handler {
	return &Handler{
		api:       api,
		validator: validator,
	}
}

// ServeHTTP handles inbound webhook requests from the backend.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MB limit
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer func() { _ = r.Body.Close() }()

	// S6: Fail-closed — reject webhooks when HMAC validation is not configured.
	if h.validator == nil {
		h.api.LogError("Webhook rejected: HMAC validator not configured (CallbackSigningSecret is empty)")
		http.Error(w, "Webhook validation not configured", http.StatusServiceUnavailable)
		return
	}

	// Validate HMAC signature.
	headers := map[string]string{
		jithmac.HeaderKeyID:     r.Header.Get(jithmac.HeaderKeyID),
		jithmac.HeaderTimestamp: r.Header.Get(jithmac.HeaderTimestamp),
		jithmac.HeaderNonce:     r.Header.Get(jithmac.HeaderNonce),
		jithmac.HeaderSignature: r.Header.Get(jithmac.HeaderSignature),
	}

	if err := h.validator.ValidateRequest(r.Method, r.URL.Path, headers, body); err != nil {
		h.api.LogWarn("Webhook HMAC validation failed", "error", err.Error())
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse the webhook payload.
	var payload api.WebhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		h.api.LogError("Failed to parse webhook payload", "error", err.Error())
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	if payload.ChannelID == "" {
		h.api.LogError("Webhook payload missing channel_id")
		http.Error(w, "Missing channel_id", http.StatusBadRequest)
		return
	}

	// Route by status.
	switch payload.Status {
	case "GRANTED":
		h.handleGranted(payload)
	case "REVOKED":
		h.handleRevoked(payload)
	case "EXPIRED":
		h.handleExpired(payload)
	case "DENIED":
		h.handleDenied(payload)
	case "ERROR":
		h.handleError(payload)
	default:
		h.api.LogWarn("Unknown webhook status", "status", payload.Status, "request_id", payload.RequestID)
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// detailsToString converts the details map to a human-readable string.
func detailsToString(details map[string]string) string {
	if len(details) == 0 {
		return ""
	}
	parts := make([]string, 0, len(details))
	for k, v := range details {
		parts = append(parts, fmt.Sprintf("%s: %s", k, v))
	}
	return strings.Join(parts, ", ")
}

// handleGranted posts a success message when access has been granted.
func (h *Handler) handleGranted(payload api.WebhookPayload) {
	details := detailsToString(payload.Details)
	if details == "" {
		details = "Access has been provisioned."
	}

	actorInfo := ""
	if payload.Actor != "" {
		actorInfo = fmt.Sprintf(" by **%s**", payload.Actor)
	}

	attachment := &model.SlackAttachment{
		Color:    "#36a64f", // green
		Title:    fmt.Sprintf("Access Granted: %s", payload.RequestID),
		Fallback: fmt.Sprintf("Access granted for request %s", payload.RequestID),
		Text: fmt.Sprintf(
			":white_check_mark: **Access Granted**%s\n\n**Request:** `%s`\n**Account:** `%s`\n\n%s",
			actorInfo, payload.RequestID, payload.AccountID, details,
		),
	}

	h.postAttachment(payload.ChannelID, attachment)
}

// handleRevoked posts a revocation notice.
func (h *Handler) handleRevoked(payload api.WebhookPayload) {
	actorInfo := ""
	if payload.Actor != "" {
		actorInfo = fmt.Sprintf(" by **%s**", payload.Actor)
	}

	details := ""
	if d := detailsToString(payload.Details); d != "" {
		details = fmt.Sprintf("\n**Details:** %s", d)
	}

	attachment := &model.SlackAttachment{
		Color:    "#d9534f", // red
		Title:    fmt.Sprintf("Access Revoked: %s", payload.RequestID),
		Fallback: fmt.Sprintf("Access revoked for request %s", payload.RequestID),
		Text: fmt.Sprintf(
			":rotating_light: **Access Revoked**%s\n\n**Request:** `%s`\n**Account:** `%s`%s",
			actorInfo, payload.RequestID, payload.AccountID, details,
		),
	}

	h.postAttachment(payload.ChannelID, attachment)
}

// handleExpired posts an expiration notice.
func (h *Handler) handleExpired(payload api.WebhookPayload) {
	attachment := &model.SlackAttachment{
		Color:    "#f0ad4e", // yellow
		Title:    fmt.Sprintf("Access Expired: %s", payload.RequestID),
		Fallback: fmt.Sprintf("Access expired for request %s", payload.RequestID),
		Text: fmt.Sprintf(
			":clock4: **Access Expired**\n\n**Request:** `%s`\n**Account:** `%s`\n\nThe temporary access window has ended and permissions have been removed.",
			payload.RequestID, payload.AccountID,
		),
	}

	h.postAttachment(payload.ChannelID, attachment)
}

// handleDenied posts a denial notice.
func (h *Handler) handleDenied(payload api.WebhookPayload) {
	actorInfo := ""
	if payload.Actor != "" {
		actorInfo = fmt.Sprintf(" by **%s**", payload.Actor)
	}

	details := ""
	if d := detailsToString(payload.Details); d != "" {
		details = fmt.Sprintf("\n**Reason:** %s", d)
	}

	attachment := &model.SlackAttachment{
		Color:    "#d9534f", // red
		Title:    fmt.Sprintf("Access Denied: %s", payload.RequestID),
		Fallback: fmt.Sprintf("Access denied for request %s", payload.RequestID),
		Text: fmt.Sprintf(
			":no_entry_sign: **Access Denied**%s\n\n**Request:** `%s`\n**Account:** `%s`%s",
			actorInfo, payload.RequestID, payload.AccountID, details,
		),
	}

	h.postAttachment(payload.ChannelID, attachment)
}

// handleError posts an error notice.
func (h *Handler) handleError(payload api.WebhookPayload) {
	details := detailsToString(payload.Details)
	if details == "" {
		details = "An unknown error occurred while processing the request."
	}

	attachment := &model.SlackAttachment{
		Color:    "#d9534f", // red
		Title:    fmt.Sprintf("Error: %s", payload.RequestID),
		Fallback: fmt.Sprintf("Error processing request %s", payload.RequestID),
		Text: fmt.Sprintf(
			":x: **Error**\n\n**Request:** `%s`\n**Account:** `%s`\n\n%s",
			payload.RequestID, payload.AccountID, details,
		),
	}

	h.postAttachment(payload.ChannelID, attachment)
}

// postAttachment creates a post with a Slack-style attachment in the given channel.
func (h *Handler) postAttachment(channelID string, attachment *model.SlackAttachment) {
	post := &model.Post{
		ChannelId: channelID,
		Message:   "",
		Props: model.StringInterface{
			"attachments": []*model.SlackAttachment{attachment},
		},
	}

	if _, appErr := h.api.CreatePost(post); appErr != nil {
		h.api.LogError("Failed to post webhook message",
			"channel_id", channelID,
			"error", appErr.Error(),
		)
	}
}
