package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
	mmPlugin "github.com/mattermost/mattermost/server/public/plugin"

	"github.com/dgwhited/mattermost-plugin-aws-jit-access/server/api"
	"github.com/dgwhited/mattermost-plugin-aws-jit-access/server/commands"
	"github.com/dgwhited/mattermost-plugin-aws-jit-access/server/webhook"
)

const (
	routeWebhook       = "/webhook"
	routeRequestDialog = "/api/v1/request-dialog"
	routeAction        = "/api/v1/action"
	routeDenyDialog    = "/api/v1/deny-dialog"
)

// mmUserIDHeader is the header Mattermost sets on authenticated requests routed
// to plugin ServeHTTP. It contains the real user ID from the session.
const mmUserIDHeader = "Mattermost-User-Id"

// authenticateMMUser verifies that the Mattermost-User-Id header is present and
// matches the UserId in the parsed request body. This prevents spoofing via
// direct HTTP calls with forged JSON bodies (threat S5).
func authenticateMMUser(r *http.Request, bodyUserID string) (string, error) {
	headerUserID := r.Header.Get(mmUserIDHeader)
	if headerUserID == "" {
		return "", fmt.Errorf("unauthenticated: missing %s header", mmUserIDHeader)
	}
	if headerUserID != bodyUserID {
		return "", fmt.Errorf("forbidden: %s header (%s) does not match body UserId (%s)", mmUserIDHeader, headerUserID, bodyUserID)
	}
	return headerUserID, nil
}

// ServeHTTP routes inbound HTTP requests to the appropriate handler via the
// gorilla/mux router initialised in OnActivate.
func (p *Plugin) ServeHTTP(_ *mmPlugin.Context, w http.ResponseWriter, r *http.Request) {
	p.router.ServeHTTP(w, r)
}

// handleWebhook delegates to the webhook handler.
func (p *Plugin) handleWebhook(w http.ResponseWriter, r *http.Request) {
	validator := p.getValidator()
	handler := webhook.NewHandler(p.API, validator)
	handler.ServeHTTP(w, r)
}

// handleSubmitDialogRequest processes dialog submissions from the JIT request
// modal.
func (p *Plugin) handleSubmitDialogRequest(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		p.API.LogError("Failed to read dialog request body", "error", err.Error())
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer func() { _ = r.Body.Close() }()

	var request model.SubmitDialogRequest
	if err := json.Unmarshal(body, &request); err != nil {
		p.API.LogError("Failed to unmarshal dialog request", "error", err.Error())
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// NOTE: No Mattermost-User-Id header check here. Dialog callbacks use
	// http://localhost:<port> and are routed internally by the MM server,
	// which does not inject the header. The UserId in the body is set
	// server-side from the authenticated session and cannot be spoofed
	// externally (localhost is not reachable from outside the container).

	client := p.getAPIClient()
	if client == nil {
		p.API.LogError("API client is nil — plugin not fully configured")
		writeDialogError(w, "Plugin is not fully configured.")
		return
	}

	handler := commands.NewRequestHandler(p.API, client)

	_, appErr := handler.HandleRequestSubmit(request.Submission, request.UserId, request.ChannelId)
	if appErr != nil {
		p.API.LogError("HandleRequestSubmit returned error",
			"error", appErr.Message,
			"detailedError", appErr.DetailedError,
		)
		writeDialogError(w, appErr.Message)
		return
	}

	// Return an empty 200 response to close the dialog successfully.
	resp := model.SubmitDialogResponse{}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// contextString safely extracts a string from the PostAction context map.
func contextString(ctx map[string]any, key string) string {
	v, _ := ctx[key].(string)
	return v
}

// contextInt safely extracts an int from the PostAction context map.
// Mattermost may store numbers as float64 in JSON round-trips.
func contextInt(ctx map[string]any, key string) int {
	switch v := ctx[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		var n int
		_, _ = fmt.Sscanf(v, "%d", &n)
		return n
	}
	return 0
}

// handlePostAction processes interactive button clicks (Approve/Deny).
func (p *Plugin) handlePostAction(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer func() { _ = r.Body.Close() }()

	var request model.PostActionIntegrationRequest
	if err := json.Unmarshal(body, &request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// S5: Verify the caller is the authenticated Mattermost user.
	if _, err := authenticateMMUser(r, request.UserId); err != nil {
		p.API.LogWarn("Post action auth failed", "error", err.Error())
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	action := contextString(request.Context, "action")
	requestID := contextString(request.Context, "request_id")

	if action == "" || requestID == "" {
		writeActionResponse(w, "Invalid action parameters.")
		return
	}

	// Extract rich context passed from the approval card.
	requester := contextString(request.Context, "requester")
	accountID := contextString(request.Context, "account_id")
	duration := contextInt(request.Context, "duration")
	reason := contextString(request.Context, "reason")
	jiraLink := contextString(request.Context, "jira_link")

	userID := request.UserId
	channelID := request.ChannelId

	// Get the acting user.
	actingUser, appErr := p.API.GetUser(userID)
	if appErr != nil {
		writeActionResponse(w, "Failed to identify acting user.")
		return
	}

	client := p.getAPIClient()
	if client == nil {
		writeActionResponse(w, "Plugin is not fully configured.")
		return
	}

	// Verify the acting user is an approver for this channel's bound accounts.
	isApprover, checkErr := p.isUserApprover(userID, channelID)
	if checkErr != nil {
		p.API.LogError("Failed to check approver status", "error", checkErr.Error())
		writeActionResponse(w, "Failed to verify approver status.")
		return
	}

	if !isApprover && !p.isSystemAdmin(userID) {
		p.API.SendEphemeralPost(userID, &model.Post{
			UserId:    userID,
			ChannelId: channelID,
			Message:   "You are not authorized to approve or deny requests in this channel.",
		})
		writeActionResponse(w, "")
		return
	}

	switch action {
	case "approve":
		p.handleApprove(w, client, request, actingUser, requestID, requester, accountID, duration, reason, jiraLink)
	case "deny":
		p.handleDenyButtonClick(w, request, requestID, requester, accountID, duration, reason, jiraLink)
	default:
		writeActionResponse(w, fmt.Sprintf("Unknown action: %s", action))
	}
}

// handleApprove processes the Approve button click.
func (p *Plugin) handleApprove(
	w http.ResponseWriter,
	client *api.Client,
	request model.PostActionIntegrationRequest,
	actingUser *model.User,
	requestID, requester, accountID string,
	duration int,
	reason, jiraLink string,
) {
	userID := request.UserId
	channelID := request.ChannelId

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	input := api.ApproveRequestInput{
		ApproverMMUserID: userID,
		ApproverEmail:    actingUser.Email,
	}
	if err := client.ApproveRequest(ctx, requestID, input); err != nil {
		p.API.SendEphemeralPost(userID, &model.Post{
			UserId:    userID,
			ChannelId: channelID,
			Message:   fmt.Sprintf("Failed to approve request `%s`: %s", requestID, err.Error()),
		})
		writeActionResponse(w, "")
		return
	}

	// Update the original post in-place — replace the card with a resolved summary.
	// No separate confirmation post; the original card is the single source of truth.
	jiraInfo := ""
	if jiraLink != "" {
		jiraInfo = fmt.Sprintf("\n**Jira:** %s", jiraLink)
	}
	resp := &model.PostActionIntegrationResponse{
		Update: &model.Post{
			Message: "",
			Props: model.StringInterface{
				"attachments": []*model.SlackAttachment{
					{
						Color: "#36a64f",
						Title: fmt.Sprintf(":white_check_mark: APPROVED — %s", requestID),
						Text: fmt.Sprintf(
							"**Requester:** @%s\n**Account:** `%s`\n**Duration:** %d minutes\n**Reason:** %s%s\n\n*Approved by @%s*",
							requester, accountID, duration, reason, jiraInfo, actingUser.Username,
						),
					},
				},
			},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// handleDenyButtonClick opens a dialog prompting the approver for a denial reason.
func (p *Plugin) handleDenyButtonClick(
	w http.ResponseWriter,
	request model.PostActionIntegrationRequest,
	requestID, requester, accountID string,
	duration int,
	reason, jiraLink string,
) {
	listenAddr := *p.API.GetConfig().ServiceSettings.ListenAddress
	callbackBase := fmt.Sprintf("http://localhost%s", listenAddr)

	// Encode the request context into the dialog state so we can use it
	// when the dialog is submitted.
	stateMap := map[string]any{
		"request_id": requestID,
		"requester":  requester,
		"account_id": accountID,
		"duration":   duration,
		"reason":     reason,
		"jira_link":  jiraLink,
		"post_id":    request.PostId,
		"channel_id": request.ChannelId,
	}
	stateBytes, _ := json.Marshal(stateMap)

	dialog := model.OpenDialogRequest{
		TriggerId: request.TriggerId,
		URL:       callbackBase + "/plugins/com.dgwhited.jit-access" + routeDenyDialog,
		Dialog: model.Dialog{
			CallbackId:       "jit_deny_dialog",
			Title:            "Deny JIT Access Request",
			IntroductionText: fmt.Sprintf("Denying request `%s` by @%s for account `%s` (%d min).", requestID, requester, accountID, duration),
			SubmitLabel:      "Deny Request",
			State:            string(stateBytes),
			Elements: []model.DialogElement{
				{
					DisplayName: "Reason for Denial",
					Name:        "deny_reason",
					Type:        "textarea",
					Optional:    false,
					HelpText:    "Explain why this request is being denied.",
				},
			},
		},
	}

	if appErr := p.API.OpenInteractiveDialog(dialog); appErr != nil {
		p.API.LogError("Failed to open deny dialog", "error", appErr.Error())
		writeActionResponse(w, "Failed to open denial dialog.")
		return
	}

	// Return empty response — the dialog handles the rest.
	writeActionResponse(w, "")
}

// handleDenyDialogSubmit processes the denial reason dialog submission.
func (p *Plugin) handleDenyDialogSubmit(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer func() { _ = r.Body.Close() }()

	var req model.SubmitDialogRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// NOTE: No Mattermost-User-Id header check here — same reason as
	// handleSubmitDialogRequest: deny dialog callback goes through localhost.

	// Parse the state we encoded when opening the dialog.
	var state map[string]any
	if err := json.Unmarshal([]byte(req.State), &state); err != nil {
		writeDialogError(w, "Invalid dialog state.")
		return
	}

	requestID := contextString(state, "request_id")
	requester := contextString(state, "requester")
	accountID := contextString(state, "account_id")
	duration := contextInt(state, "duration")
	reason := contextString(state, "reason")
	jiraLink := contextString(state, "jira_link")
	postID := contextString(state, "post_id")
	_ = contextString(state, "channel_id") // extracted but not used; kept for state completeness
	denyReason, _ := req.Submission["deny_reason"].(string)

	if requestID == "" {
		writeDialogError(w, "Missing request ID.")
		return
	}
	if denyReason == "" {
		resp := model.SubmitDialogResponse{
			Errors: map[string]string{"deny_reason": "A reason for denial is required."},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	userID := req.UserId
	actingUser, appErr := p.API.GetUser(userID)
	if appErr != nil {
		writeDialogError(w, "Failed to identify user.")
		return
	}

	client := p.getAPIClient()
	if client == nil {
		writeDialogError(w, "Plugin is not fully configured.")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	input := api.DenyRequestInput{
		DenierMMUserID: userID,
		DenierEmail:    actingUser.Email,
		Reason:         denyReason,
	}
	if err := client.DenyRequest(ctx, requestID, input); err != nil {
		writeDialogError(w, fmt.Sprintf("Failed to deny request: %s", err.Error()))
		return
	}

	// Update the original approval card in-place — no separate denial post.
	jiraInfo := ""
	if jiraLink != "" {
		jiraInfo = fmt.Sprintf("\n**Jira:** %s", jiraLink)
	}
	if postID != "" {
		updatedPost, getErr := p.API.GetPost(postID)
		if getErr == nil {
			updatedPost.Message = ""
			updatedPost.Props = model.StringInterface{
				"attachments": []*model.SlackAttachment{
					{
						Color: "#d9534f",
						Title: fmt.Sprintf(":no_entry_sign: DENIED — %s", requestID),
						Text: fmt.Sprintf(
							"**Requester:** @%s\n**Account:** `%s`\n**Duration:** %d minutes\n**Request Reason:** %s%s\n\n**Denial Reason:** %s\n*Denied by @%s*",
							requester, accountID, duration, reason, jiraInfo, denyReason, actingUser.Username,
						),
					},
				},
			}
			_, _ = p.API.UpdatePost(updatedPost)
		}
	}

	// Close the dialog with success.
	resp := model.SubmitDialogResponse{}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// isUserApprover checks whether the given user is listed as an approver for
// any account bound to the given channel.
func (p *Plugin) isUserApprover(userID, channelID string) (bool, error) {
	client := p.getAPIClient()
	if client == nil {
		return false, fmt.Errorf("API client not configured")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	configs, err := client.GetBoundAccounts(ctx, channelID)
	if err != nil {
		return false, err
	}

	for _, cfg := range configs {
		if slices.Contains(cfg.ApproverMMUserIDs, userID) {
			return true, nil
		}
	}

	return false, nil
}

// writeDialogError writes an error response for a dialog submission.
func writeDialogError(w http.ResponseWriter, message string) {
	resp := model.SubmitDialogResponse{
		Error: message,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// writeActionResponse writes a simple post-action integration response.
func writeActionResponse(w http.ResponseWriter, ephemeralText string) {
	resp := &model.PostActionIntegrationResponse{}
	if ephemeralText != "" {
		resp.EphemeralText = ephemeralText
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
