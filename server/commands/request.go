package commands

import (
	"context"
	"fmt"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"

	"github.com/dgwhited/mattermost-plugin-aws-jit-access/server/api"
)

const (
	dialogCallbackURL = "/plugins/com.dgwhited.jit-access/api/v1/request-dialog"
)

// flexString extracts a string from an interface{} value. Handles both string
// and fmt.Stringer types. Returns "" for nil or non-string types.
func flexString(v interface{}) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

// RequestHandler handles the /jit request command and dialog submissions.
type RequestHandler struct {
	api    plugin.API
	client *api.Client
}

// NewRequestHandler creates a new RequestHandler.
func NewRequestHandler(api plugin.API, client *api.Client) *RequestHandler {
	return &RequestHandler{
		api:    api,
		client: client,
	}
}

// HandleRequestCommand opens an interactive dialog for creating a JIT request.
func (h *RequestHandler) HandleRequestCommand(args *model.CommandArgs) (*model.CommandResponse, *model.AppError) {
	// Fetch bound accounts for the channel to populate the dropdown.
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	accounts, err := h.client.GetBoundAccounts(ctx, args.ChannelId)
	if err != nil {
		return ephemeralResponse(h.api, args,
			fmt.Sprintf("Failed to fetch bound accounts: %s", err.Error())), nil
	}

	if len(accounts) == 0 {
		return ephemeralResponse(h.api, args,
			"No AWS accounts are bound to this channel. Ask an admin to run `/jit bind <account_id>` first."), nil
	}

	// Determine the max duration from the config. Use the minimum across
	// all bound accounts to be safe (usually there's only one).
	maxMinutes := 480 // default fallback
	for _, acct := range accounts {
		if acct.MaxRequestHours > 0 {
			acctMax := acct.MaxRequestHours * 60
			if acctMax < maxMinutes {
				maxMinutes = acctMax
			}
		}
	}

	// Build the account dropdown options.
	accountOptions := make([]*model.PostActionOptions, 0, len(accounts))
	for _, acct := range accounts {
		accountOptions = append(accountOptions, &model.PostActionOptions{
			Text:  acct.AccountID,
			Value: acct.AccountID,
		})
	}

	// Use the SiteURL for the dialog callback. If the server is behind
	// Docker/NAT where the external IP isn't reachable from inside the
	// container, fall back to http://localhost:<port>.
	siteURL := *h.api.GetConfig().ServiceSettings.SiteURL
	listenAddr := *h.api.GetConfig().ServiceSettings.ListenAddress
	if listenAddr == "" {
		listenAddr = ":8065"
	}
	callbackBase := fmt.Sprintf("http://localhost%s", listenAddr)
	_ = siteURL // keep for action button URLs (browser-facing)

	dialog := model.OpenDialogRequest{
		TriggerId: args.TriggerId,
		URL:       callbackBase + dialogCallbackURL,
		Dialog: model.Dialog{
			CallbackId:       "jit_request_dialog",
			Title:            "Request JIT AWS Access",
			IntroductionText: "Fill in the details below to request temporary AWS access.",
			SubmitLabel:      "Submit Request",
			Elements: []model.DialogElement{
				{
					DisplayName: "AWS Account",
					Name:        "account_id",
					Type:        "select",
					Options:     accountOptions,
					Optional:    false,
					HelpText:    "Select the AWS account to request access to.",
				},
				{
					DisplayName: "Duration (minutes)",
					Name:        "duration",
					Type:        "text",
					SubType:     "number",
					Default:     "60",
					Optional:    false,
					HelpText:    fmt.Sprintf("How long (in minutes) do you need access? Maximum %d.", maxMinutes),
				},
				{
					DisplayName: "Jira Link",
					Name:        "jira_link",
					Type:        "text",
					Optional:    false,
					HelpText:    "Jira ticket link related to this request.",
				},
				{
					DisplayName: "Reason",
					Name:        "reason",
					Type:        "textarea",
					Optional:    false,
					HelpText:    "Describe why you need this access.",
				},
			},
		},
	}

	if appErr := h.api.OpenInteractiveDialog(dialog); appErr != nil {
		return ephemeralResponse(h.api, args,
			fmt.Sprintf("Failed to open request dialog: %s", appErr.Message)), nil
	}

	return &model.CommandResponse{}, nil
}

// HandleRequestSubmit processes the dialog submission and creates a JIT
// request via the backend API. It also posts an interactive approval card
// in the channel.
func (h *RequestHandler) HandleRequestSubmit(submission map[string]interface{}, userID, channelID string) (*model.CommandResponse, *model.AppError) {
	// Extract fields with flexible type handling. Mattermost dialog submissions
	// may return text/number fields as either string or float64 depending on
	// the subtype and Mattermost version.
	accountID := flexString(submission["account_id"])
	durationRaw := submission["duration"]
	jiraLink := flexString(submission["jira_link"])
	reason := flexString(submission["reason"])

	h.api.LogInfo("HandleRequestSubmit called",
		"userID", userID,
		"channelID", channelID,
		"accountID", accountID,
		"durationRaw", fmt.Sprintf("%v (type %T)", durationRaw, durationRaw),
		"jiraLink", jiraLink,
		"reason", reason,
	)

	if accountID == "" || reason == "" {
		h.api.LogError("Validation failed", "accountID", accountID, "reason", reason)
		return nil, model.NewAppError("HandleRequestSubmit", "jit.request.validation", nil, "account_id and reason are required", 400)
	}

	duration := 60
	switch v := durationRaw.(type) {
	case string:
		if v != "" {
			if _, err := fmt.Sscanf(v, "%d", &duration); err != nil {
				return nil, model.NewAppError("HandleRequestSubmit", "jit.request.validation", nil, "invalid duration", 400)
			}
		}
	case float64:
		duration = int(v)
	case nil:
		// keep default
	default:
		h.api.LogWarn("Unexpected duration type", "type", fmt.Sprintf("%T", durationRaw), "value", fmt.Sprintf("%v", durationRaw))
	}

	if duration < 1 {
		return nil, model.NewAppError("HandleRequestSubmit", "jit.request.validation", nil, "duration must be at least 1 minute", 400)
	}

	// Get the requesting user's email.
	user, appErr := h.api.GetUser(userID)
	if appErr != nil {
		h.api.LogError("Failed to get user", "userID", userID, "error", appErr.Message)
		return nil, appErr
	}

	h.api.LogInfo("Creating backend request",
		"email", user.Email,
		"accountID", accountID,
		"duration", fmt.Sprintf("%d", duration),
	)

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	input := api.CreateRequestInput{
		RequesterMMUserID:        userID,
		RequesterEmail:           user.Email,
		AccountID:                accountID,
		ChannelID:                channelID,
		RequestedDurationMinutes: duration,
		Jira:                     jiraLink,
		Reason:                   reason,
	}

	jitReq, err := h.client.CreateRequest(ctx, input)
	if err != nil {
		h.api.LogError("Backend CreateRequest failed", "error", err.Error())
		errPost := &model.Post{
			UserId:    userID,
			ChannelId: channelID,
			Message:   fmt.Sprintf(":x: Failed to create JIT request: %s", err.Error()),
		}
		h.api.SendEphemeralPost(userID, errPost)
		return &model.CommandResponse{}, nil
	}

	h.api.LogInfo("Backend CreateRequest succeeded", "requestID", jitReq.RequestID)

	// Post an interactive approval card in the channel.
	jiraInfo := ""
	if jiraLink != "" {
		jiraInfo = fmt.Sprintf("\n**Jira:** %s", jiraLink)
	}

	// Action button integration URL. Use a relative plugin path — Mattermost
	// internally routes /plugins/{id}/... to the plugin's ServeHTTP.
	actionURL := "/plugins/com.dgwhited.jit-access/api/v1/action"

	attachment := &model.SlackAttachment{
		Color:    "#2389D7",
		Title:    fmt.Sprintf("JIT Access Request: %s", jitReq.RequestID),
		Fallback: fmt.Sprintf("JIT access request %s by @%s", jitReq.RequestID, user.Username),
		Text: fmt.Sprintf(
			"**Requester:** @%s\n**Account:** `%s`\n**Duration:** %d minutes\n**Reason:** %s%s",
			user.Username, accountID, duration, reason, jiraInfo,
		),
		Actions: []*model.PostAction{
			{
				// Id left empty — Mattermost auto-generates an alphanumeric ID
				// that matches the route regex [A-Za-z0-9]+. Custom IDs with
				// underscores/hyphens cause 404s on the DoPostAction endpoint.
				Name:  "Approve",
				Type:  model.PostActionTypeButton,
				Style: "good",
				Integration: &model.PostActionIntegration{
					URL: actionURL,
					Context: map[string]interface{}{
						"action":     "approve",
						"request_id": jitReq.RequestID,
						"requester":  user.Username,
						"account_id": accountID,
						"duration":   duration,
						"reason":     reason,
						"jira_link":  jiraLink,
					},
				},
			},
			{
				Name:  "Deny",
				Type:  model.PostActionTypeButton,
				Style: "danger",
				Integration: &model.PostActionIntegration{
					URL: actionURL,
					Context: map[string]interface{}{
						"action":     "deny",
						"request_id": jitReq.RequestID,
						"requester":  user.Username,
						"account_id": accountID,
						"duration":   duration,
						"reason":     reason,
						"jira_link":  jiraLink,
					},
				},
			},
		},
	}

	post := &model.Post{
		UserId:    userID,
		ChannelId: channelID,
		Props: model.StringInterface{
			"attachments": []*model.SlackAttachment{attachment},
		},
	}
	h.api.CreatePost(post)

	return &model.CommandResponse{}, nil
}
